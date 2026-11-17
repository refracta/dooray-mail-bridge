package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

var errCodeIMAPAuthentication = errors.New("verification IMAP authentication was rejected")
var errCodeMailboxReset = errors.New("verification mailbox UID namespace changed or UIDNEXT moved backwards; restart the login attempt")
var errCodeIMAPUnavailable = errors.New("verification IMAP mailbox is unavailable")

const maxCodeMessageBytes = 1 << 20
const maxCodeCandidates = 32

// imapCodeSource only holds a connection during an email verification attempt.
// There is no mailbox mirroring, background polling, or persistent mail cache.
type imapCodeSource struct {
	opts        Options
	mu          sync.Mutex
	client      *imapclient.Client
	conn        net.Conn
	tlsConfig   *tls.Config
	lastUIDNext imap.UID
	lastRecord  codeRecord
}

func newIMAPCodeSource(opts Options) *imapCodeSource {
	host, _, _ := net.SplitHostPort(opts.CodeIMAPAddr)
	return &imapCodeSource{opts: opts, tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}
}

func (s *imapCodeSource) connect(ctx context.Context) error {
	if s.client != nil {
		return nil
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: s.tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", s.opts.CodeIMAPAddr)
	if err != nil {
		return fmt.Errorf("%w: TLS connection failed", errCodeIMAPUnavailable)
	}
	s.conn = conn
	s.client = imapclient.New(conn, nil)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := s.client.Login(s.opts.CodeIMAPUsername, s.opts.CodeIMAPPassword).Wait(); err != nil {
		s.closeLocked()
		var status *imap.Error
		if errors.As(err, &status) && status.Code != imap.ResponseCodeUnavailable {
			return errCodeIMAPAuthentication
		}
		return fmt.Errorf("%w: greeting or login failed", errCodeIMAPUnavailable)
	}
	return nil
}

func (s *imapCodeSource) closeLocked() {
	if s.client != nil {
		s.client.Close()
	}
	s.client = nil
	s.conn = nil
}

func (s *imapCodeSource) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	s.lastUIDNext = 0
	s.lastRecord = codeRecord{}
}

func (s *imapCodeSource) examine(ctx context.Context) (*imap.SelectData, error) {
	if err := s.connect(ctx); err != nil {
		return nil, err
	}
	conn := s.conn
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	selected, err := s.client.Select(s.opts.CodeIMAPMailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		s.closeLocked()
		return nil, fmt.Errorf("%w: read-only EXAMINE failed", errCodeIMAPUnavailable)
	}
	// Naver reports UIDVALIDITY 0 in practice. Keep it as a real namespace
	// token; UIDNEXT, not nonzero UIDVALIDITY, identifies an IMAP baseline.
	if selected.UIDNext == 0 {
		s.closeLocked()
		return nil, fmt.Errorf("%w: mailbox did not provide UIDNEXT", errCodeIMAPUnavailable)
	}
	return selected, nil
}

func (s *imapCodeSource) baseline(ctx context.Context) (codeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	selected, err := s.examine(ctx)
	if err != nil {
		return codeRecord{}, err
	}
	id, _ := json.Marshal(fmt.Sprintf("imap:%d:before:%d", selected.UIDValidity, selected.UIDNext))
	record := codeRecord{ID: id, ServerTime: time.Now().UnixMilli(), imapUIDValidity: selected.UIDValidity, imapUIDNext: selected.UIDNext}
	s.lastUIDNext = 0
	s.lastRecord = codeRecord{}
	return record, nil
}

func (s *imapCodeSource) next(ctx context.Context, baseline codeRecord) (codeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	selected, err := s.examine(ctx)
	if err != nil {
		return codeRecord{}, err
	}
	if baseline.imapUIDNext == 0 || selected.UIDValidity != baseline.imapUIDValidity || selected.UIDNext < baseline.imapUIDNext || s.lastUIDNext != 0 && selected.UIDNext < s.lastUIDNext {
		s.closeLocked()
		return codeRecord{}, errCodeMailboxReset
	}
	now := time.Now()
	if selected.UIDNext == s.lastUIDNext {
		record := s.lastRecord
		record.ServerTime = now.UnixMilli()
		return record, nil
	}
	if selected.UIDNext <= baseline.imapUIDNext {
		return codeRecord{ServerTime: now.UnixMilli()}, nil
	}
	conn := s.conn
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	criteria := &imap.SearchCriteria{UID: []imap.UIDSet{{{Start: baseline.imapUIDNext, Stop: 0}}}, Header: []imap.SearchCriteriaHeaderField{{Key: "From", Value: verificationSender}}}
	result, err := s.client.UIDSearch(criteria, nil).Wait()
	if err != nil {
		s.closeLocked()
		return codeRecord{}, fmt.Errorf("%w: UID SEARCH failed", errCodeIMAPUnavailable)
	}
	uids := result.AllUIDs()
	sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
	if len(uids) > maxCodeCandidates {
		uids = uids[:maxCodeCandidates]
	}
	latest := codeRecord{ServerTime: now.UnixMilli()}
	for _, uid := range uids {
		// IMAP n:* can include the previous last UID when n is above it.
		if uid < baseline.imapUIDNext {
			continue
		}
		section := &imap.FetchItemBodySection{Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: maxCodeMessageBytes + 1}}
		messages, err := s.client.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{UID: true, InternalDate: true, RFC822Size: true, BodySection: []*imap.FetchItemBodySection{section}}).Collect()
		if err != nil {
			s.closeLocked()
			return codeRecord{}, fmt.Errorf("%w: BODY.PEEK fetch failed", errCodeIMAPUnavailable)
		}
		for _, message := range messages {
			if message.UID != uid || message.RFC822Size > maxCodeMessageBytes {
				continue
			}
			raw := message.FindBodySection(section)
			if len(raw) > maxCodeMessageBytes {
				continue
			}
			code, date, ok := parseVerificationMail(raw, s.opts.CodeIMAPRecipient)
			if !ok {
				continue
			}
			id, _ := json.Marshal(fmt.Sprintf("imap:%d:%d", selected.UIDValidity, uid))
			record := codeRecord{Code: code, ID: id, Date: date.Format(time.RFC3339Nano), ServerTime: now.UnixMilli(), imapUIDValidity: selected.UIDValidity, imapUID: uid}
			if freshCode(baseline, record) {
				latest = record
				break
			}
		}
		if latest.Code != "" {
			break
		}
	}
	s.lastUIDNext = selected.UIDNext
	s.lastRecord = latest
	return latest, nil
}
