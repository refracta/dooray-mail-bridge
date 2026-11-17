package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
)

type codeRecord struct {
	Code            string          `json:"code"`
	ID              json.RawMessage `json:"id"`
	Date            string          `json:"date"`
	ServerTime      int64           `json:"serverTime"`
	imapUIDValidity uint32
	imapUIDNext     imap.UID
	imapUID         imap.UID
}

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

func (r codeRecord) id() string {
	v := strings.TrimSpace(string(r.ID))
	if v == "null" || v == `""` {
		return ""
	}
	return strings.Trim(v, `"`)
}
func freshCode(baseline, current codeRecord) bool {
	if !sixDigits.MatchString(current.Code) || current.id() == "" || current.id() == baseline.id() || baseline.ServerTime <= 0 || current.ServerTime < baseline.ServerTime {
		return false
	}
	if baseline.imapUIDNext != 0 && (current.imapUIDValidity != baseline.imapUIDValidity || current.imapUID < baseline.imapUIDNext) {
		return false
	}
	date, err := time.Parse(time.RFC3339Nano, current.Date)
	if err != nil {
		return false
	}
	ms := date.UnixMilli()
	return ms >= baseline.ServerTime-5000 && ms <= current.ServerTime+5000 && current.ServerTime-ms <= 180000
}
func (s *Session) readCode(ctx context.Context) (codeRecord, error) {
	if s.opts.CodeSource == "imap" {
		return s.codeIMAP.baseline(ctx)
	}
	return s.readHTTPCode(ctx)
}

func (s *Session) readHTTPCode(ctx context.Context) (codeRecord, error) {
	var code codeRecord
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.opts.CodeURL, nil)
	if err != nil {
		return code, errors.New("invalid verification endpoint")
	}
	req.Header.Set("Cache-Control", "no-cache")
	if s.opts.CodeToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.opts.CodeToken)
	}
	resp, err := s.codeClient.Do(req)
	if err != nil {
		return code, errors.New("verification endpoint is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return code, errors.New("verification endpoint did not return success")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&code); err != nil || code.ServerTime <= 0 {
		return codeRecord{}, errors.New("invalid verification endpoint response")
	}
	return code, nil
}
func (s *Session) waitCode(ctx context.Context, baseline codeRecord) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 170*time.Second)
	defer cancel()
	delay := time.Second
	for {
		if err := wait(ctx, delay); err != nil {
			return "", errors.New("timed out waiting for a fresh KAIST verification email")
		}
		var current codeRecord
		var err error
		if s.opts.CodeSource == "imap" {
			current, err = s.codeIMAP.next(ctx, baseline)
		} else {
			current, err = s.readHTTPCode(ctx)
		}
		if err != nil {
			if errors.Is(err, errCodeIMAPAuthentication) || errors.Is(err, errCodeMailboxReset) {
				return "", err
			}
			if delay < 8*time.Second {
				delay *= 2
			}
			continue
		}
		delay = time.Second
		if freshCode(baseline, current) {
			return current.Code, nil
		}
	}
}

func (s *Session) closeCodeSource() {
	if s.codeIMAP != nil {
		s.codeIMAP.close()
	}
}
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
