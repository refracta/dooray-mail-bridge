package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"golang.org/x/text/encoding/korean"
)

type otpWireServer struct {
	t           *testing.T
	listener    net.Listener
	roots       *x509.CertPool
	mu          sync.Mutex
	conns       map[net.Conn]bool
	messages    map[uint32][]byte
	validity    uint32
	next        uint32
	authFailure bool
	dropSearch  bool
	hangFetch   bool
	connections int
	commands    []string
	fetched     []uint32
	wg          sync.WaitGroup
}

func newOTPWireServer(t *testing.T) *otpWireServer {
	t.Helper()
	https := httptest.NewTLSServer(nil)
	certificate := https.TLS.Certificates[0]
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	https.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &otpWireServer{t: t, listener: tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}), roots: roots, conns: map[net.Conn]bool{}, messages: map[uint32][]byte{}, validity: 12, next: 1}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[conn] = true
			s.connections++
			s.mu.Unlock()
			s.wg.Add(1)
			go s.serve(conn)
		}
	}()
	t.Cleanup(func() {
		s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *otpWireServer) add(raw []byte) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid := s.next
	s.next++
	s.messages[uid] = raw
	return uid
}

func (s *otpWireServer) serve(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer func() { s.mu.Lock(); delete(s.conns, conn); s.mu.Unlock() }()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fmt.Fprint(w, "* OK [CAPABILITY IMAP4rev1] fixture IMAP\r\n")
	w.Flush()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return
		}
		tag, command := parts[0], strings.ToUpper(parts[1])
		sub := ""
		if command == "UID" && len(parts) > 2 {
			sub = strings.ToUpper(parts[2])
		}
		s.mu.Lock()
		s.commands = append(s.commands, strings.TrimSpace(command+" "+sub))
		s.mu.Unlock()
		switch command {
		case "CAPABILITY":
			fmt.Fprintf(w, "* CAPABILITY IMAP4rev1\r\n%s OK capabilities\r\n", tag)
		case "LOGIN":
			s.mu.Lock()
			failed := s.authFailure
			s.mu.Unlock()
			if failed {
				fmt.Fprintf(w, "%s NO [AUTHENTICATIONFAILED] fixture rejected sensitive diagnostic\r\n", tag)
			} else {
				fmt.Fprintf(w, "%s OK login\r\n", tag)
			}
		case "EXAMINE":
			s.mu.Lock()
			count, validity, next := len(s.messages), s.validity, s.next
			s.mu.Unlock()
			fmt.Fprintf(w, "* FLAGS (\\Seen)\r\n* %d EXISTS\r\n* OK [UIDVALIDITY %d] stable\r\n* OK [UIDNEXT %d] next\r\n%s OK [READ-ONLY] examined\r\n", count, validity, next, tag)
		case "UID":
			switch sub {
			case "SEARCH":
				s.mu.Lock()
				drop := s.dropSearch
				s.dropSearch = false
				uids := make([]uint32, 0, len(s.messages))
				for uid := range s.messages {
					uids = append(uids, uid)
				}
				s.mu.Unlock()
				if drop {
					return
				}
				sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
				fmt.Fprint(w, "* SEARCH")
				for _, uid := range uids {
					fmt.Fprintf(w, " %d", uid)
				}
				fmt.Fprintf(w, "\r\n%s OK search\r\n", tag)
			case "FETCH":
				if len(parts) < 4 {
					return
				}
				id, err := strconv.ParseUint(parts[3], 10, 32)
				if err != nil {
					s.t.Error("unexpected UID set")
					return
				}
				if !strings.Contains(strings.ToUpper(line), "BODY.PEEK[]<0.") {
					s.t.Error("OTP fetch did not use bounded BODY.PEEK")
					return
				}
				s.mu.Lock()
				raw := append([]byte(nil), s.messages[uint32(id)]...)
				s.fetched = append(s.fetched, uint32(id))
				hang := s.hangFetch
				s.mu.Unlock()
				if hang {
					r.ReadString('\n')
					return
				}
				if len(raw) > 0 {
					fmt.Fprintf(w, "* 1 FETCH (UID %d INTERNALDATE %q RFC822.SIZE %d BODY[]<0> {%d}\r\n", id, time.Now().Format("02-Jan-2006 15:04:05 -0700"), len(raw), len(raw))
					w.Write(raw)
					fmt.Fprint(w, ")\r\n")
				}
				fmt.Fprintf(w, "%s OK fetched\r\n", tag)
			default:
				s.t.Errorf("unexpected UID command %s", sub)
				return
			}
		case "LOGOUT":
			fmt.Fprintf(w, "* BYE closing\r\n%s OK logout\r\n", tag)
			w.Flush()
			return
		default:
			s.t.Errorf("OTP reader issued unexpected or mutating command %s", command)
			return
		}
		if err := w.Flush(); err != nil {
			return
		}
	}
}

func (s *otpWireServer) source(t *testing.T) *imapCodeSource {
	t.Helper()
	opts, err := normalizeCodeOptions(Options{CodeSource: "imap", CodeIMAPAddr: s.listener.Addr().String(), CodeIMAPUsername: "verify@example.invalid", CodeIMAPPassword: "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	source := newIMAPCodeSource(opts)
	source.tlsConfig.RootCAs = s.roots
	t.Cleanup(source.close)
	return source
}

func verificationMIME(code string, date time.Time) []byte {
	body := "<html><head><script>999999</script></head><body>본인 인증번호 <span>" + code + "</span></body></html>"
	return []byte(strings.Join([]string{"From: KAIST <" + verificationSender + ">", "To: verify@example.invalid", "Subject: " + mime.BEncoding.Encode("UTF-8", verificationSubject), "Date: " + date.Format(time.RFC1123Z), "MIME-Version: 1.0", "Content-Type: text/html; charset=UTF-8", "Content-Transfer-Encoding: base64", "", base64.StdEncoding.EncodeToString([]byte(body))}, "\r\n"))
}

func TestIMAPCodeWatermarkFilteringAndNoMutation(t *testing.T) {
	server := newOTPWireServer(t)
	source := server.source(t)
	now := time.Now().UTC().Truncate(time.Second)
	old := server.add(verificationMIME("012345", now))
	baseline, err := source.baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if baseline.imapUIDNext != 2 || baseline.imapUIDValidity != 12 || baseline.Code != "" {
		t.Fatal("baseline did not capture mailbox watermark")
	}
	// An identical old code in a newer message must still count as new mail.
	newUID := server.add(verificationMIME("012345", now))
	wrongFrom := strings.Replace(string(verificationMIME("111111", now)), verificationSender, "spoof@example.invalid", 1)
	server.add([]byte(wrongFrom))
	wrongRecipient := strings.Replace(string(verificationMIME("222222", now)), "verify@example.invalid", "other@example.invalid", 1)
	server.add([]byte(wrongRecipient))
	wrongSubject := strings.Replace(string(verificationMIME("333333", now)), mime.BEncoding.Encode("UTF-8", verificationSubject), "Unrelated", 1)
	server.add([]byte(wrongSubject))
	server.add(verificationMIME("444444", now.Add(-time.Hour)))
	current, err := source.next(context.Background(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	if current.Code != "012345" || current.imapUID != imap.UID(newUID) || !freshCode(baseline, current) {
		t.Fatal("new matching OTP was not selected")
	}
	server.mu.Lock()
	before := len(server.fetched)
	for _, uid := range server.fetched {
		if uid == old {
			t.Error("pre-baseline message was downloaded")
		}
	}
	server.mu.Unlock()
	if _, err := source.next(context.Background(), baseline); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	if len(server.fetched) != before {
		t.Error("unchanged UIDs were fetched again")
	}
	server.mu.Unlock()
	latestUID := server.add(verificationMIME("098765", now))
	current, err = source.next(context.Background(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	if current.Code != "098765" || current.imapUID != imap.UID(latestUID) {
		t.Fatal("newest matching code was not selected")
	}
	source.close()
}

func TestIMAPCodeReconnectAndUIDValidityReset(t *testing.T) {
	server := newOTPWireServer(t)
	source := server.source(t)
	baseline, err := source.baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	server.add(verificationMIME("012345", time.Now()))
	server.mu.Lock()
	server.dropSearch = true
	server.mu.Unlock()
	if _, err := source.next(context.Background(), baseline); !errors.Is(err, errCodeIMAPUnavailable) {
		t.Fatal("dropped connection did not fail explicitly")
	}
	current, err := source.next(context.Background(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	if current.Code != "012345" {
		t.Fatal("reconnected reader lost baseline")
	}
	server.mu.Lock()
	connections := server.connections
	server.validity++
	server.mu.Unlock()
	if connections != 2 {
		t.Fatalf("expected one reconnect, got %d connections", connections)
	}
	if _, err := source.next(context.Background(), baseline); !errors.Is(err, errCodeMailboxReset) {
		t.Fatal("UIDVALIDITY reset reused message IDs")
	}
}

func TestIMAPCodeNaverZeroUIDValidityAndCounterRegression(t *testing.T) {
	server := newOTPWireServer(t)
	source := server.source(t)
	server.mu.Lock()
	server.validity = 0
	server.mu.Unlock()
	server.add(verificationMIME("111111", time.Now()))
	baseline, err := source.baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if baseline.imapUIDValidity != 0 || baseline.imapUIDNext != 2 {
		t.Fatal("Naver zero UIDVALIDITY not preserved")
	}
	uid := server.add(verificationMIME("012345", time.Now()))
	record, err := source.next(context.Background(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	if record.Code != "012345" || !freshCode(baseline, record) || record.imapUID != imap.UID(uid) {
		t.Fatal("zero UIDVALIDITY rejected fresh OTP")
	}
	old := record
	old.imapUID = 1
	if freshCode(baseline, old) {
		t.Fatal("zero UIDVALIDITY disabled the UID watermark")
	}
	server.mu.Lock()
	server.validity = 1
	server.mu.Unlock()
	if _, err := source.next(context.Background(), baseline); !errors.Is(err, errCodeMailboxReset) {
		t.Fatal("zero-to-nonzero namespace change was missed")
	}
	server.mu.Lock()
	server.validity = 0
	server.next = 2
	server.mu.Unlock()
	if _, err := source.next(context.Background(), baseline); !errors.Is(err, errCodeMailboxReset) {
		t.Fatal("UIDNEXT regression with unchanged zero token was missed")
	}
}

func TestIMAPCodeAuthFailureTLSVerificationAndCancellation(t *testing.T) {
	server := newOTPWireServer(t)
	source := server.source(t)
	server.mu.Lock()
	server.authFailure = true
	server.mu.Unlock()
	if _, err := source.baseline(context.Background()); !errors.Is(err, errCodeIMAPAuthentication) || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("authentication failure leaked server text or was hidden")
	}
	server.mu.Lock()
	server.authFailure = false
	server.mu.Unlock()
	untrusted := newIMAPCodeSource(source.opts)
	defer untrusted.close()
	if _, err := untrusted.baseline(context.Background()); !errors.Is(err, errCodeIMAPUnavailable) {
		t.Fatal("untrusted TLS certificate was accepted")
	}
	baseline, err := source.baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	server.add(verificationMIME("012345", time.Now()))
	server.mu.Lock()
	server.hangFetch = true
	server.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := source.next(ctx, baseline); err == nil {
		t.Fatal("hung fetch succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("request cancellation did not close the IMAP connection")
	}
}

func TestVerificationMIMEScopesAndKoreanCharset(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	if code, date, ok := parseVerificationMail(verificationMIME("012345", now), "verify@example.invalid"); !ok || code != "012345" || !date.Equal(now) {
		t.Fatal("HTML/base64 Korean MIME failed")
	}
	encoded, err := korean.EUCKR.NewEncoder().Bytes([]byte("본인 인증번호는 098765 입니다."))
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(strings.Join([]string{"From: " + verificationSender, "To: verify@example.invalid", "Subject: " + mime.QEncoding.Encode("UTF-8", verificationSubject), "Date: " + now.Format(time.RFC1123Z), "Content-Type: text/plain; charset=EUC-KR", "Content-Transfer-Encoding: base64", "", base64.StdEncoding.EncodeToString(encoded)}, "\r\n"))
	if code, _, ok := parseVerificationMail(raw, "verify@example.invalid"); !ok || code != "098765" {
		t.Fatal("EUC-KR body was not decoded")
	}
	ambiguous := strings.Replace(string(verificationMIME("012345", now)), base64.StdEncoding.EncodeToString([]byte("<html><head><script>999999</script></head><body>본인 인증번호 <span>012345</span></body></html>")), base64.StdEncoding.EncodeToString([]byte("<body>012345 654321</body>")), 1)
	if _, _, ok := parseVerificationMail([]byte(ambiguous), "verify@example.invalid"); ok {
		t.Fatal("ambiguous verification code accepted")
	}
	if _, _, ok := parseVerificationMail(verificationMIME("012345", now), "another@example.invalid"); ok {
		t.Fatal("wrong recipient accepted")
	}
	if _, _, ok := parseVerificationMail(verificationMIME("00123456", now), "verify@example.invalid"); ok {
		t.Fatal("six digits inside a larger number accepted")
	}
}

func TestCodeSourceOptionsAndUIDFreshness(t *testing.T) {
	valid := Options{CodeSource: "imap", CodeIMAPAddr: "imap.example.invalid:993", CodeIMAPUsername: "verify@example.invalid", CodeIMAPPassword: "synthetic"}
	opts, err := normalizeCodeOptions(valid)
	if err != nil {
		t.Fatal(err)
	}
	if opts.CodeIMAPMailbox != "INBOX" || opts.CodeIMAPRecipient != valid.CodeIMAPUsername {
		t.Fatal("IMAP defaults missing")
	}
	for _, change := range []func(*Options){func(o *Options) { o.CodeIMAPAddr = "imap.example.invalid" }, func(o *Options) { o.CodeIMAPPassword = "" }, func(o *Options) { o.CodeIMAPUsername = "bare-user" }, func(o *Options) { o.CodeSource = "pop3" }} {
		bad := valid
		change(&bad)
		if _, err := normalizeCodeOptions(bad); err == nil {
			t.Fatal("invalid code-source configuration accepted")
		}
	}
	valid.CodeSource = ""
	valid.CodeURL = "https://codes.example.invalid/"
	opts, err = normalizeCodeOptions(valid)
	if err != nil || opts.CodeSource != "http" {
		t.Fatal("legacy HTTP configuration no longer takes precedence")
	}
	now := time.Now()
	base := codeRecord{ID: []byte(`"baseline"`), ServerTime: now.UnixMilli(), imapUIDValidity: 12, imapUIDNext: 10}
	current := codeRecord{Code: "012345", ID: []byte(`"imap:12:9"`), Date: now.Format(time.RFC3339Nano), ServerTime: now.UnixMilli(), imapUIDValidity: 12, imapUID: 9}
	if freshCode(base, current) {
		t.Fatal("old UID passed freshness check")
	}
	current.imapUID = 10
	current.imapUIDValidity = 13
	if freshCode(base, current) {
		t.Fatal("reset UID namespace passed freshness check")
	}
}
