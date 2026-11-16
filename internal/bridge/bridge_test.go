package bridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/refracta/dooray-mail-bridge/internal/model"
)

type fakeMail struct {
	meta   model.Message
	raw    []byte
	folder string
}
type sentMail struct {
	from string
	to   []string
	raw  []byte
}
type fakeProvider struct {
	mu                                                   sync.Mutex
	folders                                              map[string]model.Folder
	messages                                             map[string]*fakeMail
	nextID                                               int
	authCalls, readCalls, rawCalls, flagCalls, sendCalls int
	failFlags, failScan, failSend                        error
	sent                                                 []sentMail
}

func newFake() *fakeProvider {
	return &fakeProvider{
		folders:  map[string]model.Folder{"inbox": {ID: "inbox", Name: "INBOX"}, "sent": {ID: "sent", Name: "Sent", SpecialUse: "\\Sent"}},
		messages: make(map[string]*fakeMail),
	}
}

func (p *fakeProvider) add(folder string, raw []byte, flags ...string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addLocked(folder, raw, flags)
}

func (p *fakeProvider) addLocked(folder string, raw []byte, flags []string) string {
	p.nextID++
	id := fmt.Sprint(p.nextID)
	p.messages[id] = &fakeMail{meta: model.Message{ID: id, Date: time.Date(2026, 11, 17, 12, 0, p.nextID, 0, time.FixedZone("KST", 9*3600)), Flags: append([]string(nil), flags...), Size: int64(len(raw))}, raw: append([]byte(nil), raw...), folder: folder}
	return id
}

func (p *fakeProvider) Authenticate(_ context.Context, username, password string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authCalls++
	if username != "fixture" || password != "fixture-password" {
		return model.ErrAuthentication
	}
	return nil
}

func (p *fakeProvider) Folders(context.Context) ([]model.Folder, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readCalls++
	var result []model.Folder
	for _, folder := range p.folders {
		result = append(result, folder)
	}
	return result, nil
}

func (p *fakeProvider) Messages(_ context.Context, folder string) ([]model.Message, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readCalls++
	if p.failScan != nil {
		return nil, p.failScan
	}
	var result []model.Message
	for _, message := range p.messages {
		if message.folder != folder {
			continue
		}
		copy := message.meta
		copy.Flags = append([]string(nil), copy.Flags...)
		result = append(result, copy)
	}
	return result, nil
}

func (p *fakeProvider) Raw(_ context.Context, id string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rawCalls++
	message := p.messages[id]
	if message == nil {
		return nil, model.ErrNotFound
	}
	return append([]byte(nil), message.raw...), nil
}

func (p *fakeProvider) SetFlags(_ context.Context, id string, flags []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flagCalls++
	if p.failFlags != nil {
		return p.failFlags
	}
	message := p.messages[id]
	if message == nil {
		return model.ErrNotFound
	}
	message.meta.Flags = append([]string(nil), flags...)
	return nil
}

func (p *fakeProvider) Move(_ context.Context, ids []string, folder string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.folders[folder]; !exists {
		return model.ErrNotFound
	}
	for _, id := range ids {
		if p.messages[id] == nil {
			return model.ErrNotFound
		}
	}
	for _, id := range ids {
		p.messages[id].folder = folder
	}
	return nil
}

func (p *fakeProvider) Copy(_ context.Context, ids []string, folder string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.folders[folder]; !exists {
		return model.ErrNotFound
	}
	for _, id := range ids {
		if p.messages[id] == nil {
			return model.ErrNotFound
		}
	}
	for _, id := range ids {
		msg := p.messages[id]
		p.addLocked(folder, msg.raw, msg.meta.Flags)
	}
	return nil
}

func (p *fakeProvider) Delete(_ context.Context, ids []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		delete(p.messages, id)
	}
	return nil
}

func (p *fakeProvider) CreateFolder(_ context.Context, name string) (model.Folder, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextID++
	id := "folder-" + fmt.Sprint(p.nextID)
	folder := model.Folder{ID: id, Name: name}
	p.folders[id] = folder
	return folder, nil
}

func (p *fakeProvider) RenameFolder(_ context.Context, id, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	folder, exists := p.folders[id]
	if !exists {
		return model.ErrNotFound
	}
	folder.Name = name
	p.folders[id] = folder
	return nil
}

func (p *fakeProvider) DeleteFolder(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.folders, id)
	return nil
}

func (p *fakeProvider) Append(_ context.Context, folder string, raw []byte, flags []string, date time.Time) (string, error) {
	id := p.add(folder, raw, flags...)
	// The real provider ignores a requested INTERNALDATE on MIME import.
	return id, nil
}

func (p *fakeProvider) Send(_ context.Context, from string, to []string, raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sendCalls++
	if p.failSend != nil {
		return p.failSend
	}
	p.sent = append(p.sent, sentMail{from, append([]string(nil), to...), append([]byte(nil), raw...)})
	return nil
}

func plainMessage(subject string) []byte {
	return []byte("From: Fixture <fixture@example.test>\r\nTo: fixture@example.test\r\nSubject: " + subject + "\r\nDate: Tue, 17 Nov 2026 12:00:00 +0900\r\nMessage-ID: <fixture@example.test>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello fixture.\r\n")
}

func wireBridge(t *testing.T, provider model.Provider, dir string) (*Bridge, string, func()) {
	t.Helper()
	b, err := New(provider, dir, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Close()
		t.Fatal(err)
	}
	server := imapserver.New(&imapserver.Options{NewSession: b.NewIMAPSession, Caps: Capabilities(), InsecureAuth: true, Logger: log.New(io.Discard, "", 0)})
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	var once sync.Once
	stop := func() { once.Do(func() { server.Close(); <-done; b.Close() }) }
	t.Cleanup(stop)
	return b, listener.Addr().String(), stop
}

func client(t *testing.T, address string, handler *imapclient.UnilateralDataHandler) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(address, &imapclient.Options{UnilateralDataHandler: handler})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Login("fixture", "fixture-password").Wait(); err != nil {
		t.Fatal(err)
	}
	return c
}

func mustSelect(t *testing.T, c *imapclient.Client, name string, readOnly bool) *imap.SelectData {
	t.Helper()
	result, err := c.Select(name, &imap.SelectOptions{ReadOnly: readOnly}).Wait()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func fetchOne(t *testing.T, c *imapclient.Client, set imap.NumSet, options *imap.FetchOptions) *imapclient.FetchMessageBuffer {
	t.Helper()
	result, err := c.Fetch(set, options).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("got %d messages, expected one", len(result))
	}
	return result[0]
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func TestIMAPAuthenticationFailureDoesNotReadMail(t *testing.T) {
	p := newFake()
	_, addr, _ := wireBridge(t, p, t.TempDir())
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("fixture", "incorrect").Wait(); err == nil {
		t.Fatal("incorrect password accepted")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authCalls != 1 || p.readCalls != 0 || p.rawCalls != 0 {
		t.Fatalf("unexpected backend activity: auth=%d read=%d raw=%d", p.authCalls, p.readCalls, p.rawCalls)
	}
}

func TestUIDsSurviveRestartAndRemovedIDsAreNeverReused(t *testing.T) {
	p := newFake()
	first := p.add("inbox", plainMessage("first"))
	p.add("inbox", plainMessage("second"))
	dir := t.TempDir()
	_, addr, stop := wireBridge(t, p, dir)
	c := client(t, addr, nil)
	before := mustSelect(t, c, "INBOX", false)
	got := fetchOne(t, c, imap.SeqSetNum(2), &imap.FetchOptions{UID: true})
	if got.UID != 2 {
		t.Fatalf("unexpected initial UID %d", got.UID)
	}
	c.Close()
	stop()
	p.Delete(context.Background(), []string{first})
	p.add("inbox", plainMessage("third"))
	_, addr, _ = wireBridge(t, p, dir)
	c = client(t, addr, nil)
	after := mustSelect(t, c, "INBOX", false)
	if after.UIDValidity != before.UIDValidity {
		t.Fatal("UIDVALIDITY changed after restart")
	}
	all, err := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{UID: true}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].UID != 2 || all[1].UID != 3 || after.UIDNext != 4 {
		t.Fatalf("unexpected UID continuity: %#v next=%d", all, after.UIDNext)
	}
}

func TestPeekAndExaminePreserveUnreadAndFetchMarksRead(t *testing.T) {
	p := newFake()
	id := p.add("inbox", plainMessage("read state"))
	_, addr, _ := wireBridge(t, p, t.TempDir())
	c := client(t, addr, nil)
	mustSelect(t, c, "INBOX", true)
	fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}})
	if err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}}, nil).Close(); err == nil {
		t.Fatal("EXAMINE allowed STORE")
	}
	if err := c.Expunge().Close(); err == nil {
		t.Fatal("EXAMINE allowed EXPUNGE")
	}
	mustSelect(t, c, "INBOX", false)
	fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Peek: true}}})
	p.mu.Lock()
	calls := p.flagCalls
	p.mu.Unlock()
	if calls != 0 {
		t.Fatal("PEEK or EXAMINE changed remote flags")
	}
	got := fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{Flags: true, BodySection: []*imap.FetchItemBodySection{{}}})
	if !hasFlag(got.Flags, imap.FlagSeen) {
		t.Fatal("FETCH did not return Seen")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.flagCalls != 1 || !reflect.DeepEqual(p.messages[id].meta.Flags, []string{string(imap.FlagSeen)}) {
		t.Fatal("FETCH did not synchronize Seen")
	}
}

func TestMIMEBytePreservationAttachmentsPartialAndSearch(t *testing.T) {
	attachment := []byte{0, 1, 2, 3, 255, 254, 13, 10, 128}
	subject := base64.StdEncoding.EncodeToString([]byte("테스트 제목"))
	raw := []byte("From: Fixture <fixture@example.test>\r\nTo: fixture@example.test\r\nSubject: =?UTF-8?B?" + subject + "?=\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture-boundary\r\n\r\n--fixture-boundary\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n검색 가능한 본문\r\n--fixture-boundary\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=binary.bin\r\n\r\n" + base64.StdEncoding.EncodeToString(attachment) + "\r\n--fixture-boundary--\r\n")
	p := newFake()
	p.add("inbox", raw)
	_, addr, _ := wireBridge(t, p, t.TempDir())
	c := client(t, addr, nil)
	mustSelect(t, c, "INBOX", false)
	got := fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{Envelope: true, RFC822Size: true, BodyStructure: &imap.FetchItemBodyStructure{Extended: true}, BodySection: []*imap.FetchItemBodySection{{Peek: true}}})
	if len(got.BodySection) != 1 || !bytes.Equal(got.BodySection[0].Bytes, raw) {
		t.Fatal("full MIME octets changed")
	}
	if got.Envelope == nil || got.Envelope.Subject != "테스트 제목" || got.BodyStructure == nil || got.RFC822Size != int64(len(raw)) {
		t.Fatalf("MIME metadata incorrect: %#v", got)
	}
	partial := fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Peek: true, Partial: &imap.SectionPartial{Offset: 10, Size: 24}}}})
	if !bytes.Equal(partial.BodySection[0].Bytes, raw[10:34]) {
		t.Fatal("partial FETCH incorrect")
	}
	binary := fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{{Part: []int{2}, Peek: true}}, BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}}})
	if len(binary.BinarySection) != 1 || !bytes.Equal(binary.BinarySection[0].Bytes, attachment) || binary.BinarySectionSize[0].Size != uint32(len(attachment)) {
		t.Fatal("attachment binary changed")
	}
	for _, criteria := range []*imap.SearchCriteria{{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "테스트"}}}, {Body: []string{"가능한"}}, {Not: []imap.SearchCriteria{{Body: []string{"missing"}}}}} {
		result, err := c.UIDSearch(criteria, nil).Wait()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(result.AllUIDs(), []imap.UID{1}) {
			t.Fatalf("SEARCH mismatch: %#v", result)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rawCalls != 1 || p.flagCalls != 0 {
		t.Fatalf("cache/read preservation failed: raw=%d flag=%d", p.rawCalls, p.flagCalls)
	}
}

func TestDeleteFlagPersistsAndExpungeDeletesOnlyMarkedMessages(t *testing.T) {
	p := newFake()
	first := p.add("inbox", plainMessage("first"))
	p.add("inbox", plainMessage("second"))
	dir := t.TempDir()
	_, addr, stop := wireBridge(t, p, dir)
	c := client(t, addr, nil)
	mustSelect(t, c, "INBOX", false)
	if err := c.Store(imap.UIDSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}, Silent: true}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	calls := p.flagCalls
	size := len(p.messages)
	p.mu.Unlock()
	if calls != 0 || size != 2 {
		t.Fatal("STORE Deleted performed a premature remote deletion")
	}
	c.Close()
	stop()
	_, addr, _ = wireBridge(t, p, dir)
	c = client(t, addr, nil)
	mustSelect(t, c, "INBOX", false)
	got := fetchOne(t, c, imap.UIDSetNum(1), &imap.FetchOptions{Flags: true})
	if !hasFlag(got.Flags, imap.FlagDeleted) {
		t.Fatal("Deleted flag lost on restart")
	}
	expunged, err := c.Expunge().Collect()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expunged, []uint32{1}) {
		t.Fatalf("EXPUNGE responses: %v", expunged)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.messages) != 1 || p.messages[first] != nil {
		t.Fatal("EXPUNGE did not remove exactly the marked message")
	}
}

func TestProviderFailuresDoNotReportSuccessfulWrites(t *testing.T) {
	p := newFake()
	p.add("inbox", plainMessage("failure"))
	p.failFlags = errors.New("fixture provider outage")
	_, addr, _ := wireBridge(t, p, t.TempDir())
	c := client(t, addr, nil)
	mustSelect(t, c, "INBOX", false)
	if err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}}, nil).Close(); err == nil {
		t.Fatal("remote flag failure acknowledged as successful")
	}
	got := fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{Flags: true})
	if hasFlag(got.Flags, imap.FlagSeen) {
		t.Fatal("failed remote STORE changed local state")
	}
	if err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagAnswered}}, nil).Close(); err == nil {
		t.Fatal("unsupported Answered write accepted")
	}
}

func TestFoldersAppendCopyMoveAndUIDValidityOnRecreate(t *testing.T) {
	p := newFake()
	p.add("inbox", plainMessage("source"))
	_, addr, _ := wireBridge(t, p, t.TempDir())
	c := client(t, addr, nil)
	if c.Caps().Has(imap.CapUIDPlus) {
		t.Fatal("UIDPLUS incorrectly advertised")
	}
	if err := c.Create("테스트", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	initial := mustSelect(t, c, "테스트", false)
	appendCmd := c.Append("테스트", int64(len(plainMessage("imported"))), nil)
	if _, err := appendCmd.Write(plainMessage("imported")); err != nil {
		t.Fatal(err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatal(err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if appendData.UID != 1 || appendData.UIDValidity != initial.UIDValidity {
		t.Fatalf("bad APPENDUID: %#v", appendData)
	}
	if err := c.Rename("테스트", "Renamed", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if renamed := mustSelect(t, c, "Renamed", false); renamed.UIDValidity != initial.UIDValidity {
		t.Fatal("rename changed UIDVALIDITY")
	}
	if err := c.Unsubscribe("Renamed").Wait(); err != nil {
		t.Fatal(err)
	}
	listed, err := c.List("", "*", &imap.ListOptions{SelectSubscribed: true}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range listed {
		if entry.Mailbox == "Renamed" {
			t.Fatal("unsubscribed mailbox listed by LSUB")
		}
	}
	mustSelect(t, c, "INBOX", false)
	if _, err := c.Copy(imap.UIDSetNum(1), "Renamed").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Move(imap.UIDSetNum(1), "Sent").Wait(); err != nil {
		t.Fatal(err)
	}
	if state := mustSelect(t, c, "INBOX", false); state.NumMessages != 0 {
		t.Fatal("MOVE did not remove source")
	}
	if state := mustSelect(t, c, "Sent", false); state.NumMessages != 1 {
		t.Fatal("MOVE did not add destination")
	}
	if state := mustSelect(t, c, "Renamed", false); state.NumMessages != 2 {
		t.Fatal("COPY did not preserve destination/imported message")
	}
	if err := c.Unselect().Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete("Renamed").Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Create("Renamed", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if state := mustSelect(t, c, "Renamed", false); state.UIDValidity == initial.UIDValidity {
		t.Fatal("recreated mailbox reused UIDVALIDITY")
	}
}

func TestPendingExpungeKeepsOtherClientSequenceNumbersStable(t *testing.T) {
	p := newFake()
	first := p.add("inbox", plainMessage("first"))
	p.add("inbox", plainMessage("second"))
	p.add("inbox", plainMessage("third"))
	b, addr, _ := wireBridge(t, p, t.TempDir())
	c := client(t, addr, nil)
	mustSelect(t, c, "INBOX", false)
	p.Delete(context.Background(), []string{first})
	m, _ := b.mailbox("INBOX")
	waitUntil(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return len(m.state.Messages) == 2 })
	got := fetchOne(t, c, imap.SeqSetNum(2), &imap.FetchOptions{UID: true})
	if got.UID != 2 {
		t.Fatalf("deferred EXPUNGE shifted sequence 2 to UID %d", got.UID)
	}
	if err := c.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	got = fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{UID: true})
	if got.UID != 2 {
		t.Fatal("sequence was not renumbered after EXPUNGE delivery")
	}
}

func TestIdleReportsNewMailAndChangesFromAnotherClient(t *testing.T) {
	p := newFake()
	p.add("inbox", plainMessage("first"))
	_, addr, _ := wireBridge(t, p, t.TempDir())
	counts := make(chan uint32, 16)
	flags := make(chan *imapclient.FetchMessageBuffer, 16)
	handler := &imapclient.UnilateralDataHandler{
		Mailbox: func(d *imapclient.UnilateralDataMailbox) {
			if d.NumMessages != nil {
				counts <- *d.NumMessages
			}
		},
		Fetch: func(m *imapclient.FetchMessageData) {
			data, err := m.Collect()
			if err == nil {
				flags <- data
			}
		},
	}
	one := client(t, addr, handler)
	two := client(t, addr, nil)
	mustSelect(t, one, "INBOX", false)
	mustSelect(t, two, "INBOX", false)
	idle, err := one.Idle()
	if err != nil {
		t.Fatal(err)
	}
	p.add("inbox", plainMessage("new one"))
	p.add("inbox", plainMessage("new two"))
	deadline := time.After(3 * time.Second)
	for {
		select {
		case n := <-counts:
			if n == 3 {
				goto arrived
			}
		case <-deadline:
			t.Fatal("IDLE missed new mail")
		}
	}
arrived:
	if err := two.Store(imap.UIDSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagFlagged}, Silent: true}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-flags:
		if message.UID != 1 || !hasFlag(message.Flags, imap.FlagFlagged) {
			t.Fatalf("unexpected IDLE flags: %#v", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("IDLE missed other client's STORE")
	}
	if err := idle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := idle.Wait(); err != nil {
		t.Fatal(err)
	}
	got := fetchOne(t, one, imap.SeqSetNum(3), &imap.FetchOptions{UID: true})
	if got.UID != 3 {
		t.Fatal("multiple new-message sequence mapping failed")
	}
}

func smtpFixture(t *testing.T, p *fakeProvider) (string, *Bridge) {
	t.Helper()
	b, err := New(p, t.TempDir(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s := smtp.NewServer(b.SMTPBackend())
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	s.MaxMessageBytes = MaxMessageBytes
	s.ReadTimeout = 5 * time.Second
	s.WriteTimeout = 5 * time.Second
	s.ErrorLog = log.New(io.Discard, "", 0)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() { s.Close(); <-done; b.Close() })
	return l.Addr().String(), b
}

func TestSMTPRejectsUnauthenticatedAndWrongPassword(t *testing.T) {
	p := newFake()
	addr, _ := smtpFixture(t, p)
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Mail("fixture@example.test", nil); err == nil {
		t.Fatal("unauthenticated MAIL accepted")
	}
	if err := c.Auth(sasl.NewPlainClient("", "fixture", "wrong")); err == nil {
		t.Fatal("wrong SMTP password accepted")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sendCalls != 0 || p.readCalls != 0 {
		t.Fatal("unauthenticated client touched mailbox")
	}
}

func TestSMTPPlainAndLoginPreserveMessageAndEnvelope(t *testing.T) {
	for _, mechanism := range []string{"PLAIN", "LOGIN"} {
		t.Run(mechanism, func(t *testing.T) {
			p := newFake()
			addr, _ := smtpFixture(t, p)
			c, err := smtp.Dial(addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var auth sasl.Client = sasl.NewPlainClient("", "fixture", "fixture-password")
			if mechanism == "LOGIN" {
				auth = sasl.NewLoginClient("fixture", "fixture-password")
			}
			if err := c.Auth(auth); err != nil {
				t.Fatal(err)
			}
			raw := plainMessage("SMTP fixture")
			if err := c.SendMail("fixture@example.test", []string{"first@example.test", "second@example.test"}, bytes.NewReader(raw)); err != nil {
				t.Fatal(err)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if len(p.sent) != 1 || !bytes.Equal(p.sent[0].raw, raw) || !reflect.DeepEqual(p.sent[0].to, []string{"first@example.test", "second@example.test"}) || p.sent[0].from != "fixture@example.test" {
				t.Fatalf("incorrect submission: %#v", p.sent)
			}
		})
	}
}

func TestSMTPProviderFailureIsNotRetriedOrAcknowledged(t *testing.T) {
	p := newFake()
	p.failSend = errors.New("uncertain transport failure")
	addr, _ := smtpFixture(t, p)
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Auth(sasl.NewPlainClient("", "fixture", "fixture-password")); err != nil {
		t.Fatal(err)
	}
	err = c.SendMail("fixture@example.test", []string{"fixture@example.test"}, strings.NewReader(string(plainMessage("failure"))))
	if err == nil {
		t.Fatal("failed submission acknowledged")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sendCalls != 1 || len(p.sent) != 0 {
		t.Fatal("submission was retried or accepted")
	}
}

func TestAppendInternalDateSurvivesSyncRestartAndMove(t *testing.T) {
	p := newFake()
	dir := t.TempDir()
	_, addr, stop := wireBridge(t, p, dir)
	c := client(t, addr, nil)
	mustSelect(t, c, "INBOX", false)
	date := time.Date(2001, 2, 3, 4, 5, 6, 0, time.FixedZone("fixture", -7*3600))
	raw := plainMessage("old import")
	command := c.Append("INBOX", int64(len(raw)), &imap.AppendOptions{Time: date})
	if _, err := command.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := command.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	stop()
	_, addr, _ = wireBridge(t, p, dir)
	c = client(t, addr, nil)
	mustSelect(t, c, "INBOX", false)
	got := fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{InternalDate: true})
	if !got.InternalDate.Equal(date) {
		t.Fatalf("requested INTERNALDATE lost: %v", got.InternalDate)
	}
	if _, err := c.Copy(imap.UIDSetNum(1), "Sent").Wait(); err == nil {
		t.Fatal("COPY silently discarded bridge-only INTERNALDATE")
	}
	if _, err := c.Move(imap.UIDSetNum(1), "Sent").Wait(); err != nil {
		t.Fatal(err)
	}
	mustSelect(t, c, "Sent", false)
	got = fetchOne(t, c, imap.SeqSetNum(1), &imap.FetchOptions{InternalDate: true})
	if !got.InternalDate.Equal(date) {
		t.Fatal("MOVE lost requested INTERNALDATE")
	}
}

func TestFailedMailboxScanPreservesSnapshotAndUIDs(t *testing.T) {
	p := newFake()
	p.add("inbox", plainMessage("one"))
	p.add("inbox", plainMessage("two"))
	b, addr, _ := wireBridge(t, p, t.TempDir())
	c := client(t, addr, nil)
	before := mustSelect(t, c, "INBOX", false)
	m, _ := b.mailbox("INBOX")
	p.mu.Lock()
	p.failScan = errors.New("incomplete HTTP pagination")
	p.mu.Unlock()
	m.mu.Lock()
	err := b.syncBoxLocked(m, true)
	count, next := len(m.state.Messages), m.state.Next
	m.mu.Unlock()
	if err == nil || count != 2 || next != before.UIDNext {
		t.Fatal("failed scan replaced a valid mailbox snapshot")
	}
	p.mu.Lock()
	p.failScan = nil
	p.mu.Unlock()
	m.mu.Lock()
	err = b.syncBoxLocked(m, true)
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	got := fetchOne(t, c, imap.SeqSetNum(2), &imap.FetchOptions{UID: true})
	if got.UID != 2 {
		t.Fatal("recovery changed UID")
	}
}

func TestSubjectSearchUsesMetadataWithoutDownloadingMIME(t *testing.T) {
	p := newFake()
	first := p.add("inbox", plainMessage("Quarterly 테스트 Report"))
	second := p.add("inbox", plainMessage("Unrelated attachment archive"))
	third := p.add("inbox", plainMessage(""))
	p.mu.Lock()
	for id, subject := range map[string]string{first: "Quarterly 테스트 Report", second: "Unrelated attachment archive", third: ""} {
		value := subject
		p.messages[id].meta.Subject = &value
	}
	p.mu.Unlock()
	_, address, _ := wireBridge(t, p, t.TempDir())
	c := client(t, address, nil)
	mustSelect(t, c, "INBOX", false)
	for _, test := range []struct {
		term string
		want []imap.UID
	}{
		{"quarterly 테스트 REPORT", []imap.UID{1}},
		{"ARCHIVE", []imap.UID{2}},
		{"does not match any message", nil},
	} {
		result, err := c.UIDSearch(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "sUbJeCt", Value: test.term}}}, nil).Wait()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(result.AllUIDs(), test.want) {
			t.Fatalf("SUBJECT %q: got %v, want %v", test.term, result.AllUIDs(), test.want)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rawCalls != 0 {
		t.Fatalf("metadata SUBJECT searches downloaded %d original messages", p.rawCalls)
	}
}

func TestSubjectMetadataHintKeepsOriginalHeaderSemantics(t *testing.T) {
	empty := ""
	known := "Known decoded subject"
	for _, test := range []struct {
		name      string
		hint      *string
		raw       []byte
		criteria  imap.SearchCriteria
		want      bool
		wantReads int
	}{
		{"unknown hint uses original", nil, plainMessage("Actual Subject"), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "ACTUAL"}}}, true, 1},
		{"unknown hint decodes original", nil, plainMessage("=?UTF-8?B?7YWM7Iqk7Yq4?="), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "테스트"}}}, true, 1},
		{"empty original subject exists", &empty, plainMessage(""), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: ""}}}, true, 1},
		{"missing original subject does not exist", &empty, []byte("From: fixture@example.test\r\n\r\nNo subject header.\r\n"), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: ""}}}, false, 1},
		{"known empty subject cannot match nonempty term", &empty, plainMessage(""), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "anything"}}}, false, 0},
		{"subject nonmatch skips other header fetch", &known, plainMessage("Known decoded subject"), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "From", Value: "fixture"}, {Key: "Subject", Value: "unrelated"}}}, false, 0},
		{"other headers still use original", &known, plainMessage("Known decoded subject"), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "KNOWN"}, {Key: "From", Value: "fixture"}}}, true, 1},
		{"body still uses original", &known, plainMessage("Known decoded subject"), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "KNOWN"}}, Body: []string{"Hello fixture"}}, true, 1},
		{"sent date still uses original", &known, plainMessage("Known decoded subject"), imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "KNOWN"}}, SentSince: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)}, true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			message := &searchMessage{meta: &storedMessage{Meta: model.Message{Subject: test.hint}, UID: 1}, sequence: 1, load: func() ([]byte, error) { reads++; return test.raw, nil }}
			matched, err := message.matches(&test.criteria)
			if err != nil {
				t.Fatal(err)
			}
			if matched != test.want || reads != test.wantReads {
				t.Fatalf("got match=%v reads=%d, want match=%v reads=%d", matched, reads, test.want, test.wantReads)
			}
		})
	}
}
