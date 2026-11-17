package dooray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/refracta/dooray-mail-bridge/internal/model"
)

type fakeTransport struct {
	auth func(string, string) error
	do   func(string, string, []byte, string) (*http.Response, error)
}

func (f *fakeTransport) Authenticate(_ context.Context, user, password string) error {
	if f.auth != nil {
		return f.auth(user, password)
	}
	return nil
}

func (f *fakeTransport) Do(_ context.Context, method, path string, body []byte, ct string) (*http.Response, error) {
	return f.do(method, path, body, ct)
}

func okResponse(result any) *http.Response {
	b, _ := json.Marshal(map[string]any{"header": map[string]any{"isSuccessful": true, "resultCode": 0}, "result": result})
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(b))}
}

func statusResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
}

func originalResponse(raw []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"message/rfc822"}}, Body: io.NopCloser(bytes.NewReader(raw))}
}

func withInbox(f *fakeTransport) *Client {
	c := New(f, "sender@example.test")
	c.folders["inbox"] = webFolder{ID: "inbox", Name: "inbox", Type: "system"}
	c.folders["target"] = webFolder{ID: "target", Name: "Target", Type: "user"}
	return c
}

func decodeObject(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func messageRecord(id string) map[string]any {
	return map[string]any{"id": id, "createdAt": "2026-01-02T03:04:05Z", "mailSummary": map[string]any{"mimeSize": 123, "flags": map[string]bool{"read": true, "replied": true}}, "annotations": map[string]bool{"favorited": true}}
}

func TestAuthenticateChecksBothCredentialTransportAndIdentity(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprint(mismatch), func(t *testing.T) {
			called := false
			f := &fakeTransport{auth: func(user, password string) error {
				called = true
				if user != "sender" || password != "test-password" {
					t.Fatal("credentials changed")
				}
				return nil
			}}
			f.do = func(method, path string, _ []byte, _ string) (*http.Response, error) {
				if method != "GET" || path != "/v2/wapi/members/me" {
					t.Fatal(method, path)
				}
				email := "sender@example.test"
				if mismatch {
					email = "different@example.test"
				}
				return okResponse(map[string]any{"content": map[string]string{"emailAddress": email}}), nil
			}
			err := New(f, "sender@example.test").Authenticate(context.Background(), "sender", "test-password")
			if !called || mismatch != errors.Is(err, model.ErrAuthentication) {
				t.Fatalf("called=%v err=%v", called, err)
			}
		})
	}
}

func TestFolderHierarchyAndSpecialUse(t *testing.T) {
	f := &fakeTransport{do: func(method, path string, _ []byte, _ string) (*http.Response, error) {
		u, _ := url.Parse(path)
		folders := []webFolder{{ID: "one", Name: "inbox", Type: "system"}, {ID: "two", Name: "draft", Type: "system"}}
		if u.Query().Get("type") == "user" {
			folders = []webFolder{{ID: "three", Name: "Research", Type: "user"}, {ID: "four", Name: "Projects", Type: "user", ParentID: "three"}}
		}
		return okResponse(map[string]any{"totalCount": len(folders), "contents": folders}), nil
	}}
	folders, err := New(f, "sender@example.test").Folders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Folder{{ID: "two", Name: "Drafts", SpecialUse: `\Drafts`}, {ID: "one", Name: "INBOX"}, {ID: "three", Name: "Research"}, {ID: "four", Name: "Research/Projects"}}
	if !reflect.DeepEqual(folders, want) {
		t.Fatalf("got %#v", folders)
	}
}

func TestMessagesPaginationSizesAndFlags(t *testing.T) {
	calls := 0
	f := &fakeTransport{do: func(method, path string, _ []byte, _ string) (*http.Response, error) {
		calls++
		u, _ := url.Parse(path)
		if method != "GET" || u.Path != "/v2/wapi/mails" || u.Query().Get("folderId") != "inbox" || u.Query().Get("preview") != "false" {
			t.Fatal(method, path)
		}
		var records []map[string]any
		if u.Query().Get("page") == "0" {
			for i := 0; i < 100; i++ {
				record := messageRecord(fmt.Sprint(i + 1))
				if i == 0 {
					record["subject"] = "한글 메일"
				}
				records = append(records, record)
			}
		} else {
			records = []map[string]any{messageRecord("101")}
		}
		return okResponse(map[string]any{"totalCount": 101, "contents": records}), nil
	}}
	messages, err := withInbox(f).Messages(context.Background(), "inbox")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 101 || calls != 2 || messages[0].Size != 123 || !reflect.DeepEqual(messages[0].Flags, []string{`\Seen`, `\Flagged`, `\Answered`}) {
		t.Fatalf("calls=%d count=%d first=%#v", calls, len(messages), messages[0])
	}
	if messages[0].Subject == nil || *messages[0].Subject != "한글 메일" || messages[1].Subject != nil {
		t.Fatal("decoded subject metadata or unknown-subject fallback was lost")
	}
}

func TestMessagePaginationRejectsIncompleteSnapshot(t *testing.T) {
	f := &fakeTransport{do: func(method, path string, _ []byte, _ string) (*http.Response, error) {
		return okResponse(map[string]any{"totalCount": 1, "contents": []any{}}), nil
	}}
	if _, err := withInbox(f).Messages(context.Background(), "inbox"); !errors.Is(err, model.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestRawPreservesAllOctetsAndNeverUsesRenderedEndpoint(t *testing.T) {
	raw := append([]byte("From: sender@example.test\r\nSubject: octets\r\n\r\n"), 0, 255, 128, 10)
	f := &fakeTransport{do: func(method, path string, _ []byte, _ string) (*http.Response, error) {
		if method != "GET" || path != "/v2/wapi/mails/123?type=raw" {
			t.Fatal(method, path)
		}
		return originalResponse(raw), nil
	}}
	got, err := withInbox(f).Raw(context.Background(), "123")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("err=%v got=%v", err, got)
	}
}

func TestRawRejectsLoginHTML(t *testing.T) {
	f := &fakeTransport{do: func(method, path string, _ []byte, _ string) (*http.Response, error) {
		return okResponse(map[string]any{}), nil
	}}
	if _, err := withInbox(f).Raw(context.Background(), "123"); !errors.Is(err, model.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestFlagsMapToReadAndFavorite(t *testing.T) {
	var paths []string
	f := &fakeTransport{do: func(method, path string, body []byte, _ string) (*http.Response, error) {
		paths = append(paths, method+" "+path)
		v := decodeObject(t, body)
		if method == "PUT" && (v["mailId"] != "123" || v["favorited"] != true) {
			t.Fatal(v)
		}
		if method == "POST" && !reflect.DeepEqual(v["mailIdList"], []any{"123"}) {
			t.Fatal(v)
		}
		return okResponse(nil), nil
	}}
	c := withInbox(f)
	if err := c.SetFlags(context.Background(), "123", []string{`\Seen`, `\Flagged`}); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /v2/wapi/mails/read", "PUT /v2/wapi/mails/123/annotations"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatal(paths)
	}
	if err := c.SetFlags(context.Background(), "123", []string{`\Answered`}); !errors.Is(err, model.ErrUnsupported) {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatal("unsupported flag caused mutation")
	}
}

func TestWritesUseExactIDsAndDoNotRetry(t *testing.T) {
	var paths []string
	f := &fakeTransport{do: func(method, path string, body []byte, _ string) (*http.Response, error) {
		paths = append(paths, path)
		v := decodeObject(t, body)
		if method != "POST" || !reflect.DeepEqual(v["mailIdList"], []any{"a", "b"}) {
			t.Fatal(method, v)
		}
		if path != "/v2/wapi/mails/delete" && v["targetFolderId"] != "target" {
			t.Fatal(v)
		}
		return okResponse(nil), nil
	}}
	c := withInbox(f)
	for _, op := range []func() error{func() error { return c.Move(context.Background(), []string{"a", "b"}, "target") }, func() error { return c.Copy(context.Background(), []string{"a", "b"}, "target") }, func() error { return c.Delete(context.Background(), []string{"a", "b"}) }} {
		if err := op(); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(paths, []string{"/v2/wapi/mails/move", "/v2/wapi/mails/copy", "/v2/wapi/mails/delete"}) {
		t.Fatal(paths)
	}
	calls := 0
	f.do = func(string, string, []byte, string) (*http.Response, error) { calls++; return statusResponse(503), nil }
	if err := c.Delete(context.Background(), []string{"a"}); !errors.Is(err, model.ErrUnavailable) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestSystemFoldersCannotBeRenamedOrDeleted(t *testing.T) {
	f := &fakeTransport{do: func(string, string, []byte, string) (*http.Response, error) {
		t.Fatal("unexpected request")
		return nil, nil
	}}
	c := withInbox(f)
	if err := c.RenameFolder(context.Background(), "inbox", "New"); !errors.Is(err, model.ErrUnsupported) {
		t.Fatal(err)
	}
	if err := c.DeleteFolder(context.Background(), "inbox"); !errors.Is(err, model.ErrUnsupported) {
		t.Fatal(err)
	}
}

func uploadedFile(t *testing.T, body []byte, ct string) ([]byte, string) {
	t.Helper()
	_, p, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatal(err)
	}
	r := multipart.NewReader(bytes.NewReader(body), p["boundary"])
	part, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if part.FormName() != "file" {
		t.Fatal(part.FormName())
	}
	data, err := io.ReadAll(part)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.NextPart(); err != io.EOF {
		t.Fatal("extra multipart field")
	}
	return data, part.FileName()
}

func TestAppendUploadsOriginalAndUsesReturnedID(t *testing.T) {
	raw := []byte("From: sender@example.test\r\nTo: sender@example.test\r\nSubject: original\r\n\r\nexact bytes\r\n")
	var paths []string
	f := &fakeTransport{do: func(method, path string, body []byte, ct string) (*http.Response, error) {
		paths = append(paths, path)
		if strings.HasPrefix(path, "/v2/wapi/mails?") {
			return okResponse(map[string]any{"totalCount": 0, "contents": []any{}}), nil
		}
		if path == "/v2/wapi/mail-folders/inbox/import-mail" {
			got, name := uploadedFile(t, body, ct)
			if !bytes.Equal(got, raw) || name != "message.eml" {
				t.Fatalf("name=%s got=%q", name, got)
			}
			return okResponse(map[string]any{"content": map[string]string{"id": "new-message"}}), nil
		}
		if path != "/v2/wapi/mails/unread" && path != "/v2/wapi/mails/new-message/annotations" {
			t.Fatal(method, path)
		}
		return okResponse(nil), nil
	}}
	id, err := withInbox(f).Append(context.Background(), "inbox", raw, nil, time.Now())
	if err != nil || id != "new-message" || len(paths) != 4 {
		t.Fatalf("id=%s err=%v paths=%v", id, err, paths)
	}
}

func TestAppendWithoutIDReconcilesByOriginalBytes(t *testing.T) {
	raw := []byte("From: sender@example.test\r\nSubject: original\r\n\r\nhello\r\n")
	imported := false
	f := &fakeTransport{do: func(method, path string, body []byte, ct string) (*http.Response, error) {
		if strings.HasPrefix(path, "/v2/wapi/mails?") {
			items := []map[string]any{}
			if imported {
				items = []map[string]any{messageRecord("unrelated"), messageRecord("imported")}
			}
			return okResponse(map[string]any{"totalCount": len(items), "contents": items}), nil
		}
		switch path {
		case "/v2/wapi/mail-folders/inbox/import-mail":
			imported = true
			return okResponse(nil), nil
		case "/v2/wapi/mails/unrelated?type=raw":
			return originalResponse([]byte("different")), nil
		case "/v2/wapi/mails/imported?type=raw":
			return originalResponse(raw), nil
		case "/v2/wapi/mails/read", "/v2/wapi/mails/imported/annotations":
			return okResponse(nil), nil
		default:
			t.Fatal(method, path)
			return nil, nil
		}
	}}
	id, err := withInbox(f).Append(context.Background(), "inbox", raw, []string{`\Seen`}, time.Now())
	if err != nil || id != "imported" {
		t.Fatalf("id=%s err=%v", id, err)
	}
}

func TestAppendDraftPreservesMIMEAndSynchronizesWritableFlags(t *testing.T) {
	for _, tc := range []struct {
		name, readPath string
		flags          []string
		favorite       bool
	}{
		{"draft only", "/v2/wapi/mails/unread", []string{`\Draft`}, false},
		{"outlook draft", "/v2/wapi/mails/read", []string{`\Seen`, `\Draft`}, false},
		{"case insensitive", "/v2/wapi/mails/read", []string{`\draft`, `\seen`, `\flagged`}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(submission)
			imported := false
			writes := 0
			f := &fakeTransport{do: func(method, path string, body []byte, ct string) (*http.Response, error) {
				if strings.HasPrefix(path, "/v2/wapi/mails?") {
					q, _ := url.Parse(path)
					if q.Query().Get("folderId") != "drafts" {
						t.Fatal("draft saved to a different mailbox")
					}
					items := []any{}
					if imported {
						items = append(items, messageRecord("saved-draft"))
					}
					return okResponse(map[string]any{"totalCount": len(items), "contents": items}), nil
				}
				switch path {
				case "/v2/wapi/mail-folders/drafts/import-mail":
					writes++
					got, filename := uploadedFile(t, body, ct)
					if method != "POST" || filename != "message.eml" || !bytes.Equal(got, raw) {
						t.Fatal("draft headers, body or attachment bytes changed")
					}
					imported = true
					// The live import API omits the inserted ID.
					return okResponse(nil), nil
				case "/v2/wapi/mails/saved-draft?type=raw":
					return originalResponse(raw), nil
				case tc.readPath:
					if !reflect.DeepEqual(decodeObject(t, body), map[string]any{"mailIdList": []any{"saved-draft"}}) {
						t.Fatal("wrong draft read-state target")
					}
					return okResponse(nil), nil
				case "/v2/wapi/mails/saved-draft/annotations":
					if decodeObject(t, body)["favorited"] != tc.favorite {
						t.Fatal("favorite flag lost")
					}
					return okResponse(nil), nil
				default:
					t.Fatalf("unexpected draft request: %s %s", method, path)
					return nil, errors.New("unexpected request")
				}
			}}
			c := withInbox(f)
			c.folders["drafts"] = webFolder{ID: "drafts", Name: "draft", Type: "system"}
			id, err := c.Append(context.Background(), "drafts", raw, tc.flags, time.Time{})
			if err != nil || id != "saved-draft" || writes != 1 {
				t.Fatalf("draft save failed: id=%s writes=%d err=%v", id, writes, err)
			}
			messages, err := c.Messages(context.Background(), "drafts")
			if err != nil || len(messages) != 1 {
				t.Fatalf("saved draft missing: %v", err)
			}
			if !strings.Contains(strings.Join(messages[0].Flags, " "), `\Draft`) {
				t.Fatal("Drafts mailbox membership did not supply the draft flag")
			}
		})
	}
}

func TestAppendDraftFlagRequiresTheSystemDraftsMailbox(t *testing.T) {
	for _, folder := range []webFolder{
		{ID: "folder", Name: "inbox", Type: "system"},
		{ID: "folder", Name: "draft", Type: "user"},
		{ID: "folder", Name: "Drafts", Type: "user"},
	} {
		c := New(&fakeTransport{do: func(method, path string, _ []byte, _ string) (*http.Response, error) {
			t.Fatalf("unsupported draft request reached HTTP: %s %s", method, path)
			return nil, errors.New("unexpected request")
		}}, "sender@example.test")
		c.folders[folder.ID] = folder
		_, err := c.Append(context.Background(), folder.ID, []byte("Subject: unfinished\r\n\r\n"), []string{`\Draft`}, time.Time{})
		if !errors.Is(err, model.ErrUnsupported) {
			t.Fatalf("unsupported draft flag accepted for %#v: %v", folder, err)
		}
	}
}

const submission = "From: Sender <sender@example.test>\r\nTo: Visible <to@example.test>, unrequested@example.test\r\nCc: cc@example.test\r\nSubject: =?UTF-8?B?7YWM7Iqk7Yq4?=\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=test\r\n\r\n--test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n--test\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=sample.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAP+A\r\n--test--\r\n"

func TestSendUsesEnvelopeRecipientsAndAttachmentOctets(t *testing.T) {
	var paths []string
	f := &fakeTransport{do: func(method, path string, body []byte, ct string) (*http.Response, error) {
		paths = append(paths, method+" "+path)
		switch path {
		case "/v2/wapi/members/me":
			return okResponse(map[string]any{"content": map[string]string{"emailAddress": "sender@example.test", "name": "Account Name"}}), nil
		case "/v2/wapi/mail-drafts":
			var forms []map[string]any
			if err := json.Unmarshal(body, &forms); err != nil {
				t.Fatal(err)
			}
			form := forms[0]
			if form["subject"] != "테스트" {
				t.Fatal(form["subject"])
			}
			users := form["users"].(map[string]any)
			for key, want := range map[string]string{"to": "to@example.test", "cc": "cc@example.test", "bcc": "hidden@example.test"} {
				list := users[key].([]any)
				if len(list) != 1 || list[0].(map[string]any)["emailUser"].(map[string]any)["emailAddress"] != want {
					t.Fatal(key, list)
				}
			}
			if users["from"].(map[string]any)["emailUser"].(map[string]any)["name"] != "Account Name" {
				t.Fatal(users["from"])
			}
			return okResponse(map[string]any{"contents": []any{map[string]any{"id": "draft", "version": 7}}}), nil
		case "/v2/wapi/mail-drafts/draft/files":
			data, name := uploadedFile(t, body, ct)
			if name != "sample.bin" || !bytes.Equal(data, []byte{0, 255, 128}) {
				t.Fatal(name, data)
			}
			return okResponse(map[string]any{"contents": []any{map[string]string{"id": "file"}}}), nil
		case "/v2/wapi/mail-drafts/draft":
			form := decodeObject(t, body)
			if method != "PUT" || !reflect.DeepEqual(form["fileIdList"], []any{"file"}) || form["version"] != float64(7) {
				t.Fatal(method, form)
			}
			return okResponse(nil), nil
		case "/v2/wapi/mails/send":
			if !reflect.DeepEqual(decodeObject(t, body), map[string]any{"draftId": "draft"}) {
				t.Fatal(string(body))
			}
			return okResponse(nil), nil
		default:
			t.Fatal(method, path)
			return nil, nil
		}
	}}
	err := withInbox(f).Send(context.Background(), "sender@example.test", []string{"to@example.test", "cc@example.test", "hidden@example.test"}, []byte(submission))
	if err != nil || len(paths) != 5 {
		t.Fatalf("err=%v paths=%v", err, paths)
	}
}

func TestSenderMismatchIsRejectedBeforeAnyWebRequest(t *testing.T) {
	f := &fakeTransport{do: func(string, string, []byte, string) (*http.Response, error) {
		t.Fatal("unexpected web request")
		return nil, nil
	}}
	c := withInbox(f)
	if err := c.Send(context.Background(), "other@example.test", []string{"to@example.test"}, []byte(submission)); err == nil {
		t.Fatal("accepted wrong envelope sender")
	}
	bad := strings.Replace(submission, "Sender <sender@example.test>", "Other <other@example.test>", 1)
	if err := c.Send(context.Background(), "sender@example.test", []string{"to@example.test"}, []byte(bad)); err == nil {
		t.Fatal("accepted wrong MIME sender")
	}
}

func TestSubmissionErrorDoesNotRetrySending(t *testing.T) {
	sends := 0
	f := &fakeTransport{do: func(method, path string, _ []byte, _ string) (*http.Response, error) {
		switch path {
		case "/v2/wapi/members/me":
			return okResponse(map[string]any{"content": map[string]string{"emailAddress": "sender@example.test"}}), nil
		case "/v2/wapi/mail-drafts":
			return okResponse([]any{map[string]any{"id": "draft", "version": 0}}), nil
		case "/v2/wapi/mail-drafts/draft":
			return okResponse(nil), nil
		case "/v2/wapi/mails/send":
			sends++
			return nil, context.DeadlineExceeded
		default:
			t.Fatal(path)
			return nil, nil
		}
	}}
	raw := []byte("From: sender@example.test\r\nTo: to@example.test\r\nSubject: test\r\n\r\nhello")
	err := withInbox(f).Send(context.Background(), "sender@example.test", []string{"to@example.test"}, raw)
	if !errors.Is(err, context.DeadlineExceeded) || sends != 1 {
		t.Fatalf("err=%v sends=%d", err, sends)
	}
}

func TestSendDoesNotGuessDraftVersion(t *testing.T) {
	f := &fakeTransport{do: func(method, path string, _ []byte, _ string) (*http.Response, error) {
		switch path {
		case "/v2/wapi/members/me":
			return okResponse(map[string]any{"content": map[string]string{"emailAddress": "sender@example.test"}}), nil
		case "/v2/wapi/mail-drafts":
			return okResponse([]any{map[string]string{"id": "draft"}}), nil
		default:
			t.Fatalf("unexpected request after incomplete draft result: %s %s", method, path)
			return nil, errors.New("unexpected request")
		}
	}}
	c := New(f, "sender@example.test")
	if err := c.Send(context.Background(), "sender@example.test", []string{"to@example.test"}, []byte(submission)); !errors.Is(err, model.ErrUnavailable) {
		t.Fatalf("incomplete draft result must fail, got %v", err)
	}
}

func TestMIMEParsingPreservesKoreanCharset(t *testing.T) {
	raw := []byte("From: sender@example.test\r\nTo: to@example.test\r\nSubject: test\r\nContent-Type: text/plain; charset=euc-kr\r\nContent-Transfer-Encoding: base64\r\n\r\nxde9usau")
	got, err := parseOutgoing(raw, "sender@example.test", []string{"to@example.test"}, "sender@example.test")
	if err != nil || got.Text != "테스트" {
		t.Fatalf("err=%v text=%q", err, got.Text)
	}
}

func TestAPIErrorNeverIncludesPrivateResponseBody(t *testing.T) {
	f := &fakeTransport{do: func(string, string, []byte, string) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"header":{"isSuccessful":false,"resultCode":42,"resultMessage":"private mailbox data"},"result":null}`))}, nil
	}}
	err := withInbox(f).Delete(context.Background(), []string{"id"})
	if err == nil || strings.Contains(err.Error(), "private mailbox data") {
		t.Fatal(err)
	}
}

func TestAuthErrorsDifferFromPermissionErrors(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := &fakeTransport{do: func(string, string, []byte, string) (*http.Response, error) { return statusResponse(status), nil }}
			err := withInbox(f).Delete(context.Background(), []string{"id"})
			if err == nil || errors.Is(err, model.ErrAuthentication) != (status == 401) {
				t.Fatal(err)
			}
		})
	}
	f := &fakeTransport{do: func(string, string, []byte, string) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"header":{"isSuccessful":false,"resultCode":-24400100},"result":null}`))}, nil
	}}
	if err := withInbox(f).Delete(context.Background(), []string{"id"}); !errors.Is(err, model.ErrAuthentication) {
		t.Fatal(err)
	}
}
