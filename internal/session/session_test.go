package session

import (
	"context"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geeksbaek/seed"
	"github.com/refracta/dooray-mail-bridge/internal/model"
)

func testSession(t *testing.T, server *httptest.Server) *Session {
	t.Helper()
	s, err := New(Options{BaseURL: server.URL, Username: "student", Password: "fixture-password", Email: "student@example.invalid", CodeURL: server.URL + "/code", DataDir: t.TempDir(), LoginTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s.sso, _ = url.Parse(server.URL)
	s.client.Transport = server.Client().Transport
	s.loginClient.Transport = server.Client().Transport
	s.codeClient.Transport = server.Client().Transport
	t.Cleanup(func() { s.Close() })
	return s
}

func identityJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"header":{"isSuccessful":true},"result":{"content":{"emailAddress":"student@example.invalid"}}}`)
}

func TestHTTPLoginMFADeviceNoticeSAMLAndPersistence(t *testing.T) {
	var calls, auths, sends, validations, registrations atomic.Int32
	var samlRequests atomic.Int32
	var sent atomic.Bool
	const key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	now := time.Now().UTC()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		cookie, _ := r.Cookie("SESSION")
		authenticated := cookie != nil && cookie.Value == "fixture-authenticated"
		if strings.Contains(r.URL.Path, "ajax") || strings.HasSuffix(r.URL.Path, "/init") || strings.HasSuffix(r.URL.Path, "/auth") {
			w.Header().Set("Content-Type", "application/json")
		}
		switch r.URL.Path {
		case "/v2/wapi/members/me":
			if !authenticated {
				w.WriteHeader(401)
				return
			}
			identityJSON(w)
		case "/mail/systems/inbox":
			if !authenticated {
				http.Redirect(w, r, "/idp/multi", 302)
				return
			}
			fmt.Fprint(w, "<title>Mail</title>")
		case "/idp/multi":
			fmt.Fprint(w, `<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"multiLoginButtons":[{"url":"/idp/login"},{"url":"/idp/login/saml?redirectUrl=%2Fmail%2Fsystems%2Finbox"}]}}}</script>`)
		case "/idp/login/saml":
			http.Redirect(w, r, "/auth/kaist/user/login/view", 302)
		case "/auth/kaist/user/login/view":
			fmt.Fprint(w, `<input id="agt_id" value="fixture-agent"><input id="login_id"><input id="login_pwd" type="password"><script>var linkUrl="/kaist/user/saml/login/link/redirect";</script>`)
		case "/auth/user/login/init":
			fmt.Fprintf(w, `{"result_data":%q}`, key+"unused-suffix")
		case "/auth/user/login/auth":
			auths.Add(1)
			r.ParseForm()
			encrypted, err := hex.DecodeString(r.Form.Get("user_data"))
			if err != nil || len(encrypted) == 0 || len(encrypted)%16 != 0 {
				t.Error("invalid encrypted login submission")
				w.WriteHeader(400)
				return
			}
			material, _ := hex.DecodeString(key)
			block, _ := seed.NewCipher(material[:16])
			plain := make([]byte, len(encrypted))
			cipher.NewCBCDecrypter(block, material[32:]).CryptBlocks(plain, encrypted)
			padding := int(plain[len(plain)-1])
			if padding < 1 || padding > 16 {
				t.Error("invalid X9.23 padding")
				w.WriteHeader(400)
				return
			}
			var payload map[string]any
			if json.Unmarshal(plain[:len(plain)-padding], &payload) != nil {
				t.Error("invalid encrypted JSON")
				w.WriteHeader(400)
				return
			}
			if payload["login_id"] != "student" || payload["login_pwd"] != "fixture-password" || payload["agt_id"] != "fixture-agent" {
				fmt.Fprint(w, `{"code":"EAU001"}`)
				return
			}
			fmt.Fprint(w, `{"code":"SS0098"}`)
		case "/auth/kaist/user/login/second/view":
			r.ParseForm()
			if r.Form.Get("user_gubun") != "user" {
				t.Error("missing MFA login context")
			}
			fmt.Fprint(w, `<input id="crtfc_no" name="crtfc_no" disabled><input id="email">`)
		case "/code":
			id, code := "old", ""
			if sent.Load() {
				id, code = "new", "012345"
			}
			json.NewEncoder(w).Encode(map[string]any{"id": id, "code": code, "date": now.Format(time.RFC3339Nano), "serverTime": now.UnixMilli()})
		case "/auth/kaist/user/login/second/ajaxSendMail":
			sends.Add(1)
			sent.Store(true)
			fmt.Fprint(w, `{"errorCode":"SS0001"}`)
		case "/auth/kaist/user/login/second/ajaxValidCrtfcNo":
			validations.Add(1)
			r.ParseForm()
			if r.Form.Get("crtfc_no") != "012345" {
				t.Error("OTP leading zero lost")
			}
			fmt.Fprint(w, `{"code":"SS0099"}`)
		case "/auth/kaist/user/device/view":
			fmt.Fprint(w, `<a href="javascript:nextProc();">Do not register</a><script>function nextProc(){location.replace('/auth/kaist/user/device/login');}</script>`)
		case "/auth/kaist/user/device/ajaxRegist":
			registrations.Add(1)
			t.Error("client must not register trusted devices")
			w.WriteHeader(400)
		case "/auth/kaist/user/device/login":
			http.Redirect(w, r, "/auth/kaist/user/saml/login/link/redirect", 302)
		case "/auth/kaist/user/saml/login/link/redirect":
			if samlRequests.Add(1) != 1 {
				// The upstream SAML request is consumed when its assertion is
				// created. Fetching the return path again cannot recover it.
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `<form method="post" action="/saml/acs"><input type="hidden" name="SAMLResponse" value="fixture-assertion"><input type="hidden" name="RelayState" value="fixture-relay"></form><script>document.forms[0].submit()</script>`)
		case "/saml/acs":
			r.ParseForm()
			if r.Form.Get("SAMLResponse") != "fixture-assertion" || r.Form.Get("RelayState") != "fixture-relay" {
				t.Error("SAML form was not preserved")
			}
			http.SetCookie(w, &http.Cookie{Name: "SESSION", Value: "fixture-authenticated", Path: "/", Secure: true, HttpOnly: true})
			http.Redirect(w, r, "/mail/systems/inbox", 302)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s := testSession(t, server)
	if err := s.Authenticate(context.Background(), "student", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	if auths.Load() != 1 || sends.Load() != 1 || validations.Load() != 1 || registrations.Load() != 0 || samlRequests.Load() != 1 {
		t.Fatal("login or verification was replayed")
	}
	before := calls.Load()
	for _, pair := range [][2]string{{"wrong", "fixture-password"}, {"student", "wrong"}, {"", ""}} {
		if err := s.Authenticate(context.Background(), pair[0], pair[1]); !errors.Is(err, model.ErrAuthentication) {
			t.Fatal("invalid credentials accepted")
		}
	}
	if calls.Load() != before {
		t.Fatal("invalid protocol credentials reached upstream")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(s.opts.DataDir, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("session permissions %o", info.Mode().Perm())
	}
	reopened, err := New(s.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.client.Transport = server.Client().Transport
	if err := reopened.Authenticate(context.Background(), "student@example.invalid", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	if auths.Load() != 1 {
		t.Fatal("restart did not reuse authenticated session")
	}
	opts := s.opts
	opts.Password = "changed-password"
	changed, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.Close()
	changed.client.Transport = server.Client().Transport
	if len(changed.jar.Cookies(changed.base)) != 0 {
		t.Fatal("session reused after credential configuration changed")
	}
}

func TestSafeReadRecoverySingleFlightAndNoMutationReplay(t *testing.T) {
	var authorized atomic.Bool
	var reads, writes, logins atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/wapi/members/me":
			if !authorized.Load() {
				w.WriteHeader(401)
				return
			}
			identityJSON(w)
		case "/v2/wapi/mails":
			reads.Add(1)
			if !authorized.Load() {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, "fixture")
		case "/v2/wapi/mails/send":
			writes.Add(1)
			w.WriteHeader(401)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s := testSession(t, server)
	s.loginFn = func(context.Context) error {
		logins.Add(1)
		time.Sleep(20 * time.Millisecond)
		authorized.Store(true)
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Authenticate(context.Background(), "student", "fixture-password"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if logins.Load() != 1 {
		t.Fatalf("concurrent authentication ran %d logins", logins.Load())
	}
	authorized.Store(false)
	resp, err := s.Do(context.Background(), "GET", "/v2/wapi/mails", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "fixture" {
		t.Fatal("read retry failed")
	}
	if reads.Load() != 2 || logins.Load() != 2 {
		t.Fatal("safe read recovery did not use one renewal and one retry")
	}
	_, err = s.Do(context.Background(), "POST", "/v2/wapi/mails/send", []byte(`{}`), "application/json")
	if !errors.Is(err, model.ErrUnavailable) || writes.Load() != 1 || logins.Load() != 2 {
		t.Fatal("mutation was replayed or renewed automatically")
	}
	if ready, _ := s.State(); ready {
		t.Fatal("rejected session was still marked ready")
	}
}

func TestPermissionsDoNotTriggerReauthentication(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/wapi/members/me" {
			identityJSON(w)
			return
		}
		w.WriteHeader(403)
	}))
	defer server.Close()
	s := testSession(t, server)
	s.loginFn = func(context.Context) error { t.Fatal("ACL denial triggered login"); return nil }
	resp, err := s.Do(context.Background(), "POST", "/v2/wapi/mails/delete", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("permission error was hidden")
	}
}

func TestCookieScopePersistenceAndDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.json")
	jar, err := newJar(path, "fixture-binding")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://login.example.invalid/auth/form")
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "fixture", Secure: true, MaxAge: 600}})
	if err := jar.save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := newJar(path, "fixture-binding")
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Cookies(u)) != 1 {
		t.Fatal("session cookie was not restored")
	}
	other, _ := url.Parse("https://mail.example.invalid/auth/form")
	if len(reopened.Cookies(other)) != 0 {
		t.Fatal("host-only cookie crossed host boundary")
	}
	root, _ := url.Parse("https://login.example.invalid/other")
	if len(reopened.Cookies(root)) != 0 {
		t.Fatal("default cookie path was widened")
	}
	reopened.SetCookies(u, []*http.Cookie{{Name: "session", Path: "/auth", MaxAge: -1}})
	if err := reopened.save(); err != nil {
		t.Fatal(err)
	}
	deleted, err := newJar(path, "fixture-binding")
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted.Cookies(u)) != 0 {
		t.Fatal("deleted cookie reappeared after restart")
	}
}

func TestFreshVerificationMessages(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	base := codeRecord{ID: json.RawMessage(`"10"`), ServerTime: now.UnixMilli()}
	valid := codeRecord{Code: "012345", ID: json.RawMessage(`"11"`), Date: now.Format(time.RFC3339Nano), ServerTime: now.Add(time.Second).UnixMilli()}
	if !freshCode(base, valid) {
		t.Fatal("fresh leading-zero code rejected")
	}
	for _, change := range []func(*codeRecord){func(r *codeRecord) { r.ID = base.ID }, func(r *codeRecord) { r.ID = nil }, func(r *codeRecord) { r.Code = "12345" }, func(r *codeRecord) { r.Date = now.Add(-time.Minute).Format(time.RFC3339Nano) }, func(r *codeRecord) { r.ServerTime = now.Add(4 * time.Minute).UnixMilli() }, func(r *codeRecord) { r.Date = now.Add(time.Hour).Format(time.RFC3339Nano) }} {
		bad := valid
		change(&bad)
		if freshCode(base, bad) {
			t.Fatal("stale or malformed code accepted")
		}
	}
}

func TestSessionRequestBoundaries(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("invalid target reached server") }))
	defer server.Close()
	s := testSession(t, server)
	for _, path := range []string{"https://other.invalid/v2/wapi/mails", "//other.invalid/v2/wapi/mails", "/admin", "/v2/wapi/%2e%2e/secret", "/v2/wapi/mails#fragment"} {
		if _, err := s.Do(context.Background(), "GET", path, nil, ""); err == nil {
			t.Fatalf("invalid API target accepted %s", path)
		}
	}
	for _, raw := range []string{"http://sso.kaist.ac.kr/auth/login", "https://sso.kaist.ac.kr.attacker.invalid/", "https://user:password@sso.kaist.ac.kr/"} {
		u, _ := url.Parse(raw)
		if s.allowedLoginURL(u) {
			t.Fatal("untrusted login target accepted")
		}
	}
}
