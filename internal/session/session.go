// Package session implements KAIST SAML over HTTP with HTTP or IMAP email verification.
// It does not launch a browser, execute downloaded JavaScript, or depend on MCP.
package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/refracta/dooray-mail-bridge/internal/model"
)

type Options struct {
	BaseURL           string
	Username          string
	Password          string
	Email             string
	CodeURL           string
	CodeToken         string
	CodeSource        string
	CodeIMAPAddr      string
	CodeIMAPUsername  string
	CodeIMAPPassword  string
	CodeIMAPMailbox   string
	CodeIMAPRecipient string
	DataDir           string
	LoginTimeout      time.Duration
}

type Session struct {
	opts         Options
	base         *url.URL
	sso          *url.URL
	jar          *persistentJar
	client       *http.Client
	loginClient  *http.Client
	codeClient   *http.Client
	codeIMAP     *imapCodeSource
	gate         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	ready        bool
	lastVerified time.Time
	lastAttempt  time.Time
	lastError    error
	loginFn      func(context.Context) error // injectable state-machine boundary in tests
}

func New(opts Options) (*Session, error) {
	var codeErr error
	opts, codeErr = normalizeCodeOptions(opts)
	if codeErr != nil {
		return nil, codeErr
	}
	u, err := url.Parse(opts.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("DOORAY_URL must be an HTTPS origin")
	}
	if opts.Username == "" || opts.Password == "" || opts.Email == "" || opts.DataDir == "" {
		return nil, errors.New("KAIST credentials, account email, and data directory are required")
	}
	if opts.CodeSource == "http" {
		v, err := url.Parse(opts.CodeURL)
		if err != nil || v.Scheme != "https" || v.Host == "" || v.User != nil {
			return nil, errors.New("KAIST_CODE_URL must be an HTTPS URL without embedded credentials")
		}
	}
	if opts.LoginTimeout == 0 {
		opts.LoginTimeout = 4 * time.Minute
	}
	sso, _ := url.Parse("https://sso.kaist.ac.kr")
	binding := sha256.Sum256([]byte(opts.BaseURL + "\x00" + opts.Email + "\x00" + opts.Username + "\x00" + opts.Password))
	jar, err := newJar(filepath.Join(opts.DataDir, "session.json"), hex.EncodeToString(binding[:]))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{opts: opts, base: u, sso: sso, jar: jar, gate: make(chan struct{}, 1), ctx: ctx, cancel: cancel}
	if opts.CodeSource == "imap" {
		s.codeIMAP = newIMAPCodeSource(opts)
	}
	s.client = &http.Client{Jar: jar, Timeout: 60 * time.Second, CheckRedirect: noRedirect}
	s.codeClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirect}
	s.loginClient = &http.Client{Jar: jar, Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 15 {
			return errors.New("too many authentication redirects")
		}
		if !s.allowedLoginURL(req.URL) {
			return errors.New("authentication redirected outside the configured tenant and KAIST SSO")
		}
		return nil
	}}
	s.loginFn = s.login
	return s, nil
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
func sameSecret(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

func (s *Session) Authenticate(ctx context.Context, username, password string) error {
	if !(sameSecret(username, s.opts.Username) || sameSecret(username, s.opts.Email)) || !sameSecret(password, s.opts.Password) {
		return model.ErrAuthentication
	}
	return s.ensure(ctx)
}

func (s *Session) State() (bool, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready, s.lastVerified
}
func (s *Session) invalidate() { s.mu.Lock(); s.ready = false; s.mu.Unlock() }

func (s *Session) ensure(ctx context.Context) error {
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	ready, lastVerified, lastAttempt, lastError := s.ready, s.lastVerified, s.lastAttempt, s.lastError
	s.mu.Unlock()
	if ready && time.Since(lastVerified) < time.Minute {
		return nil
	}
	ok, err := s.identity(ctx)
	if err != nil {
		return err
	}
	if ok {
		s.mu.Lock()
		s.ready = true
		s.lastVerified = time.Now()
		s.mu.Unlock()
		return nil
	}
	s.invalidate()
	if lastError != nil && time.Since(lastAttempt) < time.Minute {
		return fmt.Errorf("%w: login retry is cooling down", model.ErrUnavailable)
	}
	s.mu.Lock()
	s.lastAttempt = time.Now()
	s.mu.Unlock()
	loginCtx, cancel := context.WithTimeout(ctx, s.opts.LoginTimeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	err = s.loginFn(loginCtx)
	if err == nil {
		ok, err = s.identity(loginCtx)
		if err == nil && !ok {
			err = fmt.Errorf("%w: authenticated session was not accepted", model.ErrUnavailable)
		}
	}
	if err == nil {
		err = s.jar.save()
	}
	s.mu.Lock()
	s.lastError = err
	if err != nil {
		s.lastAttempt = time.Now()
	}
	s.ready = err == nil
	if err == nil {
		s.lastVerified = time.Now()
	}
	s.mu.Unlock()
	return err
}

func (s *Session) Close() error {
	s.cancel()
	s.invalidate()
	s.closeCodeSource()
	s.client.CloseIdleConnections()
	s.loginClient.CloseIdleConnections()
	s.codeClient.CloseIdleConnections()
	return s.jar.save()
}

func (s *Session) Do(ctx context.Context, method, path string, body []byte, contentType string) (*http.Response, error) {
	if _, err := s.apiURL(path); err != nil {
		return nil, err
	}
	if err := s.ensure(ctx); err != nil {
		return nil, err
	}
	resp, err := s.request(ctx, method, path, body, contentType)
	if err != nil {
		return nil, err
	}
	if !s.expired(resp) {
		return resp, nil
	}
	resp.Body.Close()
	s.invalidate()
	if method != http.MethodGet && method != http.MethodHead {
		return nil, fmt.Errorf("%w: session expired; reconnect before retrying the write", model.ErrUnavailable)
	}
	if err := s.ensure(ctx); err != nil {
		return nil, err
	}
	resp, err = s.request(ctx, method, path, body, contentType)
	if err == nil && s.expired(resp) {
		resp.Body.Close()
		s.invalidate()
		return nil, fmt.Errorf("%w: renewed session was rejected", model.ErrUnavailable)
	}
	return resp, err
}

func (s *Session) apiURL(path string) (*url.URL, error) {
	u, err := url.Parse(path)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/v2/wapi/") || strings.Contains(u.Path, "..") || u.Fragment != "" {
		return nil, errors.New("request must target this tenant's /v2/wapi/ API")
	}
	return s.base.ResolveReference(u), nil
}

func (s *Session) request(ctx context.Context, method, path string, body []byte, contentType string) (*http.Response, error) {
	u, err := s.apiURL(path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid webmail request")
	}
	req.Header.Set("User-Agent", "dooray-mail-bridge/0.1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", s.base.Scheme+"://"+s.base.Host)
	req.Header.Set("Referer", s.base.Scheme+"://"+s.base.Host+"/mail/")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: webmail request failed", model.ErrUnavailable)
	}
	return resp, nil
}

func (s *Session) expired(resp *http.Response) bool {
	if resp.StatusCode == http.StatusUnauthorized {
		return true
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		u, err := url.Parse(resp.Header.Get("Location"))
		return err == nil && (strings.HasPrefix(u.Path, "/idp/") || strings.HasPrefix(u.Path, "/auth/"))
	}
	// Permission-denied HTTP 403 is not evidence of an expired session.
	if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "json") {
		prefix, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body = &restoredBody{Reader: io.MultiReader(bytes.NewReader(prefix), resp.Body), Closer: resp.Body}
		var wrapper struct {
			Header struct {
				ResultCode int64 `json:"resultCode"`
			} `json:"header"`
		}
		if json.Unmarshal(prefix, &wrapper) == nil && wrapper.Header.ResultCode == -24400100 {
			return true
		}
	}
	return false
}

type restoredBody struct {
	io.Reader
	io.Closer
}

func (s *Session) identity(ctx context.Context) (bool, error) {
	resp, err := s.request(ctx, http.MethodGet, "/v2/wapi/members/me", nil, "")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if s.expired(resp) {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, model.ErrUnavailable
	}
	var wrapper struct {
		Header struct {
			IsSuccessful bool `json:"isSuccessful"`
		} `json:"header"`
		Result struct {
			Content struct {
				EmailAddress string `json:"emailAddress"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&wrapper); err != nil {
		return false, model.ErrUnavailable
	}
	if !wrapper.Header.IsSuccessful {
		return false, model.ErrUnavailable
	}
	if !strings.EqualFold(wrapper.Result.Content.EmailAddress, s.opts.Email) {
		return false, errors.New("authenticated Dooray account does not match configuration")
	}
	return true, nil
}

func (s *Session) allowedLoginURL(u *url.URL) bool {
	return u.User == nil && u.Scheme == "https" && (u.Host == s.base.Host || u.Host == s.sso.Host)
}
