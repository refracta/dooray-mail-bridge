package session

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

type storedCookie struct {
	URL    string      `json:"url"`
	Cookie http.Cookie `json:"cookie"`
}
type cookieFile struct {
	Version int            `json:"version"`
	Binding string         `json:"binding"`
	Cookies []storedCookie `json:"cookies"`
}

// persistentJar stores only the service's own cookies. File replacement is
// atomic and mode 0600; sessions are bound to the configured account/password.
type persistentJar struct {
	jar     *cookiejar.Jar
	mu      sync.Mutex
	path    string
	binding string
	records map[string]storedCookie
}

func newJar(path, binding string) (*persistentJar, error) {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	p := &persistentJar{jar: jar, path: path, binding: binding, records: make(map[string]storedCookie)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, errors.New("could not read private session file")
	}
	var saved cookieFile
	if err := json.Unmarshal(data, &saved); err != nil || saved.Version != 1 {
		return nil, errors.New("invalid private session file")
	}
	if saved.Binding != binding {
		return p, nil
	}
	for _, r := range saved.Cookies {
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		if !r.Cookie.Expires.IsZero() && time.Now().After(r.Cookie.Expires) {
			continue
		}
		c := r.Cookie
		c.MaxAge = 0
		p.jar.SetCookies(u, []*http.Cookie{&c})
		p.records[cookieKey(u, &c)] = storedCookie{URL: r.URL, Cookie: c}
	}
	return p, nil
}

func cookieKey(u *url.URL, c *http.Cookie) string {
	domain := c.Domain
	if domain == "" {
		domain = u.Hostname()
	}
	return strings.TrimPrefix(strings.ToLower(domain), ".") + "\x00" + c.Path + "\x00" + c.Name
}

func (p *persistentJar) Cookies(u *url.URL) []*http.Cookie { return p.jar.Cookies(u) }

func (p *persistentJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.jar.SetCookies(u, cookies)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, input := range cookies {
		c := *input
		if c.Path == "" || !strings.HasPrefix(c.Path, "/") {
			c.Path = "/"
			if index := strings.LastIndex(u.Path, "/"); index > 0 {
				c.Path = u.Path[:index]
			}
		}
		key := cookieKey(u, &c)
		if c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(time.Now())) {
			delete(p.records, key)
			continue
		}
		if c.MaxAge > 0 {
			c.Expires = time.Now().Add(time.Duration(c.MaxAge) * time.Second)
			c.MaxAge = 0
		}
		origin := u.Scheme + "://" + u.Host + c.Path
		p.records[key] = storedCookie{URL: origin, Cookie: c}
	}
}

func (p *persistentJar) save() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	file := cookieFile{Version: 1, Binding: p.binding}
	for _, r := range p.records {
		if r.Cookie.Expires.IsZero() || r.Cookie.Expires.After(time.Now()) {
			file.Cookies = append(file.Cookies, r)
		}
	}
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0700); err != nil {
		return errors.New("could not create private session directory")
	}
	f, err := os.CreateTemp(filepath.Dir(p.path), ".session-*")
	if err != nil {
		return errors.New("could not write private session file")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("could not persist private session")
	}
	if err = os.Rename(tmp, p.path); err != nil {
		return errors.New("could not replace private session file")
	}
	return nil
}
