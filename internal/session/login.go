package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/refracta/dooray-mail-bridge/internal/model"
)

type loginResponse struct {
	Code       string `json:"code"`
	ErrorCode  string `json:"errorCode"`
	ResultData string `json:"result_data"`
}
type loginDocument struct {
	URL  *url.URL
	Body []byte
}

func (s *Session) loginRequest(ctx context.Context, method string, target *url.URL, form url.Values, ajax bool) (loginDocument, error) {
	if !s.allowedLoginURL(target) {
		return loginDocument{}, errors.New("refused authentication request outside KAIST SSO and the configured Dooray tenant")
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return loginDocument{}, errors.New("invalid authentication request")
	}
	req.Header.Set("User-Agent", "dooray-mail-bridge/0.1")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", target.Scheme+"://"+target.Host)
		req.Header.Set("Referer", target.Scheme+"://"+target.Host+"/auth/kaist/user/login/view")
	}
	if ajax {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Accept", "application/json")
	}
	resp, err := s.loginClient.Do(req)
	if err != nil {
		return loginDocument{}, fmt.Errorf("%w: authentication request failed", model.ErrUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return loginDocument{}, fmt.Errorf("%w: authentication HTTP status %d", model.ErrUnavailable, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return loginDocument{}, errors.New("invalid authentication response size")
	}
	return loginDocument{URL: resp.Request.URL, Body: data}, nil
}

func (s *Session) ssoURL(path string) *url.URL {
	u, _ := url.Parse(path)
	return s.sso.ResolveReference(u)
}
func (s *Session) loginJSON(ctx context.Context, path string, values url.Values) (loginResponse, error) {
	doc, err := s.loginRequest(ctx, http.MethodPost, s.ssoURL(path), values, true)
	if err != nil {
		return loginResponse{}, err
	}
	var value loginResponse
	if err := json.Unmarshal(doc.Body, &value); err != nil {
		return value, errors.New("invalid KAIST authentication response")
	}
	return value, nil
}

func (s *Session) login(ctx context.Context) error {
	entry := s.base.ResolveReference(&url.URL{Path: "/mail/systems/inbox"})
	doc, err := s.loginRequest(ctx, http.MethodGet, entry, nil, false)
	if err != nil {
		return err
	}
	return s.completeLogin(ctx, doc)
}

func (s *Session) completeLogin(ctx context.Context, doc loginDocument) error {
	for step := 0; step < 10; step++ {
		if doc.URL.Host == s.base.Host && strings.HasPrefix(doc.URL.Path, "/mail/") {
			return nil
		}
		p, err := parseLoginPage(doc.Body)
		if err != nil {
			return err
		}
		if doc.URL.Host == s.sso.Host && doc.URL.Path == "/auth/kaist/user/device/view" {
			doc, err = s.skipDeviceNotice(ctx, doc)
			if err != nil {
				return err
			}
			continue
		}
		if len(p.NextData) > 0 {
			link, err := p.samlLoginURL()
			if err != nil {
				return err
			}
			u, err := url.Parse(link)
			if err != nil {
				return errors.New("invalid Dooray SAML login URL")
			}
			target := doc.URL.ResolveReference(u)
			if target.Host != s.base.Host || target.Path != "/idp/login/saml" {
				return errors.New("unexpected Dooray SAML login URL")
			}
			doc, err = s.loginRequest(ctx, http.MethodGet, target, nil, false)
			if err != nil {
				return err
			}
			continue
		}
		if _, hasPassword := p.Inputs["login_pwd"]; hasPassword {
			if doc.URL.Host != s.sso.Host || !strings.HasPrefix(doc.URL.Path, "/auth/kaist/user/login/") {
				return errors.New("refused credentials on an unexpected login page")
			}
			if p.Inputs["agt_id"] == "" || p.LinkURL == "" {
				return errors.New("KAIST login form has changed")
			}
			link, err := url.Parse(p.LinkURL)
			if err != nil || link.IsAbs() || link.Host != "" || !strings.HasPrefix(link.Path, "/kaist/user/") {
				return errors.New("invalid KAIST return path")
			}
			init, err := s.loginJSON(ctx, "/auth/user/login/init", url.Values{})
			if err != nil {
				return err
			}
			payload, err := json.Marshal(struct {
				ID       string   `json:"login_id"`
				Password string   `json:"login_pwd"`
				Agent    string   `json:"agt_id"`
				Link     string   `json:"linkUrl"`
				Devices  []string `json:"device_cd"`
			}{s.opts.Username, s.opts.Password, p.Inputs["agt_id"], p.LinkURL, []string{}})
			if err != nil {
				return err
			}
			encrypted, err := encryptLogin(init.ResultData, payload)
			clear(payload)
			if err != nil {
				return err
			}
			result, err := s.loginJSON(ctx, "/auth/user/login/auth", url.Values{"user_data": {encrypted}})
			if err != nil {
				return err
			}
			switch result.Code {
			case "SS0001":
				doc, err = s.loginRequest(ctx, http.MethodGet, s.ssoURL("/auth"+p.LinkURL), nil, false)
			case "SS0098":
				doc, err = s.loginRequest(ctx, http.MethodPost, s.ssoURL("/auth/kaist/user/login/second/view"), url.Values{"user_gubun": {"user"}, "linkUrl": {p.LinkURL}}, false)
				if err == nil {
					err = s.verifyEmail(ctx, doc)
				}
				if err == nil {
					doc, err = s.loginRequest(ctx, http.MethodGet, s.ssoURL("/auth"+p.LinkURL), nil, false)
				}
			case "SS0099":
				doc, err = s.loginRequest(ctx, http.MethodGet, s.ssoURL("/auth/kaist/user/device/view"), nil, false)
				if err == nil {
					doc, err = s.skipDeviceNotice(ctx, doc)
				}
			case "EAU001":
				return model.ErrAuthentication
			default:
				return errors.New("KAIST requires an unsupported account or device action before login")
			}
			if err != nil {
				return err
			}
			continue
		}
		// SAML HTTP-POST binding normally uses a tiny auto-submitting form.
		// Submit its fields directly; never evaluate downloaded JavaScript.
		submitted := false
		for _, form := range p.Forms {
			if form.Values.Get("SAMLResponse") == "" {
				continue
			}
			u, err := url.Parse(form.Action)
			if err != nil {
				return errors.New("invalid SAML response destination")
			}
			target := doc.URL.ResolveReference(u)
			if target.Host != s.base.Host || form.Method != "POST" {
				return errors.New("unexpected SAML response destination")
			}
			doc, err = s.loginRequest(ctx, http.MethodPost, target, form.Values, false)
			if err != nil {
				return err
			}
			submitted = true
			break
		}
		if submitted {
			continue
		}
		// A callback can complete authentication without navigating to /mail.
		if doc.URL.Host == s.base.Host {
			ok, err := s.identity(ctx)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
		return errors.New("KAIST authentication flow reached an unsupported page")
	}
	return errors.New("too many KAIST authentication steps")
}

func (s *Session) verifyEmail(ctx context.Context, doc loginDocument) error {
	if s.opts.CodeURL == "" {
		return errors.New("KAIST_CODE_URL is required for email verification")
	}
	if doc.URL.Host != s.sso.Host || doc.URL.Path != "/auth/kaist/user/login/second/view" {
		return errors.New("unexpected KAIST verification page")
	}
	p, err := parseLoginPage(doc.Body)
	if err != nil {
		return err
	}
	if _, ok := p.Inputs["crtfc_no"]; !ok {
		return errors.New("KAIST email verification form has changed")
	}
	// The real page refreshes the server-side login nonce on pageshow.
	if _, err := s.loginJSON(ctx, "/auth/user/login/init", url.Values{}); err != nil {
		return err
	}
	baseline, err := s.readCode(ctx)
	if err != nil {
		return err
	}
	result, err := s.loginJSON(ctx, "/auth/kaist/user/login/second/ajaxSendMail", url.Values{})
	if err != nil {
		return err
	}
	if result.ErrorCode != "SS0001" {
		return errors.New("KAIST could not send the verification email")
	}
	code, err := s.waitCode(ctx, baseline)
	if err != nil {
		return err
	}
	result, err = s.loginJSON(ctx, "/auth/kaist/user/login/second/ajaxValidCrtfcNo", url.Values{"crtfc_no": {code}})
	if err != nil {
		return err
	}
	if result.Code != "SS0001" {
		switch result.Code {
		case "SS0099":
			doc, err := s.loginRequest(ctx, http.MethodGet, s.ssoURL("/auth/kaist/user/device/view"), nil, false)
			if err != nil {
				return err
			}
			_, err = s.skipDeviceNotice(ctx, doc)
			return err
		case "SS0007":
			return errors.New("KAIST email verification succeeded; concurrent-session confirmation is required")
		case "E001":
			return errors.New("KAIST rejected the verification code")
		case "E002":
			return errors.New("KAIST verification code expired")
		case "E003":
			return errors.New("KAIST verification attempt limit reached")
		default:
			return errors.New("KAIST email verification response was not supported")
		}
	}
	return nil
}

func (s *Session) skipDeviceNotice(ctx context.Context, doc loginDocument) (loginDocument, error) {
	// Choose the site's explicit "do not register" action; do not enroll a
	// trusted device or change the user's MFA settings merely to log in.
	if doc.URL.Host != s.sso.Host || doc.URL.Path != "/auth/kaist/user/device/view" || !strings.Contains(string(doc.Body), "/auth/kaist/user/device/login") || !strings.Contains(string(doc.Body), "javascript:nextProc();") {
		return loginDocument{}, errors.New("KAIST new-device notice has changed")
	}
	return s.loginRequest(ctx, http.MethodGet, s.ssoURL("/auth/kaist/user/device/login"), nil, false)
}
