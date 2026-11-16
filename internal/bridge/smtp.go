package bridge

import (
	"errors"
	"io"
	"net/mail"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/refracta/dooray-mail-bridge/internal/model"
)

func (b *Bridge) SMTPBackend() smtp.Backend {
	return smtp.BackendFunc(func(_ *smtp.Conn) (smtp.Session, error) { return &smtpSession{b: b}, nil })
}

type smtpSession struct {
	b             *Bridge
	authenticated bool
	from          string
	recipients    []string
}

func (s *smtpSession) AuthMechanisms() []string { return []string{sasl.Plain, sasl.Login} }

func (s *smtpSession) authenticate(username, password string) error {
	if len(username) > 1024 || len(password) > 16384 {
		return smtp.ErrAuthFailed
	}
	ctx, cancel := s.b.context()
	defer cancel()
	if err := s.b.provider.Authenticate(ctx, username, password); err != nil {
		if errors.Is(err, model.ErrAuthentication) {
			return smtp.ErrAuthFailed
		}
		return smtpFailure(err)
	}
	s.authenticated = true
	return nil
}

func (s *smtpSession) Auth(mechanism string) (sasl.Server, error) {
	switch mechanism {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if identity != "" && identity != username {
				return smtp.ErrAuthFailed
			}
			return s.authenticate(username, password)
		}), nil
	case sasl.Login:
		return &loginServer{authenticate: s.authenticate}, nil
	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

type loginServer struct {
	stage        int
	username     string
	authenticate func(string, string) error
}

func (s *loginServer) Next(response []byte) ([]byte, bool, error) {
	if len(response) > 16384 {
		return nil, true, smtp.ErrAuthFailed
	}
	switch s.stage {
	case 0:
		if response == nil {
			s.stage = 1
			return []byte("Username:"), false, nil
		}
		fallthrough
	case 1:
		s.username = string(response)
		s.stage = 2
		return []byte("Password:"), false, nil
	case 2:
		s.stage = 3
		err := s.authenticate(s.username, string(response))
		s.username = ""
		return nil, true, err
	default:
		return nil, true, smtp.ErrAuthFailed
	}
}

func smtpAddress(address string) bool {
	if strings.ContainsAny(address, "\r\n\x00") {
		return false
	}
	parsed, err := mail.ParseAddress(address)
	return err == nil && parsed.Name == "" && parsed.Address == address
}

func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authenticated {
		return smtp.ErrAuthRequired
	}
	if !smtpAddress(from) {
		return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 7}, Message: "A valid authenticated sender address is required"}
	}
	s.from, s.recipients = from, nil
	return nil
}

func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if !s.authenticated {
		return smtp.ErrAuthRequired
	}
	if s.from == "" {
		return &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "MAIL required first"}
	}
	if !smtpAddress(to) {
		return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "Invalid recipient address"}
	}
	if len(s.recipients) >= 100 {
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients"}
	}
	s.recipients = append(s.recipients, to)
	return nil
}

func (s *smtpSession) Data(reader io.Reader) error {
	if !s.authenticated {
		return smtp.ErrAuthRequired
	}
	if s.from == "" || len(s.recipients) == 0 {
		return &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "MAIL and RCPT required first"}
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxMessageBytes+1))
	if err != nil {
		return smtpFailure(err)
	}
	if len(raw) > MaxMessageBytes {
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message exceeds size limit"}
	}
	ctx, cancel := s.b.context()
	defer cancel()
	// A submission is attempted once. A transport error after acceptance is
	// uncertain, so retry belongs to the mail client rather than this bridge.
	err = s.b.provider.Send(ctx, s.from, append([]string(nil), s.recipients...), raw)
	s.Reset()
	return smtpFailure(err)
}

func (s *smtpSession) Reset()        { s.from, s.recipients = "", nil }
func (s *smtpSession) Logout() error { s.Reset(); s.authenticated = false; return nil }

func smtpFailure(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, model.ErrAuthentication) {
		return smtp.ErrAuthFailed
	}
	if errors.Is(err, model.ErrUnsupported) {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "The mail provider cannot submit this message"}
	}
	return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Mail provider submission failed; delivery status may be uncertain"}
}
