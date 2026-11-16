package config

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/refracta/dooray-mail-bridge/internal/session"
)

type Config struct {
	Session         session.Options
	DataDir         string
	IMAPAddress     string
	SMTPAddress     string
	TLSCert         string
	TLSKey          string
	InsecureLocal   bool
	PollInterval    time.Duration
	MaxMessageBytes int64
}

func FromEnv() (Config, error) {
	get := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}
	c := Config{DataDir: get("DATA_DIR", "data"), IMAPAddress: get("IMAP_ADDR", "127.0.0.1:1993"), SMTPAddress: get("SMTP_ADDR", "127.0.0.1:1465"), TLSCert: os.Getenv("TLS_CERT"), TLSKey: os.Getenv("TLS_KEY"), InsecureLocal: os.Getenv("ALLOW_INSECURE_LOCAL") == "true", PollInterval: 30 * time.Second, MaxMessageBytes: 32 << 20}
	c.Session = session.Options{BaseURL: get("DOORAY_URL", "https://kaist.gov-dooray.com"), Username: os.Getenv("KAIST_ID"), Password: os.Getenv("KAIST_PASSWORD"), Email: os.Getenv("DOORAY_EMAIL"), CodeURL: os.Getenv("KAIST_CODE_URL"), CodeToken: os.Getenv("KAIST_CODE_TOKEN"), DataDir: filepath.Join(c.DataDir, "session")}
	if c.Session.Email == "" && c.Session.Username != "" {
		c.Session.Email = c.Session.Username + "@kaist.ac.kr"
	}
	if value := os.Getenv("POLL_INTERVAL"); value != "" {
		interval, err := time.ParseDuration(value)
		if err != nil || interval < 5*time.Second {
			return c, errors.New("POLL_INTERVAL must be a duration of at least 5s")
		}
		c.PollInterval = interval
	}
	if value := os.Getenv("MAX_MESSAGE_BYTES"); value != "" {
		size, err := strconv.ParseInt(value, 10, 64)
		if err != nil || size < 1024 || size > 128<<20 {
			return c, errors.New("MAX_MESSAGE_BYTES must be between 1024 and 134217728")
		}
		c.MaxMessageBytes = size
	}
	if c.Session.Username == "" || c.Session.Password == "" {
		return c, errors.New("KAIST_ID and KAIST_PASSWORD are required")
	}
	if strings.ContainsAny(c.Session.Username, "\r\n\x00") || strings.ContainsAny(c.Session.Email, "\r\n\x00") {
		return c, errors.New("invalid account identifier")
	}
	if err := c.ValidateListeners(); err != nil {
		return c, err
	}
	return c, nil
}

func (c Config) ValidateListeners() error {
	for _, addr := range []string{c.IMAPAddress, c.SMTPAddress} {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return errors.New("IMAP_ADDR and SMTP_ADDR must be host:port addresses")
		}
		if c.InsecureLocal {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return errors.New("ALLOW_INSECURE_LOCAL only permits numeric loopback listener addresses")
			}
		}
	}
	if !c.InsecureLocal && (c.TLSCert == "" || c.TLSKey == "") {
		return errors.New("TLS_CERT and TLS_KEY are required (or allow plaintext on loopback with ALLOW_INSECURE_LOCAL=true)")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("TLS_CERT and TLS_KEY must be supplied together")
	}
	return nil
}
