package session

import (
	"errors"
	"net"
	"net/mail"
	"strconv"
	"strings"
)

func normalizeCodeOptions(opts Options) (Options, error) {
	source := strings.ToLower(strings.TrimSpace(opts.CodeSource))
	if source == "" {
		if opts.CodeURL != "" {
			source = "http"
		} else if opts.CodeIMAPAddr != "" || opts.CodeIMAPUsername != "" || opts.CodeIMAPPassword != "" {
			source = "imap"
		}
	}
	if source != "" && source != "http" && source != "imap" {
		return opts, errors.New("KAIST_CODE_SOURCE must be http or imap")
	}
	if source == "http" && opts.CodeURL == "" {
		return opts, errors.New("KAIST_CODE_URL is required for the HTTP code source")
	}
	if source == "imap" {
		host, port, err := net.SplitHostPort(opts.CodeIMAPAddr)
		p, portErr := strconv.Atoi(port)
		if err != nil || host == "" || strings.ContainsAny(host, "/@?#") || portErr != nil || p < 1 || p > 65535 {
			return opts, errors.New("KAIST_CODE_IMAP_ADDR must specify host:port for implicit TLS")
		}
		if opts.CodeIMAPUsername == "" || opts.CodeIMAPPassword == "" {
			return opts, errors.New("KAIST_CODE_IMAP_USERNAME and KAIST_CODE_IMAP_PASSWORD are required")
		}
		if opts.CodeIMAPMailbox == "" {
			opts.CodeIMAPMailbox = "INBOX"
		}
		if strings.ContainsAny(opts.CodeIMAPMailbox, "\x00\r\n") {
			return opts, errors.New("invalid verification mailbox name")
		}
		if opts.CodeIMAPRecipient == "" {
			opts.CodeIMAPRecipient = opts.CodeIMAPUsername
		}
		recipient := strings.TrimSpace(opts.CodeIMAPRecipient)
		parsed, err := mail.ParseAddress(recipient)
		if err != nil || parsed.Address != recipient || !strings.Contains(recipient, "@") {
			return opts, errors.New("KAIST_CODE_IMAP_RECIPIENT must be an email address (or use an email address as the IMAP username)")
		}
		opts.CodeIMAPRecipient = strings.ToLower(recipient)
	}
	opts.CodeSource = source
	return opts, nil
}
