package session

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"time"

	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"golang.org/x/net/html"
)

const verificationSender = "ssoadmin@kaist.ac.kr"
const verificationSubject = "[발신전용] KAIST 본인인증번호"

var codeInText = regexp.MustCompile(`\b[0-9]{6}\b`)

func parseVerificationMail(raw []byte, recipient string) (string, time.Time, bool) {
	if len(raw) == 0 || len(raw) > maxCodeMessageBytes {
		return "", time.Time{}, false
	}
	r, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return "", time.Time{}, false
	}
	defer r.Close()
	from, err := r.Header.AddressList("From")
	if err != nil || len(from) != 1 || !strings.EqualFold(from[0].Address, verificationSender) {
		return "", time.Time{}, false
	}
	subject, err := r.Header.Subject()
	if err != nil || subject != verificationSubject {
		return "", time.Time{}, false
	}
	to, err := r.Header.AddressList("To")
	if err != nil {
		return "", time.Time{}, false
	}
	matched := false
	for _, address := range to {
		if strings.EqualFold(address.Address, recipient) {
			matched = true
			break
		}
	}
	if !matched {
		return "", time.Time{}, false
	}
	date, err := r.Header.Date()
	if err != nil || date.IsZero() {
		return "", time.Time{}, false
	}
	codes := map[string]bool{}
	for parts := 0; parts < 64; parts++ {
		part, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", time.Time{}, false
		}
		header, ok := part.Header.(*mail.InlineHeader)
		if !ok {
			continue
		}
		mediaType, _, err := header.ContentType()
		if err != nil || mediaType != "text/plain" && mediaType != "text/html" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(part.Body, maxCodeMessageBytes+1))
		if err != nil || len(data) > maxCodeMessageBytes {
			return "", time.Time{}, false
		}
		text := string(data)
		if mediaType == "text/html" {
			text = visibleHTMLText(data)
		}
		for _, code := range codeInText.FindAllString(text, -1) {
			codes[code] = true
		}
	}
	if len(codes) != 1 {
		return "", time.Time{}, false
	}
	for code := range codes {
		return code, date, true
	}
	return "", time.Time{}, false
}

func visibleHTMLText(data []byte) string {
	root, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "head" || n.Data == "noscript") {
			return
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		if n.Type == html.ElementNode && (n.Data == "br" || n.Data == "p" || n.Data == "div" || n.Data == "td" || n.Data == "tr") {
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return b.String()
}
