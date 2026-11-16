package dooray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	_ "github.com/emersion/go-message/charset"
	messageMail "github.com/emersion/go-message/mail"
	"github.com/refracta/dooray-mail-bridge/internal/model"
)

type emailUser struct {
	Name  string `json:"name"`
	Email string `json:"emailAddress"`
}

type userRecord struct {
	Type string    `json:"type"`
	User emailUser `json:"emailUser"`
}

func recipient(a *mail.Address) userRecord {
	return userRecord{Type: "emailUser", User: emailUser{Name: a.Name, Email: a.Address}}
}

type sendAttachment struct {
	Name        string
	ContentType string
	ContentID   string
	Data        []byte
}

type outgoing struct {
	Subject     string
	Text        string
	HTML        string
	To          []userRecord
	CC          []userRecord
	BCC         []userRecord
	Attachments []sendAttachment
}

func parseOutgoing(raw []byte, envelopeFrom string, recipients []string, expectedEmail string) (outgoing, error) {
	var out outgoing
	if len(raw) > maxResponseBytes {
		return out, errors.New("message exceeds size limit")
	}
	if !strings.EqualFold(envelopeFrom, expectedEmail) || expectedEmail == "" {
		return out, errors.New("SMTP sender must match the authenticated account")
	}
	if len(recipients) == 0 {
		return out, errors.New("at least one SMTP recipient is required")
	}
	allowed := make(map[string]*mail.Address)
	var ordered []string
	for _, address := range recipients {
		a, err := mail.ParseAddress(address)
		if err != nil || a.Address != strings.TrimSpace(address) || strings.ContainsAny(address, "\r\n") {
			return out, errors.New("invalid SMTP recipient")
		}
		key := strings.ToLower(a.Address)
		if _, exists := allowed[key]; !exists {
			ordered = append(ordered, key)
		}
		allowed[key] = a
	}
	r, err := messageMail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return out, errors.New("invalid or unsupported MIME message")
	}
	defer r.Close()
	from, err := r.Header.AddressList("From")
	if err != nil || len(from) != 1 || !strings.EqualFold(from[0].Address, expectedEmail) {
		return out, errors.New("MIME From must match the authenticated account")
	}
	fromFields := r.Header.FieldsByKey("From")
	for count := 0; fromFields.Next(); count++ {
		if count != 0 {
			return out, errors.New("multiple MIME From headers are unsupported")
		}
	}
	if r.Header.Get("Sender") != "" {
		sender, err := r.Header.AddressList("Sender")
		if err != nil || len(sender) != 1 || !strings.EqualFold(sender[0].Address, expectedEmail) {
			return out, errors.New("MIME Sender must match the authenticated account")
		}
	}
	out.Subject, err = r.Header.Subject()
	if err != nil {
		return out, errors.New("invalid MIME subject")
	}
	out.To, out.CC, out.BCC = []userRecord{}, []userRecord{}, []userRecord{}
	visible := make(map[string]bool)
	for _, field := range []string{"To", "Cc"} {
		addresses, err := r.Header.AddressList(field)
		if err != nil {
			return out, fmt.Errorf("invalid MIME %s header", field)
		}
		for _, a := range addresses {
			key := strings.ToLower(a.Address)
			if _, ok := allowed[key]; !ok || visible[key] {
				continue
			}
			visible[key] = true
			if field == "To" {
				out.To = append(out.To, recipient(a))
			} else {
				out.CC = append(out.CC, recipient(a))
			}
		}
	}
	// SMTP RCPT TO is the delivery authority. Envelope-only recipients stay
	// hidden even when the submitted MIME has no Bcc header.
	for _, key := range ordered {
		if !visible[key] {
			out.BCC = append(out.BCC, recipient(allowed[key]))
		}
	}
	var plainParts, htmlParts []string
	for count := 0; ; count++ {
		if count == 1000 {
			return out, errors.New("too many MIME parts")
		}
		part, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, errors.New("invalid or unsupported MIME part")
		}
		data, err := readBounded(part.Body)
		if err != nil {
			return out, err
		}
		mediaType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			mediaType = "text/plain"
		}
		disposition, dispositionParams, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		filename := dispositionParams["filename"]
		if filename == "" {
			filename = params["name"]
		}
		if filename == "" && disposition != "attachment" {
			if mediaType == "text/plain" {
				plainParts = append(plainParts, string(data))
				continue
			}
			if mediaType == "text/html" {
				htmlParts = append(htmlParts, string(data))
				continue
			}
		}
		if filename == "" {
			filename = "attachment"
		}
		if h, ok := part.Header.(*messageMail.AttachmentHeader); ok {
			if name, err := h.Filename(); err == nil && name != "" {
				filename = name
			}
		}
		cid := strings.Trim(part.Header.Get("Content-ID"), " <>")
		if disposition == "attachment" {
			cid = ""
		}
		out.Attachments = append(out.Attachments, sendAttachment{Name: filename, ContentType: mediaType, ContentID: cid, Data: data})
	}
	out.Text = strings.Join(plainParts, "\n")
	out.HTML = strings.Join(htmlParts, "\n")
	return out, nil
}

func (c *Client) Send(ctx context.Context, from string, recipients []string, raw []byte) error {
	message, err := parseOutgoing(raw, from, recipients, c.email)
	if err != nil {
		return err
	}
	who, err := c.identity(ctx)
	if err != nil {
		return err
	}
	bodyType, body := "text/plain", message.Text
	if message.HTML != "" {
		bodyType, body = "text/html", message.HTML
	}
	form := map[string]any{
		"id": nil,
		"users": map[string]any{
			"from": userRecord{Type: "emailUser", User: emailUser{Name: who.Name, Email: who.Email}},
			"to":   message.To, "cc": message.CC, "bcc": message.BCC,
		},
		"subject":  message.Subject,
		"priority": 3,
		"body":     map[string]any{"mimeType": bodyType, "content": body},
		"fileList": []any{}, "fileIdList": []string{},
		"security":       map[string]any{"level": "normal", "resend": true, "autoDelete": false, "retentionDays": 0},
		"relation":       map[string]any{},
		"reservation":    map[string]any{"type": "", "toBeSentAt": nil, "toBeSentTimezone": nil},
		"individualSend": false, "securityEditable": true, "version": 0, "mimeSize": 0,
	}
	result, err := c.jsonRequest(ctx, http.MethodPost, "/v2/wapi/mail-drafts", []any{form})
	if err != nil {
		return err
	}
	var drafts []struct {
		ID      string `json:"id"`
		Version *int64 `json:"version"`
	}
	if err := json.Unmarshal(content(result), &drafts); err != nil || len(drafts) != 1 || drafts[0].ID == "" || drafts[0].Version == nil || *drafts[0].Version < 0 {
		return fmt.Errorf("%w: created draft ID or version missing", model.ErrUnavailable)
	}
	draftID := drafts[0].ID
	form["id"] = draftID
	form["version"] = *drafts[0].Version
	fileIDs := []string{}
	for _, attachment := range message.Attachments {
		data, contentType, err := multipartFile(attachment.Name, attachment.ContentType, attachment.Data)
		if err != nil {
			return err
		}
		path := "/v2/wapi/mail-drafts/" + url.PathEscape(draftID) + "/files"
		inline := attachment.ContentID != "" && strings.Contains(body, "cid:"+attachment.ContentID)
		if inline {
			path += "?inlinefile=true"
		}
		rawResult, err := c.request(ctx, http.MethodPost, path, data, contentType)
		if err != nil {
			return err
		}
		fileID := recordID(rawResult)
		if fileID == "" {
			return fmt.Errorf("%w: uploaded attachment ID missing", model.ErrUnavailable)
		}
		if inline {
			body = strings.ReplaceAll(body, "cid:"+attachment.ContentID, "/mail-drafts/"+url.PathEscape(draftID)+"/files/"+url.PathEscape(fileID)+"?type=raw")
		} else {
			fileIDs = append(fileIDs, fileID)
		}
	}
	form["fileIdList"] = fileIDs
	form["body"] = map[string]any{"mimeType": bodyType, "content": body}
	if _, err := c.jsonRequest(ctx, http.MethodPut, "/v2/wapi/mail-drafts/"+url.PathEscape(draftID), form); err != nil {
		return err
	}
	// A timeout here has an unknown outcome. Neither this method nor its
	// transport may blindly retry: the server may already have sent the mail.
	_, err = c.jsonRequest(ctx, http.MethodPost, "/v2/wapi/mails/send", map[string]string{"draftId": draftID})
	return err
}
