// Package dooray adapts Dooray's authenticated web-mail requests to the mailbox
// provider interface. The web API is private and can change independently of
// this project; unsuccessful or unrecognized responses are never acknowledged
// as successful mail operations.
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
	"net/mail"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/refracta/dooray-mail-bridge/internal/model"
)

const maxResponseBytes = 100 << 20
const pageSize = 100
const maxPages = 10000

// Transport owns the HTTP login session and cookies. Do must not automatically replay a
// mutating request whose outcome is unknown.
type Transport interface {
	Authenticate(context.Context, string, string) error
	Do(context.Context, string, string, []byte, string) (*http.Response, error)
}

type Client struct {
	transport Transport
	email     string
	mu        sync.RWMutex
	folders   map[string]webFolder
	// Import responses can omit the inserted ID. Serializing our own imports
	// makes a before/after lookup unambiguous without relying on mail order.
	appendMu sync.Mutex
	flagsMu  sync.Mutex
}

var _ model.Provider = (*Client)(nil)

func New(transport Transport, email string) *Client {
	return &Client{transport: transport, email: strings.TrimSpace(email), folders: make(map[string]webFolder)}
}

type envelope struct {
	Header struct {
		Successful bool `json:"isSuccessful"`
		Code       int  `json:"resultCode"`
	} `json:"header"`
	Result json.RawMessage `json:"result"`
}

func (c *Client) request(ctx context.Context, method, path string, body []byte, contentType string) (json.RawMessage, error) {
	res, err := c.transport.Do(ctx, method, path, body, contentType)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, statusError(res.StatusCode)
	}
	data, err := readBounded(res.Body)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%w: invalid Dooray JSON response", model.ErrUnavailable)
	}
	if !env.Header.Successful {
		if env.Header.Code == -24400100 { // AUTH_UNAUTHORIZED_ERROR in the web client.
			return nil, model.ErrAuthentication
		}
		return nil, fmt.Errorf("%w: Dooray rejected request (code %d)", model.ErrUnavailable, env.Header.Code)
	}
	return env.Result, nil
}

func statusError(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return model.ErrAuthentication
	case http.StatusForbidden:
		return errors.New("Dooray denied permission for this operation")
	case http.StatusNotFound:
		return model.ErrNotFound
	default:
		return fmt.Errorf("%w: Dooray HTTP %d", model.ErrUnavailable, status)
	}
}

func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err == nil && len(b) > maxResponseBytes {
		return nil, fmt.Errorf("%w: Dooray response exceeds size limit", model.ErrUnavailable)
	}
	return b, err
}

func (c *Client) jsonRequest(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	return c.request(ctx, method, path, data, "application/json")
}

func content(raw json.RawMessage) json.RawMessage {
	var wrapped map[string]json.RawMessage
	if json.Unmarshal(raw, &wrapped) == nil {
		for _, name := range []string{"contents", "content"} {
			if v, ok := wrapped[name]; ok {
				return v
			}
		}
	}
	return raw
}

type identity struct {
	Email string `json:"emailAddress"`
	Name  string `json:"name"`
}

func (c *Client) identity(ctx context.Context) (identity, error) {
	var who identity
	raw, err := c.jsonRequest(ctx, http.MethodGet, "/v2/wapi/members/me", nil)
	if err != nil {
		return who, err
	}
	if err := json.Unmarshal(content(raw), &who); err != nil || c.email == "" || !strings.EqualFold(who.Email, c.email) {
		return identity{}, model.ErrAuthentication
	}
	return who, nil
}

func (c *Client) Authenticate(ctx context.Context, username, password string) error {
	if err := c.transport.Authenticate(ctx, username, password); err != nil {
		return err
	}
	_, err := c.identity(ctx)
	return err
}

type webFolder struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	ParentID string `json:"parentFolderId"`
}

var systemNames = map[string]string{
	"inbox": "INBOX", "sent": "Sent", "draft": "Drafts", "archive": "Archive", "spam": "Junk", "trash": "Trash",
}
var specialUse = map[string]string{
	"sent": `\Sent`, "draft": `\Drafts`, "archive": `\Archive`, "spam": `\Junk`, "trash": `\Trash`,
}

func (c *Client) Folders(ctx context.Context) ([]model.Folder, error) {
	byID := make(map[string]webFolder)
	var ordered []webFolder
	for _, kind := range []string{"system", "user"} {
		for page := 0; ; page++ {
			if page == maxPages {
				return nil, fmt.Errorf("%w: folder pagination exceeded limit", model.ErrUnavailable)
			}
			q := url.Values{"type": {kind}, "size": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}}
			raw, err := c.jsonRequest(ctx, http.MethodGet, "/v2/wapi/mail-folders?"+q.Encode(), nil)
			if err != nil {
				return nil, err
			}
			var result struct {
				Total    *int        `json:"totalCount"`
				Contents []webFolder `json:"contents"`
			}
			if err := json.Unmarshal(raw, &result); err != nil || result.Contents == nil {
				return nil, fmt.Errorf("%w: invalid folder list", model.ErrUnavailable)
			}
			for _, f := range result.Contents {
				if f.ID == "" || f.Name == "" {
					return nil, fmt.Errorf("%w: invalid folder record", model.ErrUnavailable)
				}
				if _, exists := byID[f.ID]; exists {
					return nil, fmt.Errorf("%w: unstable folder pagination", model.ErrUnavailable)
				}
				byID[f.ID] = f
				ordered = append(ordered, f)
			}
			count := page*pageSize + len(result.Contents)
			if result.Total != nil && count >= *result.Total || result.Total == nil && len(result.Contents) < pageSize {
				break
			}
			if len(result.Contents) == 0 {
				return nil, fmt.Errorf("%w: incomplete folder list", model.ErrUnavailable)
			}
		}
	}
	var out []model.Folder
	seenNames := make(map[string]bool)
	for _, f := range ordered {
		name, err := folderName(f, byID, make(map[string]bool))
		if err != nil {
			return nil, err
		}
		if seenNames[name] {
			return nil, fmt.Errorf("%w: duplicate mailbox names", model.ErrUnavailable)
		}
		seenNames[name] = true
		m := model.Folder{ID: f.ID, Name: name}
		if f.Type == "system" {
			m.SpecialUse = specialUse[f.Name]
		}
		out = append(out, m)
	}
	c.mu.Lock()
	c.folders = byID
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func folderName(f webFolder, all map[string]webFolder, seen map[string]bool) (string, error) {
	if seen[f.ID] {
		return "", fmt.Errorf("%w: cyclic folder hierarchy", model.ErrUnavailable)
	}
	seen[f.ID] = true
	if f.Type == "system" {
		if name, ok := systemNames[f.Name]; ok {
			return name, nil
		}
		return f.Name, nil
	}
	if f.ParentID == "" || f.ParentID == "root" {
		return f.Name, nil
	}
	p, ok := all[f.ParentID]
	if !ok {
		return "", fmt.Errorf("%w: missing parent folder", model.ErrUnavailable)
	}
	name, err := folderName(p, all, seen)
	if err != nil {
		return "", err
	}
	return name + "/" + f.Name, nil
}

func (c *Client) folder(ctx context.Context, id string) (webFolder, error) {
	c.mu.RLock()
	f, ok := c.folders[id]
	c.mu.RUnlock()
	if !ok {
		if _, err := c.Folders(ctx); err != nil {
			return f, err
		}
		c.mu.RLock()
		f, ok = c.folders[id]
		c.mu.RUnlock()
	}
	if !ok {
		return f, model.ErrNotFound
	}
	return f, nil
}

type webMessage struct {
	ID        string          `json:"id"`
	Subject   *string         `json:"subject"`
	CreatedAt time.Time       `json:"createdAt"`
	MIMESize  json.RawMessage `json:"mimeSize"`
	Summary   struct {
		MIMESize json.RawMessage `json:"mimeSize"`
		Flags    struct {
			Read    bool `json:"read"`
			Replied bool `json:"replied"`
			Draft   bool `json:"draft"`
		} `json:"flags"`
	} `json:"mailSummary"`
	Annotations struct {
		Favorited bool `json:"favorited"`
	} `json:"annotations"`
}

func (c *Client) Messages(ctx context.Context, folderID string) ([]model.Message, error) {
	f, err := c.folder(ctx, folderID)
	if err != nil {
		return nil, err
	}
	var messages []model.Message
	seen := make(map[string]bool)
	for page := 0; page < maxPages; page++ {
		q := url.Values{"folderId": {f.ID}, "preview": {"false"}, "size": {strconv.Itoa(pageSize)}, "page": {strconv.Itoa(page)}, "order": {"id"}, "view": {"timeline"}, "excludeTotalCount": {"false"}}
		raw, err := c.jsonRequest(ctx, http.MethodGet, "/v2/wapi/mails?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			Total    *int         `json:"totalCount"`
			Contents []webMessage `json:"contents"`
		}
		if err := json.Unmarshal(raw, &result); err != nil || result.Contents == nil {
			return nil, fmt.Errorf("%w: invalid message list", model.ErrUnavailable)
		}
		for _, m := range result.Contents {
			if m.ID == "" || m.CreatedAt.IsZero() || seen[m.ID] {
				return nil, fmt.Errorf("%w: invalid or unstable message pagination", model.ErrUnavailable)
			}
			seen[m.ID] = true
			v := model.Message{ID: m.ID, Date: m.CreatedAt, Subject: m.Subject}
			if len(m.MIMESize) == 0 || string(m.MIMESize) == "null" {
				m.MIMESize = m.Summary.MIMESize
			}
			if len(m.MIMESize) > 0 && string(m.MIMESize) != "null" {
				v.Size, err = strconv.ParseInt(strings.Trim(string(m.MIMESize), `"`), 10, 64)
				if err != nil || v.Size < 0 {
					return nil, fmt.Errorf("%w: invalid message size", model.ErrUnavailable)
				}
			}
			if m.Summary.Flags.Read {
				v.Flags = append(v.Flags, `\Seen`)
			}
			if m.Annotations.Favorited {
				v.Flags = append(v.Flags, `\Flagged`)
			}
			if m.Summary.Flags.Replied {
				v.Flags = append(v.Flags, `\Answered`)
			}
			if m.Summary.Flags.Draft || f.Type == "system" && f.Name == "draft" {
				v.Flags = append(v.Flags, `\Draft`)
			}
			messages = append(messages, v)
		}
		if result.Total != nil && len(messages) >= *result.Total || result.Total == nil && len(result.Contents) < pageSize {
			return messages, nil
		}
		if len(result.Contents) == 0 {
			return nil, fmt.Errorf("%w: incomplete mailbox snapshot", model.ErrUnavailable)
		}
	}
	return nil, fmt.Errorf("%w: mailbox pagination exceeded limit", model.ErrUnavailable)
}

func (c *Client) Raw(ctx context.Context, id string) ([]byte, error) {
	res, err := c.transport.Do(ctx, http.MethodGet, "/v2/wapi/mails/"+url.PathEscape(id)+"?type=raw", nil, "")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, statusError(res.StatusCode)
	}
	mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if mediaType != "message/rfc822" {
		return nil, fmt.Errorf("%w: expected original MIME response", model.ErrUnavailable)
	}
	return readBounded(res.Body)
}

func (c *Client) SetFlags(ctx context.Context, id string, flags []string) error {
	seen, flagged := false, false
	for _, flag := range flags {
		switch flag {
		case `\Seen`:
			seen = true
		case `\Flagged`:
			flagged = true
		default:
			return fmt.Errorf("%w: only Seen and Flagged can be written to Dooray", model.ErrUnsupported)
		}
	}
	c.flagsMu.Lock()
	defer c.flagsMu.Unlock()
	path := "/v2/wapi/mails/unread"
	if seen {
		path = "/v2/wapi/mails/read"
	}
	if _, err := c.jsonRequest(ctx, http.MethodPost, path, map[string]any{"mailIdList": []string{id}}); err != nil {
		return err
	}
	_, err := c.jsonRequest(ctx, http.MethodPut, "/v2/wapi/mails/"+url.PathEscape(id)+"/annotations", map[string]any{"mailId": id, "favorited": flagged})
	return err
}

func (c *Client) transfer(ctx context.Context, action string, ids []string, target string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := c.folder(ctx, target); err != nil {
		return err
	}
	_, err := c.jsonRequest(ctx, http.MethodPost, "/v2/wapi/mails/"+action, map[string]any{"mailIdList": ids, "targetFolderId": target})
	return err
}

func (c *Client) Move(ctx context.Context, ids []string, target string) error {
	return c.transfer(ctx, "move", ids, target)
}

func (c *Client) Copy(ctx context.Context, ids []string, target string) error {
	return c.transfer(ctx, "copy", ids, target)
}

// Delete permanently deletes only the supplied messages. The protocol layer
// calls it for EXPUNGE, after keeping the Deleted marker locally.
func (c *Client) Delete(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := c.jsonRequest(ctx, http.MethodPost, "/v2/wapi/mails/delete", map[string]any{"mailIdList": ids})
	return err
}

func validFolderName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "\x00\r\n") && !strings.HasPrefix(name, "/") && !strings.HasSuffix(name, "/") && !strings.Contains(name, "//")
}

func (c *Client) CreateFolder(ctx context.Context, name string) (model.Folder, error) {
	if !validFolderName(name) {
		return model.Folder{}, errors.New("invalid mailbox name")
	}
	if _, err := c.jsonRequest(ctx, http.MethodPost, "/v2/wapi/mail-folders/create-path", []any{map[string]any{"name": name, "order": 1}}); err != nil {
		return model.Folder{}, err
	}
	folders, err := c.Folders(ctx)
	if err != nil {
		return model.Folder{}, err
	}
	for _, f := range folders {
		if f.Name == name {
			return f, nil
		}
	}
	return model.Folder{}, fmt.Errorf("%w: created mailbox not visible", model.ErrUnavailable)
}

func (c *Client) RenameFolder(ctx context.Context, id, name string) error {
	f, err := c.folder(ctx, id)
	if err != nil {
		return err
	}
	if f.Type == "system" {
		return fmt.Errorf("%w: system mailbox cannot be renamed", model.ErrUnsupported)
	}
	if !validFolderName(name) {
		return errors.New("invalid mailbox name")
	}
	if _, err := c.jsonRequest(ctx, http.MethodPost, "/v2/wapi/mail-folders/"+url.PathEscape(id)+"/update-path", map[string]string{"name": name}); err != nil {
		return err
	}
	_, err = c.Folders(ctx)
	return err
}

func (c *Client) DeleteFolder(ctx context.Context, id string) error {
	f, err := c.folder(ctx, id)
	if err != nil {
		return err
	}
	if f.Type == "system" {
		return fmt.Errorf("%w: system mailbox cannot be deleted", model.ErrUnsupported)
	}
	if _, err := c.jsonRequest(ctx, http.MethodPost, "/v2/wapi/mail-folders/"+url.PathEscape(id)+"/delete-path", map[string]string{"folderId": id}); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.folders, id)
	c.mu.Unlock()
	return nil
}

func multipartFile(filename, contentType string, data []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": "file", "filename": filename}))
	h.Set("Content-Type", contentType)
	p, err := w.CreatePart(h)
	if err != nil {
		return nil, "", err
	}
	if _, err := p.Write(data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

func recordID(raw json.RawMessage) string {
	var one struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(content(raw), &one) == nil && one.ID != "" {
		return one.ID
	}
	var many []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(content(raw), &many) == nil && len(many) == 1 {
		return many[0].ID
	}
	return ""
}

func (c *Client) Append(ctx context.Context, folderID string, raw []byte, flags []string, _ time.Time) (string, error) {
	if len(raw) > maxResponseBytes {
		return "", errors.New("message exceeds size limit")
	}
	if _, err := mail.ReadMessage(bytes.NewReader(raw)); err != nil {
		return "", errors.New("invalid MIME message")
	}
	folder, err := c.folder(ctx, folderID)
	if err != nil {
		return "", err
	}
	var importFlags []string
	for _, flag := range flags {
		switch {
		case strings.EqualFold(flag, `\Seen`):
			importFlags = append(importFlags, `\Seen`)
		case strings.EqualFold(flag, `\Flagged`):
			importFlags = append(importFlags, `\Flagged`)
		case strings.EqualFold(flag, `\Draft`) && folder.Type == "system" && folder.Name == "draft":
			// Dooray imports original MIME into its Drafts mailbox. Membership
			// supplies the draft flag; the read/favorite API cannot set it.
		default:
			return "", fmt.Errorf("%w: requested import flags cannot be synchronized", model.ErrUnsupported)
		}
	}
	c.appendMu.Lock()
	defer c.appendMu.Unlock()
	before, err := c.Messages(ctx, folderID)
	if err != nil {
		return "", err
	}
	body, ct, err := multipartFile("message.eml", "message/rfc822", raw)
	if err != nil {
		return "", err
	}
	result, err := c.request(ctx, http.MethodPost, "/v2/wapi/mail-folders/"+url.PathEscape(folderID)+"/import-mail", body, ct)
	if err != nil {
		return "", err
	}
	id := recordID(result)
	if id == "" {
		known := make(map[string]bool, len(before))
		for _, m := range before {
			known[m.ID] = true
		}
		// Match the downloaded original, not just a subject or latest message;
		// unrelated concurrently arriving mail must never be mistaken for APPEND.
		for attempt := 0; attempt < 5 && id == ""; attempt++ {
			after, err := c.Messages(ctx, folderID)
			if err != nil {
				return "", err
			}
			for _, m := range after {
				if known[m.ID] {
					continue
				}
				candidate, err := c.Raw(ctx, m.ID)
				if err != nil {
					return "", err
				}
				if bytes.Equal(candidate, raw) {
					if id != "" {
						return "", fmt.Errorf("%w: import succeeded but multiple matching IDs found; do not automatically retry", model.ErrUnavailable)
					}
					id = m.ID
				}
			}
			if id == "" {
				timer := time.NewTimer(200 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return "", ctx.Err()
				case <-timer.C:
				}
			}
		}
	}
	if id == "" {
		return "", fmt.Errorf("%w: import succeeded but original message ID could not be verified; do not automatically retry", model.ErrUnavailable)
	}
	if err := c.SetFlags(ctx, id, importFlags); err != nil {
		return "", fmt.Errorf("import succeeded but flag update failed: %w", err)
	}
	return id, nil
}
