// Package bridge exposes a single mail provider over IMAP and SMTP.
package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/refracta/dooray-mail-bridge/internal/model"
	bolt "go.etcd.io/bbolt"
)

// MaxMessageBytes bounds APPEND and SMTP literals as well as the raw cache.
const MaxMessageBytes = 64 << 20

var folderBucket = []byte("folders-v1")
var rawBucket = []byte("raw-v1")
var metaBucket = []byte("meta-v1")

type storedMessage struct {
	Meta    model.Message `json:"meta"`
	UID     imap.UID      `json:"uid"`
	Deleted bool          `json:"deleted,omitempty"`
	// Dooray imports cannot set INTERNALDATE. Preserve the client's requested
	// APPEND date locally without changing the provider's metadata timestamp.
	InternalDate *time.Time `json:"internalDate,omitempty"`
}

type folderState struct {
	Info       model.Folder     `json:"info"`
	Validity   uint32           `json:"validity"`
	Next       imap.UID         `json:"next"`
	Subscribed bool             `json:"subscribed"`
	Messages   []*storedMessage `json:"messages"`
}

type mailbox struct {
	mu        sync.Mutex
	state     folderState
	lastSync  time.Time
	lastError error
	selected  int
	removed   bool
}

// Bridge owns durable UIDs and caches. One instance represents one account.
// Close the protocol servers before closing their Bridge.
type Bridge struct {
	provider     model.Provider
	db           *bolt.DB
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	closeOnce    sync.Once
	closeErr     error
	pollInterval time.Duration
	mu           sync.Mutex
	folders      map[string]*mailbox
	folderSyncMu sync.Mutex
}

func New(provider model.Provider, dataDir string, pollInterval time.Duration) (*Bridge, error) {
	if provider == nil {
		return nil, errors.New("mail provider is required")
	}
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dataDir, "mail.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Bridge{provider: provider, db: db, ctx: ctx, cancel: cancel, pollInterval: pollInterval, folders: make(map[string]*mailbox)}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{folderBucket, rawBucket, metaBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return tx.Bucket(folderBucket).ForEach(func(k, v []byte) error {
			var state folderState
			if err := json.Unmarshal(v, &state); err != nil {
				return fmt.Errorf("invalid mailbox database: %w", err)
			}
			if state.Validity == 0 || state.Next == 0 || state.Info.ID != string(k) {
				return errors.New("invalid mailbox identity in database")
			}
			b.folders[string(k)] = &mailbox{state: state}
			return nil
		})
	})
	if err != nil {
		cancel()
		db.Close()
		return nil, err
	}
	b.wg.Add(1)
	go b.pollLoop()
	return b, nil
}

func (b *Bridge) Close() error {
	b.closeOnce.Do(func() { b.cancel(); b.wg.Wait(); b.closeErr = b.db.Close() })
	return b.closeErr
}

// Cancel aborts pending upstream operations before protocol listeners close.
// Call Close after the protocol servers have stopped using the database.
func (b *Bridge) Cancel() { b.cancel() }

// Capabilities omits UIDPLUS because Dooray's COPY endpoint does not return an
// exact source/destination ID mapping. Do not claim IMAP4rev2 without that.
func Capabilities() imap.CapSet {
	return imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapNamespace: {}, imap.CapMove: {}, imap.CapSpecialUse: {}, imap.CapChildren: {}, imap.CapESearch: {}, imap.CapBinary: {}}
}

func (b *Bridge) context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(b.ctx, 4*time.Minute)
}

func (b *Bridge) pollLoop() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			boxes := make([]*mailbox, 0, len(b.folders))
			for _, m := range b.folders {
				boxes = append(boxes, m)
			}
			b.mu.Unlock()
			for _, m := range boxes {
				m.mu.Lock()
				if m.selected > 0 && !m.removed {
					m.lastError = b.syncBoxLocked(m, false)
				}
				m.mu.Unlock()
				if b.ctx.Err() != nil {
					return
				}
			}
		}
	}
}

func (b *Bridge) saveState(s folderState) error {
	buf, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(folderBucket).Put([]byte(s.Info.ID), buf) })
}

func (b *Bridge) newState(info model.Folder) (folderState, error) {
	state := folderState{Info: info, Next: 1, Subscribed: true}
	err := b.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		var prev uint32
		if raw := meta.Get([]byte("uidvalidity")); len(raw) == 4 {
			prev = binary.BigEndian.Uint32(raw)
		}
		next := uint32(time.Now().Unix())
		if next <= prev {
			next = prev + 1
		}
		if next == 0 {
			return errors.New("UIDVALIDITY exhausted")
		}
		state.Validity = next
		var data [4]byte
		binary.BigEndian.PutUint32(data[:], next)
		if err := meta.Put([]byte("uidvalidity"), data[:]); err != nil {
			return err
		}
		buf, err := json.Marshal(state)
		if err != nil {
			return err
		}
		return tx.Bucket(folderBucket).Put([]byte(info.ID), buf)
	})
	return state, err
}

func (b *Bridge) syncFolders() error {
	b.folderSyncMu.Lock()
	defer b.folderSyncMu.Unlock()
	ctx, cancel := b.context()
	defer cancel()
	folders, err := b.provider.Folders(ctx)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(folders))
	names := make(map[string]bool, len(folders))
	for _, f := range folders {
		if f.ID == "" || f.Name == "" || seen[f.ID] || names[f.Name] {
			return errors.New("provider returned duplicate or invalid folders")
		}
		seen[f.ID], names[f.Name] = true, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, info := range folders {
		m := b.folders[info.ID]
		if m == nil {
			state, err := b.newState(info)
			if err != nil {
				return err
			}
			b.folders[info.ID] = &mailbox{state: state}
			continue
		}
		m.mu.Lock()
		if m.state.Info != info {
			state := m.state
			state.Info = info
			err = b.saveState(state)
			if err == nil {
				m.state = state
			}
		}
		m.mu.Unlock()
		if err != nil {
			return err
		}
	}
	for id, m := range b.folders {
		if seen[id] {
			continue
		}
		if err := b.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(folderBucket).Delete([]byte(id)) }); err != nil {
			return err
		}
		m.mu.Lock()
		m.removed = true
		m.mu.Unlock()
		delete(b.folders, id)
	}
	return nil
}

func (b *Bridge) mailbox(name string) (*mailbox, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, m := range b.folders {
		m.mu.Lock()
		match := m.state.Info.Name == name || (strings.EqualFold(name, "INBOX") && m.state.Info.Name == "INBOX")
		m.mu.Unlock()
		if match {
			return m, nil
		}
	}
	return nil, model.ErrNotFound
}

// syncBoxLocked stages and commits a complete snapshot before publishing any
// sequence/UID updates. A failed or incomplete provider scan leaves it intact.
func (b *Bridge) syncBoxLocked(m *mailbox, force bool) error {
	if m.removed {
		return model.ErrNotFound
	}
	if !force && !m.lastSync.IsZero() && time.Since(m.lastSync) < b.pollInterval {
		return m.lastError
	}
	ctx, cancel := b.context()
	defer cancel()
	remote, err := b.provider.Messages(ctx, m.state.Info.ID)
	if err != nil {
		m.lastError = err
		return err
	}
	seen := make(map[string]model.Message, len(remote))
	for _, meta := range remote {
		if meta.ID == "" {
			return errors.New("provider returned empty message ID")
		}
		if _, exists := seen[meta.ID]; exists {
			return errors.New("provider returned duplicate message ID")
		}
		meta.Flags = normalizeRemoteFlags(meta.Flags)
		seen[meta.ID] = meta
	}
	state := m.state
	state.Messages = make([]*storedMessage, 0, len(remote))
	for _, msg := range m.state.Messages {
		meta, exists := seen[msg.Meta.ID]
		if !exists {
			continue
		}
		copy := *msg
		// A cached exact size remains useful when the provider omits it.
		if meta.Size == 0 && meta.Date.Equal(msg.Meta.Date) {
			meta.Size = msg.Meta.Size
		}
		copy.Meta = meta
		state.Messages = append(state.Messages, &copy)
		delete(seen, meta.ID)
	}
	newMessages := make([]model.Message, 0, len(seen))
	for _, meta := range seen {
		newMessages = append(newMessages, meta)
	}
	sort.Slice(newMessages, func(i, j int) bool {
		if newMessages[i].Date.Equal(newMessages[j].Date) {
			return newMessages[i].ID < newMessages[j].ID
		}
		return newMessages[i].Date.Before(newMessages[j].Date)
	})
	for _, meta := range newMessages {
		if state.Next == 0 || state.Next == imap.UID(math.MaxUint32) {
			return errors.New("mailbox UID space exhausted")
		}
		state.Messages = append(state.Messages, &storedMessage{Meta: meta, UID: state.Next})
		state.Next++
	}
	if !reflect.DeepEqual(state, m.state) {
		if err := b.saveState(state); err != nil {
			return err
		}
		m.state = state
	}
	m.lastSync, m.lastError = time.Now(), nil
	return nil
}

func (b *Bridge) raw(msg *storedMessage) ([]byte, error) {
	key := sha256.Sum256([]byte(msg.Meta.ID))
	cacheable := !hasFlag(msg.flags(), imap.FlagDraft)
	var raw []byte
	if cacheable {
		if err := b.db.View(func(tx *bolt.Tx) error {
			if v := tx.Bucket(rawBucket).Get(key[:]); v != nil {
				raw = append([]byte(nil), v...)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if raw != nil {
			return raw, nil
		}
	}
	ctx, cancel := b.context()
	defer cancel()
	raw, err := b.provider.Raw(ctx, msg.Meta.ID)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxMessageBytes {
		return nil, errors.New("message exceeds bridge size limit")
	}
	if cacheable {
		if err := b.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(rawBucket).Put(key[:], raw) }); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func normalizeRemoteFlags(flags []string) []string {
	m := make(map[string]bool)
	for _, f := range flags {
		for _, known := range []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.FlagAnswered, imap.FlagDraft} {
			if strings.EqualFold(f, string(known)) {
				m[string(known)] = true
			}
		}
	}
	result := make([]string, 0, len(m))
	for f := range m {
		result = append(result, f)
	}
	sort.Strings(result)
	return result
}

func (m *storedMessage) flags() []imap.Flag {
	flags := make([]imap.Flag, 0, len(m.Meta.Flags)+1)
	for _, f := range m.Meta.Flags {
		flags = append(flags, imap.Flag(f))
	}
	if m.Deleted {
		flags = append(flags, imap.FlagDeleted)
	}
	sort.Slice(flags, func(i, j int) bool { return flags[i] < flags[j] })
	return flags
}

func (m *storedMessage) date() time.Time {
	if m.InternalDate != nil {
		return *m.InternalDate
	}
	return m.Meta.Date
}

func hasFlag(flags []imap.Flag, flag imap.Flag) bool {
	for _, f := range flags {
		if strings.EqualFold(string(f), string(flag)) {
			return true
		}
	}
	return false
}

func protocolError(err error) error {
	if err == nil {
		return nil
	}
	var existing *imap.Error
	if errors.As(err, &existing) {
		return err
	}
	code, message := imap.ResponseCodeUnavailable, "Mail provider operation failed"
	switch {
	case errors.Is(err, model.ErrAuthentication):
		return imapserver.ErrAuthFailed
	case errors.Is(err, model.ErrNotFound):
		code, message = imap.ResponseCodeNonExistent, "Mailbox or message no longer exists"
	case errors.Is(err, model.ErrUnsupported):
		code, message = imap.ResponseCodeCannot, "Operation is not supported by this mail provider"
	}
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: code, Text: message}
}

func readOnlyError() error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: "READ-ONLY", Text: "Selected mailbox is read-only"}
}
