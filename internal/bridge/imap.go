package bridge

import (
	"io"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/refracta/dooray-mail-bridge/internal/model"
)

var advertisedFlags = []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.FlagAnswered, imap.FlagDraft, imap.FlagDeleted}
var writableFlags = []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.FlagDeleted}

type imapSession struct {
	b             *Bridge
	authenticated bool
	box           *mailbox
	readOnly      bool
	// view and observedFlags are guarded by box.mu. Missing messages remain
	// in view until an EXPUNGE can legally be delivered to this connection.
	view          []imap.UID
	observedFlags map[imap.UID][]imap.Flag
	searchRes     imap.UIDSet
}

var _ imapserver.Session = (*imapSession)(nil)
var _ imapserver.SessionMove = (*imapSession)(nil)
var _ imapserver.SessionNamespace = (*imapSession)(nil)
var _ imapserver.SessionAppendLimit = (*imapSession)(nil)

func (b *Bridge) NewIMAPSession(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	return &imapSession{b: b}, nil, nil
}

func (s *imapSession) Login(username, password string) error {
	ctx, cancel := s.b.context()
	defer cancel()
	if err := s.b.provider.Authenticate(ctx, username, password); err != nil {
		return protocolError(err)
	}
	if err := s.b.syncFolders(); err != nil {
		return protocolError(err)
	}
	s.authenticated = true
	return nil
}

func (s *imapSession) requireAuth() error {
	if !s.authenticated {
		return imapserver.ErrAuthFailed
	}
	return nil
}

func (s *imapSession) Close() error { return s.Unselect() }

func (s *imapSession) Unselect() error {
	if s.box != nil {
		s.box.mu.Lock()
		s.box.selected--
		s.box.mu.Unlock()
	}
	s.box, s.view, s.observedFlags, s.searchRes = nil, nil, nil, nil
	return nil
}

func (s *imapSession) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	if err := s.requireAuth(); err != nil {
		return nil, err
	}
	if err := s.b.syncFolders(); err != nil {
		return nil, protocolError(err)
	}
	m, err := s.b.mailbox(name)
	if err != nil {
		return nil, protocolError(err)
	}
	s.Unselect()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := s.b.syncBoxLocked(m, true); err != nil {
		return nil, protocolError(err)
	}
	s.box, s.readOnly = m, options.ReadOnly
	s.observedFlags = make(map[imap.UID][]imap.Flag, len(m.state.Messages))
	var firstUnseen uint32
	for i, msg := range m.state.Messages {
		s.view = append(s.view, msg.UID)
		s.observedFlags[msg.UID] = msg.flags()
		if firstUnseen == 0 && !hasFlag(msg.flags(), imap.FlagSeen) {
			firstUnseen = uint32(i + 1)
		}
	}
	m.selected++
	permanent := writableFlags
	if s.readOnly {
		permanent = []imap.Flag{}
	}
	return &imap.SelectData{Flags: advertisedFlags, PermanentFlags: permanent, NumMessages: uint32(len(s.view)), FirstUnseenSeqNum: firstUnseen, UIDNext: m.state.Next, UIDValidity: m.state.Validity, ReadOnly: s.readOnly}, nil
}

func (s *imapSession) Namespace() (*imap.NamespaceData, error) {
	if err := s.requireAuth(); err != nil {
		return nil, err
	}
	return &imap.NamespaceData{Personal: []imap.NamespaceDescriptor{{Delim: '/'}}}, nil
}

func validMailboxName(name string) bool {
	return name != "" && len(name) <= 1024 && !strings.ContainsAny(name, "\r\n\x00")
}

func (s *imapSession) Create(name string, options *imap.CreateOptions) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	name = strings.TrimSuffix(name, "/")
	if !validMailboxName(name) {
		return protocolError(model.ErrUnsupported)
	}
	if len(options.SpecialUse) != 0 {
		return protocolError(model.ErrUnsupported)
	}
	if err := s.b.syncFolders(); err != nil {
		return protocolError(err)
	}
	if _, err := s.b.mailbox(name); err == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeAlreadyExists, Text: "Mailbox already exists"}
	}
	ctx, cancel := s.b.context()
	defer cancel()
	if _, err := s.b.provider.CreateFolder(ctx, name); err != nil {
		return protocolError(err)
	}
	return protocolError(s.b.syncFolders())
}

func (s *imapSession) Delete(name string) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	if strings.EqualFold(name, "INBOX") {
		return protocolError(model.ErrUnsupported)
	}
	if err := s.b.syncFolders(); err != nil {
		return protocolError(err)
	}
	m, err := s.b.mailbox(name)
	if err != nil {
		return protocolError(err)
	}
	m.mu.Lock()
	id := m.state.Info.ID
	m.mu.Unlock()
	ctx, cancel := s.b.context()
	defer cancel()
	if err := s.b.provider.DeleteFolder(ctx, id); err != nil {
		return protocolError(err)
	}
	return protocolError(s.b.syncFolders())
}

func (s *imapSession) Rename(name, newName string, _ *imap.RenameOptions) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	newName = strings.TrimSuffix(newName, "/")
	if !validMailboxName(newName) || strings.EqualFold(name, "INBOX") || strings.EqualFold(newName, "INBOX") {
		return protocolError(model.ErrUnsupported)
	}
	if err := s.b.syncFolders(); err != nil {
		return protocolError(err)
	}
	if name == newName {
		return nil
	}
	if _, err := s.b.mailbox(newName); err == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeAlreadyExists, Text: "Mailbox already exists"}
	}
	m, err := s.b.mailbox(name)
	if err != nil {
		return protocolError(err)
	}
	m.mu.Lock()
	id := m.state.Info.ID
	m.mu.Unlock()
	ctx, cancel := s.b.context()
	defer cancel()
	if err := s.b.provider.RenameFolder(ctx, id, newName); err != nil {
		return protocolError(err)
	}
	return protocolError(s.b.syncFolders())
}

func (s *imapSession) subscription(name string, subscribed bool) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	m, err := s.b.mailbox(name)
	if err != nil {
		return protocolError(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.state
	state.Subscribed = subscribed
	if err := s.b.saveState(state); err != nil {
		return protocolError(err)
	}
	m.state = state
	return nil
}

func (s *imapSession) Subscribe(name string) error   { return s.subscription(name, true) }
func (s *imapSession) Unsubscribe(name string) error { return s.subscription(name, false) }

func (s *imapSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	if err := s.b.syncFolders(); err != nil {
		return protocolError(err)
	}
	if len(patterns) == 0 || (len(patterns) == 1 && patterns[0] == "") {
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: '/'})
	}
	s.b.mu.Lock()
	var boxes []*mailbox
	var names []string
	for _, m := range s.b.folders {
		boxes = append(boxes, m)
		m.mu.Lock()
		names = append(names, m.state.Info.Name)
		m.mu.Unlock()
	}
	s.b.mu.Unlock()
	var results []imap.ListData
	for _, m := range boxes {
		m.mu.Lock()
		info := m.state.Info
		matches := false
		for _, pattern := range patterns {
			if imapserver.MatchList(info.Name, '/', ref, pattern) {
				matches = true
			}
		}
		if !matches || (options.SelectSubscribed && !m.state.Subscribed) || (options.SelectSpecialUse && info.SpecialUse == "") {
			m.mu.Unlock()
			continue
		}
		attrs := []imap.MailboxAttr{}
		if m.state.Subscribed && options.ReturnSubscribed {
			attrs = append(attrs, imap.MailboxAttrSubscribed)
		}
		if info.SpecialUse != "" {
			attrs = append(attrs, imap.MailboxAttr(info.SpecialUse))
		}
		hasChildren := false
		for _, name := range names {
			if strings.HasPrefix(name, info.Name+"/") {
				hasChildren = true
				break
			}
		}
		if hasChildren {
			attrs = append(attrs, imap.MailboxAttrHasChildren)
		} else {
			attrs = append(attrs, imap.MailboxAttrHasNoChildren)
		}
		result := imap.ListData{Mailbox: info.Name, Delim: '/', Attrs: attrs}
		if options.ReturnStatus != nil {
			if err := s.b.syncBoxLocked(m, false); err != nil {
				m.mu.Unlock()
				return protocolError(err)
			}
			result.Status = statusData(m, options.ReturnStatus)
		}
		results = append(results, result)
		m.mu.Unlock()
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Mailbox < results[j].Mailbox })
	for i := range results {
		if err := w.WriteList(&results[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *imapSession) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if err := s.requireAuth(); err != nil {
		return nil, err
	}
	if err := s.b.syncFolders(); err != nil {
		return nil, protocolError(err)
	}
	m, err := s.b.mailbox(name)
	if err != nil {
		return nil, protocolError(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := s.b.syncBoxLocked(m, false); err != nil {
		return nil, protocolError(err)
	}
	return statusData(m, options), nil
}

func statusData(m *mailbox, options *imap.StatusOptions) *imap.StatusData {
	data := &imap.StatusData{Mailbox: m.state.Info.Name}
	var unread, deleted uint32
	var size int64
	for _, msg := range m.state.Messages {
		if !hasFlag(msg.flags(), imap.FlagSeen) {
			unread++
		}
		if msg.Deleted {
			deleted++
		}
		size += msg.Meta.Size
	}
	if options.NumMessages {
		n := uint32(len(m.state.Messages))
		data.NumMessages = &n
	}
	if options.NumUnseen {
		data.NumUnseen = &unread
	}
	if options.NumDeleted {
		data.NumDeleted = &deleted
	}
	if options.NumRecent {
		n := uint32(0)
		data.NumRecent = &n
	}
	if options.UIDNext {
		data.UIDNext = m.state.Next
	}
	if options.UIDValidity {
		data.UIDValidity = m.state.Validity
	}
	if options.Size {
		data.Size = &size
	}
	return data
}

func (s *imapSession) AppendLimit() uint32 { return MaxMessageBytes }

func (s *imapSession) Append(name string, reader imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if err := s.requireAuth(); err != nil {
		return nil, err
	}
	if reader.Size() > MaxMessageBytes {
		return nil, protocolError(model.ErrUnsupported)
	}
	if err := s.b.syncFolders(); err != nil {
		return nil, protocolError(err)
	}
	m, err := s.b.mailbox(name)
	if err != nil {
		return nil, protocolError(err)
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxMessageBytes || len(raw) == 0 {
		return nil, protocolError(model.ErrUnsupported)
	}
	flags := make([]string, 0, len(options.Flags))
	deleted := false
	for _, flag := range options.Flags {
		if !hasFlag(advertisedFlags, flag) {
			return nil, protocolError(model.ErrUnsupported)
		}
		if strings.EqualFold(string(flag), string(imap.FlagDeleted)) {
			deleted = true
		} else {
			flags = append(flags, string(flag))
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := s.b.context()
	defer cancel()
	id, err := s.b.provider.Append(ctx, m.state.Info.ID, raw, flags, options.Time)
	if err != nil {
		return nil, protocolError(err)
	}
	if err := s.b.syncBoxLocked(m, true); err != nil {
		return nil, protocolError(err)
	}
	if id == "" {
		return nil, nil
	}
	for _, msg := range m.state.Messages {
		if msg.Meta.ID != id {
			continue
		}
		if deleted || !options.Time.IsZero() {
			msg.Deleted = deleted
			if !options.Time.IsZero() {
				date := options.Time
				msg.InternalDate = &date
			}
			if err := s.b.saveState(m.state); err != nil {
				return nil, protocolError(err)
			}
		}
		return &imap.AppendData{UIDValidity: m.state.Validity, UID: msg.UID}, nil
	}
	// Some providers expose imported messages only after indexing completes.
	// A successful import is still successful; do not invent an APPENDUID.
	return nil, nil
}

func (s *imapSession) selected() error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	if s.box == nil {
		return &imap.Error{Type: imap.StatusResponseTypeBad, Text: "Select a mailbox first"}
	}
	return nil
}

func (s *imapSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.box == nil {
		return nil
	}
	m := s.box
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := s.b.syncBoxLocked(m, false); err != nil {
		return protocolError(err)
	}
	current := s.messagesByUIDLocked()
	if allowExpunge {
		if err := s.removeMissingLocked(current, w.WriteExpunge); err != nil {
			return err
		}
	}
	known := make(map[imap.UID]bool, len(s.view))
	for _, uid := range s.view {
		known[uid] = true
	}
	added := false
	for _, msg := range m.state.Messages {
		if !known[msg.UID] {
			s.view = append(s.view, msg.UID)
			s.observedFlags[msg.UID] = msg.flags()
			added = true
		}
	}
	if added {
		if err := w.WriteNumMessages(uint32(len(s.view))); err != nil {
			return err
		}
	}
	for i, uid := range s.view {
		msg := current[uid]
		if msg == nil || reflect.DeepEqual(msg.flags(), s.observedFlags[uid]) {
			continue
		}
		if err := w.WriteMessageFlags(uint32(i+1), uid, msg.flags()); err != nil {
			return err
		}
		s.observedFlags[uid] = msg.flags()
	}
	return nil
}

func (s *imapSession) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	if s.box == nil {
		<-stop
		return nil
	}
	if err := s.Poll(w, true); err != nil {
		return err
	}
	interval := min(s.b.pollInterval, 250*time.Millisecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-s.b.ctx.Done():
			return protocolError(model.ErrUnavailable)
		case <-ticker.C:
			if err := s.Poll(w, true); err != nil {
				return err
			}
		}
	}
}

func (s *imapSession) messagesByUIDLocked() map[imap.UID]*storedMessage {
	result := make(map[imap.UID]*storedMessage, len(s.box.state.Messages))
	for _, msg := range s.box.state.Messages {
		result[msg.UID] = msg
	}
	return result
}

func (s *imapSession) removeMissingLocked(current map[imap.UID]*storedMessage, write func(uint32) error) error {
	for i := len(s.view) - 1; i >= 0; i-- {
		if current[s.view[i]] != nil {
			continue
		}
		if err := write(uint32(i + 1)); err != nil {
			return err
		}
		delete(s.observedFlags, s.view[i])
		s.view = append(s.view[:i], s.view[i+1:]...)
	}
	return nil
}

type selectedMessage struct {
	sequence uint32
	message  *storedMessage
}

func (s *imapSession) matchingLocked(set imap.NumSet) []selectedMessage {
	set = s.staticSetLocked(set)
	current := s.messagesByUIDLocked()
	var results []selectedMessage
	for i, uid := range s.view {
		msg := current[uid]
		if msg == nil {
			continue
		}
		seq := uint32(i + 1)
		match := false
		switch set := set.(type) {
		case imap.SeqSet:
			match = set.Contains(seq)
		case imap.UIDSet:
			match = set.Contains(uid)
		}
		if match {
			results = append(results, selectedMessage{seq, msg})
		}
	}
	return results
}

func (s *imapSession) staticSetLocked(set imap.NumSet) imap.NumSet {
	if imap.IsSearchRes(set) {
		return append(imap.UIDSet(nil), s.searchRes...)
	}
	switch set := set.(type) {
	case imap.SeqSet:
		set = append(imap.SeqSet(nil), set...)
		for i := range set {
			staticRange(&set[i].Start, &set[i].Stop, uint32(len(s.view)))
		}
		return set
	case imap.UIDSet:
		set = append(imap.UIDSet(nil), set...)
		var largest imap.UID
		for _, msg := range s.box.state.Messages {
			if msg.UID > largest {
				largest = msg.UID
			}
		}
		for i := range set {
			staticRange((*uint32)(&set[i].Start), (*uint32)(&set[i].Stop), uint32(largest))
		}
		return set
	default:
		return set
	}
}

func staticRange(start, stop *uint32, maxValue uint32) {
	changed := false
	if *start == 0 {
		*start = maxValue
		changed = true
	}
	if *stop == 0 {
		*stop = maxValue
		changed = true
	}
	if changed && *start > *stop {
		*start, *stop = *stop, *start
	}
}

func (s *imapSession) Fetch(w *imapserver.FetchWriter, set imap.NumSet, options *imap.FetchOptions) error {
	if err := s.selected(); err != nil {
		return err
	}
	m := s.box
	m.mu.Lock()
	defer m.mu.Unlock()
	markRead := false
	for _, section := range options.BodySection {
		if !section.Peek {
			markRead = true
		}
	}
	for _, section := range options.BinarySection {
		if !section.Peek {
			markRead = true
		}
	}
	for _, selected := range s.matchingLocked(set) {
		msg := selected.message
		needRaw := options.RFC822Size || options.Envelope || options.BodyStructure != nil || len(options.BodySection) > 0 || len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0
		var raw []byte
		if needRaw {
			var err error
			raw, err = s.b.raw(msg)
			if err != nil {
				return protocolError(err)
			}
		}
		if markRead && !s.readOnly && !hasFlag(msg.flags(), imap.FlagSeen) {
			flags := append(msg.flags(), imap.FlagSeen)
			if err := s.changeFlagsLocked(msg, flags); err != nil {
				return protocolError(err)
			}
		}
		response := w.CreateMessage(selected.sequence)
		copyOptions := *options
		// A non-PEEK fetch which changes \Seen must report the new flags.
		if markRead && !s.readOnly {
			copyOptions.Flags = true
		}
		if err := writeMessage(response, msg, raw, &copyOptions); err != nil {
			return err
		}
		if copyOptions.Flags {
			s.observedFlags[msg.UID] = msg.flags()
		}
	}
	return nil
}

func (s *imapSession) changeFlagsLocked(msg *storedMessage, flags []imap.Flag) error {
	for _, flag := range flags {
		if !hasFlag(advertisedFlags, flag) {
			return model.ErrUnsupported
		}
	}
	for _, flag := range []imap.Flag{imap.FlagAnswered, imap.FlagDraft} {
		if hasFlag(msg.flags(), flag) != hasFlag(flags, flag) {
			return model.ErrUnsupported
		}
	}
	var target []string
	for _, flag := range []imap.Flag{imap.FlagSeen, imap.FlagFlagged} {
		if hasFlag(flags, flag) {
			target = append(target, string(flag))
		}
	}
	remoteChanged := hasFlag(flags, imap.FlagSeen) != hasFlag(msg.flags(), imap.FlagSeen) || hasFlag(flags, imap.FlagFlagged) != hasFlag(msg.flags(), imap.FlagFlagged)
	if remoteChanged {
		ctx, cancel := s.b.context()
		defer cancel()
		if err := s.b.provider.SetFlags(ctx, msg.Meta.ID, target); err != nil {
			return err
		}
	}
	for _, flag := range []imap.Flag{imap.FlagAnswered, imap.FlagDraft} {
		if hasFlag(msg.flags(), flag) {
			target = append(target, string(flag))
		}
	}
	msg.Meta.Flags = normalizeRemoteFlags(target)
	msg.Deleted = hasFlag(flags, imap.FlagDeleted)
	return s.b.saveState(s.box.state)
}

func (s *imapSession) Store(w *imapserver.FetchWriter, set imap.NumSet, operation *imap.StoreFlags, _ *imap.StoreOptions) error {
	if err := s.selected(); err != nil {
		return err
	}
	if s.readOnly {
		return readOnlyError()
	}
	m := s.box
	m.mu.Lock()
	defer m.mu.Unlock()
	if operation.Op != imap.StoreFlagsSet && operation.Op != imap.StoreFlagsAdd && operation.Op != imap.StoreFlagsDel {
		return protocolError(model.ErrUnsupported)
	}
	for _, flag := range operation.Flags {
		if !hasFlag(advertisedFlags, flag) {
			return protocolError(model.ErrUnsupported)
		}
	}
	for _, selected := range s.matchingLocked(set) {
		msg := selected.message
		var next []imap.Flag
		if operation.Op != imap.StoreFlagsSet {
			next = append(next, msg.flags()...)
		}
		if operation.Op == imap.StoreFlagsDel {
			filtered := next[:0]
			for _, flag := range next {
				if !hasFlag(operation.Flags, flag) {
					filtered = append(filtered, flag)
				}
			}
			next = filtered
		} else {
			for _, flag := range operation.Flags {
				if !hasFlag(next, flag) {
					next = append(next, flag)
				}
			}
		}
		if err := s.changeFlagsLocked(msg, next); err != nil {
			return protocolError(err)
		}
		if !operation.Silent {
			if err := writeMessage(w.CreateMessage(selected.sequence), msg, nil, &imap.FetchOptions{Flags: true}); err != nil {
				return err
			}
		}
		// .SILENT suppresses our own FLAGS response, not other clients'.
		s.observedFlags[msg.UID] = msg.flags()
	}
	return nil
}

func (s *imapSession) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if err := s.selected(); err != nil {
		return err
	}
	if s.readOnly {
		return readOnlyError()
	}
	m := s.box
	m.mu.Lock()
	defer m.mu.Unlock()
	var allowed imap.UIDSet
	if uids != nil {
		allowed = s.staticSetLocked(*uids).(imap.UIDSet)
	}
	var ids []string
	for _, msg := range m.state.Messages {
		if msg.Deleted && (uids == nil || allowed.Contains(msg.UID)) {
			ids = append(ids, msg.Meta.ID)
		}
	}
	if len(ids) > 0 {
		ctx, cancel := s.b.context()
		defer cancel()
		if err := s.b.provider.Delete(ctx, ids); err != nil {
			return protocolError(err)
		}
		if err := s.b.syncBoxLocked(m, true); err != nil {
			return protocolError(err)
		}
	}
	return s.removeMissingLocked(s.messagesByUIDLocked(), w.WriteExpunge)
}

func (s *imapSession) destination(name string) (*mailbox, error) {
	if err := s.b.syncFolders(); err != nil {
		return nil, err
	}
	dest, err := s.b.mailbox(name)
	if err != nil {
		return nil, err
	}
	if dest == s.box {
		return nil, model.ErrUnsupported
	}
	return dest, nil
}

func (s *imapSession) transfer(set imap.NumSet, name string, move bool) error {
	if err := s.selected(); err != nil {
		return err
	}
	if move && s.readOnly {
		return readOnlyError()
	}
	dest, err := s.destination(name)
	if err != nil {
		return protocolError(err)
	}
	dest.mu.Lock()
	destID := dest.state.Info.ID
	dest.mu.Unlock()
	m := s.box
	m.mu.Lock()
	var ids []string
	overlays := make(map[string]storedMessage)
	for _, selected := range s.matchingLocked(set) {
		// COPY does not return destination IDs, so bridge-only attributes
		// cannot be correlated with the new copies without guessing.
		if !move && (selected.message.InternalDate != nil || selected.message.Deleted) {
			m.mu.Unlock()
			return protocolError(model.ErrUnsupported)
		}
		ids = append(ids, selected.message.Meta.ID)
		overlays[selected.message.Meta.ID] = *selected.message
	}
	if len(ids) == 0 {
		m.mu.Unlock()
		return nil
	}
	ctx, cancel := s.b.context()
	defer cancel()
	if move {
		err = s.b.provider.Move(ctx, ids, destID)
	} else {
		err = s.b.provider.Copy(ctx, ids, destID)
	}
	if err == nil && move {
		err = s.b.syncBoxLocked(m, true)
	}
	m.mu.Unlock()
	if err != nil {
		return protocolError(err)
	}
	dest.mu.Lock()
	err = s.b.syncBoxLocked(dest, true)
	if err == nil && move {
		changed := false
		for _, message := range dest.state.Messages {
			if source, exists := overlays[message.Meta.ID]; exists && (source.InternalDate != nil || source.Deleted) {
				message.InternalDate, message.Deleted = source.InternalDate, source.Deleted
				changed = true
			}
		}
		if changed {
			err = s.b.saveState(dest.state)
		}
	}
	dest.mu.Unlock()
	return protocolError(err)
}

func (s *imapSession) Copy(set imap.NumSet, name string) (*imap.CopyData, error) {
	return nil, s.transfer(set, name, false)
}

func (s *imapSession) Move(w *imapserver.MoveWriter, set imap.NumSet, name string) error {
	if err := s.transfer(set, name, true); err != nil {
		return err
	}
	if err := w.WriteCopyData(nil); err != nil {
		return err
	}
	s.box.mu.Lock()
	defer s.box.mu.Unlock()
	return s.removeMissingLocked(s.messagesByUIDLocked(), w.WriteExpunge)
}
