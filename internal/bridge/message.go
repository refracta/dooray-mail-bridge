package bridge

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
	"github.com/refracta/dooray-mail-bridge/internal/model"
)

func writeMessage(w *imapserver.FetchResponseWriter, msg *storedMessage, raw []byte, options *imap.FetchOptions) error {
	w.WriteUID(msg.UID)
	if options.Flags {
		w.WriteFlags(msg.flags())
	}
	if options.InternalDate {
		w.WriteInternalDate(msg.date())
	}
	if options.RFC822Size {
		w.WriteRFC822Size(int64(len(raw)))
	}
	if options.Envelope {
		header, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return protocolError(model.ErrUnavailable)
		}
		w.WriteEnvelope(imapserver.ExtractEnvelope(header))
	}
	if options.BodyStructure != nil {
		w.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(raw)))
	}
	for _, section := range options.BodySection {
		content := imapserver.ExtractBodySection(bytes.NewReader(raw), section)
		literal := w.WriteBodySection(section, int64(len(content)))
		_, writeErr := literal.Write(content)
		closeErr := literal.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	for _, section := range options.BinarySection {
		content := imapserver.ExtractBinarySection(bytes.NewReader(raw), section)
		literal := w.WriteBinarySection(section, int64(len(content)))
		_, writeErr := literal.Write(content)
		closeErr := literal.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	for _, section := range options.BinarySectionSize {
		w.WriteBinarySectionSize(section, imapserver.ExtractBinarySectionSize(bytes.NewReader(raw), section))
	}
	return w.Close()
}

func (s *imapSession) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	if err := s.selected(); err != nil {
		return nil, err
	}
	if criteria.ModSeq != nil {
		return nil, protocolError(model.ErrUnsupported)
	}
	s.box.mu.Lock()
	defer s.box.mu.Unlock()
	resolved := s.searchCriteriaLocked(*criteria)
	var sequenceSet imap.SeqSet
	var uidSet imap.UIDSet
	result := &imap.SearchData{}
	current := s.messagesByUIDLocked()
	for index, uid := range s.view {
		msg := current[uid]
		if msg == nil {
			continue
		}
		sequence := uint32(index + 1)
		matcher := &searchMessage{meta: msg, sequence: sequence, load: func() ([]byte, error) { return s.b.raw(msg) }}
		matches, err := matcher.matches(&resolved)
		if err != nil {
			return nil, protocolError(err)
		}
		if !matches {
			continue
		}
		uidSet.AddNum(uid)
		sequenceSet.AddNum(sequence)
		number := sequence
		if kind == imapserver.NumKindUID {
			number = uint32(uid)
		}
		if result.Min == 0 || number < result.Min {
			result.Min = number
		}
		if number > result.Max {
			result.Max = number
		}
		result.Count++
	}
	if kind == imapserver.NumKindUID {
		result.All = uidSet
	} else {
		result.All = sequenceSet
	}
	if options.ReturnSave {
		s.searchRes = uidSet
	}
	return result, nil
}

func (s *imapSession) searchCriteriaLocked(criteria imap.SearchCriteria) imap.SearchCriteria {
	criteria.SeqNum = append([]imap.SeqSet(nil), criteria.SeqNum...)
	criteria.UID = append([]imap.UIDSet(nil), criteria.UID...)
	for i, set := range criteria.SeqNum {
		criteria.SeqNum[i] = s.staticSetLocked(set).(imap.SeqSet)
	}
	for i, set := range criteria.UID {
		criteria.UID[i] = s.staticSetLocked(set).(imap.UIDSet)
	}
	criteria.Not = append([]imap.SearchCriteria(nil), criteria.Not...)
	for i := range criteria.Not {
		criteria.Not[i] = s.searchCriteriaLocked(criteria.Not[i])
	}
	criteria.Or = append([][2]imap.SearchCriteria(nil), criteria.Or...)
	for i := range criteria.Or {
		criteria.Or[i][0] = s.searchCriteriaLocked(criteria.Or[i][0])
		criteria.Or[i][1] = s.searchCriteriaLocked(criteria.Or[i][1])
	}
	return criteria
}

type searchMessage struct {
	meta     *storedMessage
	sequence uint32
	load     func() ([]byte, error)
	raw      []byte
	loaded   bool
}

func (m *searchMessage) bytes() ([]byte, error) {
	if !m.loaded {
		var err error
		m.raw, err = m.load()
		if err != nil {
			return nil, err
		}
		m.loaded = true
	}
	return m.raw, nil
}

func (m *searchMessage) entity() (*gomessage.Entity, error) {
	raw, err := m.bytes()
	if err != nil {
		return nil, err
	}
	entity, err := gomessage.Read(bytes.NewReader(raw))
	if entity != nil {
		return entity, nil
	}
	return nil, err
}

func (m *searchMessage) matches(criteria *imap.SearchCriteria) (bool, error) {
	if criteria.ModSeq != nil {
		return false, model.ErrUnsupported
	}
	for _, set := range criteria.SeqNum {
		if !set.Contains(m.sequence) {
			return false, nil
		}
	}
	for _, set := range criteria.UID {
		if !set.Contains(m.meta.UID) {
			return false, nil
		}
	}
	if !dateMatches(m.meta.date(), criteria.Since, criteria.Before) {
		return false, nil
	}
	for _, flag := range criteria.Flag {
		if !hasFlag(m.meta.flags(), flag) {
			return false, nil
		}
	}
	for _, flag := range criteria.NotFlag {
		if hasFlag(m.meta.flags(), flag) {
			return false, nil
		}
	}
	// Dooray exposes decoded subjects in its lightweight list response. Use
	// that hint before any MIME-dependent criteria so an unrelated message
	// does not download its attachments just to reject its subject. An empty
	// search term tests header existence, which an empty hint cannot establish.
	var originalHeaders []imap.SearchCriteriaHeaderField
	for _, field := range criteria.Header {
		if strings.EqualFold(field.Key, "Subject") && field.Value != "" && m.meta.Meta.Subject != nil {
			if !strings.Contains(strings.ToLower(*m.meta.Meta.Subject), strings.ToLower(field.Value)) {
				return false, nil
			}
			continue
		}
		originalHeaders = append(originalHeaders, field)
	}
	if criteria.Larger != 0 || criteria.Smaller != 0 {
		raw, err := m.bytes()
		if err != nil {
			return false, err
		}
		size := int64(len(raw))
		if (criteria.Larger != 0 && size <= criteria.Larger) || (criteria.Smaller != 0 && size >= criteria.Smaller) {
			return false, nil
		}
	}
	if len(originalHeaders) > 0 || !criteria.SentSince.IsZero() || !criteria.SentBefore.IsZero() {
		entity, err := m.entity()
		if err != nil {
			return false, err
		}
		header := mail.Header{Header: entity.Header}
		for _, field := range originalHeaders {
			if !headerMatches(header.FieldsByKey(field.Key), field.Value) {
				return false, nil
			}
		}
		if !criteria.SentSince.IsZero() || !criteria.SentBefore.IsZero() {
			date, err := header.Date()
			if err != nil || !dateMatches(date, criteria.SentSince, criteria.SentBefore) {
				return false, nil
			}
		}
	}
	for _, term := range criteria.Body {
		entity, err := m.entity()
		if err != nil {
			return false, err
		}
		found, err := entityMatches(entity, term, false, 0)
		if err != nil || !found {
			return false, err
		}
	}
	for _, term := range criteria.Text {
		entity, err := m.entity()
		if err != nil {
			return false, err
		}
		found, err := entityMatches(entity, term, true, 0)
		if err != nil || !found {
			return false, err
		}
	}
	for _, nested := range criteria.Not {
		found, err := m.matches(&nested)
		if err != nil || found {
			return false, err
		}
	}
	for _, nested := range criteria.Or {
		left, err := m.matches(&nested[0])
		if err != nil {
			return false, err
		}
		if left {
			continue
		}
		right, err := m.matches(&nested[1])
		if err != nil || !right {
			return false, err
		}
	}
	return true, nil
}

func dateMatches(date, since, before time.Time) bool {
	// IMAP date predicates ignore the time and zone, including the zone of
	// INTERNALDATE; normalizing to the same UTC calendar date is intentional.
	date = time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	return (since.IsZero() || !date.Before(since)) && (before.IsZero() || date.Before(before))
}

func headerMatches(fields gomessage.HeaderFields, term string) bool {
	if term == "" {
		return fields.Len() > 0
	}
	for fields.Next() {
		text, err := fields.Text()
		if err != nil {
			text = fields.Value()
		}
		if strings.Contains(strings.ToLower(text), strings.ToLower(term)) {
			return true
		}
	}
	return false
}

func entityMatches(entity *gomessage.Entity, term string, includeHeaders bool, depth int) (bool, error) {
	if depth > 50 {
		return false, model.ErrUnsupported
	}
	if term == "" {
		return true, nil
	}
	if includeHeaders && headerMatches(entity.Header.Fields(), term) {
		return true, nil
	}
	if multipart := entity.MultipartReader(); multipart != nil {
		for {
			part, err := multipart.NextPart()
			if err == io.EOF {
				return false, nil
			}
			if part == nil {
				return false, err
			}
			found, err := entityMatches(part, term, includeHeaders, depth+1)
			if err != nil || found {
				return found, err
			}
		}
	}
	contentType, _, _ := entity.Header.ContentType()
	if contentType == "message/rfc822" {
		nested, err := gomessage.Read(entity.Body)
		if nested == nil {
			return false, err
		}
		return entityMatches(nested, term, true, depth+1)
	}
	if !strings.HasPrefix(contentType, "text/") {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(entity.Body, MaxMessageBytes+1))
	if err != nil {
		return false, err
	}
	if len(body) > MaxMessageBytes {
		return false, model.ErrUnsupported
	}
	return strings.Contains(strings.ToLower(string(body)), strings.ToLower(term)), nil
}
