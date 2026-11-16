package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type codeRecord struct {
	Code       string          `json:"code"`
	ID         json.RawMessage `json:"id"`
	Date       string          `json:"date"`
	ServerTime int64           `json:"serverTime"`
}

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

func (r codeRecord) id() string {
	v := strings.TrimSpace(string(r.ID))
	if v == "null" || v == `""` {
		return ""
	}
	return strings.Trim(v, `"`)
}
func freshCode(baseline, current codeRecord) bool {
	if !sixDigits.MatchString(current.Code) || current.id() == "" || current.id() == baseline.id() || baseline.ServerTime <= 0 || current.ServerTime < baseline.ServerTime {
		return false
	}
	date, err := time.Parse(time.RFC3339Nano, current.Date)
	if err != nil {
		return false
	}
	ms := date.UnixMilli()
	return ms >= baseline.ServerTime-5000 && ms <= current.ServerTime+5000 && current.ServerTime-ms <= 180000
}
func (s *Session) readCode(ctx context.Context) (codeRecord, error) {
	var code codeRecord
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.opts.CodeURL, nil)
	if err != nil {
		return code, errors.New("invalid verification endpoint")
	}
	req.Header.Set("Cache-Control", "no-cache")
	if s.opts.CodeToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.opts.CodeToken)
	}
	resp, err := s.codeClient.Do(req)
	if err != nil {
		return code, errors.New("verification endpoint is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return code, errors.New("verification endpoint did not return success")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&code); err != nil || code.ServerTime <= 0 {
		return codeRecord{}, errors.New("invalid verification endpoint response")
	}
	return code, nil
}
func (s *Session) waitCode(ctx context.Context, baseline codeRecord) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 170*time.Second)
	defer cancel()
	for {
		if err := wait(ctx, time.Second); err != nil {
			return "", errors.New("timed out waiting for a fresh KAIST verification email")
		}
		current, err := s.readCode(ctx)
		if err != nil {
			continue
		}
		if freshCode(baseline, current) {
			return current.Code, nil
		}
	}
}
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
