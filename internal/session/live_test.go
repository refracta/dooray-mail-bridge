package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

// Explicit opt-in: this may request a real verification email. All credentials
// and session data remain local; test output contains no mailbox contents.
func TestLiveAuthentication(t *testing.T) {
	if os.Getenv("DMB_LIVE_LOGIN") != "1" {
		t.Skip("set DMB_LIVE_LOGIN=1 to exercise configured KAIST authentication")
	}
	if err := godotenv.Load("../../.env"); err != nil {
		t.Fatal("live test requires a local .env file")
	}
	data := os.Getenv("DATA_DIR")
	if data == "" {
		data = "data"
	}
	if !filepath.IsAbs(data) {
		data = filepath.Join("../..", data)
	}
	data = filepath.Join(data, "session")
	s, err := New(Options{BaseURL: os.Getenv("DOORAY_URL"), Username: os.Getenv("KAIST_ID"), Password: os.Getenv("KAIST_PASSWORD"), Email: os.Getenv("DOORAY_EMAIL"), CodeURL: os.Getenv("KAIST_CODE_URL"), CodeToken: os.Getenv("KAIST_CODE_TOKEN"), DataDir: data})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := s.Authenticate(ctx, os.Getenv("KAIST_ID"), os.Getenv("KAIST_PASSWORD")); err != nil {
		t.Fatal(err)
	}
	ok, _ := s.State()
	if !ok {
		t.Fatal("authenticated session is not ready")
	}
	t.Log("HTTP-only login completed; authenticated account matches configuration")
}
