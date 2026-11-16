package session

import (
	"strings"
	"testing"
)

// Synthetic inputs cross-checked against the public KAIST form's CryptoJS
// implementation; no account credentials or server-generated keys are fixtures.
func TestEncryptLoginCompatibility(t *testing.T) {
	tests := []struct{ key, plain, want string }{
		{strings.Repeat("0123456789abcdef", 6), "test", "66b3c4a1cd99e0b9529442b38c1bb35f"},
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f", `{"login_id":"test-user","login_pwd":"synthetic-password","agt_id":"example-agent","linkUrl":"/return","device_cd":[]}`, "c407b83e7f22e6b12b5ff63ee3133ade1608f6611ac9f9d46c2dad11454ad92b0e7a5e79e8bf02c9d01a90394f749d295536518b34e2346a9c5a8fd58c887203549738620d2c49a9ed0a075ded0fa2b3e48dd181aff11e495a1834e7b01a77cc8cf7d46212aeb7f9163a0107ae86df12b30f17c3afacfeeb14d4f15b847557ce"},
		{strings.Repeat("00", 48), "한글 테스트", "9ba0b9bae927e1e8efb9151a74ab892071dfeb8a8378afb07e0f5268cd315ad3"},
	}
	for _, tc := range tests {
		got, err := encryptLogin(tc.key, []byte(tc.plain))
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("SEED-CBC compatibility failed: %s", got)
		}
	}
	got, err := encryptLogin(tests[0].key+"unused-server-suffix", []byte(tests[0].plain))
	if err != nil || got != tests[0].want {
		t.Fatal("server suffix was not ignored like the web form")
	}
	for _, key := range []string{"", strings.Repeat("g", 96), strings.Repeat("0", 95)} {
		if _, err := encryptLogin(key, nil); err == nil {
			t.Fatal("malformed key accepted")
		}
	}
}
