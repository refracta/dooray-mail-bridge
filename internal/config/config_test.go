package config

import "testing"

func TestPlaintextRequiresLoopback(t *testing.T) {
	for _, addr := range []string{":143", "0.0.0.0:143", "[::]:143", "localhost:143", "192.0.2.1:143"} {
		c := Config{IMAPAddress: addr, SMTPAddress: "127.0.0.1:1025", InsecureLocal: true}
		if c.ValidateListeners() == nil {
			t.Fatalf("plaintext accepted on %s", addr)
		}
	}
	c := Config{IMAPAddress: "127.0.0.1:1143", SMTPAddress: "[::1]:1025", InsecureLocal: true}
	if err := c.ValidateListeners(); err != nil {
		t.Fatal(err)
	}
	c.InsecureLocal = false
	if c.ValidateListeners() == nil {
		t.Fatal("TLS credentials not required")
	}
	c.TLSCert = "cert.pem"
	c.TLSKey = "key.pem"
	if err := c.ValidateListeners(); err != nil {
		t.Fatal(err)
	}
}
