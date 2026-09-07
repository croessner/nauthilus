package dkim2projection

import "testing"

// TestClientIPRejectsScopedSMTPIdentity prevents local interface zones from entering globally correlated peer evidence.
func TestClientIPRejectsScopedSMTPIdentity(t *testing.T) {
	for _, address := range []string{"2001:db8::1%eth0", "2001:db8::1%25eth0"} {
		if _, err := parseCanonicalClientIP(address); err == nil {
			t.Fatal("scoped SMTP address accepted")
		}
	}
}
