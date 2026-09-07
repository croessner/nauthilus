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

// TestClientIPKeepsPrivateContractAddressesAndRejectsLocalOnlyPeers preserves the transport identity boundary.
func TestClientIPKeepsPrivateContractAddressesAndRejectsLocalOnlyPeers(t *testing.T) {
	for _, tc := range []struct {
		address string
		valid   bool
	}{{"127.0.0.1", false}, {"::1", false}, {"169.254.1.1", false}, {"fe80::1", false}, {"10.23.45.67", true}, {"fd00::25", true}} {
		if _, err := parseCanonicalClientIP(tc.address); (err == nil) != tc.valid {
			t.Fatalf("unexpected address validity for %s", tc.address)
		}
	}
}
