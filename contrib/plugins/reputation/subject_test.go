package main

import (
	"testing"
)

// TestSubjectCanonicalization keeps subject kinds separate while collapsing supported aliases.
func TestSubjectCanonicalization(t *testing.T) {
	cfg := testConfig(t)

	tests := []struct{ kind, input, want string }{
		{"ip", "::ffff:192.0.2.3", "192.0.2.3"},
		{"ip", "2001:0db8::1", "2001:db8::1"},
		{"network", "192.0.2.19/24", "192.0.2.0/24"},
		{"asn", "AS064500", "64500"},
		{"dns_domain", "BÜCHER.Example.", "xn--bcher-kva.example"},
		{"account", "CaseSensitive", "CaseSensitive"},
		{"service", "WORKER", "worker"},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got, err := cfg.canonicalSubject(tt.kind, tt.input)
			requireNoError(t, err)

			if got != tt.want {
				t.Fatalf("canonical value=%q, want %q", got, tt.want)
			}
		})
	}

	for _, tt := range []struct{ kind, value string }{
		{"ip", "fe80::1%en0"}, {"ip", " 192.0.2.1"}, {"asn", "0"}, {"asn", "4294967296"},
		{"dns_domain", "a..example"}, {"dns_domain", "*"}, {"account", "a\nb"}, {"service", "unconfigured"}, {"country", "DE"},
	} {
		t.Run(tt.kind+tt.value, func(t *testing.T) { _, err := cfg.canonicalSubject(tt.kind, tt.value); requireError(t, err) })
	}
}
