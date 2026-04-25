package config

import "testing"

func TestSetDefaultHeadersSetsExternalSessionHeader(t *testing.T) {
	cfg := &FileSettings{
		Server: &ServerSection{},
	}

	if err := cfg.setDefaultHeaders(); err != nil {
		t.Fatalf("setDefaultHeaders failed: %v", err)
	}

	if got := cfg.GetExternalSessionID(); got != "X-External-Session-ID" {
		t.Fatalf("expected external session header default %q, got %q", "X-External-Session-ID", got)
	}
}
