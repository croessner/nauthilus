package configfx

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// TestProviderVersionMonotonicOnCandidatePreparationFailure proves failed preparation is unpublished.
func TestProviderVersionMonotonicOnCandidatePreparationFailure(t *testing.T) {
	p := NewProviderWithCandidate(&config.FileSettings{}, policyruntime.NewGenerationStore())

	cur := p.Current()
	if cur.Version != 1 {
		t.Fatalf("expected version 1, got %d", cur.Version)
	}

	// Candidate preparation will fail because Viper has no config; ensure version does not change.
	_, err := p.Prepare()
	if err == nil {
		t.Fatalf("expected reload error")
	}

	after := p.Current()
	if after.Version != cur.Version {
		t.Fatalf("expected version to remain %d, got %d", cur.Version, after.Version)
	}
}

// TestProviderWithCandidateCapturesBootstrapState protects the off-side bootstrap handoff.
func TestProviderWithCandidateCapturesBootstrapState(t *testing.T) {
	prepared := &config.FileSettings{}
	store := policyruntime.NewGenerationStore()
	reloader := NewProviderWithCandidate(prepared, store)

	provider, ok := reloader.(*provider)
	if !ok {
		t.Fatalf("NewProviderWithCandidate() = %T, want *provider", reloader)
	}

	if provider.generations != store {
		t.Fatal("provider does not retain the sole generation store")
	}

	before := provider.Current()
	if before.File != prepared || before.Version != 1 {
		t.Fatalf("prepared snapshot = %#v, want candidate version 1", before)
	}
}
