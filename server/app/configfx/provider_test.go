package configfx

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
)

// TestProviderNewProviderRequiresConfigLoaded preserves the pre-generation startup guard.
func TestProviderNewProviderRequiresConfigLoaded(t *testing.T) {
	// Ensure global config is not set.
	config.SetTestFile(nil)

	_, err := NewProvider()
	if err == nil {
		t.Fatalf("expected error")
	}

	if _, ok := errors.AsType[config.ErrConfigNotLoaded](err); !ok {
		t.Fatalf("expected ErrConfigNotLoaded, got %T", err)
	}
}

// TestProviderVersionMonotonicOnCandidatePreparationFailure proves failed preparation is unpublished.
func TestProviderVersionMonotonicOnCandidatePreparationFailure(t *testing.T) {
	// Use a test file to avoid reading from disk.
	config.SetTestFile(&config.FileSettings{})

	p, err := NewProvider()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cur := p.Current()
	if cur.Version != 1 {
		t.Fatalf("expected version 1, got %d", cur.Version)
	}

	// Candidate preparation will fail because Viper has no config; ensure version does not change.
	_, err = p.Prepare()
	if err == nil {
		t.Fatalf("expected reload error")
	}

	after := p.Current()
	if after.Version != cur.Version {
		t.Fatalf("expected version to remain %d, got %d", cur.Version, after.Version)
	}
}
