package pluginruntime

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// TestOpaqueTaggerSeparatesInputsAndRotationVersions checks stable keyed identifiers and explicit candidates.
func TestOpaqueTaggerSeparatesInputsAndRotationVersions(t *testing.T) {
	tagger, err := NewOpaqueIdentifierTagger([]OpaqueIdentifierScopeKeys{{
		Scope: "workflow", Active: OpaqueIdentifierKey{Version: "current", Secret: secret.FromBytes(bytes.Repeat([]byte{1}, 32))},
		Previous: &OpaqueIdentifierKey{Version: "previous", Secret: secret.FromBytes(bytes.Repeat([]byte{2}, 32))},
	}})
	if err != nil {
		t.Fatal(err)
	}

	input := pluginapi.OpaqueIdentifierInput{Scope: "workflow", Kind: "object", Value: "resource-123"}

	active, err := tagger.Tag(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}

	if active.String() != "hmac-sha256-v1:current:A27Obh_LHegmCfcmOPoLxN63QllMMS-qWRUgyCO91Mc" {
		t.Fatal("HMAC framing vector changed")
	}

	if fmt.Sprintf("%#v", tagger) != "[opaque identifier tagger]" {
		t.Fatal("tagger diagnostic formatting exposed internal state")
	}

	repeated, err := tagger.Tag(t.Context(), input)
	if err != nil || active != repeated || active.Version() != "current" || strings.Contains(active.String(), input.Value) {
		t.Fatalf("unstable or unsafe tag: %v", err)
	}

	assertOpaqueTagRotation(t, tagger, input, active)
	assertOpaqueTagInputSeparation(t, tagger, input, active)
}

// TestOpaqueTaggerRejectsUnsafeInputsAndMissingService enforces generic bounds without leaking input.
func TestOpaqueTaggerRejectsUnsafeInputsAndMissingService(t *testing.T) {
	if _, err := NewHost().OpaqueIdentifierTagger(); err == nil {
		t.Fatal("unconfigured tagger was accepted")
	}

	for _, input := range []pluginapi.OpaqueIdentifierInput{
		{}, {Scope: "workflow", Kind: "object", Value: ""},
		{Scope: "workflow", Kind: "object", Value: string([]byte{0xff})},
		{Scope: strings.Repeat("x", 65), Kind: "object", Value: "secret-value"},
		{Scope: "workflow", Kind: "object", Value: strings.Repeat("x", 65537)},
	} {
		if err := pluginapi.ValidateOpaqueIdentifierInput(input); err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatal("invalid opaque input accepted or exposed")
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	tagger, err := NewOpaqueIdentifierTagger([]OpaqueIdentifierScopeKeys{{Scope: "workflow", Active: OpaqueIdentifierKey{Version: "current", Secret: secret.FromBytes(bytes.Repeat([]byte{1}, 32))}}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = tagger.Tag(ctx, pluginapi.OpaqueIdentifierInput{Scope: "workflow", Kind: "object", Value: "value"}); err == nil {
		t.Fatal("cancelled work accepted")
	}
}

// TestOpaqueTaggerSeparatesConfiguredScopes prevents equal identifiers in different domains from colliding.
func TestOpaqueTaggerSeparatesConfiguredScopes(t *testing.T) {
	key := OpaqueIdentifierKey{Version: "current", Secret: secret.FromBytes(bytes.Repeat([]byte{1}, 32))}

	tagger, err := NewOpaqueIdentifierTagger([]OpaqueIdentifierScopeKeys{{Scope: "workflow", Active: key}, {Scope: "cache", Active: key}})
	if err != nil {
		t.Fatal(err)
	}

	first, err := tagger.Tag(t.Context(), pluginapi.OpaqueIdentifierInput{Scope: "workflow", Kind: "object", Value: "same"})
	if err != nil {
		t.Fatal(err)
	}

	second, err := tagger.Tag(t.Context(), pluginapi.OpaqueIdentifierInput{Scope: "cache", Kind: "object", Value: "same"})
	if err != nil || first == second {
		t.Fatal("scope separation failed")
	}
}

// assertOpaqueTagRotation verifies explicit ordered candidates and rejects unknown key versions.
func assertOpaqueTagRotation(t *testing.T, tagger pluginapi.OpaqueIdentifierTagger, input pluginapi.OpaqueIdentifierInput, active pluginapi.OpaqueIdentifierTag) {
	t.Helper()

	candidates, err := tagger.Candidates(t.Context(), input)
	if err != nil || len(candidates) != 2 || candidates[0] != active || candidates[1].Version() != "previous" || candidates[0] == candidates[1] {
		t.Fatalf("invalid rotation candidates: %v", err)
	}

	previous, err := tagger.TagVersion(t.Context(), input, "previous")
	if err != nil || previous != candidates[1] {
		t.Fatal("explicit previous version did not match rotation candidate")
	}

	if _, err = tagger.TagVersion(t.Context(), input, "unknown"); err == nil {
		t.Fatal("unsupported version accepted")
	}
}

// assertOpaqueTagInputSeparation checks that kind and value changes cannot collide.
func assertOpaqueTagInputSeparation(t *testing.T, tagger pluginapi.OpaqueIdentifierTagger, input pluginapi.OpaqueIdentifierInput, active pluginapi.OpaqueIdentifierTag) {
	t.Helper()

	for _, mutated := range []pluginapi.OpaqueIdentifierInput{
		{Scope: "workflow", Kind: "other", Value: input.Value},
		{Scope: "workflow", Kind: input.Kind, Value: "different"},
	} {
		changed, err := tagger.Tag(t.Context(), mutated)
		if err != nil || changed == active {
			t.Fatal("typed inputs collided")
		}
	}
}
