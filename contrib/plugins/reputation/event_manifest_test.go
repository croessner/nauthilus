package main

import (
	"context"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// manifestTestTagger supplies a stable allocation scope and a configurable subject rotation ring.
func manifestTestTagger(t *testing.T, rotated bool) pluginapi.OpaqueIdentifierTagger {
	t.Helper()
	return manifestTestTaggerWithAllocation(t, rotated, "00112233445566770011223344556677")
}

// manifestTestTaggerWithAllocation permits explicit drain-protocol tests without exposing host key bytes to the plugin.
func manifestTestTaggerWithAllocation(t *testing.T, rotated bool, allocation string) pluginapi.OpaqueIdentifierTagger {
	t.Helper()

	subject := pluginruntime.OpaqueIdentifierScopeKeys{Scope: "reputation-subject", Active: pluginruntime.OpaqueIdentifierKey{Version: "current", Secret: secret.New("0123456789abcdef0123456789abcdef")}}
	if rotated {
		previous := subject.Active
		subject.Previous = &previous
		subject.Active = pluginruntime.OpaqueIdentifierKey{Version: "next", Secret: secret.New("abcdef0123456789abcdef0123456789")}
	}

	tagger, err := pluginruntime.NewOpaqueIdentifierTagger([]pluginruntime.OpaqueIdentifierScopeKeys{subject, {Scope: "reputation-manifest", Active: pluginruntime.OpaqueIdentifierKey{Version: "allocation", Secret: secret.New(allocation)}}})
	requireNoError(t, err)

	return tagger
}

// testManifestPlan admits a canonical observation and constructs its complete immutable candidate set.
func testManifestPlan(t *testing.T, tagger pluginapi.OpaqueIdentifierTagger, input observationInput) manifestRequest {
	t.Helper()
	cfg := testConfig(t)
	admitted, reason, err := cfg.admitObservation(context.Background(), cfg.apiSources["ScanWriter"], input, input.observedAt, tagger, nil)
	requireNoError(t, err)

	if reason != reasonValid {
		t.Fatal("test observation was not admitted")
	}

	model, err := compileModel(cfg)
	requireNoError(t, err)
	planner, err := newManifestPlanner(cfg, tagger, []*modelDefinition{model})
	requireNoError(t, err)
	result, err := planner.plan(context.Background(), admitted)
	requireNoError(t, err)

	return result
}

// TestManifestAllocationSurvivesSubjectRotationWithoutStoringRawEvidence prevents cross-generation allocation races.
func TestManifestAllocationSurvivesSubjectRotationWithoutStoringRawEvidence(t *testing.T) {
	input := testObservation()
	old := testManifestPlan(t, manifestTestTagger(t, false), input)

	rotated := testManifestPlan(t, manifestTestTagger(t, true), input)
	if old.AllocationTag != rotated.AllocationTag || len(rotated.Candidates) != 2 {
		t.Fatal("subject rotation changed event allocation")
	}

	if old.Candidates[0].Payload != rotated.Candidates[1].Payload {
		t.Fatal("new writer cannot reproduce previous immutable plan")
	}

	for _, candidate := range rotated.Candidates {
		for _, forbidden := range []string{input.eventID, input.subjects[0].value, "ScanWriter"} {
			if strings.Contains(candidate.Payload, forbidden) {
				t.Fatal("raw evidence retained in manifest")
			}
		}
	}

	input.eventID = "different-event"

	different := testManifestPlan(t, manifestTestTagger(t, false), input)
	if old.AllocationTag == different.AllocationTag {
		t.Fatal("distinct events share an allocation")
	}
}

// TestManifestPayloadBindsAllSubjectAndEvidenceSemantics prevents retries from changing the admitted contribution.
func TestManifestPayloadBindsAllSubjectAndEvidenceSemantics(t *testing.T) {
	tagger := manifestTestTagger(t, false)
	first := testManifestPlan(t, tagger, testObservation())
	changed := testObservation()
	changed.subjects[0].value = "192.0.3.4"

	second := testManifestPlan(t, tagger, changed)
	if first.AllocationTag != second.AllocationTag || first.Candidates[0].Payload == second.Candidates[0].Payload {
		t.Fatal("payload substitution was not bound to the same event allocation")
	}
}

// TestManifestPreservesExactTimestampPrecision rejects payload substitution below floating-point epoch precision.
func TestManifestPreservesExactTimestampPrecision(t *testing.T) {
	tagger := manifestTestTagger(t, false)
	input := testObservation()
	first := testManifestPlan(t, tagger, input)
	input.observedAt = input.observedAt.Add(1)

	second := testManifestPlan(t, tagger, input)
	if first.Candidates[0].Payload == second.Candidates[0].Payload {
		t.Fatal("distinct observation timestamps share one payload identity")
	}
}
