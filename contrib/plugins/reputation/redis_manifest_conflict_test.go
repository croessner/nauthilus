//go:build reputation_integration

package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestReputationRedisManifestRejectsEveryContributionSubstitution binds all frozen dimensions before fan-out.
func TestReputationRedisManifestRejectsEveryContributionSubstitution(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*manifestPayload)
	}{
		{"signal", func(p *manifestPayload) { p.Signal = "scan.changed" }},
		{"magnitude", func(p *manifestPayload) { value := 0.5; p.Magnitude = &value }},
		{"timestamp", func(p *manifestPayload) { p.ObservedAt-- }},
		{"exact timestamp", func(p *manifestPayload) { p.ObservedTime = "2026-01-01T00:00:00Z" }},
		{"origin", func(p *manifestPayload) { p.Origin = "host_backend_outcome" }},
		{"model", func(p *manifestPayload) { p.Models[0].ID = "other-model" }},
		{"fingerprint", func(p *manifestPayload) { p.Models[0].Fingerprint = strings.Repeat("a", 64) }},
		{"role", func(p *manifestPayload) { p.Models[0].Subjects[0].Role = "other" }},
		{"kind", func(p *manifestPayload) { p.Models[0].Subjects[0].Kind = kindAccount }},
		{"subject", func(p *manifestPayload) { p.Models[0].Subjects[0].Tag = p.SeenTag }},
		{"removed derived subject", func(p *manifestPayload) { p.Models[0].Subjects = p.Models[0].Subjects[:1] }},
	}
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			admitted := integrationObservation(t, cfg, tagger, tt.name)
			plan, err := owner.planner.plan(t.Context(), admitted)
			requireNoError(t, err)
			_, _, err = owner.admitManifest(t.Context(), plan)
			requireNoError(t, err)

			var payload manifestPayload
			requireNoError(t, json.Unmarshal([]byte(plan.Candidates[0].Payload), &payload))
			tt.mutate(&payload)
			encoded, err := json.Marshal(payload)
			requireNoError(t, err)

			plan.Candidates[0].Payload = string(encoded)

			_, _, err = owner.admitManifest(t.Context(), plan)
			if !errors.Is(err, errEventConflict) {
				t.Fatal("changed frozen dimension did not reject as conflict", err)
			}

			result, err := owner.ingest(t.Context(), admitted)
			requireNoError(t, err)

			if result.Applied != 2 {
				t.Fatal("conflict mutated original subject state")
			}
		})
	}
}
