//go:build reputation_integration

package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReputationRedisManagementAuditsAndVerifiesOverrideLifecycle(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	ttl := int64(3600)
	input := managementInput{Kind: kindIP, Subject: "192.0.2.8", Band: bandBlocked, Reason: "incident", Origin: "operator",
		AuditID: "change-one", TTLSeconds: &ttl}
	written, err := owner.manage(t.Context(), managementPut, input, "verified-admin")
	requireNoError(t, err)
	if written.Audit == nil || written.Audit.Creator != "verified-admin" || written.Audit.AuditID != input.AuditID || written.Profiles[profileOperational].Band != bandBlocked {
		t.Fatal("management write lacks verified actor, receipt or primary readback")
	}

	_, err = owner.manage(t.Context(), managementPut, input, "verified-admin")
	if err != errOverrideConflict {
		t.Fatal("stale override creation overwrote a newer revision")
	}
	input.PreviousAudit, input.AuditID = input.AuditID, "change-two"
	removed, err := owner.manage(t.Context(), managementDelete, input, "verified-admin")
	requireNoError(t, err)
	if removed.Audit == nil || removed.Audit.Operation != managementDelete || removed.Profiles[profileOperational].Override != overrideNone {
		t.Fatal("override removal lacks durable audit or readback")
	}

	encoded, err := json.Marshal(removed)
	requireNoError(t, err)
	if strings.Contains(string(encoded), input.Subject) || strings.Contains(string(encoded), `"tag"`) {
		t.Fatal("operator response exposed a raw subject or storage identity")
	}
	assertManagementResponseSchema(t, written)
	assertManagementResponseSchema(t, removed)
}

func TestReputationRedisManagementSharesDecayAndSourceClassesWithoutWrites(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := shortRetentionConfig(t)
	cfg.raw.Bands.DiversityMassFloor = 0.2
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "operator-view")
	_, err = owner.ingest(t.Context(), admitted)
	requireNoError(t, err)
	subject := admitted.subjects[0]
	input := managementInput{Kind: subject.kind, Subject: subject.value}
	before, err := owner.manage(t.Context(), managementLookup, input, "")
	requireNoError(t, err)
	if len(before.Evidence[0].SourceClasses[profileFast]) != 1 || before.Evidence[0].SourceClasses[profileFast][0] != admitted.source.config.SourceClass {
		t.Fatal("operator view lost actual contributing source class")
	}
	key := owner.keys.subject(subject.tag, cfg.raw.ModelID).State
	stored, err := client.HGetAll(t.Context(), key).Result()
	requireNoError(t, err)
	ttl, err := client.PTTL(t.Context(), key).Result()
	requireNoError(t, err)
	time.Sleep(1100 * time.Millisecond)
	after, err := owner.manage(t.Context(), managementLookup, input, "")
	requireNoError(t, err)
	readback, err := client.HGetAll(t.Context(), key).Result()
	requireNoError(t, err)
	remaining, err := client.PTTL(t.Context(), key).Result()
	requireNoError(t, err)
	if !reflect.DeepEqual(stored, readback) || remaining >= ttl || after.Profiles[profileFast].Details.Samples >= before.Profiles[profileFast].Details.Samples {
		t.Fatal("management changed state or failed to apply read-time decay")
	}
	assertManagementResponseSchema(t, after)
}

func TestReputationRedisManagementPreservesRotationAndExpiryAuthority(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, true), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	ttl := int64(1)
	input := managementInput{Kind: kindIP, Subject: "192.0.2.8", Slot: "previous", Band: bandBlocked, Reason: "incident", Origin: "operator", AuditID: "previous-write", TTLSeconds: &ttl}
	view, err := owner.manage(t.Context(), managementPut, input, "verified-admin")
	requireNoError(t, err)
	if len(view.Evidence) != 2 || view.Evidence[0].Override != nil || view.Evidence[1].Override == nil || view.Profiles[profileOperational].Band != bandBlocked {
		t.Fatal("management lost previous-slot authority")
	}
	time.Sleep(1100 * time.Millisecond)
	view, err = owner.manage(t.Context(), managementLookup, input, "")
	requireNoError(t, err)
	if view.Evidence[1].Override != nil || view.Evidence[1].Audit == nil || view.Profiles[profileOperational].Override != overrideNone {
		t.Fatal("expired override retained authority or lost its bounded audit receipt")
	}
	assertManagementResponseSchema(t, view)
}

// assertManagementResponseSchema checks actual service output against the committed generated-client contract.
func assertManagementResponseSchema(t *testing.T, value managementView) {
	t.Helper()
	encoded, err := json.Marshal(value)
	requireNoError(t, err)
	var decoded any
	requireNoError(t, json.Unmarshal(encoded, &decoded))
	requireNoError(t, managementContract(t).Components.Schemas["ReputationView"].Value.VisitJSON(decoded))
}

func TestReputationRedisManagementDomainUsesCanonicalContract(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	ttl := int64(0)
	input := managementInput{Kind: kindDomain, Subject: "example.test", Band: bandNeutral, Reason: "static.classification", Origin: "operator", AuditID: "domain-import", TTLSeconds: &ttl}
	result, err := owner.manage(t.Context(), managementPut, input, "verified-admin")
	requireNoError(t, err)
	assertManagementResponseSchema(t, result)
	if result.Kind != kindDomain || result.Audit == nil || result.Audit.Kind != kindDomain {
		t.Fatal("DNS domain contract differs from primary audit state")
	}
}
