//go:build reputation_integration

package main

import "testing"

// TestReputationRedisNetworkOverridePreservesSpecificityAndExactIdentity proves real primary lookup without inferred learned state.
func TestReputationRedisNetworkOverridePreservesSpecificityAndExactIdentity(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	cfg.raw.IPOverrideNetworks = []string{"192.0.2.0/24", "192.0.2.16/28"}
	requireNoError(t, cfg.compileOverrideNetworks())
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	for _, entry := range []struct{ value, band, audit string }{{"192.0.2.0/24", "blocked", "broad"}, {"192.0.2.16/28", "neutral", "specific"}} {
		_, err = owner.putOverride(t.Context(), subjectInput{kind: kindNetwork, value: entry.value}, overrideInput{Band: entry.band, Reason: "static.classification", Creator: "migration-fixture", AuditID: entry.audit, Origin: "cutover.static_dkim2_v4"})
		requireNoError(t, err)
	}

	for _, entry := range []struct{ value, band string }{{"192.0.2.20", "neutral"}, {"192.0.2.4", "blocked"}, {"198.51.100.2", "unknown"}} {
		tuple := owner.assess(t.Context(), subjectInput{kind: kindIP, value: entry.value}, profileOperational)
		if tuple.Band != entry.band || tuple.State != assessmentMissing || tuple.Details != nil {
			t.Fatalf("network override lost specificity or invented evidence: %#v", tuple)
		}
	}

	exact := subjectInput{kind: kindIP, value: "192.0.2.20"}
	_, err = owner.putOverride(t.Context(), exact, overrideInput{Band: bandTrusted, Reason: "operator.exact", Creator: "operator-fixture", AuditID: "exact", Origin: "operator"})
	requireNoError(t, err)

	if owner.assess(t.Context(), exact, profileOperational).Band != bandTrusted {
		t.Fatal("network override replaced exact-IP authority")
	}

	requireNoError(t, client.Close())

	if owner.assess(t.Context(), subjectInput{kind: kindIP, value: "192.0.2.4"}, profileOperational).State != assessmentUnavailable {
		t.Fatal("failed primary lookup became static trust")
	}
}

// TestReputationRedisUnavailableIPDoesNotBorrowReadableNetworkAuthority preserves explicit per-subject failure with a healthy CIDR key.
func TestReputationRedisUnavailableIPDoesNotBorrowReadableNetworkAuthority(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	cfg.raw.IPOverrideNetworks = []string{"192.0.2.0/24"}
	requireNoError(t, cfg.compileOverrideNetworks())
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	network := subjectInput{kind: kindNetwork, value: "192.0.2.0/24"}
	_, err = owner.putOverride(t.Context(), network, overrideInput{Band: bandTrusted, Reason: "operator.trust", Creator: "operator", AuditID: "healthy-network", Origin: "operator"})
	requireNoError(t, err)

	ip := subjectInput{kind: kindIP, value: "192.0.2.16"}
	record, err := owner.putOverride(t.Context(), ip, overrideInput{Band: bandTrusted, Reason: "operator.trust", Creator: "operator", AuditID: "corrupt-ip", Origin: "operator"})
	requireNoError(t, err)

	key := owner.keys.subject(record.Tag, cfg.raw.ModelID).Override
	requireNoError(t, client.HSet(t.Context(), key, "creator", "operator\nforged").Err())

	for _, tuple := range owner.assessProfiles(t.Context(), ip) {
		if tuple.validate() != nil || tuple.State != assessmentUnavailable || tuple.Band != assessmentUnavailable || tuple.Override != overrideNone {
			t.Fatalf("unavailable IP borrowed CIDR authority: %#v", tuple)
		}
	}

	if tuple := owner.assess(t.Context(), network, profileOperational); tuple.validate() != nil || tuple.Override != bandTrusted {
		t.Fatalf("independent network override must remain readable: %#v", tuple)
	}
}
