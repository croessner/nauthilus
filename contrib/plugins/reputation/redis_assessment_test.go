//go:build reputation_integration

package main

import (
	"reflect"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestReputationRedisAssessmentDecaysWithoutMutation proves primary snapshots age mass and samples without refreshing state.
func TestReputationRedisAssessmentDecaysWithoutMutation(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := shortRetentionConfig(t)
	cfg.raw.Bands.DiversityMassFloor = 0.2
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "decaying-evidence")
	_, err = owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	subject := admitted.subjects[0].subjectInput

	first := owner.assess(t.Context(), subject, profileFast)
	if first.State != assessmentFresh || first.Details == nil {
		t.Fatal("written primary state was not visible")
	}

	key := owner.keys.subject(admitted.subjects[0].tag, cfg.raw.ModelID).State
	before, err := client.HGetAll(t.Context(), key).Result()
	requireNoError(t, err)
	ttl, err := client.PTTL(t.Context(), key).Result()
	requireNoError(t, err)
	time.Sleep(1100 * time.Millisecond)

	next := owner.assess(t.Context(), subject, profileFast)
	if next.State != assessmentFresh || next.Details.Confidence >= first.Details.Confidence || next.Details.Samples >= first.Details.Samples*0.6 || next.Details.Diversity >= first.Details.Diversity {
		t.Fatal("read-time evidence did not decay")
	}

	after, err := client.HGetAll(t.Context(), key).Result()
	requireNoError(t, err)
	nextTTL, err := client.PTTL(t.Context(), key).Result()
	requireNoError(t, err)

	if !reflect.DeepEqual(before, after) || nextTTL >= ttl {
		t.Fatal("assessment rewrote state or refreshed its TTL")
	}
}

// TestReputationRedisAssessmentDistinguishesMissingAndUnavailable forbids an empty or failed read from inventing neutrality.
func TestReputationRedisAssessmentDistinguishesMissingAndUnavailable(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	subject := subjectInput{kind: kindIP, value: "192.0.2.9"}

	missing := owner.assess(t.Context(), subject, profileOperational)
	if missing.State != assessmentMissing || missing.Band != bandUnknown || missing.Details != nil {
		t.Fatal("missing evidence acquired an invented score")
	}

	requireNoError(t, client.Close())

	unavailable := owner.assess(t.Context(), subject, profileOperational)
	if unavailable.State != assessmentUnavailable || unavailable.Band != assessmentUnavailable || unavailable.Details != nil {
		t.Fatal("failed primary read became empty or neutral")
	}
}

// TestReputationRedisOverridePrecedenceAndRotationFailure preserves a previous-key block even when active history is empty.
func TestReputationRedisOverridePrecedenceAndRotationFailure(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	oldTagger := manifestTestTagger(t, false)
	old, err := newStateOwner(cfg, oldTagger, facade)
	requireNoError(t, err)
	requireNoError(t, old.start(t.Context()))

	subject := subjectInput{kind: kindIP, value: "192.0.2.9"}
	record, err := old.putOverride(t.Context(), subject, overrideInput{Band: bandBlocked, Reason: "operator.block", Creator: "operator-one", AuditID: "audit-one", Origin: "operator"})
	requireNoError(t, err)

	if record.Band != bandBlocked || record.CreatedAt <= 0 {
		t.Fatal("override audit readback missing")
	}

	nextTagger := manifestTestTagger(t, true)
	next, err := newStateOwner(cfg, nextTagger, facade)
	requireNoError(t, err)
	requireNoError(t, next.start(t.Context()))
	_, err = next.putOverride(t.Context(), subject, overrideInput{Band: bandTrusted, Reason: "operator.trust", Creator: "operator-two", AuditID: "audit-two", Origin: "operator"})
	requireNoError(t, err)

	assessment := next.assess(t.Context(), subject, profileOperational)
	if assessment.State != assessmentMissing || assessment.Band != bandBlocked || assessment.Details != nil {
		t.Fatal("previous block lost to active trust or invented evidence")
	}

	tag, err := oldTagger.Tag(t.Context(), pluginapi.OpaqueIdentifierInput{Scope: cfg.raw.SubjectScope, Kind: subject.kind, Value: subject.value})
	requireNoError(t, err)

	key := old.keys.subject(tag.String(), cfg.raw.ModelID).Override
	requireNoError(t, client.HDel(t.Context(), key, "reason").Err())

	failed := next.assess(t.Context(), subject, profileOperational)
	if failed.State != assessmentUnavailable || failed.Band != assessmentUnavailable {
		t.Fatal("malformed previous block was masked by active trust")
	}
}

// TestReputationRedisOverrideExpiryAndCompareGuard prevents expired authority and stale operator updates from taking effect.
func TestReputationRedisOverrideExpiryAndCompareGuard(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	subject := subjectInput{kind: kindIP, value: "192.0.2.10"}
	input := overrideInput{Band: bandNeutral, Reason: "operator.review", Creator: "operator", AuditID: "audit-expiring", Origin: "operator", TTL: 100 * time.Millisecond}
	record, err := owner.putOverride(t.Context(), subject, input)
	requireNoError(t, err)

	input.AuditID = "stale-update"
	_, err = owner.putOverride(t.Context(), subject, input)
	requireError(t, err)

	key := owner.keys.subject(record.Tag, cfg.raw.ModelID).Override
	before, err := client.HGetAll(t.Context(), key).Result()
	requireNoError(t, err)
	ttl, err := client.PTTL(t.Context(), key).Result()
	requireNoError(t, err)
	time.Sleep(20 * time.Millisecond)

	current := owner.assess(t.Context(), subject, profileOperational)
	if current.Band != bandNeutral || current.Override != bandNeutral {
		t.Fatal("neutral override was not visible on the primary")
	}

	after, err := client.HGetAll(t.Context(), key).Result()
	requireNoError(t, err)
	afterTTL, err := client.PTTL(t.Context(), key).Result()
	requireNoError(t, err)

	if !reflect.DeepEqual(before, after) || afterTTL >= ttl {
		t.Fatal("assessment refreshed or rewrote override authority")
	}

	time.Sleep(150 * time.Millisecond)

	expired := owner.assess(t.Context(), subject, profileOperational)
	if expired.Band != bandUnknown || expired.Override != overrideNone {
		t.Fatal("expired override retained authority")
	}
}

// TestReputationRedisZeroMagnitudeRemainsMeasuredUnknown avoids classifying valid zero-weight state as a storage failure.
func TestReputationRedisZeroMagnitudeRemainsMeasuredUnknown(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "zero-measurement")
	admitted.input.magnitude = new(float64)
	_, err = owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	result := owner.assess(t.Context(), admitted.subjects[0].subjectInput, profileOperational)
	if result.State != assessmentFresh || result.Band != bandUnknown || result.Details == nil || result.Details.Confidence != 0 {
		t.Fatal("valid zero-weight measurement became unavailable", result.State)
	}
}

// TestReputationRedisPreviousRotationTimeoutCannotPermit requires both independent key slots even when the active override trusts.
func TestReputationRedisPreviousRotationTimeoutCannotPermit(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, true), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	subject := subjectInput{kind: kindIP, value: "192.0.2.11"}
	_, err = owner.putOverride(t.Context(), subject, overrideInput{Band: bandTrusted, Reason: "operator.trust", Creator: "operator", AuditID: "timeout-test", Origin: "operator"})
	requireNoError(t, err)

	owner.redis = interruptRedis(facade, scriptAssessment, false, 2)

	result := owner.assess(t.Context(), subject, profileOperational)
	if result.State != assessmentUnavailable || result.Override != overrideNone {
		t.Fatal("active trust masked unavailable previous slot")
	}
}

// TestReputationRedisOverrideReadbackAndConditionalRemoval preserves audit identity across model-independent management.
func TestReputationRedisOverrideReadbackAndConditionalRemoval(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	subject := subjectInput{kind: kindIP, value: "192.0.2.15"}
	input := overrideInput{Band: bandBlocked, Reason: "operator.block", Creator: "operator", AuditID: "audit-readback", Origin: "operator"}
	written, err := owner.putOverride(t.Context(), subject, input)
	requireNoError(t, err)
	read, err := owner.getOverride(t.Context(), subject)
	requireNoError(t, err)

	if read == nil || *read != written {
		t.Fatal("primary readback lost override audit metadata")
	}

	requireError(t, owner.deleteOverride(t.Context(), subject, "wrong-audit"))
	requireNoError(t, owner.deleteOverride(t.Context(), subject, written.AuditID))
	absent, err := owner.getOverride(t.Context(), subject)
	requireNoError(t, err)

	if absent != nil {
		t.Fatal("removed override still visible")
	}
}

// TestReputationRedisMalformedOverrideAuditMakesAssessmentUnavailable rejects corrupted audit metadata before using its band.
func TestReputationRedisMalformedOverrideAuditMakesAssessmentUnavailable(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	subject := subjectInput{kind: kindIP, value: "192.0.2.16"}
	record, err := owner.putOverride(t.Context(), subject, overrideInput{Band: bandTrusted, Reason: "operator.trust", Creator: "operator", AuditID: "audit-corrupt", Origin: "operator"})
	requireNoError(t, err)

	key := owner.keys.subject(record.Tag, cfg.raw.ModelID).Override
	requireNoError(t, client.HSet(t.Context(), key, "creator", "operator\nforged").Err())

	result := owner.assess(t.Context(), subject, profileOperational)
	if result.State != assessmentUnavailable {
		t.Fatal("malformed operator audit metadata retained trust")
	}
}

// TestReputationRedisLearnedBandAgesWithoutNewEvents proves that old trust loses its promotion through read-time decay alone.
func TestReputationRedisLearnedBandAgesWithoutNewEvents(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := shortRetentionConfig(t)
	cfg.raw.Bands.Positive = evidenceThreshold{Score: 0.0008, Confidence: 0.001, Samples: 0.1}
	cfg.raw.Bands.MinimumConfidence, cfg.raw.Bands.MinimumSamples = 0.001, 0.1
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "aging-band")
	_, err = owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	initial := owner.assess(t.Context(), admitted.subjects[0].subjectInput, profileOperational)
	if initial.Band != bandPositive {
		t.Fatal("calibrated initial trust not positive", initial.Band)
	}

	time.Sleep(1100 * time.Millisecond)

	later := owner.assess(t.Context(), admitted.subjects[0].subjectInput, profileOperational)
	if later.State != assessmentFresh || later.Band == bandPositive || later.Band == bandTrusted {
		t.Fatal("old evidence retained a promotion without enough current mass", later.Band)
	}
}

// TestReputationRedisModelChangePreservesOperatorOverride keeps model-independent authority readable after a clean model switch.
func TestReputationRedisModelChangePreservesOperatorOverride(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	subject := subjectInput{kind: kindIP, value: "192.0.2.17"}
	_, err = owner.putOverride(t.Context(), subject, overrideInput{Band: bandBlocked, Reason: "operator.block", Creator: "operator", AuditID: "model-independent", Origin: "operator"})
	requireNoError(t, err)
	nextCfg := testConfig(t)
	nextCfg.raw.ModelID = "other-model"
	next, err := newStateOwner(nextCfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, next.start(t.Context()))

	result := next.assess(t.Context(), subject, profileOperational)
	if result.State != assessmentMissing || result.Band != bandBlocked {
		t.Fatal("model switch dropped operator block")
	}
}
