// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mfastate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/redis/go-redis/v9"
)

type aggregateClock struct{ now time.Time }

func (c aggregateClock) Now() time.Time { return c.now }

func TestAggregateOwnsIndexedEnrollmentStepUpAndTOTPRecords(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, time.August, 17, 17, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)
	stores, session := seedAggregateAnchor(t, mini.Addr(), now)
	aggregate := NewAggregate(stores, session, 5*time.Minute)

	enrollment := &sessionstate.EnrollmentRecord{
		Record:  sessionstate.Record{Handle: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"},
		Session: session, Flow: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		IdentityReference: "identity-42", CurrentStep: "select",
	}
	if err := aggregate.SaveEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("save enrollment: %v", err)
	}

	stepUp := &sessionstate.StepUpRecord{
		Record:  sessionstate.Record{Handle: "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"},
		Session: session, Flow: enrollment.Flow, RequestedLevel: 2,
	}
	if err := aggregate.SaveStepUp(ctx, stepUp); err != nil {
		t.Fatalf("save step-up: %v", err)
	}

	operation := &sessionstate.TOTPRecoveryRecord{
		Record:  sessionstate.Record{Handle: "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"},
		Session: session, Flow: enrollment.Flow, IdentityReference: "identity-42", Kind: "totp",
	}
	if err := aggregate.SaveTOTPRecovery(ctx, operation); err != nil {
		t.Fatalf("save TOTP operation: %v", err)
	}

	assertAggregateIndexes(t, stores, session, enrollment.Handle, stepUp.Handle, operation.Handle)
	assertAggregateLoads(t, aggregate, enrollment, stepUp, operation)
	deleteAggregateRecords(t, aggregate, enrollment.Handle, stepUp.Handle, operation.Handle)
	assertAggregateIndexes(t, stores, session, "", "", "")
}

func TestAggregateAdvancesEnrollmentInOrderAndRejectsReplacementOrReplay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 17, 0, 0, 0, time.UTC)
	stores, session := seedAggregateAnchor(t, miniredis.RunT(t).Addr(), now)
	aggregate := NewAggregate(stores, session, 5*time.Minute)
	enrollment := &sessionstate.EnrollmentRecord{
		Record:            sessionstate.Record{Handle: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"},
		Session:           session,
		Flow:              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		AccountReference:  "alice",
		IdentityReference: "identity-42",
		RequiredMethods:   []string{"totp", "webauthn"},
		CurrentStep:       "totp",
		Continuation:      "/oidc/authorize",
	}

	if err := aggregate.BeginEnrollment(context.Background(), enrollment); err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}

	replacement := *enrollment

	replacement.Revision = 0
	if err := aggregate.BeginEnrollment(context.Background(), &replacement); !errors.Is(err, sessionstate.ErrRevisionConflict) {
		t.Fatalf("replacement error = %v, want %v", err, sessionstate.ErrRevisionConflict)
	}

	if _, err := aggregate.CompleteEnrollmentMethod(context.Background(), enrollment.Handle, "webauthn"); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("out-of-order completion error = %v, want %v", err, sessionstate.ErrBindingMismatch)
	}

	advanced, err := aggregate.CompleteEnrollmentMethod(context.Background(), enrollment.Handle, "totp")
	if err != nil || advanced.Value.CurrentStep != "webauthn" || advanced.Value.Completed {
		t.Fatalf("advanced enrollment = %#v, err = %v", advanced, err)
	}

	if _, err = aggregate.CompleteEnrollmentMethod(context.Background(), enrollment.Handle, "totp"); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("replay completion error = %v, want %v", err, sessionstate.ErrBindingMismatch)
	}

	completed, err := aggregate.CompleteEnrollmentMethod(context.Background(), enrollment.Handle, "webauthn")
	if err != nil || !completed.Value.Completed || completed.Value.CurrentStep != "complete" {
		t.Fatalf("completed enrollment = %#v, err = %v", completed, err)
	}
}

func TestAggregateBoundsEnrollmentContinuationAtValidRequestURISize(t *testing.T) {
	t.Parallel()

	base := sessionstate.EnrollmentRecord{
		Record:            sessionstate.Record{Handle: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"},
		Session:           "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
		Flow:              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		AccountReference:  "alice",
		IdentityReference: "identity-42",
		RequiredMethods:   []string{"totp"},
		CurrentStep:       "totp",
		Continuation:      "/" + strings.Repeat("a", maxEnrollmentContinuationBytes-1),
	}

	if err := validateNewEnrollment(&base); err != nil {
		t.Fatalf("maximum bounded continuation rejected: %v", err)
	}

	base.Continuation += "a"
	if err := validateNewEnrollment(&base); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("oversized continuation error = %v, want %v", err, sessionstate.ErrBindingMismatch)
	}
}

func TestAggregateBeginsBoundStepUpAndRejectsReplacement(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 17, 0, 0, 0, time.UTC)
	stores, session := seedAggregateAnchor(t, miniredis.RunT(t).Addr(), now)
	aggregate := NewAggregate(stores, session, 5*time.Minute)
	record := &sessionstate.StepUpRecord{
		Record: sessionstate.Record{Handle: "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"}, Session: session,
		Flow: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", RequestedLevel: 2,
		SupportedMethods: []string{"totp", "webauthn"}, Scope: "oidc:client-a",
	}

	if err := aggregate.BeginStepUp(context.Background(), record); err != nil {
		t.Fatalf("begin step-up: %v", err)
	}

	replacement := *record

	replacement.Revision = 0
	if err := aggregate.BeginStepUp(context.Background(), &replacement); !errors.Is(err, sessionstate.ErrRevisionConflict) {
		t.Fatalf("step-up replacement error = %v, want %v", err, sessionstate.ErrRevisionConflict)
	}

	invalid := *record
	invalid.Handle = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV"
	invalid.Revision = 0

	invalid.Flow = ""
	if err := aggregate.BeginStepUp(context.Background(), &invalid); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("unbound step-up error = %v, want %v", err, sessionstate.ErrBindingMismatch)
	}
}

func TestAggregatePersistsBoundedFailLatchedPendingIdentityWithoutAuthenticatingAnchor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 17, 0, 0, 0, time.UTC)
	stores, session := seedAggregateAnchor(t, miniredis.RunT(t).Addr(), now)
	aggregate := NewAggregate(stores, session, 5*time.Minute)
	record := &sessionstate.StepUpRecord{
		Record: sessionstate.Record{Handle: "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL"}, Session: session,
		Flow: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", RequestedLevel: 1,
		SupportedMethods: []string{"totp"}, Scope: "oidc:client-a", AuthOutcome: "fail_latched",
		PendingIdentityReference: "identity-42",
		PendingIdentity: sessionstate.IdentitySummary{
			Account: "alice", Subject: "identity-42", DisplayName: "Alice", Protocol: "oidc",
		},
		PendingBackendAffinity: sessionstate.BackendAffinitySummary{
			Type: "remote", Name: "authority-a", Protocol: "oidc",
			Authority: "authority-a", OpaqueToken: "opaque-capability",
		},
	}

	if err := aggregate.BeginStepUp(context.Background(), record); err != nil {
		t.Fatalf("begin fail-latched step-up: %v", err)
	}

	loaded, err := aggregate.LoadStepUp(context.Background(), record.Handle)
	if err != nil || loaded.Value.PendingIdentityReference != "identity-42" ||
		loaded.Value.PendingIdentity.Account != "alice" ||
		loaded.Value.PendingBackendAffinity.OpaqueToken != "opaque-capability" ||
		loaded.Value.AuthOutcome != "fail_latched" {
		t.Fatalf("loaded fail-latched step-up = %#v, err = %v", loaded, err)
	}

	anchor, err := stores.Session.Load(context.Background(), sessionstate.Reference{Session: session, Record: session})
	if err != nil || anchor.Value.Authenticated || anchor.Value.IdentityReference != "" ||
		anchor.Value.Assurance.Level != 0 {
		t.Fatalf("fail-latched anchor = %#v, err = %v", anchor, err)
	}
}

func TestAggregateRejectsPartialOrUnboundedPendingStepUpIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 17, 0, 0, 0, time.UTC)
	stores, session := seedAggregateAnchor(t, miniredis.RunT(t).Addr(), now)
	aggregate := NewAggregate(stores, session, 5*time.Minute)
	base := sessionstate.StepUpRecord{
		Record: sessionstate.Record{Handle: "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL"}, Session: session,
		Flow: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", RequestedLevel: 1,
		SupportedMethods: []string{"totp"}, Scope: "oidc:client-a", AuthOutcome: "fail_latched",
		PendingIdentityReference: "identity-42",
		PendingIdentity:          sessionstate.IdentitySummary{Account: "alice", Subject: "identity-42", Protocol: "oidc"},
	}

	testCases := []struct {
		name   string
		mutate func(*sessionstate.StepUpRecord)
	}{
		{name: "missing reference", mutate: func(record *sessionstate.StepUpRecord) { record.PendingIdentityReference = "" }},
		{name: "missing account", mutate: func(record *sessionstate.StepUpRecord) { record.PendingIdentity.Account = "" }},
		{name: "oversized account", mutate: func(record *sessionstate.StepUpRecord) { record.PendingIdentity.Account = string(make([]byte, 513)) }},
		{name: "partial affinity", mutate: func(record *sessionstate.StepUpRecord) {
			record.PendingBackendAffinity = sessionstate.BackendAffinitySummary{Type: "remote"}
		}},
		{name: "success cannot carry pending identity", mutate: func(record *sessionstate.StepUpRecord) { record.AuthOutcome = "ok" }},
	}

	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			record := base
			record.Handle = sessionstate.Handle(string(rune('M'+index)) + string(base.Handle[1:]))
			testCase.mutate(&record)

			if err := aggregate.BeginStepUp(context.Background(), &record); !errors.Is(err, sessionstate.ErrBindingMismatch) {
				t.Fatalf("invalid pending step-up error = %v, want %v", err, sessionstate.ErrBindingMismatch)
			}
		})
	}
}

func assertAggregateLoads(
	t *testing.T,
	aggregate *Aggregate,
	enrollment *sessionstate.EnrollmentRecord,
	stepUp *sessionstate.StepUpRecord,
	operation *sessionstate.TOTPRecoveryRecord,
) {
	t.Helper()

	loaded, err := aggregate.LoadEnrollment(context.Background(), enrollment.Handle)
	if err != nil || loaded.Value.IdentityReference != "identity-42" {
		t.Fatalf("load enrollment = %#v, err = %v", loaded, err)
	}

	loadedStepUp, err := aggregate.LoadStepUp(context.Background(), stepUp.Handle)
	if err != nil || loadedStepUp.Value.RequestedLevel != 2 {
		t.Fatalf("load step-up = %#v, err = %v", loadedStepUp, err)
	}

	loadedOperation, err := aggregate.LoadTOTPRecovery(context.Background(), operation.Handle)
	if err != nil || loadedOperation.Value.Kind != "totp" {
		t.Fatalf("load TOTP operation = %#v, err = %v", loadedOperation, err)
	}
}

func deleteAggregateRecords(
	t *testing.T,
	aggregate *Aggregate,
	enrollment sessionstate.Handle,
	stepUp sessionstate.Handle,
	operation sessionstate.Handle,
) {
	t.Helper()

	if err := aggregate.DeleteEnrollment(context.Background(), enrollment); err != nil {
		t.Fatalf("delete enrollment: %v", err)
	}

	if err := aggregate.DeleteStepUp(context.Background(), stepUp); err != nil {
		t.Fatalf("delete step-up: %v", err)
	}

	if err := aggregate.DeleteTOTPRecovery(context.Background(), operation); err != nil {
		t.Fatalf("delete TOTP operation: %v", err)
	}
}

func seedAggregateAnchor(t *testing.T, address string, now time.Time) (*sessionstate.RedisStores, sessionstate.Handle) {
	t.Helper()

	stores, err := sessionstate.NewRedisStores(
		redis.NewClient(&redis.Options{Addr: address}), []byte("mfa-aggregate-test-key-32-bytes-long"),
		aggregateClock{now: now}, sessionstate.RedisStoreConfig{Prefix: "mfa-aggregate"},
	)
	if err != nil {
		t.Fatalf("create stores: %v", err)
	}

	session := sessionstate.Handle("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS")
	if _, err = stores.Session.Commit(context.Background(), sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference: sessionstate.Reference{Session: session, Record: session},
		Value: sessionstate.SessionAnchor{
			Record: sessionstate.Record{Handle: session}, SchemaVersion: 1, CreatedAt: now,
			IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
		},
		TTL: time.Hour,
	}); err != nil {
		t.Fatalf("commit anchor: %v", err)
	}

	return stores, session
}

func assertAggregateIndexes(
	t *testing.T,
	stores *sessionstate.RedisStores,
	session sessionstate.Handle,
	enrollment sessionstate.Handle,
	stepUp sessionstate.Handle,
	operation sessionstate.Handle,
) {
	t.Helper()

	anchor, err := stores.Session.Load(context.Background(), sessionstate.Reference{Session: session, Record: session})
	if err != nil {
		t.Fatalf("load anchor: %v", err)
	}

	wantEnrollments := []sessionstate.Handle(nil)
	if enrollment != "" {
		wantEnrollments = []sessionstate.Handle{enrollment}
	}

	wantStepUps := optionalIndex(stepUp)
	wantOperations := optionalIndex(operation)

	if len(anchor.Value.Enrollments) != len(wantEnrollments) || len(anchor.Value.StepUps) != len(wantStepUps) ||
		len(anchor.Value.TOTPRecovery) != len(wantOperations) ||
		len(wantStepUps) == 1 && anchor.Value.StepUps[0] != stepUp ||
		len(wantOperations) == 1 && anchor.Value.TOTPRecovery[0] != operation {
		t.Fatalf("anchor indexes = enrollment %v step-up %v operation %v",
			anchor.Value.Enrollments, anchor.Value.StepUps, anchor.Value.TOTPRecovery)
	}
}

func optionalIndex(handle sessionstate.Handle) []sessionstate.Handle {
	if handle == "" {
		return nil
	}

	return []sessionstate.Handle{handle}
}
