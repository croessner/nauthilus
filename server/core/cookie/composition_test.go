// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo,funlen // Canonical session tests keep each atomic lifecycle in one security contract.
package cookie

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
)

func TestCanonicalSessionExposesBoundedIdentityAndAssuranceAggregates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 16, 0, 0, 0, time.UTC)
	session := &CanonicalSession{Anchor: sessionstate.Versioned[sessionstate.SessionAnchor]{Value: sessionstate.SessionAnchor{
		Authenticated: true, IdentityReference: "identity-42",
		Identity: sessionstate.IdentitySummary{
			Account: "alice", Subject: "identity-42", DisplayName: "Alice Example", Protocol: "oidc",
		},
		BackendAffinity: sessionstate.BackendAffinitySummary{
			Type: "remote", Name: "authority", Protocol: "grpc", Authority: "edge-a", OpaqueToken: "opaque-capability",
		},
		Assurance: sessionstate.AssuranceSummary{
			Level: 3, Method: "webauthn", Scope: "oidc:client-a",
			ProvenAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		},
	}}}
	assertSessionIdentity(t, session)
	assertSessionBackendAffinity(t, session)
	assertSessionAssurance(t, session, now)

	session.Anchor.Value.IdentityReference = ""
	if _, ok := session.Identity(); ok {
		t.Fatal("authenticated anchor without identity reference was accepted")
	}

	session.Anchor.Value.Assurance.ExpiresAt = now
	if _, ok := session.Assurance(now); ok {
		t.Fatal("expired assurance was accepted")
	}
}

func TestCanonicalSessionCommitsAssuranceByAnchorCAS(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	runtime := newCanonicalMiddlewareRuntime(t, miniredis.RunT(t), "canonical-assurance")

	session, err := runtime.Create(context.Background(), httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create canonical session: %v", err)
	}

	if err = session.CommitIdentity(context.Background(), IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", Protocol: "oidc",
	}); err != nil {
		t.Fatalf("commit identity: %v", err)
	}

	stale := *session

	proof := SessionAssurance{
		Level: 3, Method: "webauthn", Scope: "oidc:client-a",
		ProvenAt: now.Add(-time.Minute), ExpiresAt: now.Add(9 * time.Minute),
	}
	if err = session.CommitAssurance(context.Background(), proof); err != nil {
		t.Fatalf("commit assurance: %v", err)
	}

	committed, ok := session.Assurance(now)
	if !ok || committed != proof {
		t.Fatalf("committed assurance = %#v, ok = %v", committed, ok)
	}

	if err = stale.CommitAssurance(context.Background(), proof); !errors.Is(err, sessionstate.ErrRevisionConflict) {
		t.Fatalf("stale assurance error = %v, want %v", err, sessionstate.ErrRevisionConflict)
	}
}

func TestCanonicalSessionCompletesStepUpAndAssuranceAtomicallyOnce(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	runtime := newCanonicalMiddlewareRuntime(t, miniredis.RunT(t), "canonical-step-up-complete")

	session, err := runtime.Create(context.Background(), httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create canonical session: %v", err)
	}

	if err = session.CommitIdentity(context.Background(), IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", Protocol: "oidc",
	}); err != nil {
		t.Fatalf("commit identity: %v", err)
	}

	handle := sessionstate.Handle("TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT")

	flowHandle := sessionstate.Handle("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	if err = mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).BeginStepUp(
		context.Background(),
		&sessionstate.StepUpRecord{
			Record: sessionstate.Record{Handle: handle}, Session: session.Handle, Flow: flowHandle,
			RequestedLevel: 2, SupportedMethods: []string{definitions.MFAMethodTOTP}, Scope: "oidc:client-a",
		},
	); err != nil {
		t.Fatalf("begin step-up: %v", err)
	}

	session.Anchor, err = session.Stores.Session.Load(
		context.Background(), sessionstate.Reference{Session: session.Handle, Record: session.Handle},
	)
	if err != nil {
		t.Fatalf("reload session after beginning step-up: %v", err)
	}

	completion, err := session.CompleteStepUp(
		context.Background(), handle, definitions.MFAMethodTOTP, 10*time.Minute,
	)
	if err != nil || completion.Flow != flowHandle {
		t.Fatalf("complete step-up = %#v, err = %v", completion, err)
	}

	assurance, ok := session.Assurance(now)
	if !ok || assurance.Level != 2 || assurance.Method != definitions.MFAMethodTOTP || assurance.Scope != "oidc:client-a" {
		t.Fatalf("completed assurance = %#v, ok = %t", assurance, ok)
	}

	loaded, err := session.Stores.StepUp.Load(context.Background(), sessionstate.Reference{Session: session.Handle, Record: handle})
	if err != nil || !loaded.Value.Completed || loaded.Value.ProofMethod != definitions.MFAMethodTOTP {
		t.Fatalf("completed step-up record = %#v, err = %v", loaded, err)
	}

	if _, err = session.CompleteStepUp(
		context.Background(), handle, definitions.MFAMethodTOTP, 10*time.Minute,
	); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("replayed step-up error = %v, want %v", err, sessionstate.ErrBindingMismatch)
	}
}

func TestCanonicalSessionCompletesSelfServiceStepUpAndAssuranceAtomicallyOnce(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	runtime := newCanonicalMiddlewareRuntime(t, miniredis.RunT(t), "canonical-self-service-step-up")

	session, err := runtime.Create(context.Background(), httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create canonical session: %v", err)
	}

	if err = session.CommitIdentity(context.Background(), IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", Protocol: "oidc",
	}); err != nil {
		t.Fatalf("commit identity: %v", err)
	}

	handle := sessionstate.Handle("UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU")

	const operation = "webauthn_device_name"

	if err = mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).BeginStepUp(
		context.Background(),
		&sessionstate.StepUpRecord{
			Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
			SelfServiceOperation: operation, RequestedLevel: 2,
			SupportedMethods: []string{definitions.MFAMethodTOTP}, Scope: "self-service",
		},
	); err != nil {
		t.Fatalf("begin self-service step-up: %v", err)
	}

	session.Anchor, err = session.Stores.Session.Load(
		context.Background(), sessionstate.Reference{Session: session.Handle, Record: session.Handle},
	)
	if err != nil {
		t.Fatalf("reload session after beginning self-service step-up: %v", err)
	}

	completion, err := session.CompleteStepUp(
		context.Background(), handle, definitions.MFAMethodTOTP, 10*time.Minute,
	)
	if err != nil || completion.Flow != "" || completion.SelfServiceOperation != operation {
		t.Fatalf("complete self-service step-up = %#v, err = %v", completion, err)
	}

	assurance, ok := session.Assurance(now)
	if !ok || assurance.Level != 2 || assurance.Method != definitions.MFAMethodTOTP || assurance.Scope != "self-service" {
		t.Fatalf("self-service assurance = %#v, ok = %t", assurance, ok)
	}

	if _, err = session.CompleteStepUp(
		context.Background(), handle, definitions.MFAMethodTOTP, 10*time.Minute,
	); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("replayed self-service step-up error = %v, want %v", err, sessionstate.ErrBindingMismatch)
	}
}

func TestCanonicalSessionRecordsBoundedTypedOIDCLogoutContext(t *testing.T) {
	t.Parallel()

	runtime := newCanonicalMiddlewareRuntime(t, miniredis.RunT(t), "canonical-oidc-logout")

	session, err := runtime.Create(context.Background(), httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create canonical OIDC logout session: %v", err)
	}

	if err = session.CommitIdentity(context.Background(), IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", Protocol: "oidc",
	}); err != nil {
		t.Fatalf("commit canonical OIDC logout identity: %v", err)
	}

	identity, ok := session.Identity()
	if !ok {
		t.Fatal("canonical OIDC logout identity unavailable")
	}

	for _, clientID := range []string{"client-b", "client-a", "client-b"} {
		if err = session.RecordOIDCClient(context.Background(), identity, clientID); err != nil {
			t.Fatalf("record canonical OIDC logout client %q: %v", clientID, err)
		}
	}

	logout, err := session.OIDCLogoutContext(context.Background())
	if err != nil || logout.Identity != identity || len(logout.ClientIDs) != 2 ||
		logout.ClientIDs[0] != "client-a" || logout.ClientIDs[1] != "client-b" {
		t.Fatalf("canonical OIDC logout context = %#v, err = %v", logout, err)
	}

	if len(session.Anchor.Value.LogoutIndexes) != 1 {
		t.Fatalf("canonical OIDC logout anchor indexes = %v", session.Anchor.Value.LogoutIndexes)
	}

	staleIdentity := identity

	staleIdentity.Reference = "identity-99"
	if err = session.RecordOIDCClient(context.Background(), staleIdentity, "client-c"); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("mismatched OIDC logout identity error = %v, want binding mismatch", err)
	}

	for index := 2; index < 16; index++ {
		clientID := fmt.Sprintf("client-%02d", index)
		if err = session.RecordOIDCClient(context.Background(), identity, clientID); err != nil {
			t.Fatalf("fill canonical OIDC logout index %q: %v", clientID, err)
		}
	}

	if err = session.RecordOIDCClient(context.Background(), identity, "client-overflow"); !errors.Is(err, sessionstate.ErrActiveFlowLimit) {
		t.Fatalf("oversized canonical OIDC logout index error = %v, want active-flow limit", err)
	}
}

func assertSessionIdentity(t *testing.T, session *CanonicalSession) {
	t.Helper()

	identity, ok := session.Identity()
	if !ok || identity.Reference != "identity-42" || identity.Account != "alice" || identity.Subject != "identity-42" ||
		identity.DisplayName != "Alice Example" || identity.Protocol != "oidc" {
		t.Fatalf("identity = %#v, ok = %v", identity, ok)
	}
}

func assertSessionBackendAffinity(t *testing.T, session *CanonicalSession) {
	t.Helper()

	affinity, ok := session.BackendAffinity()
	if !ok || affinity.OpaqueToken != "opaque-capability" || affinity.Authority != "edge-a" {
		t.Fatalf("backend affinity = %#v, ok = %v", affinity, ok)
	}
}

func assertSessionAssurance(t *testing.T, session *CanonicalSession, now time.Time) {
	t.Helper()

	assurance, ok := session.Assurance(now)
	if !ok || assurance.Level != 3 || assurance.Method != "webauthn" || assurance.Scope != "oidc:client-a" {
		t.Fatalf("assurance = %#v, ok = %v", assurance, ok)
	}
}
