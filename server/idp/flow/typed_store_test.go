// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo // Typed-store tests assert every protocol binding and index mutation together.
package flow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/redis/go-redis/v9"
)

type typedStoreClock struct {
	now time.Time
}

const (
	testSAMLRequestIDMetadata     = "saml_request_id"
	testSAMLRequestDigestMetadata = "saml_request_digest"
	testSAMLRelayStateMetadata    = "saml_relay_state"
	testSAMLDestinationMetadata   = "saml_destination"
)

func (c typedStoreClock) Now() time.Time { return c.now }

func TestTypedStorePartitionsParallelOIDCAndSAMLFlows(t *testing.T) {
	t.Parallel()

	fixture := seedParallelTypedFlows(t)
	assertParallelTypedFlows(t, fixture)
	assertTypedFlowBindingAndDelete(t, fixture)
}

type parallelTypedFlowFixture struct {
	ctx        context.Context
	stores     *sessionstate.RedisStores
	anchorRef  sessionstate.Reference
	oidcStore  *TypedStore
	samlStore  *TypedStore
	oidcID     string
	samlID     string
	otherStore *TypedStore
}

func seedParallelTypedFlows(t *testing.T) parallelTypedFlowFixture {
	t.Helper()

	ctx := context.Background()
	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)

	stores, err := sessionstate.NewRedisStores(
		redis.NewClient(&redis.Options{Addr: mini.Addr()}),
		[]byte("typed-flow-test-digest-secret-32-bytes"),
		typedStoreClock{now: now},
		sessionstate.RedisStoreConfig{Prefix: "typed-flow-test"},
	)
	if err != nil {
		t.Fatalf("create typed repositories: %v", err)
	}

	session := sessionstate.Handle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	anchorRef := sessionstate.Reference{Session: session, Record: session}

	anchor := sessionstate.SessionAnchor{
		Record:            sessionstate.Record{Handle: session},
		SchemaVersion:     1,
		CreatedAt:         now,
		IdleExpiresAt:     now.Add(30 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if _, err = stores.Session.Commit(ctx, sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference: anchorRef,
		Value:     anchor,
		TTL:       time.Hour,
	}); err != nil {
		t.Fatalf("commit session anchor: %v", err)
	}

	oidcStore := NewTypedStore(stores, session, FlowProtocolOIDC, 10*time.Minute)
	samlStore := NewTypedStore(stores, session, FlowProtocolSAML, 10*time.Minute)
	oidcID := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	samlID := "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	oidc, saml := parallelFlowStates(oidcID, samlID)

	if err = oidcStore.Save(ctx, oidc); err != nil {
		t.Fatalf("save OIDC flow: %v", err)
	}

	if err = samlStore.Save(ctx, saml); err != nil {
		t.Fatalf("save SAML flow: %v", err)
	}

	otherSession := sessionstate.Handle("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")

	return parallelTypedFlowFixture{
		ctx: ctx, stores: stores, anchorRef: anchorRef, oidcStore: oidcStore, samlStore: samlStore,
		oidcID: oidcID, samlID: samlID,
		otherStore: NewTypedStore(stores, otherSession, FlowProtocolOIDC, 10*time.Minute),
	}
}

func parallelFlowStates(oidcID string, samlID string) (*State, *State) {
	oidc := &State{
		FlowID:      oidcID,
		Type:        FlowTypeOIDCAuthorization,
		Protocol:    FlowProtocolOIDC,
		CurrentStep: FlowStepLogin,
		AuthOutcome: AuthOutcomeUnknown,
		Metadata: map[string]string{
			FlowMetadataClientID: "client-a",
			FlowMetadataState:    "oidc-state",
		},
	}
	saml := &State{
		FlowID:      samlID,
		Type:        FlowTypeSAML,
		Protocol:    FlowProtocolSAML,
		CurrentStep: FlowStepLogin,
		AuthOutcome: AuthOutcomeUnknown,
		Metadata: map[string]string{
			FlowMetadataSAMLEntityID:      "https://sp.example.test",
			FlowMetadataOriginalURL:       "/saml/sso?request=opaque",
			FlowMetadataResumeTarget:      "/saml/sso?flow=opaque-ticket",
			testSAMLRequestIDMetadata:     "request-id-42",
			testSAMLRequestDigestMetadata: "sha256:opaque-request-digest",
			testSAMLRelayStateMetadata:    "relay-state-42",
			testSAMLDestinationMetadata:   "https://idp.example.test/saml/sso",
		},
	}

	return oidc, saml
}

func assertParallelTypedFlows(t *testing.T, fixture parallelTypedFlowFixture) {
	t.Helper()

	indexedAnchor, err := fixture.stores.Session.Load(fixture.ctx, fixture.anchorRef)
	if err != nil {
		t.Fatalf("load indexed anchor: %v", err)
	}

	if len(indexedAnchor.Value.OIDCFlows) != 1 || indexedAnchor.Value.OIDCFlows[0] != sessionstate.Handle(fixture.oidcID) {
		t.Fatalf("OIDC anchor index = %#v, want isolated flow handle", indexedAnchor.Value.OIDCFlows)
	}

	if len(indexedAnchor.Value.SAMLFlows) != 1 || indexedAnchor.Value.SAMLFlows[0] != sessionstate.Handle(fixture.samlID) {
		t.Fatalf("SAML anchor index = %#v, want isolated flow handle", indexedAnchor.Value.SAMLFlows)
	}

	loadedOIDC, err := fixture.oidcStore.Load(fixture.ctx, fixture.oidcID)
	if err != nil {
		t.Fatalf("load OIDC flow: %v", err)
	}

	loadedSAML, err := fixture.samlStore.Load(fixture.ctx, fixture.samlID)
	if err != nil {
		t.Fatalf("load SAML flow: %v", err)
	}

	if loadedOIDC.Protocol != FlowProtocolOIDC || loadedOIDC.Metadata[FlowMetadataState] != "oidc-state" {
		t.Fatalf("OIDC state crossed repository boundary: %#v", loadedOIDC)
	}

	if loadedSAML.Protocol != FlowProtocolSAML || loadedSAML.Metadata[FlowMetadataOriginalURL] == "" {
		t.Fatalf("SAML state crossed repository boundary: %#v", loadedSAML)
	}

	wantSAMLBinding := map[string]string{
		FlowMetadataOriginalURL:       "/saml/sso?request=opaque",
		FlowMetadataResumeTarget:      "/saml/sso?flow=opaque-ticket",
		testSAMLRequestIDMetadata:     "request-id-42",
		testSAMLRequestDigestMetadata: "sha256:opaque-request-digest",
		testSAMLRelayStateMetadata:    "relay-state-42",
		testSAMLDestinationMetadata:   "https://idp.example.test/saml/sso",
	}
	for key, want := range wantSAMLBinding {
		if got := loadedSAML.Metadata[key]; got != want {
			t.Fatalf("SAML binding metadata %q = %q, want %q", key, got, want)
		}
	}
}

func assertTypedFlowBindingAndDelete(t *testing.T, fixture parallelTypedFlowFixture) {
	t.Helper()

	if _, err := fixture.otherStore.Load(fixture.ctx, fixture.oidcID); !errors.Is(err, sessionstate.ErrParentMissing) {
		t.Fatalf("cross-session load error = %v, want parent missing", err)
	}

	if err := fixture.oidcStore.Delete(fixture.ctx, fixture.oidcID); err != nil {
		t.Fatalf("delete OIDC flow: %v", err)
	}

	loadedSAML, err := fixture.samlStore.Load(fixture.ctx, fixture.samlID)
	if err != nil {
		t.Fatalf("load SAML flow before consume: %v", err)
	}

	consumedSAML, err := fixture.samlStore.ConsumeSAML(
		fixture.ctx,
		fixture.samlID,
		loadedSAML.Revision,
	)
	if err != nil {
		t.Fatalf("consume SAML flow: %v", err)
	}

	if consumedSAML.Metadata[testSAMLRequestIDMetadata] != "request-id-42" {
		t.Fatalf("consumed SAML flow lost request binding: %#v", consumedSAML.Metadata)
	}

	if _, err = fixture.samlStore.ConsumeSAML(
		fixture.ctx,
		fixture.samlID,
		loadedSAML.Revision,
	); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("replayed SAML consume error = %v, want not found", err)
	}

	indexedAnchor, err := fixture.stores.Session.Load(fixture.ctx, fixture.anchorRef)
	if err != nil {
		t.Fatalf("load anchor after flow delete: %v", err)
	}

	if len(indexedAnchor.Value.OIDCFlows) != 0 || len(indexedAnchor.Value.SAMLFlows) != 0 {
		t.Fatalf("indexes after OIDC delete: oidc=%#v saml=%#v", indexedAnchor.Value.OIDCFlows, indexedAnchor.Value.SAMLFlows)
	}
}

func TestTypedStoreRejectsProtocolConfusionAndStaleRevision(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)

	stores, err := sessionstate.NewRedisStores(
		redis.NewClient(&redis.Options{Addr: mini.Addr()}),
		[]byte("typed-flow-negative-secret-32-bytes"),
		typedStoreClock{now: now},
		sessionstate.RedisStoreConfig{Prefix: "typed-flow-negative"},
	)
	if err != nil {
		t.Fatalf("create typed repositories: %v", err)
	}

	session := sessionstate.Handle("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")

	anchor := sessionstate.SessionAnchor{
		Record: sessionstate.Record{Handle: session}, CreatedAt: now,
		IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if _, err = stores.Session.Commit(ctx, sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference: sessionstate.Reference{Session: session, Record: session}, Value: anchor, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("commit session anchor: %v", err)
	}

	oidcStore := NewTypedStore(stores, session, FlowProtocolOIDC, 10*time.Minute)
	flowID := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

	state := newTypedOIDCState(flowID)
	if err = oidcStore.Save(ctx, state); err != nil {
		t.Fatalf("save initial OIDC flow: %v", err)
	}

	stale := *state

	state.CurrentStep = FlowStepLogin
	if err = oidcStore.Save(ctx, state); err != nil {
		t.Fatalf("save current OIDC revision: %v", err)
	}

	stale.CurrentStep = FlowStepMFA
	if err = oidcStore.Save(ctx, &stale); !errors.Is(err, sessionstate.ErrRevisionConflict) {
		t.Fatalf("stale save error = %v, want revision conflict", err)
	}

	confused := *state

	confused.Protocol = FlowProtocolSAML
	if err = oidcStore.Save(ctx, &confused); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("protocol-confused save error = %v, want binding mismatch", err)
	}

	samlStore := NewTypedStore(stores, session, FlowProtocolSAML, 10*time.Minute)
	if _, err = samlStore.Load(ctx, flowID); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("cross-protocol load error = %v, want not found", err)
	}
}

func newTypedOIDCState(flowID string) *State {
	return &State{
		FlowID: flowID, Type: FlowTypeOIDCAuthorization, Protocol: FlowProtocolOIDC,
		CurrentStep: FlowStepStart, AuthOutcome: AuthOutcomeUnknown,
	}
}
