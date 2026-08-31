// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package flow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/redis/go-redis/v9"
)

func TestProtocolAggregateResolvesExactlyOneTypedFlow(t *testing.T) {
	t.Parallel()

	aggregate, stores, session := newProtocolAggregateFixture(t)
	oidcID := "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"

	saveAggregateFlow(t, stores, session, FlowProtocolOIDC, &State{
		FlowID: oidcID, Type: FlowTypeOIDCAuthorization, Protocol: FlowProtocolOIDC,
		CurrentStep: FlowStepLogin, AuthOutcome: AuthOutcomeUnknown,
		Metadata: map[string]string{FlowMetadataClientID: "client-a"},
	})

	state, err := aggregate.Load(context.Background(), oidcID)
	if err != nil {
		t.Fatalf("load OIDC flow: %v", err)
	}

	if state.Protocol != FlowProtocolOIDC || state.Metadata[FlowMetadataClientID] != "client-a" {
		t.Fatalf("resolved state = %#v", state)
	}

	saveAggregateFlow(t, stores, session, FlowProtocolSAML, &State{
		FlowID: oidcID, Type: FlowTypeSAML, Protocol: FlowProtocolSAML,
		CurrentStep: FlowStepLogin, AuthOutcome: AuthOutcomeUnknown,
		Metadata: map[string]string{FlowMetadataSAMLEntityID: "sp-a"},
	})

	if _, err = aggregate.Load(context.Background(), oidcID); !errors.Is(err, ErrAmbiguousProtocolFlow) {
		t.Fatalf("ambiguous load error = %v, want %v", err, ErrAmbiguousProtocolFlow)
	}

	if _, err = aggregate.Load(context.Background(), "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"); !errors.Is(err, ErrFlowNotFound) {
		t.Fatalf("missing load error = %v, want %v", err, ErrFlowNotFound)
	}
}

func TestProtocolAggregateResumesSelectedTypedFlow(t *testing.T) {
	t.Parallel()

	aggregate, stores, session := newProtocolAggregateFixture(t)
	flowID := "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
	saveAggregateFlow(t, stores, session, FlowProtocolOIDC, &State{
		FlowID: flowID, Type: FlowTypeOIDCAuthorization, Protocol: FlowProtocolOIDC,
		CurrentStep: FlowStepLogin, AuthOutcome: AuthOutcomeOK,
		ReturnTarget: "/oidc/authorize?client_id=client-a",
		Metadata:     map[string]string{FlowMetadataClientID: "client-a"},
	})

	decision, err := aggregate.Resume(context.Background(), flowID)
	if err != nil {
		t.Fatalf("resume typed OIDC flow: %v", err)
	}

	want := "/oidc/authorize?client_id=client-a&flow=" + flowID
	if decision.Type != DecisionTypeRedirect || decision.RedirectURI != want {
		t.Fatalf("resume decision = %#v, want redirect %q", decision, want)
	}
}

func newProtocolAggregateFixture(t *testing.T) (*ProtocolAggregate, *sessionstate.RedisStores, sessionstate.Handle) {
	t.Helper()

	now := time.Date(2026, time.August, 17, 15, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)

	stores, err := sessionstate.NewRedisStores(
		redis.NewClient(&redis.Options{Addr: mini.Addr()}),
		[]byte("protocol-aggregate-test-key-32bytes"),
		typedStoreClock{now: now},
		sessionstate.RedisStoreConfig{Prefix: "protocol-aggregate"},
	)
	if err != nil {
		t.Fatalf("create stores: %v", err)
	}

	session := sessionstate.Handle("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS")
	if _, err = stores.Session.Commit(context.Background(), sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference: sessionstate.Reference{Session: session, Record: session},
		Value: sessionstate.SessionAnchor{
			Record: sessionstate.Record{Handle: session}, SchemaVersion: 1,
			CreatedAt: now, IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
		},
		TTL: time.Hour,
	}); err != nil {
		t.Fatalf("commit session anchor: %v", err)
	}

	aggregate := NewProtocolAggregate(stores, session, 10*time.Minute)

	return aggregate, stores, session
}

func saveAggregateFlow(
	t *testing.T,
	stores *sessionstate.RedisStores,
	session sessionstate.Handle,
	protocol Protocol,
	state *State,
) {
	t.Helper()

	if err := NewTypedStore(stores, session, protocol, 10*time.Minute).Save(context.Background(), state); err != nil {
		t.Fatalf("save %s flow: %v", protocol, err)
	}
}
