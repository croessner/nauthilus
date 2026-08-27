// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

type canonicalCeremonyClock struct {
	now time.Time
}

func (c canonicalCeremonyClock) Now() time.Time { return c.now }

func TestCanonicalWebAuthnCeremonyIsBoundAndSingleUse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)

	stores, err := sessionstate.NewRedisStores(
		redis.NewClient(&redis.Options{Addr: mini.Addr()}),
		[]byte("canonical-ceremony-test-secret-32bytes"),
		canonicalCeremonyClock{now: now},
		sessionstate.RedisStoreConfig{Prefix: "canonical-ceremony"},
	)
	if err != nil {
		t.Fatalf("create typed repositories: %v", err)
	}

	session := sessionstate.Handle("IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII")

	anchor := sessionstate.SessionAnchor{
		Record: sessionstate.Record{Handle: session}, CreatedAt: now,
		IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if _, err = stores.Session.Commit(ctx, sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference: sessionstate.Reference{Session: session, Record: session}, Value: anchor, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("commit session anchor: %v", err)
	}

	ceremonies := newCanonicalWebAuthnCeremonyStore(
		stores, sessionstate.NewRandomHandleGenerator(nil), session,
	)
	flow := sessionstate.Handle("JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ")
	data := &webauthn.SessionData{Challenge: "opaque-challenge", UserID: []byte("stable-user-reference")}

	reference, err := ceremonies.Store(ctx, flow, "identity-reference", "oidc", webAuthnCeremonyLogin, data)
	if err != nil {
		t.Fatalf("store ceremony: %v", err)
	}

	indexed, err := stores.Session.Load(ctx, sessionstate.Reference{Session: session, Record: session})
	if err != nil || len(indexed.Value.Ceremonies) != 1 || indexed.Value.Ceremonies[0] != reference {
		t.Fatalf("ceremony anchor index after store = %#v err=%v", indexed.Value.Ceremonies, err)
	}

	consumed, err := ceremonies.Take(ctx, reference, flow, "identity-reference", "oidc", webAuthnCeremonyLogin)
	if err != nil || consumed.Challenge != data.Challenge {
		t.Fatalf("take ceremony: value=%#v err=%v", consumed, err)
	}

	if _, err = ceremonies.Take(ctx, reference, flow, "identity-reference", "oidc", webAuthnCeremonyLogin); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("replay error = %v, want not found", err)
	}

	indexed, err = stores.Session.Load(ctx, sessionstate.Reference{Session: session, Record: session})
	if err != nil || len(indexed.Value.Ceremonies) != 0 {
		t.Fatalf("ceremony anchor index after consume = %#v err=%v", indexed.Value.Ceremonies, err)
	}
}

func TestWebAuthnSessionRoundTripPreservesTypedExtensions(t *testing.T) {
	data := webauthn.SessionData{
		Challenge: "opaque-challenge",
		Extensions: protocol.SessionExtensions{
			Requested: []string{protocol.ExtensionCredProps, protocol.ExtensionPRF},
		},
	}

	payload, err := jsonIter.Marshal(&data)
	if err != nil {
		t.Fatalf("marshal WebAuthn session: %v", err)
	}

	var decoded webauthn.SessionData
	if err = jsonIter.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal WebAuthn session: %v", err)
	}

	if !slices.Equal(decoded.Extensions.Requested, data.Extensions.Requested) {
		t.Fatalf("requested extensions = %#v, want %#v", decoded.Extensions.Requested, data.Extensions.Requested)
	}
}

func TestCanonicalWebAuthnCeremonyConsumesBindingMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)

	stores, err := sessionstate.NewRedisStores(
		redis.NewClient(&redis.Options{Addr: mini.Addr()}),
		[]byte("canonical-ceremony-negative-secret-32"),
		canonicalCeremonyClock{now: now},
		sessionstate.RedisStoreConfig{Prefix: "canonical-ceremony-negative"},
	)
	if err != nil {
		t.Fatalf("create typed repositories: %v", err)
	}

	session := sessionstate.Handle("KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK")

	anchor := sessionstate.SessionAnchor{
		Record: sessionstate.Record{Handle: session}, CreatedAt: now,
		IdleExpiresAt: now.Add(30 * time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if _, err = stores.Session.Commit(ctx, sessionstate.CommitRequest[sessionstate.SessionAnchor]{
		Reference: sessionstate.Reference{Session: session, Record: session}, Value: anchor, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("commit session anchor: %v", err)
	}

	ceremonies := newCanonicalWebAuthnCeremonyStore(
		stores, sessionstate.NewRandomHandleGenerator(nil), session,
	)
	flow := sessionstate.Handle("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL")

	reference, err := ceremonies.Store(
		ctx, flow, "identity-reference", "saml", webAuthnCeremonyRegister, &webauthn.SessionData{Challenge: "opaque"},
	)
	if err != nil {
		t.Fatalf("store ceremony: %v", err)
	}

	if _, err = ceremonies.Take(ctx, reference, flow, "other-identity", "saml", webAuthnCeremonyRegister); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("binding mismatch error = %v, want binding mismatch", err)
	}

	if _, err = ceremonies.Take(ctx, reference, flow, "identity-reference", "saml", webAuthnCeremonyRegister); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("mismatched ceremony was not consumed: %v", err)
	}
}
