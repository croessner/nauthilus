// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	secrecyTestOpaqueToken  = "backend-ref-opaque-token-secret"
	secrecyTestTOTPSecret   = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	secrecyTestRecoveryCode = "recovery-code-4242-secret"
	secrecyTestChallenge    = "webauthn-challenge-secret"
)

// TestRedisRecordPayloadsDoNotExposeSessionSecrets proves that backend references, pending TOTP material,
// recovery codes, and WebAuthn ceremony data never reach Redis as readable payload text.
func TestRedisRecordPayloadsDoNotExposeSessionSecrets(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	ctx := context.Background()
	session := Handle(strings.Repeat("E", 43))
	anchorReference := Reference{Session: session, Record: session}

	anchor := SessionAnchor{
		Record: Record{Handle: session}, CreatedAt: fixture.clock.Now(),
		IdleExpiresAt: fixture.clock.Now().Add(30 * time.Minute), AbsoluteExpiresAt: fixture.clock.Now().Add(time.Hour),
		Authenticated: true, IdentityReference: "identity-42",
		BackendAffinity: BackendAffinitySummary{Type: "remote", Name: "authority", OpaqueToken: secrecyTestOpaqueToken},
	}
	if _, err := fixture.stores.Session.Commit(ctx, CommitRequest[SessionAnchor]{
		Reference: anchorReference, Value: anchor, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("commit anchor: %v", err)
	}

	totpHandle := Handle(strings.Repeat("T", 43))
	if _, err := fixture.stores.CommitTOTPRecovery(ctx, CommitRequest[TOTPRecoveryRecord]{
		Reference: Reference{Session: session, Record: totpHandle},
		Value: TOTPRecoveryRecord{
			Record: Record{Handle: totpHandle}, Session: session,
			PendingMaterial: []byte(`{"secret":"` + secrecyTestTOTPSecret + `"}`),
			RecoveryCodes:   []string{secrecyTestRecoveryCode},
		},
		TTL: 15 * time.Minute,
	}); err != nil {
		t.Fatalf("commit TOTP operation: %v", err)
	}

	ceremonyHandle := Handle(strings.Repeat("W", 43))
	if _, err := fixture.stores.CommitCeremony(ctx, CommitRequest[CeremonyRecord]{
		Reference: Reference{Session: session, Record: ceremonyHandle},
		Value: CeremonyRecord{
			Record: Record{Handle: ceremonyHandle}, Session: session,
			Payload: json.RawMessage(`{"challenge":"` + secrecyTestChallenge + `"}`),
		},
		TTL: 5 * time.Minute,
	}); err != nil {
		t.Fatalf("commit WebAuthn ceremony: %v", err)
	}

	assertPayloadHidesSecrets(t, fixture, OwnerSessionAnchor, anchorReference, secrecyTestOpaqueToken)
	assertPayloadHidesSecrets(
		t, fixture, OwnerTOTPRecovery, Reference{Session: session, Record: totpHandle},
		secrecyTestTOTPSecret, secrecyTestRecoveryCode,
	)
	assertPayloadHidesSecrets(
		t, fixture, OwnerWebAuthnCeremony, Reference{Session: session, Record: ceremonyHandle}, secrecyTestChallenge,
	)
}

// assertPayloadHidesSecrets fails when the raw Redis payload of one record contains a secret in clear or
// base64 form, the latter covering []byte fields that JSON encodes as base64.
func assertPayloadHidesSecrets(t *testing.T, fixture redisStoresFixture, owner Owner, reference Reference, secrets ...string) {
	t.Helper()

	payload := fixture.redis.HGet(deriveTestKey(t, fixture.stores.keyspace, owner, reference), "payload")
	if payload == "" {
		t.Fatalf("%s payload is missing", owner)
	}

	raw := payload
	if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil {
		raw = string(decoded)
	}

	for _, secretValue := range secrets {
		for _, form := range []string{secretValue, base64.StdEncoding.EncodeToString([]byte(secretValue))} {
			if strings.Contains(payload, form) || strings.Contains(raw, form) {
				t.Errorf("%s payload exposes %q", owner, secretValue)
			}
		}
	}

	// The TOTP material is a []byte field, so JSON stores it base64-encoded as a whole.
	if strings.Contains(payload, `"PendingMaterial":"`) || strings.Contains(raw, `"PendingMaterial":"`) {
		t.Errorf("%s payload exposes pending TOTP material", owner)
	}
}

// TestRedisRepositoryPurgesUnreadablePayloads proves that a plaintext record from before payload sealing, or a
// modified ciphertext, fails closed as a missing record that is purged, so a fresh record can replace it.
func TestRedisRepositoryPurgesUnreadablePayloads(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		mutate func(stored string) string
	}{
		{name: "legacy plaintext", mutate: func(string) string { return `{"Record":{"Handle":"forged"}}` }},
		{name: "modified ciphertext", mutate: func(stored string) string {
			raw, err := base64.StdEncoding.DecodeString(stored)
			if err != nil || len(raw) == 0 {
				return "invalid"
			}

			raw[len(raw)-1] ^= 0xff

			return base64.StdEncoding.EncodeToString(raw)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := newRedisStoresFixture(t)
			ctx := context.Background()

			reference, err := ConsentGrantReference("identity-42", "client-a")
			if err != nil {
				t.Fatalf("consent reference: %v", err)
			}

			grant := ConsentGrant{
				Record: Record{Handle: reference.Record}, IdentityReference: "identity-42", ClientID: "client-a",
				Scopes: []string{"openid"}, GrantedAt: fixture.clock.Now(), GrantExpiresAt: fixture.clock.Now().Add(time.Hour),
			}
			commit := CommitRequest[ConsentGrant]{Reference: reference, Value: grant, TTL: time.Hour}

			if _, err = fixture.stores.Consent.Commit(ctx, commit); err != nil {
				t.Fatalf("commit consent: %v", err)
			}

			key := deriveTestKey(t, fixture.stores.keyspace, OwnerConsent, reference)
			fixture.redis.HSet(key, "payload", tc.mutate(fixture.redis.HGet(key, "payload")))

			_, err = fixture.stores.Consent.Load(ctx, reference)
			if !errors.Is(err, ErrNotFound) || !errors.Is(err, ErrPayloadUnreadable) {
				t.Fatalf("unreadable load error = %v, want not found and unreadable", err)
			}

			if fixture.redis.Exists(key) {
				t.Fatal("unreadable record was not purged")
			}

			if _, err = fixture.stores.Consent.Commit(ctx, commit); err != nil {
				t.Fatalf("recommit consent after purge: %v", err)
			}
		})
	}
}
