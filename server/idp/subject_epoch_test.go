// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package idp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

// testSubjectEpochAfterFlush is the epoch a subject reaches with its first user-wide revocation.
const testSubjectEpochAfterFlush = "1000000000001"

func TestIsCurrentSubjectEpochRejectsMissingAndPreFloorEpochs(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		current string
		want    bool
	}{
		{name: "floor matches missing epoch key", token: testSubjectEpochFloor, current: testSubjectEpochFloor, want: true},
		{name: "advanced epoch matches", token: testSubjectEpochAfterFlush, current: testSubjectEpochAfterFlush, want: true},
		{name: "revoked floor epoch", token: testSubjectEpochFloor, current: testSubjectEpochAfterFlush},
		{name: "missing claim", token: "", current: testSubjectEpochFloor},
		{name: "earlier baseline", token: "0", current: testSubjectEpochFloor},
		{name: "earlier baseline with planted current", token: "0", current: "0"},
		{name: "largest pre-floor value", token: "999999999999", current: "999999999999"},
		{name: "malformed", token: "epoch", current: "epoch"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isCurrentSubjectEpoch(test.token, test.current); got != test.want {
				t.Fatalf("isCurrentSubjectEpoch(%q, %q) = %t, want %t", test.token, test.current, got, test.want)
			}
		})
	}
}

// TestValidateTokenJWTRejectsTokensIssuedBeforeEpochFloor proves that no JWT access token from the former
// epoch range survives the hard cut, whether it was revoked or not, for users and service clients alike.
func TestValidateTokenJWTRejectsTokensIssuedBeforeEpochFloor(t *testing.T) {
	tests := []struct {
		epoch     any
		expect    func(redismock.ClientMock, string, string)
		name      string
		subject   string
		wantError bool
	}{
		{name: "earlier baseline epoch", subject: testUserID, epoch: "0", expect: expectAbsentSubjectEpoch, wantError: true},
		{name: "earlier revoked epoch", subject: testUserID, epoch: "7", expect: expectAbsentSubjectEpoch, wantError: true},
		{name: "earlier service token epoch", subject: "cc-client", epoch: "0", expect: expectAbsentSubjectEpoch, wantError: true},
		{name: "planted pre-floor current epoch", subject: testUserID, epoch: "0", expect: expectPlantedSubjectEpoch("0"), wantError: true},
		{name: "missing epoch claim", subject: testUserID, expect: func(redismock.ClientMock, string, string) {}, wantError: true},
		{name: "current floor epoch", subject: testUserID, epoch: testSubjectEpochFloor, expect: expectAbsentSubjectEpochAndDenylist},
		{name: "current service token epoch", subject: "cc-client", epoch: testSubjectEpochFloor, expect: expectAbsentSubjectEpochAndDenylist},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{Issuer: testIssuer})
			kid := "epoch-floor-key"
			pemData := generateTestKey()
			claims := jwt.MapClaims{
				claimIssuer:                testIssuer,
				claimSubject:               test.subject,
				claimAudience:              testClientID,
				claimIssuedAt:              time.Now().Add(-time.Minute).Unix(),
				claimExpires:               time.Now().Add(time.Hour).Unix(),
				claimScope:                 testScopeClaim,
				definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
			}

			if test.epoch != nil {
				claims[definitions.ClaimUserTokenEpoch] = test.epoch
			}

			tokenString := signedTestTokenWithClaims(t, kid, pemData, claims)

			mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
			test.expect(mock, test.subject, tokenString)

			_, err := idp.ValidateToken(t.Context(), tokenString)
			if test.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// expectAbsentSubjectEpoch expects the epoch read of a subject that was never revoked.
func expectAbsentSubjectEpoch(mock redismock.ClientMock, subject string, _ string) {
	expectUserTokenEpoch(mock, subject)
}

// expectAbsentSubjectEpochAndDenylist expects the epoch read followed by the denylist lookup of a valid token.
func expectAbsentSubjectEpochAndDenylist(mock redismock.ClientMock, subject string, token string) {
	expectUserTokenEpoch(mock, subject)
	expectDeniedAccessTokenLookup(mock, token, false)
}

// expectPlantedSubjectEpoch returns an expectation for a subject epoch key holding the given value.
func expectPlantedSubjectEpoch(value string) func(redismock.ClientMock, string, string) {
	return func(mock redismock.ClientMock, subject string, _ string) {
		mock.ExpectGet(testUserTokenEpochKey(subject)).SetVal(value)
	}
}

func TestSubjectEpochStartsAtFloorAndFlushAdvancesFromIt(t *testing.T) {
	const subject = "epoch-floor-user"

	_, handle, storage := newSlotGuardedTokenStorage(t)
	ctx := context.Background()

	epoch, err := storage.DynamicUserEpoch(ctx, subject)
	requireNoError(t, err)

	if epoch != testSubjectEpochFloor {
		t.Fatalf("DynamicUserEpoch() without epoch key = %q, want floor %q", epoch, testSubjectEpochFloor)
	}

	session := &OIDCSession{ClientID: "static-client", UserID: subject, DynamicUserEpoch: epoch}
	requireNoError(t, storage.StoreAccessToken(ctx, "na_at_floor", session, time.Hour))

	if _, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_floor"); err != nil {
		t.Fatalf("GetAccessTokenAuthoritative() for a floor-epoch token error = %v", err)
	}

	requireNoError(t, storage.advanceDynamicUserEpoch(ctx, subject))

	if current := handle.Get(ctx, testUserTokenEpochKey(subject)).Val(); current != testSubjectEpochAfterFlush {
		t.Fatalf("epoch after first revocation = %q, want %q", current, testSubjectEpochAfterFlush)
	}

	if _, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_floor"); !errors.Is(err, ErrDynamicTokenRevoked) {
		t.Fatalf("GetAccessTokenAuthoritative() after revocation error = %v, want ErrDynamicTokenRevoked", err)
	}

	session.DynamicUserEpoch = testSubjectEpochAfterFlush
	requireNoError(t, storage.StoreAccessToken(ctx, "na_at_after_flush", session, time.Hour))

	if _, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_after_flush"); err != nil {
		t.Fatalf("GetAccessTokenAuthoritative() for a current token error = %v", err)
	}

	requireNoError(t, storage.FlushUserTokens(ctx, subject))

	if epoch, err = storage.DynamicUserEpoch(ctx, subject); err != nil || epoch != "1000000000002" {
		t.Fatalf("DynamicUserEpoch() after FlushUserTokens = (%q, %v), want the next epoch above the floor", epoch, err)
	}

	if _, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_after_flush"); err == nil {
		t.Fatal("GetAccessTokenAuthoritative() accepted a token after FlushUserTokens")
	}
}

func TestEpochBoundStateRejectsPreFloorEpochs(t *testing.T) {
	const (
		subject = "pre-floor-user"
		token   = "na_at_pre_floor"
	)

	_, handle, storage := newSlotGuardedTokenStorage(t)
	ctx := context.Background()

	session := &OIDCSession{ClientID: "static-client", UserID: subject, DynamicUserEpoch: "0"}

	if err := storage.StoreAccessToken(ctx, token, session, time.Hour); !errors.Is(err, ErrDynamicTokenRevoked) {
		t.Fatalf("StoreAccessToken() with a pre-floor epoch error = %v, want ErrDynamicTokenRevoked", err)
	}

	// Plant a pre-floor record and a matching pre-floor epoch; the floor check must still reject it.
	data, err := storage.encryptSession(session)
	requireNoError(t, err)

	reference := storage.accessTokenReference(token)
	owner := storage.keys.subject(subject)
	requireNoError(t, handle.Set(ctx, storage.keys.locator(reference), owner.slot, time.Hour).Err())
	requireNoError(t, handle.Set(ctx, owner.entry(oidcAccessTokenKeyKind, reference), data, time.Hour).Err())
	requireNoError(t, handle.Set(ctx, owner.epoch(), "0", time.Hour).Err())

	if _, err := storage.GetAccessTokenAuthoritative(ctx, token); !errors.Is(err, ErrDynamicTokenRevoked) {
		t.Fatalf("GetAccessTokenAuthoritative() for a pre-floor epoch error = %v, want ErrDynamicTokenRevoked", err)
	}
}

func TestMalformedLocatorIsTreatedAsMissingToken(t *testing.T) {
	_, handle, storage := newSlotGuardedTokenStorage(t)
	ctx := context.Background()
	reference := storage.accessTokenReference("na_at_malformed_locator")

	for _, value := range []string{"", "not-a-digest", strings.Repeat("A", 64), strings.Repeat("a", 63), "x}:{other"} {
		requireNoError(t, handle.Set(ctx, storage.keys.locator(reference), value, time.Hour).Err())

		if _, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_malformed_locator"); !errors.Is(err, redis.Nil) {
			t.Fatalf("GetAccessTokenAuthoritative() with locator %q error = %v, want redis.Nil", value, err)
		}
	}
}
