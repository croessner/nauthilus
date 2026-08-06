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

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/redis/go-redis/v9"
)

func TestDynamicRefreshTokenAncestorReuseRevokesActiveFamily(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()

	const ttl = 30 * 24 * time.Hour

	session := &OIDCSession{
		ClientID:         "dcr_client",
		UserID:           "user-1",
		RefreshFamilyID:  "family-1",
		DynamicUserEpoch: "0",
	}
	if err := storage.StoreInitialDynamicRefreshToken(ctx, "refresh-1", session, ttl); err != nil {
		t.Fatalf("StoreInitialDynamicRefreshToken() error = %v", err)
	}

	loaded, err := storage.GetDynamicRefreshToken(ctx, "refresh-1")
	if err != nil {
		t.Fatalf("GetDynamicRefreshToken() error = %v", err)
	}

	if err := storage.RotateDynamicRefreshToken(ctx, "refresh-1", "refresh-2", loaded, ttl); err != nil {
		t.Fatalf("RotateDynamicRefreshToken() error = %v", err)
	}

	if _, err := storage.GetDynamicRefreshToken(ctx, "refresh-1"); !errors.Is(err, ErrDynamicRefreshTokenReuse) {
		t.Fatalf("reused GetDynamicRefreshToken() error = %v, want ErrDynamicRefreshTokenReuse", err)
	}

	if _, err := storage.GetDynamicRefreshToken(ctx, "refresh-2"); !errors.Is(err, redis.Nil) {
		t.Fatalf("active descendant GetDynamicRefreshToken() error = %v, want redis.Nil after family revocation", err)
	}

	if !server.Exists("test:oidc:dcr:{dynamic}:dynamic_refresh_revoked:family-1") {
		t.Fatal("refresh family revocation marker missing")
	}

	for _, key := range server.Keys() {
		if strings.Contains(key, "refresh-1") || strings.Contains(key, "refresh-2") {
			t.Fatalf("Redis key %q exposed a bearer refresh token", key)
		}
	}
}

func TestDynamicAccessTokenDoesNotAppearInRedisKeys(t *testing.T) {
	const token = "na_at_dcr_sensitive-token"

	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")

	session := &OIDCSession{ClientID: "dcr_client", UserID: "user-1", DynamicUserEpoch: "0"}

	if err := storage.StoreAccessToken(context.Background(), token, session, time.Minute); err != nil {
		t.Fatalf("StoreAccessToken() error = %v", err)
	}

	if _, err := storage.GetAccessTokenAuthoritative(context.Background(), token); err != nil {
		t.Fatalf("GetAccessTokenAuthoritative() error = %v", err)
	}

	for _, key := range server.Keys() {
		if strings.Contains(key, token) {
			t.Fatalf("Redis key %q exposed an access token", key)
		}
	}
}

func TestDeleteUserRefreshTokensRevokesDynamicFamily(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	session := &OIDCSession{ClientID: "dcr_client", UserID: "user-1", RefreshFamilyID: "family-logout", DynamicUserEpoch: "0"}

	if err := storage.StoreInitialDynamicRefreshToken(context.Background(), "refresh-logout", session, time.Hour); err != nil {
		t.Fatalf("StoreInitialDynamicRefreshToken() error = %v", err)
	}

	if err := storage.DeleteUserRefreshTokens(context.Background(), session.UserID); err != nil {
		t.Fatalf("DeleteUserRefreshTokens() error = %v", err)
	}

	if _, err := storage.GetDynamicRefreshToken(context.Background(), "refresh-logout"); !errors.Is(err, redis.Nil) {
		t.Fatalf("GetDynamicRefreshToken() error = %v, want redis.Nil", err)
	}

	if !server.Exists("test:oidc:dcr:{dynamic}:dynamic_refresh_revoked:" + session.RefreshFamilyID) {
		t.Fatal("logout did not leave a family revocation marker")
	}
}

func TestFlushUserTokensRejectsLateDynamicTokenWrites(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	session := &OIDCSession{
		ClientID:         "dcr_client",
		UserID:           "user-1",
		RefreshFamilyID:  "family-race",
		DynamicUserEpoch: "0",
	}

	if err := storage.StoreInitialDynamicRefreshToken(ctx, "refresh-race", session, time.Hour); err != nil {
		t.Fatalf("StoreInitialDynamicRefreshToken() error = %v", err)
	}

	loaded, err := storage.GetDynamicRefreshToken(ctx, "refresh-race")
	if err != nil {
		t.Fatalf("GetDynamicRefreshToken() error = %v", err)
	}

	if err := storage.FlushUserTokens(ctx, session.UserID); err != nil {
		t.Fatalf("FlushUserTokens() error = %v", err)
	}

	if err := storage.StoreAccessToken(ctx, "na_at_dcr_late", loaded, time.Hour); !errors.Is(err, ErrDynamicTokenRevoked) {
		t.Fatalf("late StoreAccessToken() error = %v, want ErrDynamicTokenRevoked", err)
	}

	if err := storage.RotateDynamicRefreshToken(ctx, "refresh-race", "refresh-late", loaded, time.Hour); !errors.Is(err, ErrDynamicTokenRevoked) {
		t.Fatalf("late RotateDynamicRefreshToken() error = %v, want ErrDynamicTokenRevoked", err)
	}
}

func TestDynamicAccessTokenValidationChecksUserEpoch(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	session := &OIDCSession{ClientID: "dcr_client", UserID: "user-1", DynamicUserEpoch: "0"}

	if err := storage.StoreAccessToken(ctx, "na_at_dcr_before-logout", session, time.Hour); err != nil {
		t.Fatalf("StoreAccessToken() error = %v", err)
	}

	if err := storage.advanceDynamicUserEpoch(ctx, session.UserID); err != nil {
		t.Fatalf("advanceDynamicUserEpoch() error = %v", err)
	}

	if _, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_dcr_before-logout"); !errors.Is(err, ErrDynamicTokenRevoked) {
		t.Fatalf("GetAccessTokenAuthoritative() error = %v, want ErrDynamicTokenRevoked", err)
	}
}

func TestListAndDeleteUserSessionsIncludeDynamicAccessTokens(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	session := &OIDCSession{ClientID: "dcr_client", UserID: "user-1", DynamicUserEpoch: "0"}

	if err := storage.StoreAccessToken(ctx, "na_at_dcr_managed", session, time.Hour); err != nil {
		t.Fatalf("StoreAccessToken() error = %v", err)
	}

	sessions, err := storage.ListUserSessions(ctx, session.UserID)
	if err != nil {
		t.Fatalf("ListUserSessions() error = %v", err)
	}

	if len(sessions) != 1 {
		t.Fatalf("ListUserSessions() length = %d, want 1", len(sessions))
	}

	var managementID string
	for id := range sessions {
		managementID = id

		break
	}

	if strings.Contains(managementID, "na_at_dcr_managed") {
		t.Fatal("management ID exposed bearer material")
	}

	if err := storage.DeleteUserSession(ctx, session.UserID, managementID); err != nil {
		t.Fatalf("DeleteUserSession() error = %v", err)
	}

	if _, err := storage.GetAccessTokenAuthoritative(ctx, "na_at_dcr_managed"); !errors.Is(err, redis.Nil) {
		t.Fatalf("GetAccessTokenAuthoritative() error = %v, want redis.Nil", err)
	}
}
