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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
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

func TestFlushUserTokensRejectsLateStaticTokenWrites(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	session := &OIDCSession{
		ClientID:         "static-client",
		UserID:           "user-static-race",
		DynamicUserEpoch: "0",
	}

	if err := storage.FlushUserTokens(ctx, session.UserID); err != nil {
		t.Fatalf("FlushUserTokens() error = %v", err)
	}

	if err := storage.StoreAccessToken(ctx, "na_at_static_late", session, time.Hour); !errors.Is(err, ErrDynamicTokenRevoked) {
		t.Fatalf("late StoreAccessToken() error = %v, want ErrDynamicTokenRevoked", err)
	}

	if err := storage.StoreRefreshToken(ctx, "na_rt_static_late", session, time.Hour); !errors.Is(err, ErrDynamicTokenRevoked) {
		t.Fatalf("late StoreRefreshToken() error = %v, want ErrDynamicTokenRevoked", err)
	}
}

func TestConsumeStaticRefreshTokenAllowsOneWinner(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	session := &OIDCSession{
		ClientID:         "static-client",
		UserID:           "user-static-consume",
		DynamicUserEpoch: "0",
	}

	if err := storage.StoreRefreshToken(ctx, "na_rt_static_once", session, time.Hour); err != nil {
		t.Fatalf("StoreRefreshToken() error = %v", err)
	}

	loaded, err := storage.GetRefreshToken(ctx, "na_rt_static_once")
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)

	for range 2 {
		go func() {
			<-start

			_, consumeErr := storage.ConsumeRefreshToken(ctx, "na_rt_static_once", loaded)
			results <- consumeErr
		}()
	}

	close(start)

	var (
		succeeded       int
		alreadyConsumed int
	)

	for range 2 {
		switch consumeErr := <-results; {
		case consumeErr == nil:
			succeeded++
		case errors.Is(consumeErr, redis.Nil):
			alreadyConsumed++
		default:
			t.Fatalf("ConsumeRefreshToken() error = %v", consumeErr)
		}
	}

	if succeeded != 1 || alreadyConsumed != 1 {
		t.Fatalf("consume results = success:%d consumed:%d, want 1 each", succeeded, alreadyConsumed)
	}
}

func TestStaticRefreshTokenScriptsUseOneClusterHashTag(t *testing.T) {
	db, _ := redismock.NewClientMock()
	storage := NewRedisTokenStorage(rediscli.NewTestClient(db), "test:")
	reference := storage.staticRefreshTokenReference("na_rt_cluster-safe")
	keys := []string{
		storage.dynamicRefreshKey(oidcStaticRefreshToken, reference),
		storage.dynamicRefreshKey(oidcStaticUserRefreshTokens, "cluster-user"),
		storage.dynamicUserEpochKey("cluster-user"),
	}

	if normalized := rediscli.EnsureKeysInSameSlot(keys, "{unexpected}"); !reflect.DeepEqual(normalized, keys) {
		t.Fatalf("static refresh keys required hash-tag rewriting: got %#v, want %#v", normalized, keys)
	}
}

func TestStaticRefreshTokenConsumeRejectsStaleObservedStateAfterReuse(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	token := "na_rt_static_reused"
	session := &OIDCSession{ClientID: "static-client", UserID: "user-static-reuse", DynamicUserEpoch: "0"}

	if err := storage.StoreRefreshToken(ctx, token, session, time.Hour); err != nil {
		t.Fatalf("StoreRefreshToken() error = %v", err)
	}

	stale, err := storage.GetRefreshToken(ctx, token)
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}

	consumed, err := storage.ConsumeRefreshToken(ctx, token, stale)
	if err != nil {
		t.Fatalf("first ConsumeRefreshToken() error = %v", err)
	}

	consumed.AccessToken = "replacement-access-token"
	if err := storage.StoreRefreshToken(ctx, token, consumed, time.Hour); err != nil {
		t.Fatalf("replacement StoreRefreshToken() error = %v", err)
	}

	if _, err := storage.ConsumeRefreshToken(ctx, token, stale); !errors.Is(err, redis.Nil) {
		t.Fatalf("stale ConsumeRefreshToken() error = %v, want redis.Nil", err)
	}

	current, err := storage.GetRefreshToken(ctx, token)
	if err != nil {
		t.Fatalf("current GetRefreshToken() error = %v", err)
	}

	if _, err := storage.ConsumeRefreshToken(ctx, token, current); err != nil {
		t.Fatalf("current ConsumeRefreshToken() error = %v", err)
	}
}

func TestLegacyTokenSchemaIsRejectedAfterHardCut(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	userID := "legacy-user"
	session := &OIDCSession{ClientID: "static-client", UserID: userID}

	data, err := storage.encryptSession(session)
	if err != nil {
		t.Fatalf("encryptSession() error = %v", err)
	}

	if err := handle.Set(ctx, storage.oidcKey(oidcRefreshTokenKeyKind, "legacy-refresh"), data, time.Hour).Err(); err != nil {
		t.Fatalf("seed legacy refresh token error = %v", err)
	}

	if err := handle.Set(ctx, storage.oidcKey(oidcAccessTokenKeyKind, "legacy-access"), data, time.Hour).Err(); err != nil {
		t.Fatalf("seed legacy access token error = %v", err)
	}

	if _, err := storage.GetRefreshToken(ctx, "legacy-refresh"); !errors.Is(err, redis.Nil) {
		t.Fatalf("GetRefreshToken() error = %v, want redis.Nil", err)
	}

	if _, err := storage.GetAccessTokenAuthoritative(ctx, "legacy-access"); !errors.Is(err, redis.Nil) {
		t.Fatalf("GetAccessTokenAuthoritative() error = %v, want redis.Nil", err)
	}
}

func TestStaticAccessTokenUsesEpochBoundNamespace(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	token := "na_at_static_hashed"
	session := &OIDCSession{ClientID: "static-client", UserID: "static-access-user", DynamicUserEpoch: "0"}

	if err := storage.StoreAccessToken(ctx, token, session, time.Hour); err != nil {
		t.Fatalf("StoreAccessToken() error = %v", err)
	}

	if server.Exists(storage.oidcKey(oidcAccessTokenKeyKind, token)) {
		t.Fatal("static access token was exposed in the retired raw-token namespace")
	}

	if _, err := storage.GetAccessTokenAuthoritative(ctx, token); err != nil {
		t.Fatalf("GetAccessTokenAuthoritative() error = %v", err)
	}
}

func TestDeleteRefreshTokenRemovesStaticNamespaceState(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	storage := NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:")
	ctx := context.Background()
	token := "na_rt_delete_static"
	session := &OIDCSession{ClientID: "static-client", UserID: "delete-user", DynamicUserEpoch: "0"}

	if err := storage.StoreRefreshToken(ctx, token, session, time.Hour); err != nil {
		t.Fatalf("StoreRefreshToken() error = %v", err)
	}

	if err := storage.DeleteRefreshToken(ctx, token); err != nil {
		t.Fatalf("DeleteRefreshToken() error = %v", err)
	}

	if _, err := storage.GetRefreshToken(ctx, token); !errors.Is(err, redis.Nil) {
		t.Fatalf("GetRefreshToken() error = %v, want redis.Nil", err)
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
