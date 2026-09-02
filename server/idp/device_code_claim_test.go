// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

func TestRedisDeviceCodeStoreClaimsAndCompletesExactlyOnce(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})

	t.Cleanup(func() { _ = handle.Close() })

	const (
		prefix     = "test:"
		deviceCode = "device-code-opaque"
		userCode   = "ABCD-EFGH"
	)

	ttl := 10 * time.Minute
	store := NewRedisDeviceCodeStore(rediscli.NewTestClient(handle), prefix)

	request := testDeviceCodeRequest([]string{"openid", "profile"}, userCode, ttl)
	if err := store.StoreDeviceCode(context.Background(), deviceCode, request, ttl); err != nil {
		t.Fatalf("store device code: %v", err)
	}

	claimedCode, claimed, err := store.ClaimDeviceCodeByUserCode(context.Background(), "abcd efgh")
	assertClaimedDeviceCode(t, server, prefix, userCode, deviceCode, ttl, claimedCode, claimed, err)

	_, _, err = store.ClaimDeviceCodeByUserCode(context.Background(), userCode)
	if err == nil {
		t.Fatal("second device-code claim unexpectedly succeeded")
	}

	claimed.Scopes = []string{"openid"}

	claimed.Status = DeviceCodeStatusAuthorized
	if err = store.CompleteClaimedDeviceCode(context.Background(), deviceCode, claimed); err != nil {
		t.Fatalf("complete claimed device code: %v", err)
	}

	persisted, err := store.GetDeviceCode(context.Background(), deviceCode)
	assertCompletedDeviceCode(t, persisted, err)

	if err = store.CompleteClaimedDeviceCode(context.Background(), deviceCode, claimed); err == nil {
		t.Fatal("replayed device-code completion unexpectedly succeeded")
	}
}

func TestRedisDeviceCodeStoreClaimsAuthorizedDeviceCodeOnce(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})

	t.Cleanup(func() { _ = handle.Close() })

	const (
		prefix     = "test:"
		deviceCode = "authorized-device-code"
		clientID   = "device-client"
	)

	store := NewRedisDeviceCodeStore(rediscli.NewTestClient(handle), prefix)
	request := testDeviceCodeRequest([]string{"openid"}, "ABCD-EFGH", 10*time.Minute)
	request.ClientID = clientID
	request.Status = DeviceCodeStatusAuthorized
	request.VerificationLocked = true

	if err := store.StoreDeviceCode(t.Context(), deviceCode, request, 10*time.Minute); err != nil {
		t.Fatalf("store authorized device code: %v", err)
	}

	var waitGroup sync.WaitGroup

	start := make(chan struct{})
	results := make(chan error, 2)

	for range 2 {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			<-start

			_, err := store.ClaimAuthorizedDeviceCode(context.Background(), deviceCode, clientID)
			results <- err
		}()
	}

	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0

	for err := range results {
		if err == nil {
			successes++
		}
	}

	if successes != 1 {
		t.Fatalf("successful claims = %d, want 1", successes)
	}

	if server.Exists(prefix + "oidc:device_code:" + deviceCode) {
		t.Fatal("authorized device code remains after claim")
	}
}

func assertClaimedDeviceCode(
	t *testing.T,
	server *miniredis.Miniredis,
	prefix string,
	userCode string,
	deviceCode string,
	ttl time.Duration,
	claimedCode string,
	claimed *DeviceCodeRequest,
	err error,
) {
	t.Helper()

	if err != nil {
		t.Fatalf("claim device code: %v", err)
	}

	if claimedCode != deviceCode {
		t.Fatalf("claimed device code = %q, want %q", claimedCode, deviceCode)
	}

	if claimed == nil {
		t.Fatal("claimed request is nil")
	}

	if !claimed.VerificationLocked {
		t.Fatal("claimed request is not verification-locked")
	}

	if server.Exists(prefix + "oidc:user_code:" + userCode) {
		t.Fatal("user-code index still exists after claim")
	}

	if got := server.TTL(prefix + "oidc:device_code:" + deviceCode); got != ttl {
		t.Fatalf("device-code TTL = %s, want %s", got, ttl)
	}
}

func assertCompletedDeviceCode(t *testing.T, persisted *DeviceCodeRequest, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("load completed device code: %v", err)
	}

	if persisted.Status != DeviceCodeStatusAuthorized {
		t.Fatalf("persisted status = %q, want %q", persisted.Status, DeviceCodeStatusAuthorized)
	}

	if !persisted.VerificationLocked {
		t.Fatal("completed request lost its verification lock")
	}

	if !reflect.DeepEqual(persisted.Scopes, []string{"openid"}) {
		t.Fatalf("persisted scopes = %v, want [openid]", persisted.Scopes)
	}
}
