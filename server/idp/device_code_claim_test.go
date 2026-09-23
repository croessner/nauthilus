// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/idp/idptest"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/redisslot"
)

func TestRedisDeviceCodeStoreClaimsAndCompletesExactlyOnce(t *testing.T) {
	server, handle, _ := redisslot.NewGuardedMiniredis(t, "test:")

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
	server, handle, _ := redisslot.NewGuardedMiniredis(t, "test:")

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

	if server.Exists(idptest.DeviceCodeKey(prefix, deviceCode)) {
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

	if server.Exists(idptest.DeviceUserCodeKey(prefix, userCode)) {
		t.Fatal("user-code index still exists after claim")
	}

	if got := server.TTL(idptest.DeviceCodeKey(prefix, deviceCode)); got != ttl {
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

func TestRedisDeviceCodeStoreUserCodeClaimHasOneWinnerAndHidesCodes(t *testing.T) {
	const (
		prefix     = "test:"
		deviceCode = "device-code-race-secret"
		userCode   = "WXYZ-KMNP"
		contenders = 8
	)

	server, handle, _ := redisslot.NewGuardedMiniredis(t, prefix)
	store := NewRedisDeviceCodeStore(rediscli.NewTestClient(handle), prefix)
	ttl := 10 * time.Minute

	if err := store.StoreDeviceCode(t.Context(), deviceCode, testDeviceCodeRequest([]string{"openid"}, userCode, ttl), ttl); err != nil {
		t.Fatalf("store device code: %v", err)
	}

	for _, key := range server.Keys() {
		if strings.Contains(key, deviceCode) || strings.Contains(key, userCode) || strings.Contains(key, "WXYZKMNP") {
			t.Fatalf("Redis key %q exposes a device or user code", key)
		}
	}

	var (
		waitGroup sync.WaitGroup
		mu        sync.Mutex
		winners   []string
	)

	start := make(chan struct{})

	for range contenders {
		waitGroup.Go(func() {
			<-start

			claimedCode, _, err := store.ClaimDeviceCodeByUserCode(context.Background(), userCode)
			if err != nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()

			winners = append(winners, claimedCode)
		})
	}

	close(start)
	waitGroup.Wait()

	if len(winners) != 1 || winners[0] != deviceCode {
		t.Fatalf("user-code claim winners = %v, want exactly one claim of the stored device code", winners)
	}
}

func TestRedisDeviceCodeStoreConcurrentPollsAndClaimsIssueOnce(t *testing.T) {
	const (
		prefix     = "test:"
		deviceCode = "device-code-poll-race"
		clientID   = "device-client"
	)

	for range 20 {
		server, handle, _ := redisslot.NewGuardedMiniredis(t, prefix)
		store := NewRedisDeviceCodeStore(rediscli.NewTestClient(handle), prefix)
		request := testDeviceCodeRequest([]string{"openid"}, "PQRS-TVWX", 10*time.Minute)
		request.ClientID = clientID
		request.Status = DeviceCodeStatusAuthorized
		request.VerificationLocked = true

		if err := store.StoreDeviceCode(t.Context(), deviceCode, request, 10*time.Minute); err != nil {
			t.Fatalf("store authorized device code: %v", err)
		}

		var (
			waitGroup sync.WaitGroup
			mu        sync.Mutex
			issued    int
		)

		start := make(chan struct{})

		for range 2 {
			waitGroup.Go(func() {
				<-start

				_ = store.RecordDeviceCodePoll(context.Background(), deviceCode, time.Now())
			})

			waitGroup.Go(func() {
				<-start

				if _, err := store.ClaimAuthorizedDeviceCode(context.Background(), deviceCode, clientID); err == nil {
					mu.Lock()
					defer mu.Unlock()

					issued++
				}
			})
		}

		close(start)
		waitGroup.Wait()

		if issued != 1 {
			t.Fatalf("token issuances = %d, want exactly one", issued)
		}

		if server.Exists(idptest.DeviceCodeKey(prefix, deviceCode)) {
			t.Fatal("a poll recreated the consumed device request")
		}
	}
}

func TestRedisDeviceCodeStorePollAfterCompletionKeepsAuthorization(t *testing.T) {
	const (
		prefix     = "test:"
		deviceCode = "device-code-poll-complete"
		userCode   = "HJKM-NPQR"
	)

	_, handle, _ := redisslot.NewGuardedMiniredis(t, prefix)
	store := NewRedisDeviceCodeStore(rediscli.NewTestClient(handle), prefix)
	ttl := 10 * time.Minute

	if err := store.StoreDeviceCode(t.Context(), deviceCode, testDeviceCodeRequest([]string{"openid"}, userCode, ttl), ttl); err != nil {
		t.Fatalf("store device code: %v", err)
	}

	_, claimed, err := store.ClaimDeviceCodeByUserCode(t.Context(), userCode)
	if err != nil {
		t.Fatalf("claim device code: %v", err)
	}

	// A poller that loaded the pending request before the claim must not roll the state back.
	if err := store.RecordDeviceCodePoll(t.Context(), deviceCode, time.Now()); err != nil {
		t.Fatalf("record poll: %v", err)
	}

	claimed.Status = DeviceCodeStatusAuthorized
	if err := store.CompleteClaimedDeviceCode(t.Context(), deviceCode, claimed); err != nil {
		t.Fatalf("complete claimed device code: %v", err)
	}

	polledAt := time.Now().Add(time.Second).UTC()
	if err := store.RecordDeviceCodePoll(t.Context(), deviceCode, polledAt); err != nil {
		t.Fatalf("record poll after completion: %v", err)
	}

	persisted, err := store.GetDeviceCode(t.Context(), deviceCode)
	if err != nil {
		t.Fatalf("load device code: %v", err)
	}

	if persisted.Status != DeviceCodeStatusAuthorized || !persisted.VerificationLocked || !persisted.LastPoll.Equal(polledAt) {
		t.Fatalf("persisted request = status %q locked %t last poll %s, want authorized, locked, %s",
			persisted.Status, persisted.VerificationLocked, persisted.LastPoll, polledAt)
	}
}

func TestRedisDeviceCodeStoreWritesNeverRecreateConsumedRequests(t *testing.T) {
	const (
		prefix     = "test:"
		deviceCode = "device-code-consumed"
	)

	server, handle, _ := redisslot.NewGuardedMiniredis(t, prefix)
	store := NewRedisDeviceCodeStore(rediscli.NewTestClient(handle), prefix)
	request := testDeviceCodeRequest([]string{"openid"}, "BCDF-GHJK", 10*time.Minute)

	if err := store.StoreDeviceCode(t.Context(), deviceCode, request, 10*time.Minute); err != nil {
		t.Fatalf("store device code: %v", err)
	}

	if err := store.DeleteDeviceCode(t.Context(), deviceCode); err != nil {
		t.Fatalf("delete device code: %v", err)
	}

	if err := store.UpdateDeviceCode(t.Context(), deviceCode, request); err == nil {
		t.Fatal("UpdateDeviceCode() recreated a deleted request")
	}

	if err := store.RecordDeviceCodePoll(t.Context(), deviceCode, time.Now()); err == nil {
		t.Fatal("RecordDeviceCodePoll() recreated a deleted request")
	}

	if server.Exists(idptest.DeviceCodeKey(prefix, deviceCode)) {
		t.Fatal("deleted device request exists again")
	}
}

func TestRedisDeviceCodeStoreRejectsUserCodeCollision(t *testing.T) {
	const (
		prefix   = "test:"
		userCode = "CDFG-HJKM"
	)

	server, handle, _ := redisslot.NewGuardedMiniredis(t, prefix)
	store := NewRedisDeviceCodeStore(rediscli.NewTestClient(handle), prefix)
	ttl := 10 * time.Minute

	if err := store.StoreDeviceCode(t.Context(), "device-first", testDeviceCodeRequest([]string{"openid"}, userCode, ttl), ttl); err != nil {
		t.Fatalf("store first device code: %v", err)
	}

	err := store.StoreDeviceCode(t.Context(), "device-second", testDeviceCodeRequest([]string{"openid"}, userCode, ttl), ttl)
	if !errors.Is(err, ErrDeviceUserCodeCollision) {
		t.Fatalf("StoreDeviceCode() error = %v, want ErrDeviceUserCodeCollision", err)
	}

	if server.Exists(idptest.DeviceCodeKey(prefix, "device-second")) {
		t.Fatal("colliding device request was kept")
	}

	resolved, _, err := store.GetDeviceCodeByUserCode(t.Context(), userCode)
	if err != nil || resolved != "device-first" {
		t.Fatalf("GetDeviceCodeByUserCode() = (%q, %v), want the first device code", resolved, err)
	}
}
