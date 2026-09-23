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

package dcr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/testing/redisslot"
	"github.com/redis/go-redis/v9"
)

func TestRegistrationServicePersistsResolvableConstrainedClient(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	client := rediscli.NewTestClient(handle)
	policy := repositoryTestPolicy()
	repository := NewRepository(client, "test:", policy.GetLifecycle())
	service := NewRegistrationService(repository, policy)

	metadata, protocolErr := BuildEffectiveMetadata(RegistrationRequest{
		RedirectURIs: []string{"http://127.0.0.1/callback"},
		ClientName:   "Mail Client",
	}, policy)
	if protocolErr != nil {
		t.Fatalf("BuildEffectiveMetadata() error = %v", protocolErr)
	}

	response, err := service.Register(context.Background(), metadata, "192.0.2.10")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if !strings.HasPrefix(response.ClientID, ClientIDPrefix) || len(response.ClientID) < len(ClientIDPrefix)+43 {
		t.Fatalf("client_id = %q, want dcr_ plus at least 256 random bits", response.ClientID)
	}

	record, err := repository.Get(context.Background(), response.ClientID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	runtimeClient := record.OIDCClient()
	if !runtimeClient.Dynamic || !runtimeClient.RequiresPKCE() || runtimeClient.GetAccessTokenType("jwt") != "opaque" {
		t.Fatalf("OIDCClient() = %+v, want constrained dynamic public client", runtimeClient)
	}
}

func TestRegistrationServiceEnforcesAtomicSourceRateLimit(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	policy.Limits.SourceRegistrations = 1
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	service := NewRegistrationService(repository, policy)

	metadata, protocolErr := BuildEffectiveMetadata(RegistrationRequest{RedirectURIs: []string{"http://127.0.0.1/callback"}}, policy)
	if protocolErr != nil {
		t.Fatalf("BuildEffectiveMetadata() error = %v", protocolErr)
	}

	if err := service.ReserveAttempt(context.Background(), "192.0.2.10"); err != nil {
		t.Fatalf("first ReserveAttempt() error = %v", err)
	}

	if _, err := service.Register(context.Background(), metadata, "192.0.2.10"); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}

	if err := service.ReserveAttempt(context.Background(), "192.0.2.10"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second ReserveAttempt() error = %v, want ErrRateLimited", err)
	}
}

func TestReserveAttemptClassifiesExhaustedBudget(t *testing.T) {
	tests := []struct {
		configure func(*config.OIDCDynamicClientRegistrationLimits)
		want      error
		name      string
		reason    string
	}{
		{name: "source window", configure: func(l *config.OIDCDynamicClientRegistrationLimits) { l.SourceRegistrations = 1 }, want: ErrSourceWindowRateLimited, reason: "source_window_limit"},
		{name: "source day", configure: func(l *config.OIDCDynamicClientRegistrationLimits) { l.SourceDailyRegistrations = 1 }, want: ErrSourceDailyRateLimited, reason: "source_daily_limit"},
		{name: "global window", configure: func(l *config.OIDCDynamicClientRegistrationLimits) { l.GlobalRegistrations = 1 }, want: ErrGlobalRateLimited, reason: "global_window_limit"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := miniredis.RunT(t)
			handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
			policy := repositoryTestPolicy()
			test.configure(&policy.Limits)
			service := NewRegistrationService(NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle()), policy)

			if err := service.ReserveAttempt(context.Background(), "192.0.2.10"); err != nil {
				t.Fatalf("first ReserveAttempt() error = %v", err)
			}

			err := service.ReserveAttempt(context.Background(), "192.0.2.10")
			if !errors.Is(err, test.want) || !errors.Is(err, ErrRateLimited) {
				t.Fatalf("second ReserveAttempt() error = %v, want %v wrapping ErrRateLimited", err, test.want)
			}

			if got := RateLimitReason(err); got != test.reason {
				t.Fatalf("RateLimitReason() = %q, want %q", got, test.reason)
			}
		})
	}
}

func TestRegisterDoesNotPerformUnboundedExpiredCleanup(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	policy.Limits.ActiveClients = 1
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	now := time.Now().UTC()
	repository.now = func() time.Time { return now }
	activeKey := repository.activeKey()

	for index := 0; index < 101; index++ {
		clientID := fmt.Sprintf("dcr_expired_%d", index)
		handle.ZAdd(context.Background(), activeKey, redis.Z{Score: float64(now.Add(-time.Minute).UnixMilli()), Member: clientID})
	}

	record := &DynamicClientRecord{
		ClientID:  "dcr_new-client",
		Profile:   ProfileMailClientV1,
		CreatedAt: now,
	}

	err := repository.Register(context.Background(), record, policy.GetLimits())
	if !errors.Is(err, ErrQuota) {
		t.Fatalf("Register() error = %v, want ErrQuota until bounded cleanup removes the remainder", err)
	}

	if count := handle.ZCard(context.Background(), activeKey).Val(); count != 101 {
		t.Fatalf("active registry count = %d, want 101 without implicit unbounded cleanup", count)
	}
}

func TestRepositoryExpiresUnusedClientAndCreatesTombstone(t *testing.T) {
	server, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	service := NewRegistrationService(repository, policy)

	metadata, protocolErr := BuildEffectiveMetadata(RegistrationRequest{RedirectURIs: []string{"http://127.0.0.1/callback"}}, policy)
	if protocolErr != nil {
		t.Fatalf("BuildEffectiveMetadata() error = %v", protocolErr)
	}

	response, err := service.Register(context.Background(), metadata, "192.0.2.10")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	repository.now = func() time.Time { return time.Unix(response.ClientIDIssuedAt, 0).Add(25 * time.Hour) }
	if _, err := repository.Get(context.Background(), response.ClientID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}

	if !server.Exists("test:oidc:dcr:client:{" + response.ClientID + "}:tombstone") {
		t.Fatal("expired client tombstone missing")
	}
}

func TestRepositoryTouchesOnlyExplicitSuccessfulUse(t *testing.T) {
	server, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	service := NewRegistrationService(repository, policy)

	metadata, protocolErr := BuildEffectiveMetadata(RegistrationRequest{RedirectURIs: []string{"http://127.0.0.1/callback"}}, policy)
	if protocolErr != nil {
		t.Fatalf("BuildEffectiveMetadata() error = %v", protocolErr)
	}

	response, err := service.Register(context.Background(), metadata, "192.0.2.10")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	createdAt := time.Unix(response.ClientIDIssuedAt, 0).UTC()
	repository.now = func() time.Time { return createdAt.Add(time.Hour) }

	record, err := repository.Get(context.Background(), response.ClientID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if !record.FirstUsedAt.IsZero() || !record.LastUsedAt.IsZero() {
		t.Fatalf("Get() changed lifecycle timestamps: %+v", record)
	}

	if err := repository.Touch(context.Background(), response.ClientID); err != nil {
		t.Fatalf("Touch() error = %v", err)
	}

	record, err = repository.Get(context.Background(), response.ClientID)
	if err != nil {
		t.Fatalf("Get() after Touch error = %v", err)
	}

	if record.FirstUsedAt.IsZero() || !record.LastUsedAt.Equal(repository.now()) {
		t.Fatalf("Touch() lifecycle timestamps = %+v", record)
	}

	score, err := server.ZScore("test:oidc:dcr:{registry}:clients", response.ClientID)
	if err != nil {
		t.Fatalf("ZScore() error = %v", err)
	}

	wantScore := float64(repository.now().Add(policy.GetLifecycle().InactivityTTL).UnixMilli())
	if score != wantScore {
		t.Fatalf("active score = %f, want %f", score, wantScore)
	}
}

func TestEncodeTouchedRecordPreservesLargeDurationInteger(t *testing.T) {
	now := time.Now().UTC()
	record := &DynamicClientRecord{
		ClientID:        "dcr_duration-client",
		RefreshTokenTTL: 720 * time.Hour,
	}

	encoded, err := encodeTouchedRecord(record, now)
	if err != nil {
		t.Fatalf("encodeTouchedRecord() error = %v", err)
	}

	if bytes.Contains(bytes.ToLower(encoded), []byte("e+")) {
		t.Fatalf("encodeTouchedRecord() used exponential notation: %s", encoded)
	}

	decoded := &DynamicClientRecord{}
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.RefreshTokenTTL != record.RefreshTokenTTL {
		t.Fatalf("RefreshTokenTTL = %s, want %s", decoded.RefreshTokenTTL, record.RefreshTokenTTL)
	}

	if !decoded.FirstUsedAt.Equal(now) || !decoded.LastUsedAt.Equal(now) {
		t.Fatalf("touch timestamps = %s/%s, want %s", decoded.FirstUsedAt, decoded.LastUsedAt, now)
	}
}

// newSlotGuardedRedis returns a miniredis client that reports every operation that would fail with
// CROSSSLOT in Redis Cluster.
func newSlotGuardedRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()

	server, handle, _ := redisslot.NewGuardedMiniredis(t, "test:")

	return server, handle
}

// repositoryTestPolicy returns a complete test policy for persistence tests.
func repositoryTestPolicy() config.OIDCDynamicClientRegistrationConfig {
	return config.OIDCDynamicClientRegistrationConfig{
		Enabled:        true,
		RequiredScopes: []string{"openid"},
		SourceHMACKey:  secret.New("0123456789abcdef0123456789abcdef"),
	}
}

func TestRepositoryKeysSpreadClientsAndKeepRegistryTogether(t *testing.T) {
	repository := NewRepository(nil, "test:", repositoryTestPolicy().GetLifecycle())
	registrySlot := redisslot.Slot(repository.activeKey())

	for _, key := range []string{repository.registryKey("rate:source:hash"), repository.registryKey("rate:source-day:hash"), repository.registryKey("rate:global")} {
		if redisslot.Slot(key) != registrySlot {
			t.Fatalf("registry key %q left the atomic registry slot", key)
		}
	}

	const clients = 1000

	slots := make(map[int]struct{}, clients)
	service := NewRegistrationService(repository, repositoryTestPolicy())

	for range clients {
		clientID, err := service.generateClientID()
		if err != nil {
			t.Fatalf("generateClientID() error = %v", err)
		}

		slot := redisslot.Slot(repository.clientKey(clientID))
		if redisslot.Slot(repository.tombstoneKey(clientID)) != slot {
			t.Fatalf("tombstone of %q left the client slot", clientID)
		}

		slots[slot] = struct{}{}
	}

	if len(slots) < clients*95/100 {
		t.Fatalf("%d client records mapped to %d slots, want nearly one slot per client", clients, len(slots))
	}
}

func TestCleanupExpiredRepairsIndexEntryWithoutRecord(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", repositoryTestPolicy().GetLifecycle())
	ctx := context.Background()

	handle.ZAdd(ctx, repository.activeKey(), redis.Z{Score: float64(time.Now().Add(-time.Minute).UnixMilli()), Member: "dcr_orphan"})

	if err := repository.CleanupExpired(ctx, 10); err != nil {
		t.Fatalf("CleanupExpired() error = %v", err)
	}

	if count := handle.ZCard(ctx, repository.activeKey()).Val(); count != 0 {
		t.Fatalf("active registry count = %d, want orphaned reservation removed", count)
	}
}

func TestRegisterReleasesReservationWhenRecordAlreadyExists(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	ctx := context.Background()
	record := &DynamicClientRecord{ClientID: "dcr_existing", Profile: ProfileMailClientV1, CreatedAt: time.Now()}

	if err := handle.Set(ctx, repository.clientKey(record.ClientID), "{}", time.Hour).Err(); err != nil {
		t.Fatalf("seed client record error = %v", err)
	}

	if err := repository.Register(ctx, record, policy.GetLimits()); !errors.Is(err, errClientIDCollision) {
		t.Fatalf("Register() error = %v, want errClientIDCollision", err)
	}

	if count := handle.ZCard(ctx, repository.activeKey()).Val(); count != 0 {
		t.Fatalf("active registry count = %d, want released reservation", count)
	}
}

func TestTouchRejectsClientMissingFromRegistry(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	service := NewRegistrationService(repository, policy)
	ctx := context.Background()

	metadata, protocolErr := BuildEffectiveMetadata(RegistrationRequest{RedirectURIs: []string{"http://127.0.0.1/callback"}}, policy)
	if protocolErr != nil {
		t.Fatalf("BuildEffectiveMetadata() error = %v", protocolErr)
	}

	response, err := service.Register(ctx, metadata, "192.0.2.10")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	before := handle.Get(ctx, repository.clientKey(response.ClientID)).Val()
	handle.ZRem(ctx, repository.activeKey(), response.ClientID)

	if err := repository.Touch(ctx, response.ClientID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Touch() error = %v, want ErrNotFound", err)
	}

	if after := handle.Get(ctx, repository.clientKey(response.ClientID)).Val(); after != before {
		t.Fatal("Touch() rewrote a record that the registry no longer tracks")
	}

	if handle.Exists(ctx, repository.activeKey()).Val() != 0 {
		t.Fatal("Touch() re-added a client to the active registry")
	}
}

func TestFormerSharedTagIndexDoesNotCountAgainstQuota(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	policy.Limits.ActiveClients = 2
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	ctx := context.Background()
	future := float64(time.Now().Add(30 * 24 * time.Hour).UnixMilli())

	for _, clientID := range []string{"dcr_former-1", "dcr_former-2", "dcr_former-3"} {
		handle.ZAdd(ctx, "test:oidc:dcr:{registry}:active", redis.Z{Score: future, Member: clientID})
	}

	record := &DynamicClientRecord{ClientID: "dcr_after-cut", Profile: ProfileMailClientV1, CreatedAt: time.Now()}
	if err := repository.Register(ctx, record, policy.GetLimits()); err != nil {
		t.Fatalf("Register() error = %v, want the former index to be ignored", err)
	}
}

func TestCleanupRepairsSettledOrphansAndSparesPendingReservations(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	lifecycle := policy.GetLifecycle()
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", lifecycle)
	ctx := context.Background()
	now := time.Now()
	repository.now = func() time.Time { return now }

	settled := float64(now.Add(lifecycle.UnusedTTL - 2*repairGracePeriod).UnixMilli())
	pending := float64(now.Add(lifecycle.UnusedTTL).UnixMilli())
	handle.ZAdd(ctx, repository.activeKey(), redis.Z{Score: settled, Member: "dcr_settled-orphan"}, redis.Z{Score: pending, Member: "dcr_pending"})

	if err := repository.CleanupExpired(ctx, 10); err != nil {
		t.Fatalf("CleanupExpired() error = %v", err)
	}

	if members := handle.ZRange(ctx, repository.activeKey(), 0, -1).Val(); len(members) != 1 || members[0] != "dcr_pending" {
		t.Fatalf("index members = %v, want only the pending reservation", members)
	}
}

func TestCleanupRealignsDueScoreOfActiveClient(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	ctx := context.Background()
	now := time.Now().UTC()
	repository.now = func() time.Time { return now }
	record := &DynamicClientRecord{ClientID: "dcr_active", Profile: ProfileMailClientV1, CreatedAt: now.Add(-time.Minute)}

	if err := repository.Register(ctx, record, policy.GetLimits()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	handle.ZAdd(ctx, repository.activeKey(), redis.Z{Score: float64(now.Add(-time.Second).UnixMilli()), Member: record.ClientID})

	if err := repository.CleanupExpired(ctx, 10); err != nil {
		t.Fatalf("CleanupExpired() error = %v", err)
	}

	want := float64(repository.expiresAt(record).UnixMilli())
	if score := handle.ZScore(ctx, repository.activeKey(), record.ClientID).Val(); score != want {
		t.Fatalf("index score = %f, want record expiry %f", score, want)
	}
}

func TestRejectedAttemptSkipsCleanup(t *testing.T) {
	_, handle := newSlotGuardedRedis(t)
	policy := repositoryTestPolicy()
	policy.Limits.SourceRegistrations = 1
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	ctx := context.Background()
	due := redis.Z{Score: float64(time.Now().Add(-time.Minute).UnixMilli()), Member: "dcr_due-orphan"}

	if err := repository.ReserveAttempt(ctx, "source", policy.GetLimits()); err != nil {
		t.Fatalf("first ReserveAttempt() error = %v", err)
	}

	handle.ZAdd(ctx, repository.activeKey(), due)

	if err := repository.ReserveAttempt(ctx, "source", policy.GetLimits()); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second ReserveAttempt() error = %v, want ErrRateLimited", err)
	}

	if handle.ZCard(ctx, repository.activeKey()).Val() != 1 {
		t.Fatal("rejected attempt ran the expiry cleanup")
	}

	if err := repository.ReserveAttempt(ctx, "other-source", policy.GetLimits()); err != nil {
		t.Fatalf("admitted ReserveAttempt() error = %v", err)
	}

	if handle.ZCard(ctx, repository.activeKey()).Val() != 0 {
		t.Fatal("admitted attempt did not run the expiry cleanup")
	}
}
