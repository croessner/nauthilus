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
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/redis/go-redis/v9"
)

func TestRegistrationServicePersistsResolvableConstrainedClient(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
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
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
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

func TestRegisterDoesNotPerformUnboundedExpiredCleanup(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	policy := repositoryTestPolicy()
	policy.Limits.ActiveClients = 1
	repository := NewRepository(rediscli.NewTestClient(handle), "test:", policy.GetLifecycle())
	now := time.Now().UTC()
	repository.now = func() time.Time { return now }
	activeKey := repository.registryKey("active")

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
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
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

	if !server.Exists("test:oidc:dcr:{registry}:tombstone:" + response.ClientID) {
		t.Fatal("expired client tombstone missing")
	}
}

func TestRepositoryTouchesOnlyExplicitSuccessfulUse(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
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

	score, err := server.ZScore("test:oidc:dcr:{registry}:active", response.ClientID)
	if err != nil {
		t.Fatalf("ZScore() error = %v", err)
	}

	wantScore := float64(repository.now().Add(policy.GetLifecycle().InactivityTTL).UnixMilli())
	if score != wantScore {
		t.Fatalf("active score = %f, want %f", score, wantScore)
	}
}

// repositoryTestPolicy returns a complete test policy for persistence tests.
func repositoryTestPolicy() config.OIDCDynamicClientRegistrationConfig {
	return config.OIDCDynamicClientRegistrationConfig{
		Enabled:        true,
		RequiredScopes: []string{"openid"},
		SourceHMACKey:  secret.New("0123456789abcdef0123456789abcdef"),
	}
}
