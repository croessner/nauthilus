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
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/idp/clientauth"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/redis/go-redis/v9"
	"pgregory.net/rapid"
)

const (
	modelSessionStore = iota
	modelSessionGet
	modelSessionDelete
	modelSessionAdvance
)

const (
	modelReplayReserve = iota
	modelReplayAdvance
)

type isolatedRedisTestClient struct {
	handle          *redis.Client
	securityManager *rediscli.SecurityManager
}

type sessionModelOperation struct {
	Session OIDCSession
	Code    string
	Kind    int
	TTL     int
}

type sessionModelEntry struct {
	session   OIDCSession
	expiresAt int
}

type replayModelOperation struct {
	ClientID string
	Audience string
	JWTID    string
	Kind     int
	Lifetime int
	Advance  int
}

type replayModelScope struct {
	clientID string
	audience string
	jwtID    string
}

func TestRedisSessionModelProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		operations := rapid.SliceOfN(sessionModelOperationGenerator(), 1, 32).Draw(t, "operations")
		server, _, storage := newIsolatedRedisModelStorage(t)
		model := make(map[string]sessionModelEntry)
		now := 0

		for index, operation := range operations {
			switch operation.Kind {
			case modelSessionStore:
				assertModelSessionStore(t, storage, model, now, operation, index)
			case modelSessionGet:
				assertModelSessionGet(t, storage, model, now, operation.Code, index)
			case modelSessionDelete:
				assertModelSessionDelete(t, storage, model, operation.Code, index)
			case modelSessionAdvance:
				advance := time.Duration(operation.TTL) * time.Second
				now += operation.TTL

				server.FastForward(advance)
				expireSessionModel(model, now)
			}
		}
	})
}

func TestPrivateKeyJWTReplayModelProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		operations := rapid.SliceOfN(replayModelOperationGenerator(), 1, 32).Draw(t, "operations")
		server, _, storage := newIsolatedRedisModelStorage(t)
		model := make(map[replayModelScope]int)
		now := 0

		for index, operation := range operations {
			if operation.Kind == modelReplayAdvance {
				now += operation.Advance
				server.FastForward(time.Duration(operation.Advance) * time.Second)
				expireReplayModel(model, now)

				continue
			}

			assertReplayReservation(t, storage, model, now, operation, index)
		}
	})
}

// GetWriteHandle returns the isolated Redis write handle.
func (client *isolatedRedisTestClient) GetWriteHandle() redis.UniversalClient {
	return client.handle
}

// GetReadHandle returns the isolated Redis read handle.
func (client *isolatedRedisTestClient) GetReadHandle() redis.UniversalClient {
	return client.handle
}

// GetReadHandles reports that the isolated client has no replica handles.
func (client *isolatedRedisTestClient) GetReadHandles() []redis.UniversalClient {
	return nil
}

// GetWritePipeline creates a pipeline on the isolated Redis handle.
func (client *isolatedRedisTestClient) GetWritePipeline() redis.Pipeliner {
	return client.handle.Pipeline()
}

// GetReadPipeline creates a read pipeline on the isolated Redis handle.
func (client *isolatedRedisTestClient) GetReadPipeline() redis.Pipeliner {
	return client.handle.Pipeline()
}

// Close releases the isolated Redis handle.
func (client *isolatedRedisTestClient) Close() {
	_ = client.handle.Close()
}

// GetSecurityManager returns the fixture-owned security manager.
func (client *isolatedRedisTestClient) GetSecurityManager() *rediscli.SecurityManager {
	return client.securityManager
}

// newIsolatedRedisModelStorage constructs storage without changing the global Redis test client.
func newIsolatedRedisModelStorage(t *rapid.T) (*miniredis.Miniredis, *isolatedRedisTestClient, *RedisTokenStorage) {
	t.Helper()

	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})
	client := &isolatedRedisTestClient{
		handle:          handle,
		securityManager: rediscli.NewSecurityManager(secret.Value{}),
	}
	t.Cleanup(client.Close)

	return server, client, NewRedisTokenStorage(client, "model:")
}

// assertModelSessionStore applies one store to Redis and the independent model.
func assertModelSessionStore(
	t *rapid.T,
	storage *RedisTokenStorage,
	model map[string]sessionModelEntry,
	now int,
	operation sessionModelOperation,
	index int,
) {
	t.Helper()

	session := operation.Session

	err := storage.StoreSession(context.Background(), operation.Code, &session, time.Duration(operation.TTL)*time.Second)
	if err != nil {
		t.Fatalf("operation %d StoreSession() error = %v", index, err)
	}

	model[operation.Code] = sessionModelEntry{
		session:   operation.Session,
		expiresAt: now + operation.TTL,
	}
}

// assertModelSessionGet compares Redis visibility with the model.
func assertModelSessionGet(
	t *rapid.T,
	storage *RedisTokenStorage,
	model map[string]sessionModelEntry,
	now int,
	code string,
	index int,
) {
	t.Helper()

	got, err := storage.GetSession(context.Background(), code)

	entry, exists := model[code]
	if !exists || entry.expiresAt <= now {
		if !errors.Is(err, redis.Nil) {
			t.Fatalf("operation %d GetSession(%q) error = %v, want redis.Nil", index, code, err)
		}

		return
	}

	if err != nil {
		t.Fatalf("operation %d GetSession(%q) error = %v", index, code, err)
	}

	if !reflect.DeepEqual(*got, entry.session) {
		t.Fatalf("operation %d GetSession(%q) = %#v, want %#v", index, code, *got, entry.session)
	}
}

// assertModelSessionDelete revokes a session in Redis and the model.
func assertModelSessionDelete(
	t *rapid.T,
	storage *RedisTokenStorage,
	model map[string]sessionModelEntry,
	code string,
	index int,
) {
	t.Helper()

	if err := storage.DeleteSession(context.Background(), code); err != nil {
		t.Fatalf("operation %d DeleteSession(%q) error = %v", index, code, err)
	}

	delete(model, code)
}

// expireSessionModel removes entries at or beyond their modeled expiry.
func expireSessionModel(model map[string]sessionModelEntry, now int) {
	for code, entry := range model {
		if entry.expiresAt <= now {
			delete(model, code)
		}
	}
}

// assertReplayReservation compares scoped single-use behavior with the independent model.
func assertReplayReservation(
	t *rapid.T,
	storage *RedisTokenStorage,
	model map[replayModelScope]int,
	now int,
	operation replayModelOperation,
	index int,
) {
	t.Helper()

	scope := replayModelScope{
		clientID: operation.ClientID,
		audience: operation.Audience,
		jwtID:    operation.JWTID,
	}
	_, reserved := model[scope]
	expiresAt := time.Now().Add(time.Duration(operation.Lifetime) * time.Second)
	err := storage.ReserveClientAssertionJWTID(
		context.Background(),
		operation.ClientID,
		operation.Audience,
		operation.JWTID,
		expiresAt,
	)

	if reserved {
		if !errors.Is(err, ErrClientAssertionReplayDetected) {
			t.Fatalf("operation %d replay reservation error = %v, want replay detected", index, err)
		}

		return
	}

	if err != nil {
		t.Fatalf("operation %d replay reservation error = %v", index, err)
	}

	model[scope] = now + operation.Lifetime + int(clientauth.DefaultPrivateKeyJWTClockSkew/time.Second)
}

// expireReplayModel removes replay markers at or beyond their modeled expiry.
func expireReplayModel(model map[replayModelScope]int, now int) {
	for scope, expiresAt := range model {
		if expiresAt <= now {
			delete(model, scope)
		}
	}
}

// sessionModelOperationGenerator returns bounded synthetic session operations.
func sessionModelOperationGenerator() *rapid.Generator[sessionModelOperation] {
	return rapid.Custom(func(t *rapid.T) sessionModelOperation {
		identifier := rapid.IntRange(0, 4).Draw(t, "identifier")

		return sessionModelOperation{
			Kind: rapid.IntRange(modelSessionStore, modelSessionAdvance).Draw(t, "kind"),
			Code: "code-" + string(rune('a'+identifier)),
			TTL:  rapid.IntRange(1, 5).Draw(t, "ttl"),
			Session: OIDCSession{
				ClientID: "client-" + string(rune('a'+identifier)),
				UserID:   "user-" + string(rune('a'+identifier)),
				Username: "name-" + string(rune('a'+identifier)),
				Scopes:   []string{"openid", "profile"},
			},
		}
	})
}

// replayModelOperationGenerator returns bounded synthetic scoped replay operations.
func replayModelOperationGenerator() *rapid.Generator[replayModelOperation] {
	return rapid.Custom(func(t *rapid.T) replayModelOperation {
		return replayModelOperation{
			Kind:     rapid.IntRange(modelReplayReserve, modelReplayAdvance).Draw(t, "kind"),
			ClientID: rapid.SampledFrom([]string{"client-a", "client-b"}).Draw(t, "client"),
			Audience: rapid.SampledFrom([]string{"https://idp.example/token", "https://idp.example/introspect"}).Draw(t, "audience"),
			JWTID:    rapid.SampledFrom([]string{"jti-a", "jti-b"}).Draw(t, "jti"),
			Lifetime: rapid.IntRange(1, 5).Draw(t, "lifetime"),
			Advance:  rapid.IntRange(1, 12).Draw(t, "advance"),
		}
	})
}
