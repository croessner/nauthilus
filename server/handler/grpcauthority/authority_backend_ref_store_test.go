// Copyright (C) 2026 Christian Roessner
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

package grpcauthority

import (
	"context"
	"errors"
	"testing"
	"time"

	commonv1 "github.com/croessner/nauthilus/v3/server/grpcapi/common/v1"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/go-redis/redismock/v9"
)

const (
	authorityTestAuthority    = "authority-a"
	authorityTestBackendName  = "canonical-backend"
	authorityTestEdgeCluster  = "edge-cluster-a"
	authorityTestEdgeInstance = "edge-instance-a"
	authorityTestPrincipal    = "edge-principal"
	authorityTestProtocol     = "imap"
	authorityTestType         = "test"
	authorityTestUsername     = "identity-user@example.test"
	authorityTestUID          = "uid"
	authorityTestOK           = "ok"
	authorityTestScopeClaim   = "scope"
	authorityTestLanguage     = "en"
	authorityTestRecoveryCode = "recovery-1"
	authorityTestSecurityKey  = "security-key-a"
)

func TestRedisBackendRefStoreIssuesOpaqueReferences(t *testing.T) {
	ctx := context.Background()
	store, mock := newRedisBackendRefStoreForTest(t, time.Minute)
	payload := backendRefPayloadForTest()
	payload.IssuedAt = time.Time{}
	payload.ExpiresAt = time.Time{}

	mock.Regexp().ExpectSet("test:grpc-authority-backend-ref:.*", ".*", time.Minute).SetVal("OK")

	ref, err := store.Issue(ctx, payload)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if ref.GetOpaqueToken() == "" {
		t.Fatal("Issue returned an empty opaque token")
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestRedisBackendRefStoreValidatesAuthorityBindings(t *testing.T) {
	ctx := context.Background()
	store, mock := newRedisBackendRefStoreForTest(t, time.Minute)
	payload := backendRefPayloadForTest()
	ref, encoded := encodedBackendRefPayloadForTest(t, store, payload)

	mock.ExpectGet(store.key(ref.GetOpaqueToken())).SetVal(encoded)

	_, err := store.Validate(ctx, ref, backendRefValidationForTest(authorityTestPrincipal, authorityTestEdgeCluster, AuthorityOperationGetMFAState))
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	cases := []struct {
		name       string
		validation BackendRefValidation
		wantErr    error
	}{
		{
			name:       "wrong service principal",
			validation: backendRefValidationForTest("other-principal", authorityTestEdgeCluster, AuthorityOperationGetMFAState),
			wantErr:    ErrBackendRefPrincipalMismatch,
		},
		{
			name:       "wrong edge cluster",
			validation: backendRefValidationForTest(authorityTestPrincipal, "other-cluster", AuthorityOperationGetMFAState),
			wantErr:    ErrBackendRefEdgeClusterMismatch,
		},
		{
			name:       "wrong operation",
			validation: backendRefValidationForTest(authorityTestPrincipal, authorityTestEdgeCluster, AuthorityOperationDeleteTOTP),
			wantErr:    ErrBackendRefOperationDenied,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mock.ExpectGet(store.key(ref.GetOpaqueToken())).SetVal(encoded)

			_, err = store.Validate(ctx, ref, testCase.validation)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Validate error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func TestRedisBackendRefStoreRejectsExpiredReferences(t *testing.T) {
	ctx := context.Background()
	store, mock := newRedisBackendRefStoreForTest(t, time.Second)
	ref := backendRefProtoForTest("expired-token")
	mock.ExpectGet(store.key(ref.GetOpaqueToken())).RedisNil()

	_, err := store.Validate(ctx, ref, backendRefValidationForTest(authorityTestPrincipal, authorityTestEdgeCluster, AuthorityOperationGetMFAState))
	if !errors.Is(err, ErrBackendRefExpired) {
		t.Fatalf("Validate error = %v, want %v", err, ErrBackendRefExpired)
	}
}

func TestRedisBackendRefStoreIgnoresTamperedRequestEchoes(t *testing.T) {
	ctx := context.Background()
	store, mock := newRedisBackendRefStoreForTest(t, time.Minute)
	payload := backendRefPayloadForTest()
	ref, encoded := encodedBackendRefPayloadForTest(t, store, payload)
	mock.ExpectGet(store.key(ref.GetOpaqueToken())).SetVal(encoded)

	tampered := &commonv1.BackendRef{
		Type:        "lua",
		Name:        "attacker-controlled",
		Protocol:    "smtp",
		Authority:   "forged-authority",
		OpaqueToken: ref.GetOpaqueToken(),
	}

	resolved, err := store.Validate(ctx, tampered, backendRefValidationForTest(authorityTestPrincipal, authorityTestEdgeCluster, AuthorityOperationGetMFAState))
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if resolved.Type != payload.Type || resolved.Name != payload.Name || resolved.Protocol != payload.Protocol || resolved.Authority != payload.Authority {
		t.Fatalf("resolved payload = %#v, want Redis-backed payload %#v", resolved, payload)
	}
}

func newRedisBackendRefStoreForTest(t *testing.T, ttl time.Duration) (*RedisBackendRefStore, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)

	return NewRedisBackendRefStore(client, RedisBackendRefStoreOptions{
		KeyPrefix: "test:grpc-authority-backend-ref:",
		TTL:       ttl,
		Authority: authorityTestAuthority,
	}), mock
}

func encodedBackendRefPayloadForTest(
	t *testing.T,
	store *RedisBackendRefStore,
	payload BackendRefPayload,
) (*commonv1.BackendRef, string) {
	t.Helper()

	payload.SchemaVersion = backendRefSchemaVersion

	encoded, err := store.encodePayload(payload)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}

	return payload.backendRef("opaque-input-token"), encoded
}

func backendRefPayloadForTest() BackendRefPayload {
	now := time.Now().UTC()

	return BackendRefPayload{
		Type:             authorityTestType,
		Name:             authorityTestBackendName,
		Protocol:         authorityTestProtocol,
		Authority:        authorityTestAuthority,
		Username:         authorityTestUsername,
		Account:          authorityTestUsername,
		ServicePrincipal: authorityTestPrincipal,
		EdgeClusterID:    authorityTestEdgeCluster,
		EdgeInstanceID:   authorityTestEdgeInstance,
		AllowedOperations: []AuthorityOperation{
			AuthorityOperationResolveUser,
			AuthorityOperationGetMFAState,
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Minute),
	}
}

func backendRefValidationForTest(
	principal string,
	edgeCluster string,
	operation AuthorityOperation,
) BackendRefValidation {
	return BackendRefValidation{
		ServicePrincipal: principal,
		EdgeClusterID:    edgeCluster,
		Username:         authorityTestUsername,
		Operation:        operation,
	}
}
