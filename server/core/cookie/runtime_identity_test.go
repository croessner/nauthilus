// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/redis/go-redis/v9"
)

func TestCanonicalSessionCommitsIdentityByAnchorCAS(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 17, 18, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)

	runtime, err := NewCanonicalRuntime(
		[]byte("canonical-identity-test-secret-32-bytes"), 1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}), "canonical-identity",
		canonicalRuntimeClock{now: now}, sessionstate.NewRandomHandleGenerator(nil), false,
	)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	session, err := runtime.Create(context.Background(), httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	stale := *session

	update := IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", DisplayName: "Alice Example", Protocol: "oidc",
		BackendAffinity: &SessionBackendAffinity{
			Type: "remote", Name: "authority", Protocol: "grpc", Authority: "edge-a", OpaqueToken: "opaque-capability",
		},
	}
	if err = session.CommitIdentity(context.Background(), update); err != nil {
		t.Fatalf("commit identity: %v", err)
	}

	if identity, ok := session.Identity(); !ok || identity.Reference != "identity-42" {
		t.Fatalf("committed identity = %#v, ok = %v", identity, ok)
	}

	if err = stale.CommitIdentity(context.Background(), update); !errors.Is(err, sessionstate.ErrRevisionConflict) {
		t.Fatalf("stale identity commit error = %v, want %v", err, sessionstate.ErrRevisionConflict)
	}
}
