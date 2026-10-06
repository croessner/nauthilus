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

package main

import (
	"context"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/redis/go-redis/v9"
)

// dedupRedis models SET NX without external services; other commands are deliberately unavailable.
type dedupRedis struct {
	pluginapi.Redis
	writer dedupWriter
}

// dedupWriter implements the only Redis command needed by admission.
type dedupWriter struct {
	redis.Cmdable
	keys map[string]bool
}

// Write exposes the in-memory SET NX implementation.
func (r *dedupRedis) Write() redis.Cmdable { return &r.writer }

// Keys leaves test keys unprefixed.
func (r *dedupRedis) Keys() pluginapi.RedisKeyBuilder { return nil }

// SetNX accepts only the first occurrence of each key.
func (r *dedupWriter) SetNX(_ context.Context, key string, _ any, _ time.Duration) *redis.BoolCmd {
	exists := r.keys[key]
	r.keys[key] = true

	return redis.NewBoolResult(!exists, nil)
}

// TestDedupSeparatesLoginContexts reproduces collisions between distinct authentication contexts.
func TestDedupSeparatesLoginContexts(t *testing.T) {
	cases := []struct {
		name   string
		change func(*pluginapi.RequestSnapshot)
	}{
		{"protocol", func(s *pluginapi.RequestSnapshot) { s.Protocol = "smtp" }},
		{"service", func(s *pluginapi.RequestSnapshot) { s.Service = "idp" }},
		{"method", func(s *pluginapi.RequestSnapshot) { s.Method = "oauthbearer" }},
		{"OIDC client", func(s *pluginapi.RequestSnapshot) { s.IDP.ClientID = "another-client" }},
		{"grant", func(s *pluginapi.RequestSnapshot) { s.IDP.GrantType = "refresh_token" }},
		{"client", func(s *pluginapi.RequestSnapshot) { s.ClientID = "other-client" }},
		{"OIDC projection", func(s *pluginapi.RequestSnapshot) { s.OIDCCID = "other-oidc" }},
		{"SAML service", func(s *pluginapi.RequestSnapshot) { s.SAMLEntityID = "other-saml" }},
		{"MFA method", func(s *pluginapi.RequestSnapshot) { s.IDP.MFAMethod = "webauthn" }},
		{"MFA outcome", func(s *pluginapi.RequestSnapshot) { s.IDP.MFACompleted = true }},
		{"authorization", func(s *pluginapi.RequestSnapshot) { s.Runtime.Authorized = true }},
		{"status", func(s *pluginapi.RequestSnapshot) { s.Diagnostics.HTTPStatus = 403 }},
		{"reason", func(s *pluginapi.RequestSnapshot) { s.Diagnostics.StatusMessage = "denied" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := decodeModuleConfig(nil)
			if err != nil {
				t.Fatal(err)
			}

			state := pluginState{config: cfg, redis: &dedupRedis{writer: dedupWriter{keys: map[string]bool{}}}}
			snapshot := testRequest(t, requestOptions{authenticated: true}).Snapshot
			assertDedupAdmission(t, state, snapshot, true)
			assertDedupAdmission(t, state, snapshot, false)
			tc.change(&snapshot)
			assertDedupAdmission(t, state, snapshot, true)
		})
	}
}

// assertDedupAdmission checks that the admission decision did not fail open.
func assertDedupAdmission(t *testing.T, state pluginState, snapshot pluginapi.RequestSnapshot, want bool) {
	t.Helper()

	allowed, err := allowLoginWrite(context.Background(), state, snapshot)
	if err != nil || allowed != want {
		t.Fatalf("dedup allowed=%v error=%v, want %v", allowed, err, want)
	}
}

// TestDedupOutcomeConfiguration covers independently enabled success and failure deduplication.
func TestDedupOutcomeConfiguration(t *testing.T) {
	for _, success := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			cfg, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{"dedup_success": success, "dedup_failure": failure}))
			if err != nil {
				t.Fatal(err)
			}

			state := pluginState{config: cfg, redis: &dedupRedis{writer: dedupWriter{keys: map[string]bool{}}}}

			for _, authenticated := range []bool{true, false} {
				snapshot := testRequest(t, requestOptions{authenticated: authenticated}).Snapshot

				enabled := failure
				if authenticated {
					enabled = success
				}

				assertDedupAdmission(t, state, snapshot, true)
				assertDedupAdmission(t, state, snapshot, !enabled)
			}
		}
	}
}

// TestDedupDefaultsAndRequestMetadata keeps defaults stable and permits time-window aggregation.
func TestDedupDefaultsAndRequestMetadata(t *testing.T) {
	cfg, err := decodeModuleConfig(nil)
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.DedupSuccess || cfg.DedupFailure {
		t.Fatal("unexpected dedup defaults")
	}

	state := pluginState{config: cfg, redis: &dedupRedis{writer: dedupWriter{keys: map[string]bool{}}}}
	snapshot := testRequest(t, requestOptions{authenticated: true}).Snapshot
	assertDedupAdmission(t, state, snapshot, true)
	snapshot.Session = "new-request"
	snapshot.ExternalSessionID = "new-external-session"
	snapshot.ClientPort = "54321"
	snapshot.Diagnostics.LatencyMillis++
	assertDedupAdmission(t, state, snapshot, false)

	state.redis = nil
	snapshot.Runtime.Authenticated = false
	assertDedupAdmission(t, state, snapshot, true)
	state.config.DedupSuccess = false
	snapshot.Runtime.Authenticated = true
	assertDedupAdmission(t, state, snapshot, true)
}
