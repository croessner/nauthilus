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
		change func(*pluginapi.PostActionRequest)
	}{
		{"protocol", func(r *pluginapi.PostActionRequest) { r.Snapshot.Protocol = "smtp" }},
		{"service", func(r *pluginapi.PostActionRequest) { r.Snapshot.Service = "idp" }},
		{"method", func(r *pluginapi.PostActionRequest) { r.Snapshot.Method = "oauthbearer" }},
		{"OIDC client", func(r *pluginapi.PostActionRequest) { r.Snapshot.IDP.ClientID = "another-client" }},
		{"grant", func(r *pluginapi.PostActionRequest) { r.Snapshot.IDP.GrantType = "refresh_token" }},
		{"client", func(r *pluginapi.PostActionRequest) { r.Snapshot.ClientID = "other-client" }},
		{"OIDC projection", func(r *pluginapi.PostActionRequest) { r.Snapshot.OIDCCID = "other-oidc" }},
		{"SAML service", func(r *pluginapi.PostActionRequest) { r.Snapshot.SAMLEntityID = "other-saml" }},
		{"MFA method", func(r *pluginapi.PostActionRequest) { r.Snapshot.IDP.MFAMethod = "webauthn" }},
		{"MFA outcome", func(r *pluginapi.PostActionRequest) { r.Snapshot.IDP.MFACompleted = true }},
		{"authorization", func(r *pluginapi.PostActionRequest) { r.Snapshot.Runtime.Authorized = true }},
		{"status", func(r *pluginapi.PostActionRequest) { r.Snapshot.Diagnostics.HTTPStatus = 403 }},
		{"reason", func(r *pluginapi.PostActionRequest) { r.Snapshot.Diagnostics.StatusMessage = "denied" }},
		{"flow", func(r *pluginapi.PostActionRequest) { r.Snapshot.IDP.FlowRef = "0123456789abcdef0123456789abcdef" }},
		{"outcome marker", func(r *pluginapi.PostActionRequest) { r.Outcome.OutcomeMarker = "auth.outcome.other" }},
		{"rule", func(r *pluginapi.PostActionRequest) { r.Outcome.PolicyRule = "other_rule" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := decodeModuleConfig(nil)
			if err != nil {
				t.Fatal(err)
			}

			state := pluginState{config: cfg, redis: &dedupRedis{writer: dedupWriter{keys: map[string]bool{}}}}
			request := testRequest(t, requestOptions{authenticated: true})
			assertDedupAdmission(t, state, request, true)
			assertDedupAdmission(t, state, request, false)
			tc.change(&request)
			assertDedupAdmission(t, state, request, true)
		})
	}
}

// assertDedupAdmission checks that the admission decision did not fail open.
func assertDedupAdmission(t *testing.T, state pluginState, request pluginapi.PostActionRequest, want bool) {
	t.Helper()

	allowed, err := allowLoginWrite(context.Background(), state, request)
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
				request := testRequest(t, requestOptions{authenticated: authenticated})

				enabled := failure
				if authenticated {
					enabled = success
				}

				assertDedupAdmission(t, state, request, true)
				assertDedupAdmission(t, state, request, !enabled)
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
	request := testRequest(t, requestOptions{authenticated: true})
	assertDedupAdmission(t, state, request, true)
	request.Snapshot.Session = "new-request"
	request.Snapshot.ExternalSessionID = "new-external-session"
	request.Snapshot.ClientPort = "54321"
	request.Snapshot.Diagnostics.LatencyMillis++
	assertDedupAdmission(t, state, request, false)

	state.redis = nil
	request.Outcome.Decision = pluginapi.AuthOutcomeFail
	assertDedupAdmission(t, state, request, true)
	state.config.DedupSuccess = false
	request.Outcome.Decision = pluginapi.AuthOutcomeOK
	assertDedupAdmission(t, state, request, true)
}

// TestDedupNeverAggregatesTempFailOrUnknownOutcomes pins that diagnostic evidence of temporary failures and unsealed
// outcomes is kept even when both dedup switches are enabled; the switch follows the sealed outcome, not the
// capture-time Authenticated flag.
func TestDedupNeverAggregatesTempFailOrUnknownOutcomes(t *testing.T) {
	cfg, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{"dedup_success": true, "dedup_failure": true}))
	if err != nil {
		t.Fatal(err)
	}

	state := pluginState{config: cfg, redis: &dedupRedis{writer: dedupWriter{keys: map[string]bool{}}}}

	for _, outcome := range []pluginapi.AuthOutcome{
		{Decision: pluginapi.AuthOutcomeTempFail, Known: true},
		{Decision: pluginapi.AuthOutcomeUnknown},
	} {
		request := testRequest(t, requestOptions{authenticated: true, outcome: &outcome})
		assertDedupAdmission(t, state, request, true)
		assertDedupAdmission(t, state, request, true)
	}
}
