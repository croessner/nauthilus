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

package grpcauthority

import (
	"context"
	"testing"
	"time"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"

	"google.golang.org/grpc/keepalive"
)

func TestConnectionLifetimePolicyDefaults(t *testing.T) {
	policy := newConnectionLifetimePolicy(&config.RuntimeGRPCKeepAliveSection{})

	wantParameters := keepalive.ServerParameters{
		MaxConnectionAge:      5 * time.Minute,
		MaxConnectionAgeGrace: 60 * time.Second,
	}
	if policy.parameters != wantParameters {
		t.Fatalf("server parameters = %+v, want %+v", policy.parameters, wantParameters)
	}

	wantEnforcement := keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}
	if policy.enforcement != wantEnforcement {
		t.Fatalf("enforcement policy = %+v, want %+v", policy.enforcement, wantEnforcement)
	}

	if got := len(policy.serverOptions()); got != 2 {
		t.Fatalf("server options = %d, want keepalive parameters and enforcement policy", got)
	}
}

func TestConnectionLifetimePolicyExplicitSettings(t *testing.T) {
	age := 2 * time.Minute
	grace := 90 * time.Second
	permitWithoutStream := false

	policy := newConnectionLifetimePolicy(&config.RuntimeGRPCKeepAliveSection{
		MaxConnectionAge:      &age,
		MaxConnectionAgeGrace: &grace,
		PermitWithoutStream:   &permitWithoutStream,
		MaxConnectionIdle:     time.Minute,
		MinPingInterval:       30 * time.Second,
	})

	wantParameters := keepalive.ServerParameters{
		MaxConnectionIdle:     time.Minute,
		MaxConnectionAge:      age,
		MaxConnectionAgeGrace: grace,
	}
	if policy.parameters != wantParameters {
		t.Fatalf("server parameters = %+v, want %+v", policy.parameters, wantParameters)
	}

	wantEnforcement := keepalive.EnforcementPolicy{MinTime: 30 * time.Second}
	if policy.enforcement != wantEnforcement {
		t.Fatalf("enforcement policy = %+v, want %+v", policy.enforcement, wantEnforcement)
	}
}

// TestNewServerAgesConnectionsWithoutBreakingInFlightRPCs proves that the
// authority listener sends GOAWAY after max_connection_age, that an RPC still in
// flight at that moment completes within the grace period, and that the client
// reconnects for the next RPC. That reconnect is what lets connection-level load
// balancers redistribute long-lived clients.
func TestNewServerAgesConnectionsWithoutBreakingInFlightRPCs(t *testing.T) {
	cases := []struct {
		name     string
		age      time.Duration
		minDials int32
		maxDials int32
	}{
		// The second connection may age out as well, so a lazy third dial is tolerated.
		{name: "ageing enabled", age: 100 * time.Millisecond, minDials: 2, maxDials: 3},
		{name: "ageing disabled", age: 0, minDials: 1, maxDials: 1},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{})
			grace := time.Duration(0)

			if testCase.age > 0 {
				grace = 5 * time.Second
			}

			cfg.Runtime.Servers.GRPC.Authority.KeepAlive = config.RuntimeGRPCKeepAliveSection{
				MaxConnectionAge:      &testCase.age,
				MaxConnectionAgeGrace: &grace,
			}

			service := &slowAuthService{
				recordingService: recordingService{authOutcome: newBufconnAuthOutcome(core.AuthDecisionOK, "ageing-session")},
				delay:            400 * time.Millisecond,
			}
			client, dials := newCountingBufconnAuthServiceClient(t, cfg, service)

			authenticateOK(t, client)
			authenticateOK(t, client)

			if got := dials.Load(); got < testCase.minDials || got > testCase.maxDials {
				t.Fatalf("transport dials = %d, want %d..%d", got, testCase.minDials, testCase.maxDials)
			}
		})
	}
}

// authenticateOK issues one authenticated RPC and requires a transport-level success.
func authenticateOK(t *testing.T, client authv1.AuthServiceClient) {
	t.Helper()

	ctx, cancel := context.WithTimeout(outgoingBasicAuthContext(context.Background()), 5*time.Second)
	defer cancel()

	response, err := client.Authenticate(ctx, &authv1.AuthRequest{
		Username: "ageing@example.test",
		Password: "secret",
		ClientIp: "203.0.113.41",
		Protocol: "imap",
	})
	if err != nil {
		t.Fatalf("Authenticate returned transport error: %v", err)
	}

	if !response.GetOk() {
		t.Fatalf("Authenticate response = %+v, want ok", response)
	}
}

// slowAuthService delays authentication so an RPC outlives the connection age.
type slowAuthService struct {
	recordingService
	delay time.Duration
}

// Authenticate waits for the configured delay before returning the recorded outcome.
func (s *slowAuthService) Authenticate(ctx context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return s.recordingService.Authenticate(ctx, input)
}
