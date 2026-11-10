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
	"errors"
	"fmt"
	"log/slog"
	"testing"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/conncause"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/secret"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestUnaryServerInterceptorAnchorsRequestContext pins that the authority chain anchors the call context, so
// failure logs below the transport can classify a cancellation against the own call.
func TestUnaryServerInterceptorAnchorsRequestContext(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{})
	interceptor := UnaryServerInterceptor(ServerDeps{Cfg: cfg, Logger: slog.Default()})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", basicAuthorization("grpc-client", "grpc-secret-1234")),
	)

	var anchored bool

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, func(ctx context.Context, _ any) (any, error) {
		_, anchored = conncause.RequestContext(ctx)

		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if !anchored {
		t.Fatal("authority call context was not anchored as the request context")
	}
}

// TestResolveApplicationOutcomePassesTheCallContext pins that the temporary-failure log receives the gRPC call
// context itself, and that cancellation errors keep their gRPC status instead of reaching the temporary failure.
func TestResolveApplicationOutcomePassesTheCallContext(t *testing.T) {
	callCtx := conncause.WithRequestContext(context.Background())

	var received context.Context

	tempFail := func(ctx context.Context, _ core.AuthInput, _ error) *core.AuthOutcome {
		received = ctx

		return &core.AuthOutcome{}
	}

	_, err := resolveApplicationOutcome(callCtx, core.AuthInput{}, (*core.AuthOutcome)(nil), errors.New("backend failed"), tempFail)
	if err != nil {
		t.Fatalf("resolveApplicationOutcome() error = %v", err)
	}

	if received != callCtx {
		t.Fatal("temporary failure did not receive the gRPC call context")
	}

	received = nil

	_, err = resolveApplicationOutcome(callCtx, core.AuthInput{}, (*core.AuthOutcome)(nil),
		fmt.Errorf("native plugin refresh_user_data: %w", context.Canceled), tempFail)
	if status.Code(err) != codes.Canceled || received != nil {
		t.Fatalf("canceled application error = %v (tempfail called: %v), want gRPC Canceled", err, received != nil)
	}
}
