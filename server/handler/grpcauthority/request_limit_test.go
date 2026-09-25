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

	mdlimit "github.com/croessner/nauthilus/v4/server/middleware/limit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRequestLimitInterceptorRejectsCallsBeyondTheSharedBudget(t *testing.T) {
	limit := mdlimit.NewLimitCounter(1)
	interceptor := requestLimitInterceptor(limit)
	info := &grpc.UnaryServerInfo{FullMethod: "/nauthilus.auth.v1.AuthService/Authenticate"}

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		_, err := interceptor(t.Context(), nil, info, func(context.Context, any) (any, error) {
			close(entered)
			<-release

			return "ok", nil
		})
		done <- err
	}()

	<-entered

	// The HTTP API draws on the same counter, so it sees the budget as exhausted too.
	if _, acquired := limit.TryAcquire(); acquired {
		t.Fatal("the shared budget accepted a second request while the gRPC call held the only slot")
	}

	_, err := interceptor(t.Context(), nil, info, func(context.Context, any) (any, error) {
		t.Fatal("a call beyond the budget reached the handler")

		return nil, nil
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("call beyond the budget error = %v, want ResourceExhausted", err)
	}

	close(release)

	if err := <-done; err != nil {
		t.Fatalf("admitted call error = %v", err)
	}

	if _, err := interceptor(t.Context(), nil, info, func(context.Context, any) (any, error) { return "ok", nil }); err != nil {
		t.Fatalf("call after the slot was released error = %v", err)
	}

	if limit.CurrentConnections != 0 {
		t.Fatalf("active requests after all calls = %d, want 0", limit.CurrentConnections)
	}
}

func TestRequestLimitInterceptorWithoutLimitPassesCallsThrough(t *testing.T) {
	interceptor := requestLimitInterceptor(nil)

	response, err := interceptor(t.Context(), nil, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		return "ok", nil
	})
	if err != nil || response != "ok" {
		t.Fatalf("unlimited call = %v, %v", response, err)
	}
}
