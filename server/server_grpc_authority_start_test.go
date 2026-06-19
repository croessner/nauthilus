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

package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	handlerauthority "github.com/croessner/nauthilus/v3/server/handler/grpcauthority"
)

func TestStartGRPCAuthorityForHTTPFailsInitialStartup(t *testing.T) {
	startErr := errors.New("bind failed")
	store := &contextStore{}

	err := startGRPCAuthorityForHTTP(context.Background(), store, nil, nil, slog.Default(), httpServerStartOptions{
		grpcAuthorityStarter: failingGRPCAuthorityStarter(startErr),
	})
	if !errors.Is(err, startErr) {
		t.Fatalf("error = %v, want %v", err, startErr)
	}
}

func TestStartGRPCAuthorityForHTTPAllowsRestartFallback(t *testing.T) {
	startErr := errors.New("bind failed")
	store := &contextStore{
		grpcAuthorityDone: closedDoneChannel(),
	}

	err := startGRPCAuthorityForHTTP(context.Background(), store, nil, nil, slog.Default(), httpServerStartOptions{
		continueHTTPOnGRPCAuthorityError: true,
		grpcAuthorityStarter:             failingGRPCAuthorityStarter(startErr),
	})
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}

	if store.grpcAuthorityDone != nil {
		t.Fatal("grpcAuthorityDone was not cleared after tolerated gRPC start failure")
	}
}

func failingGRPCAuthorityStarter(err error) grpcAuthorityStarter {
	return func(context.Context, handlerauthority.ServerDeps) (<-chan struct{}, error) {
		return nil, err
	}
}

func closedDoneChannel() <-chan struct{} {
	done := make(chan struct{})
	close(done)

	return done
}
