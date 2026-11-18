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

package mcpserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/mcpserver/mcptest"
	"github.com/croessner/nauthilus/v4/server/supportapi"
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// slowSource holds every collection for a fixed delay or until its context ends.
type slowSource struct {
	delay       time.Duration
	ignoreAbort bool
}

// Name returns the runtime source name.
func (slowSource) Name() string { return supportops.SourceRuntime }

// Kind returns the runtime kind.
func (slowSource) Kind() supportops.SourceKind { return supportops.SourceKindLocalCurrent }

// Collect waits, then reports a complete answer; a context that ends first ends the wait unless ignoreAbort is set.
func (s slowSource) Collect(ctx context.Context, _ supportops.Query) supportops.SourceResult {
	timer := time.NewTimer(s.delay)
	defer timer.Stop()

	if s.ignoreAbort {
		<-timer.C
	} else {
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
	}

	return supportops.SourceResult{Report: supportops.SourceReport{Status: supportops.SourceStatusOK}}
}

// slowServer builds an endpoint whose diagnostics source is slow.
func slowServer(t *testing.T, source slowSource, timeout time.Duration, address string) *Server {
	t.Helper()

	operations, err := supportops.NewService(supportops.Options{Sources: []supportops.Source{source}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	server, err := New(Deps{Settings: &config.RuntimeMCPServerSection{Enabled: true, HostedResource: "support-mcp", Address: address,
		TrustedProxies: []string{"127.0.0.1/32", "::1/128"}, Limits: config.MCPLimits{Timeout: timeout}},
		Tokens: newAuthority(), Services: supportapi.Services{Operations: operations}, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}

	return server
}

// TestToolCallTimeoutInBothEras pins that limits.timeout bounds a tool call in the stateless and the handshake era:
// the slow source is cut and reported as timeout instead of holding the call.
func TestToolCallTimeoutInBothEras(t *testing.T) {
	server := slowServer(t, slowSource{delay: 10 * time.Second}, 200*time.Millisecond, "")

	for _, version := range []string{"2026-07-28", "2025-06-18"} {
		t.Run(version, func(t *testing.T) {
			started := time.Now()

			result, err := connect(t, server, "good", version).CallTool(context.Background(),
				&mcp.CallToolParams{Name: supportapi.OperationDiagnostics, Arguments: map[string]any{"schema_version": "1"}})
			if err != nil || result.IsError {
				t.Fatalf("CallTool = %+v, %v", result, err)
			}

			if elapsed := time.Since(started); elapsed > 5*time.Second ||
				!strings.Contains(result.Content[0].(*mcp.TextContent).Text, `"status":"timeout"`) {
				t.Fatalf("call took %s: %s", elapsed, result.Content[0].(*mcp.TextContent).Text)
			}
		})
	}
}

// TestMergeCancellation pins that the HTTP request context ends a legacy-era tool call and that stop unlinks.
func TestMergeCancellation(t *testing.T) {
	request, cancelRequest := context.WithCancel(context.Background())
	merged, stop := mergeCancellation(context.Background(), request)

	cancelRequest()

	select {
	case <-merged.Done():
	case <-time.After(time.Second):
		t.Fatal("the merged context must end with the request context")
	}

	stop()

	unmerged, stopNil := mergeCancellation(context.Background(), nil)
	defer stopNil()

	if unmerged.Err() != nil {
		t.Fatal("a nil request context must not cancel")
	}
}

// freeAddress returns a loopback address that was free a moment ago.
func freeAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	address := listener.Addr().String()
	_ = listener.Close()

	return address
}

// TestShutdownDrainsInFlightCalls pins that the done channel closes only after a running tool call completed.
func TestShutdownDrainsInFlightCalls(t *testing.T) {
	address := freeAddress(t)
	server := slowServer(t, slowSource{delay: 600 * time.Millisecond, ignoreAbort: true}, 5*time.Second, address)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done, err := server.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "drain-test", Version: "1"}, nil)

	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: "http://" + address + "/mcp",
		HTTPClient: &http.Client{Transport: mcptest.Transport("good")}}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-06-18"})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = session.Close() }()

	finished := make(chan error, 1)

	go func() {
		_, callErr := session.CallTool(context.Background(), &mcp.CallToolParams{Name: supportapi.OperationDiagnostics,
			Arguments: map[string]any{"schema_version": "1"}})
		finished <- callErr
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
		t.Fatal("done closed while a tool call was still running")
	case callErr := <-finished:
		if callErr != nil && !errors.Is(callErr, context.Canceled) {
			t.Fatalf("in-flight call = %v", callErr)
		}
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("done did not close after the drain")
	}
}
