// Copyright (C) 2024 Christian Rößner
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

package priorityqueue

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
)

func TestLDAPQueueRouting(t *testing.T) {
	assertLDAPQueueRouting(t, NewLDAPRequestQueue(nil), newLDAPRoutingRequest("default"), newLDAPRoutingRequest("mail"), "request")
}

func TestLDAPAuthQueueRouting(t *testing.T) {
	assertLDAPQueueRouting(t, NewLDAPAuthRequestQueue(nil), newLDAPAuthRoutingRequest("default"), newLDAPAuthRoutingRequest("mail"), "auth request")
}

type ldapRoutingQueue[T any] interface {
	AddPoolName(string)
	Push(*T, int)
	Pop(string) *T
}

// newLDAPRoutingRequest creates a lookup request for queue routing tests.
func newLDAPRoutingRequest(poolName string) *bktype.LDAPRequest {
	return &bktype.LDAPRequest{PoolName: poolName, LDAPReplyChan: make(chan *bktype.LDAPReply, 1), HTTPClientContext: context.Background()}
}

// newLDAPAuthRoutingRequest creates an auth request for queue routing tests.
func newLDAPAuthRoutingRequest(poolName string) *bktype.LDAPAuthRequest {
	return &bktype.LDAPAuthRequest{PoolName: poolName, LDAPReplyChan: make(chan *bktype.LDAPReply, 1), HTTPClientContext: context.Background()}
}

// assertLDAPQueueRouting verifies that an LDAP queue pops requests from the addressed pool only.
func assertLDAPQueueRouting[T any](t *testing.T, q ldapRoutingQueue[T], reqDefault *T, reqMail *T, label string) {
	t.Helper()

	q.AddPoolName("default")
	q.AddPoolName("mail")

	// Push in reverse order to ensure true routing, not FIFO across pools
	q.Push(reqMail, PriorityLow)
	q.Push(reqDefault, PriorityHigh)

	gotDefault := popLDAPRoutingRequest(t, q, "default", "timeout waiting for default "+label+" pop")
	if gotDefault != reqDefault {
		t.Fatalf("expected default %s, got %+v", label, gotDefault)
	}

	gotMail := popLDAPRoutingRequest(t, q, "mail", "timeout waiting for mail "+label+" pop")
	if gotMail != reqMail {
		t.Fatalf("expected mail %s, got %+v", label, gotMail)
	}
}

// popLDAPRoutingRequest waits for one routed LDAP queue pop result.
func popLDAPRoutingRequest[T any](t *testing.T, q ldapRoutingQueue[T], poolName string, timeoutMessage string) *T {
	t.Helper()

	gotCh := make(chan *T, 1)
	go func() { gotCh <- q.Pop(poolName) }()

	select {
	case got := <-gotCh:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal(timeoutMessage)
	}

	return nil
}

func TestLuaQueueRouting(t *testing.T) {
	q := NewLuaRequestQueue(nil)
	q.AddBackendName("default")
	q.AddBackendName("custom")

	reqDefault := &bktype.LuaRequest{BackendName: "default"}
	reqCustom := &bktype.LuaRequest{BackendName: "custom"}

	q.Push(reqCustom, PriorityLow)
	q.Push(reqDefault, PriorityHigh)

	gotDefaultCh := make(chan *bktype.LuaRequest, 1)
	go func() { gotDefaultCh <- q.Pop("default") }()

	select {
	case got := <-gotDefaultCh:
		if got != reqDefault {
			t.Fatalf("expected default lua request, got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for default lua pop")
	}

	gotCustomCh := make(chan *bktype.LuaRequest, 1)
	go func() { gotCustomCh <- q.Pop("custom") }()

	select {
	case got := <-gotCustomCh:
		if got != reqCustom {
			t.Fatalf("expected custom lua request, got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for custom lua pop")
	}
}

func TestLDAPQueueWarnsWithoutWorker(t *testing.T) {
	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	q := NewLDAPRequestQueue(logger)
	ctx := context.Background()
	request := &bktype.LDAPRequest{
		PoolName:          "missing",
		LDAPReplyChan:     make(chan *bktype.LDAPReply, 1),
		HTTPClientContext: ctx,
	}

	q.Push(request, PriorityLow)
	q.Push(request, PriorityLow)

	output := buf.String()
	if count := strings.Count(output, "LDAP lookup request queued without active worker"); count != 1 {
		t.Fatalf("expected single warning, got %d in output: %s", count, output)
	}
}

func TestLuaQueueWarnsWithoutWorker(t *testing.T) {
	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	q := NewLuaRequestQueue(logger)
	request := &bktype.LuaRequest{BackendName: "missing"}

	q.Push(request, PriorityLow)
	q.Push(request, PriorityLow)

	output := buf.String()
	if count := strings.Count(output, "Lua request queued without active worker"); count != 1 {
		t.Fatalf("expected single warning, got %d in output: %s", count, output)
	}
}

func TestLDAPQueuePopWithContextReturnsNilOnCancel(t *testing.T) {
	q := NewLDAPRequestQueue(nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := q.PopWithContext(ctx, "default"); got != nil {
		t.Fatalf("expected nil request, got %#v", got)
	}
}

func TestLDAPAuthQueuePopWithContextReturnsNilOnCancel(t *testing.T) {
	q := NewLDAPAuthRequestQueue(nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := q.PopWithContext(ctx, "default"); got != nil {
		t.Fatalf("expected nil request, got %#v", got)
	}
}

func TestLuaQueuePopWithContextReturnsNilOnCancel(t *testing.T) {
	q := NewLuaRequestQueue(nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := q.PopWithContext(ctx, "default"); got != nil {
		t.Fatalf("expected nil request, got %#v", got)
	}
}
