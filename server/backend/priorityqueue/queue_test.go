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

	"github.com/croessner/nauthilus/server/backend/bktype"
)

func TestLDAPQueueRouting(t *testing.T) {
	q := NewLDAPRequestQueue(nil)
	q.AddPoolName("default")
	q.AddPoolName("mail")

	ctx := context.Background()

	reqDefault := &bktype.LDAPRequest{PoolName: "default", LDAPReplyChan: make(chan *bktype.LDAPReply, 1), HTTPClientContext: ctx}
	reqMail := &bktype.LDAPRequest{PoolName: "mail", LDAPReplyChan: make(chan *bktype.LDAPReply, 1), HTTPClientContext: ctx}

	// Push in reverse order to ensure true routing, not FIFO across pools
	q.Push(reqMail, PriorityLow)
	q.Push(reqDefault, PriorityHigh)

	// Pop for default should never return the mail request
	gotDefaultCh := make(chan *bktype.LDAPRequest, 1)
	go func() { gotDefaultCh <- q.Pop("default") }()

	select {
	case got := <-gotDefaultCh:
		if got != reqDefault {
			t.Fatalf("expected default request, got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for default pop")
	}

	// Pop for mail should now return the mail request
	gotMailCh := make(chan *bktype.LDAPRequest, 1)
	go func() { gotMailCh <- q.Pop("mail") }()

	select {
	case got := <-gotMailCh:
		if got != reqMail {
			t.Fatalf("expected mail request, got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for mail pop")
	}
}

func TestLDAPAuthQueueRouting(t *testing.T) {
	q := NewLDAPAuthRequestQueue(nil)
	q.AddPoolName("default")
	q.AddPoolName("mail")

	ctx := context.Background()

	reqDefault := &bktype.LDAPAuthRequest{PoolName: "default", LDAPReplyChan: make(chan *bktype.LDAPReply, 1), HTTPClientContext: ctx}
	reqMail := &bktype.LDAPAuthRequest{PoolName: "mail", LDAPReplyChan: make(chan *bktype.LDAPReply, 1), HTTPClientContext: ctx}

	q.Push(reqMail, PriorityLow)
	q.Push(reqDefault, PriorityHigh)

	gotDefaultCh := make(chan *bktype.LDAPAuthRequest, 1)
	go func() { gotDefaultCh <- q.Pop("default") }()

	select {
	case got := <-gotDefaultCh:
		if got != reqDefault {
			t.Fatalf("expected default auth request, got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for default auth pop")
	}

	gotMailCh := make(chan *bktype.LDAPAuthRequest, 1)
	go func() { gotMailCh <- q.Pop("mail") }()

	select {
	case got := <-gotMailCh:
		if got != reqMail {
			t.Fatalf("expected mail auth request, got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for mail auth pop")
	}
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
