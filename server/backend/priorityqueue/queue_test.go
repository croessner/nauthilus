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
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
)

func TestLDAPQueueRouting(t *testing.T) {
	q := NewLDAPRequestQueue()
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
	q := NewLDAPAuthRequestQueue()
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
	q := NewLuaRequestQueue()
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
