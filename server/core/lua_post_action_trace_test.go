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

package core_test

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	corepkg "github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/action"
	"go.opentelemetry.io/otel/trace"
)

func TestRunLuaPostAction_PropagatesParentSpanContext(t *testing.T) {
	prepareLuaPostActionTest(t)

	parent := newValidPostActionSpanContext(t)
	ctx := trace.ContextWithSpanContext(context.Background(), parent)

	expected := trace.SpanContextFromContext(ctx)
	if !expected.IsValid() {
		t.Fatalf("expected extracted SpanContext to be valid")
	}

	done := make(chan struct{})
	expectPostActionParentSpan(t, done, expected)

	auth := newPostActionTraceAuthState()
	auth.RunLuaPostAction(newPostActionTraceArgs(expected))
	<-done
}

// newValidPostActionSpanContext creates the parent span used by the trace test.
func newValidPostActionSpanContext(t *testing.T) trace.SpanContext {
	t.Helper()

	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: trace.FlagsSampled,
	})
	if !parent.IsValid() {
		t.Fatalf("expected parent SpanContext to be valid")
	}

	return parent
}

// expectPostActionParentSpan verifies the worker receives the parent span.
func expectPostActionParentSpan(t *testing.T, done chan<- struct{}, expected trace.SpanContext) {
	t.Helper()

	go func() {
		act := <-action.RequestChan
		if act == nil {
			t.Errorf("action must not be nil")
			close(done)

			return
		}

		if !act.OTelParentSpanContext.IsValid() {
			t.Errorf("expected OTelParentSpanContext to be valid")
		}

		if act.OTelParentSpanContext.TraceID() != expected.TraceID() {
			t.Errorf("expected TraceID %s, got %s", expected.TraceID(), act.OTelParentSpanContext.TraceID())
		}

		if act.OTelParentSpanContext.SpanID() != expected.SpanID() {
			t.Errorf("expected SpanID %s, got %s", expected.SpanID(), act.OTelParentSpanContext.SpanID())
		}

		act.FinishedChan <- action.Done{}

		close(done)
	}()
}

// newPostActionTraceArgs creates the post-action args with the parent span.
func newPostActionTraceArgs(parent trace.SpanContext) corepkg.PostActionArgs {
	return corepkg.PostActionArgs{
		Context:       &lualib.Context{},
		HTTPRequest:   nil,
		ParentSpan:    parent,
		StatusMessage: "status-1",
		Request: lualib.CommonRequest{
			Session:   "guid-123",
			ClientIP:  "192.0.2.10",
			Protocol:  "imap",
			ClientNet: "10.0.0.0/24",
			Repeating: true,
		},
	}
}

// newPostActionTraceAuthState creates the AuthState used for trace propagation.
func newPostActionTraceAuthState() *corepkg.AuthState {
	return corepkg.NewAuthStateFromContextWithDeps(nil, corepkg.AuthDeps{
		Cfg: config.GetFile(),
	}).(*corepkg.AuthState)
}
