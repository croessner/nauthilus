package core_test

import (
	"context"
	"testing"

	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"go.opentelemetry.io/otel/trace"
)

func TestRunLuaPostAction_PropagatesParentSpanContext(t *testing.T) {
	_ = action.NewWorker()

	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: trace.FlagsSampled,
	})
	if !parent.IsValid() {
		t.Fatalf("expected parent SpanContext to be valid")
	}

	ctx := trace.ContextWithSpanContext(context.Background(), parent)
	expected := trace.SpanContextFromContext(ctx)
	if !expected.IsValid() {
		t.Fatalf("expected extracted SpanContext to be valid")
	}

	done := make(chan struct{})
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

	args := corepkg.PostActionArgs{
		Context:       &lualib.Context{},
		HTTPRequest:   nil,
		ParentSpan:    expected,
		StatusMessage: "status-1",
		Request: lualib.CommonRequest{
			Session:   "guid-123",
			ClientIP:  "192.0.2.10",
			Protocol:  "imap",
			ClientNet: "10.0.0.0/24",
			Repeating: true,
		},
	}

	corepkg.RunLuaPostAction(args)
	<-done
}
