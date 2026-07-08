// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

func TestHostGoPreservesTraceContextFromCanceledParent(t *testing.T) {
	host := NewHost()
	parent := newTestSpanContext(t)
	parentCtx, cancel := context.WithCancel(trace.ContextWithSpanContext(context.Background(), parent))
	cancel()

	workerSpanContext := make(chan trace.SpanContext, 1)
	workerErr := make(chan error, 1)

	host.Go(parentCtx, "trace_worker", func(ctx context.Context) error {
		workerErr <- ctx.Err()

		workerSpanContext <- trace.SpanContextFromContext(ctx)

		return nil
	})
	host.WaitWorkers()

	select {
	case err := <-workerErr:
		if err != nil {
			t.Fatalf("worker context err = %v, want nil", err)
		}
	default:
		t.Fatal("worker did not report context error")
	}

	select {
	case got := <-workerSpanContext:
		if got.TraceID() != parent.TraceID() || got.SpanID() != parent.SpanID() {
			t.Fatalf("worker span context = %s/%s, want %s/%s", got.TraceID(), got.SpanID(), parent.TraceID(), parent.SpanID())
		}
	default:
		t.Fatal("worker did not report span context")
	}
}

func TestHostGoCancelsWorkerWhenServiceContextEnds(t *testing.T) {
	serviceCtx, cancelService := context.WithCancel(context.Background())
	host := NewHost(WithServiceContext(serviceCtx))
	workerDone := make(chan error, 1)

	host.Go(context.Background(), "service_worker", func(ctx context.Context) error {
		<-ctx.Done()

		workerDone <- ctx.Err()

		return nil
	})

	cancelService()

	select {
	case err := <-workerDone:
		if err == nil {
			t.Fatal("worker context err = nil, want cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after service context cancellation")
	}

	host.WaitWorkers()
}

// newTestSpanContext creates the parent span context used by Host.Go tests.
func newTestSpanContext(t *testing.T) trace.SpanContext {
	t.Helper()

	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		SpanID:     trace.SpanID{8, 7, 6, 5, 4, 3, 2, 1},
		TraceFlags: trace.FlagsSampled,
	})
	if !spanContext.IsValid() {
		t.Fatal("test span context is invalid")
	}

	return spanContext
}
