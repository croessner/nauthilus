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

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	"github.com/croessner/nauthilus/v3/server/testing/tracetest"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func TestEffectBridgePostActionSpanKeepsRequestTraceAfterRequestCancel(t *testing.T) {
	collector := tracetest.Setup(t)
	target := &fakePostActionTarget{called: make(chan struct{})}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host))
	auth := newSubjectTestAuth(t)

	requestCtx, requestSpan := otel.Tracer("nauthilus/pluginruntime/effects_trace_test").Start(context.Background(), "request.parent")
	requestCtx, cancelRequest := context.WithCancel(requestCtx)
	auth.Request.HTTPClientContext.Request = auth.Request.HTTPClientContext.Request.WithContext(requestCtx)
	auth.Request.HTTPClientRequest = auth.Request.HTTPClientContext.Request
	gate := core.InstallPostActionExecutionGate(auth.Request.HTTPClientContext)

	cancelRequest()

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	requestSpan.End()
	gate.Complete()
	host.WaitWorkers()

	planSpan := requirePostActionPlanSpan(t, collector)
	if got, want := planSpan.Parent().SpanID(), requestSpan.SpanContext().SpanID(); got != want {
		t.Fatalf("post-action plan span parent = %s, want request span %s", got, want)
	}

	if planSpan.StartTime().Before(requestSpanEndTime(t, collector, requestSpan.SpanContext().SpanID())) {
		t.Fatal("post-action plan started before request span ended")
	}

	pluginSpan := requirePostActionPluginSpan(t, collector)
	if got, want := pluginSpan.Parent().SpanID(), planSpan.SpanContext().SpanID(); got != want {
		t.Fatalf("post-action plugin span parent = %s, want plan span %s", got, want)
	}
}

// requestSpanEndTime returns the exported end time for one request span ID.
func requestSpanEndTime(t *testing.T, collector *tracetest.Collector, spanID trace.SpanID) time.Time {
	t.Helper()

	for _, span := range collector.Spans() {
		if span.SpanContext().SpanID() == spanID {
			return span.EndTime()
		}
	}

	t.Fatalf("missing request span %s", spanID)

	return time.Time{}
}

func TestEffectBridgeWaitsForResponseCompletionBeforePostAction(t *testing.T) {
	target := &fakePostActionTarget{called: make(chan struct{})}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host))
	auth := newSubjectTestAuth(t)
	gate := core.InstallPostActionExecutionGate(auth.Request.HTTPClientContext)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	select {
	case <-target.called:
		t.Fatal("post-action started before response completion")
	case <-time.After(50 * time.Millisecond):
	}

	gate.Complete()
	host.WaitWorkers()

	select {
	case <-target.called:
	default:
		t.Fatal("post-action did not start after response completion")
	}
}

// requirePostActionPlanSpan finds the host-owned ordered post-action plan span.
func requirePostActionPlanSpan(t *testing.T, collector *tracetest.Collector) sdktrace.ReadOnlySpan {
	t.Helper()

	span, ok := tracetest.FindByNameAndAttributes(
		collector.Spans(),
		"auth.post_action.plan",
		attribute.Int("post_action.steps", 1),
	)
	if !ok {
		t.Fatalf("missing post-action plan span; exported spans: %v", collector.Spans())
	}

	return span
}

// requirePostActionPluginSpan finds the host-owned native post-action call span.
func requirePostActionPluginSpan(t *testing.T, collector *tracetest.Collector) sdktrace.ReadOnlySpan {
	t.Helper()

	span, ok := tracetest.FindByNameAndAttributes(
		collector.Spans(),
		"plugin.post_action_target.Enqueue",
		attribute.String("plugin.module", testRuntimeModuleName),
		attribute.String("plugin.component", effectPostActionName),
		attribute.String("plugin.extension_point", "post_action_target"),
		attribute.String("plugin.method", "Enqueue"),
	)
	if !ok {
		t.Fatalf("missing native post-action plugin span; exported spans: %v", collector.Spans())
	}

	return span
}
