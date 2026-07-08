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

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	"github.com/croessner/nauthilus/v3/server/testing/tracetest"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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

	cancelRequest()

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	host.WaitWorkers()
	requestSpan.End()

	span := requirePostActionPluginSpan(t, collector)
	if got, want := span.Parent().SpanID(), requestSpan.SpanContext().SpanID(); got != want {
		t.Fatalf("post-action plugin span parent = %s, want request span %s", got, want)
	}
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
