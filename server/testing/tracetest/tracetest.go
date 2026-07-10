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

// Package tracetest provides small OpenTelemetry helpers for focused tracing tests.
package tracetest

import (
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/testing/oteltest"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Collector aliases the config-independent OpenTelemetry test collector.
type Collector = oteltest.Collector

// Setup installs an always-sampled tracer provider and enables tracing in the test config.
func Setup(t *testing.T) *Collector {
	t.Helper()

	collector := oteltest.Setup(t)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
	}
	cfg.Server.Insights.Tracing.Enabled = true
	config.SetTestFile(cfg)

	t.Cleanup(func() {
		config.SetTestFile(nil)
	})

	return collector
}

// FindByNameAndAttributes returns the first span matching name and all attributes.
func FindByNameAndAttributes(spans []sdktrace.ReadOnlySpan, name string, attrs ...attribute.KeyValue) (sdktrace.ReadOnlySpan, bool) {
	for _, span := range spans {
		if span.Name() != name {
			continue
		}

		if hasAttributes(span, attrs...) {
			return span, true
		}
	}

	return nil, false
}

func hasAttributes(span sdktrace.ReadOnlySpan, attrs ...attribute.KeyValue) bool {
	if len(attrs) == 0 {
		return true
	}

	spanAttrs := span.Attributes()

	for _, want := range attrs {
		found := false

		for _, got := range spanAttrs {
			if got.Key == want.Key && reflect.DeepEqual(got.Value.AsInterface(), want.Value.AsInterface()) {
				found = true

				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}
