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

package runtime

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/testing/tracetest"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// TestGenerationCorrelationIsRecordedInContextAndSpan proves safe internal generation correlation.
func TestGenerationCorrelationIsRecordedInContextAndSpan(t *testing.T) {
	collector := tracetest.Setup(t)
	ctx, span := otel.Tracer("nauthilus/policy/runtime/generation_context_test").Start(
		context.Background(),
		"generation.capture",
	)

	ctx = ContextWithGeneration(ctx, 42)
	if generation, ok := GenerationFromContext(ctx); !ok || generation != 42 {
		t.Fatalf("GenerationFromContext() = (%d, %v), want (42, true)", generation, ok)
	}

	span.End()

	if _, ok := tracetest.FindByNameAndAttributes(
		collector.Spans(),
		"generation.capture",
		attribute.String(runtimeGenerationAttribute, "42"),
	); !ok {
		t.Fatal("generation span is missing the internal runtime identity")
	}
}
