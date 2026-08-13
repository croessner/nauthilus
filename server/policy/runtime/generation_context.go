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
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const runtimeGenerationAttribute = "nauthilus.policy.runtime_generation"

type generationContextKey struct{}

// ContextWithGeneration records one internal correlation identity in context and the active span.
func ContextWithGeneration(ctx context.Context, generation uint64) context.Context {
	ctx = normalizedGenerationContext(ctx)
	if generation == 0 {
		return ctx
	}

	trace.SpanFromContext(ctx).SetAttributes(attribute.String(
		runtimeGenerationAttribute,
		strconv.FormatUint(generation, 10),
	))

	return context.WithValue(ctx, generationContextKey{}, generation)
}

// GenerationFromContext returns the internal captured generation identity when present.
func GenerationFromContext(ctx context.Context) (uint64, bool) {
	if ctx == nil {
		return 0, false
	}

	generation, ok := ctx.Value(generationContextKey{}).(uint64)

	return generation, ok && generation > 0
}
