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

package lualib

import (
	"context"
	"strings"

	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// LuaScriptKindSubject identifies subject source script execution.
	LuaScriptKindSubject = "subject"

	// LuaScriptKindEnvironment identifies environment source script execution.
	LuaScriptKindEnvironment = "environment"
)

// LuaScriptTraceOptions describes stable attributes shared by all spans of one Lua script execution.
type LuaScriptTraceOptions struct {
	Kind       string
	ScriptName string
	Mode       string
	Level      int
}

// LuaScriptTrace starts child spans for the common Lua execution phases.
type LuaScriptTrace struct {
	tracer monittrace.Tracer
	attrs  []attribute.KeyValue
}

// NewLuaScriptTrace creates a trace helper with stable Lua script attributes.
func NewLuaScriptTrace(options LuaScriptTraceOptions) LuaScriptTrace {
	attrs := make([]attribute.KeyValue, 0, 4)

	if options.Kind != "" {
		attrs = append(attrs, attribute.String("lua.kind", options.Kind))
	}

	if options.ScriptName != "" {
		attrs = append(attrs, attribute.String("lua.script.name", options.ScriptName))
	}

	if options.Mode != "" {
		attrs = append(attrs, attribute.String("lua.mode", options.Mode))
	}

	if options.Level >= 0 {
		attrs = append(attrs, attribute.Int("lua.level", options.Level))
	}

	return LuaScriptTrace{
		tracer: monittrace.New("nauthilus/lua/script"),
		attrs:  attrs,
	}
}

// Start begins a Lua script phase span and attaches stable script attributes plus extra attributes.
func (t LuaScriptTrace) Start(ctx context.Context, spanName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	allAttrs := make([]attribute.KeyValue, 0, len(t.attrs)+len(attrs)+1)
	allAttrs = append(allAttrs, t.attrs...)
	allAttrs = append(allAttrs, attribute.String("lua.phase", strings.TrimPrefix(spanName, "lua.script.")))
	allAttrs = append(allAttrs, attrs...)

	return t.tracer.Start(ctx, spanName, allAttrs...)
}
