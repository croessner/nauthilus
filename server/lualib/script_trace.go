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

	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// LuaScriptKindSubject identifies subject source script execution.
	LuaScriptKindSubject = "subject"

	// LuaScriptKindEnvironment identifies environment source script execution.
	LuaScriptKindEnvironment = "environment"

	// luaScriptStableAttributes is the number of attributes every Lua script phase span can carry by itself.
	luaScriptStableAttributes = 5
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
	tracer  monittrace.Tracer
	options LuaScriptTraceOptions
}

// NewLuaScriptTrace creates a trace helper with stable Lua script attributes.
func NewLuaScriptTrace(options LuaScriptTraceOptions) LuaScriptTrace {
	return LuaScriptTrace{
		tracer:  monittrace.New("nauthilus/lua/script"),
		options: options,
	}
}

// Start begins a Lua script phase span and attaches stable script attributes plus extra attributes.
//
// The attributes are only assembled for a span that records them.
func (t LuaScriptTrace) Start(ctx context.Context, spanName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, spanName)
	if span.IsRecording() {
		span.SetAttributes(t.phaseAttributes(spanName, attrs)...)
	}

	return ctx, span
}

// phaseAttributes returns the stable script attributes, the phase name, and the extra attributes of one span.
func (t LuaScriptTrace) phaseAttributes(spanName string, attrs []attribute.KeyValue) []attribute.KeyValue {
	allAttrs := make([]attribute.KeyValue, 0, luaScriptStableAttributes+len(attrs))

	if t.options.Kind != "" {
		allAttrs = append(allAttrs, attribute.String("lua.kind", t.options.Kind))
	}

	if t.options.ScriptName != "" {
		allAttrs = append(allAttrs, attribute.String("lua.script.name", t.options.ScriptName))
	}

	if t.options.Mode != "" {
		allAttrs = append(allAttrs, attribute.String("lua.mode", t.options.Mode))
	}

	if t.options.Level >= 0 {
		allAttrs = append(allAttrs, attribute.Int("lua.level", t.options.Level))
	}

	allAttrs = append(allAttrs, attribute.String("lua.phase", strings.TrimPrefix(spanName, "lua.script.")))

	return append(allAttrs, attrs...)
}
