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

// Package observability contains policy logging, metric, and tracing helpers.
package observability

import (
	"context"
	"errors"
	"log/slog"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/util"
)

// KeyComponent is the structured field used by policy debug logs.
const KeyComponent = "policy_component"

// ErrUnknownComponent is returned when a debug component is not registered.
var ErrUnknownComponent = errors.New("unknown policy component")

// Component identifies one internal policy diagnostics area.
type Component string

const (
	// ComponentCompiler identifies compiler diagnostics.
	ComponentCompiler Component = "compiler"

	// ComponentSnapshot identifies snapshot diagnostics.
	ComponentSnapshot Component = "snapshot"

	// ComponentChecks identifies check scheduling and execution diagnostics.
	ComponentChecks Component = "checks"

	// ComponentEval identifies policy evaluation diagnostics.
	ComponentEval Component = "eval"

	// ComponentFSM identifies FSM marker diagnostics.
	ComponentFSM Component = "fsm"

	// ComponentObserve identifies observe-mode diagnostics.
	ComponentObserve Component = "observe"

	// ComponentReport identifies report diagnostics.
	ComponentReport Component = "report"
)

// DecisionLogEntry is the sanitized normal-log shape for a policy decision.
type DecisionLogEntry struct {
	Mode               string
	Set                string
	Name               string
	Reason             string
	ResponseMarker     string
	FSMEventMarker     string
	Operation          policy.Operation
	Stage              policy.Stage
	Decision           policy.Decision
	SnapshotGeneration uint64
	ObserveMismatch    bool
}

// DebugFields prepends the validated policy component field to debug key-values.
func DebugFields(component Component, keyvals ...any) ([]any, error) {
	if !component.Valid() {
		return nil, ErrUnknownComponent
	}

	fields := make([]any, 0, len(keyvals)+2)
	fields = append(fields, KeyComponent, string(component))
	fields = append(fields, keyvals...)

	return fields, nil
}

// Debug writes a policy debug-module entry when the policy module is enabled.
func Debug(ctx context.Context, cfg config.File, logger *slog.Logger, component Component, keyvals ...any) {
	fields, err := DebugFields(component, keyvals...)
	if err != nil {
		return
	}

	util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgPolicy, fields...)
}

// LogDecision writes a sanitized normal policy decision entry.
func LogDecision(ctx context.Context, logger *slog.Logger, entry DecisionLogEntry) {
	if logger == nil {
		return
	}

	_ = level.Info(logger).WithContext(ctx).Log(DecisionLogFields(entry)...)
}

// DecisionLogFields returns the safe structured fields for normal policy logs.
func DecisionLogFields(entry DecisionLogEntry) []any {
	return []any{
		"policy_mode", entry.Mode,
		"policy_set", entry.Set,
		"policy_name", entry.Name,
		"operation", string(entry.Operation),
		"stage", string(entry.Stage),
		"decision", string(entry.Decision),
		"reason", entry.Reason,
		"response_marker", entry.ResponseMarker,
		"fsm_event_marker", entry.FSMEventMarker,
		"snapshot_generation", entry.SnapshotGeneration,
		"observe_mismatch", entry.ObserveMismatch,
	}
}

// Valid reports whether a component is part of the allowed diagnostics set.
func (c Component) Valid() bool {
	switch c {
	case ComponentCompiler,
		ComponentSnapshot,
		ComponentChecks,
		ComponentEval,
		ComponentFSM,
		ComponentObserve,
		ComponentReport:
		return true
	default:
		return false
	}
}
