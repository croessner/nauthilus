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

package effectsupervisor

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// OperationalObserver emits redacted logs, trace events, and bounded state metrics.
type OperationalObserver struct {
	logger *slog.Logger
	states *prometheus.CounterVec
	audit  AuditSink
}

// AuditSink records controlled internal lifecycle evidence outside response DTOs.
type AuditSink interface {
	RecordEffect(context.Context, Event)
}

// NewOperationalObserver constructs the process observer for supervisor transitions.
func NewOperationalObserver(logger *slog.Logger, states *prometheus.CounterVec, audits ...AuditSink) *OperationalObserver {
	observer := &OperationalObserver{logger: logger, states: states}
	if len(audits) > 0 {
		observer.audit = audits[0]
	}

	return observer
}

// LoggingAuditSink writes one explicitly classified controlled-audit record.
type LoggingAuditSink struct {
	logger *slog.Logger
}

// NewLoggingAuditSink constructs the internal audit adapter for the configured logger.
func NewLoggingAuditSink(logger *slog.Logger) *LoggingAuditSink {
	return &LoggingAuditSink{logger: logger}
}

// RecordEffect emits one redacted effect-state audit record.
func (s *LoggingAuditSink) RecordEffect(ctx context.Context, event Event) {
	if s == nil || s.logger == nil {
		return
	}

	attributes := append([]slog.Attr{slog.String("audit_class", "policy_effect")}, eventLogAttributes(event)...)
	s.logger.LogAttrs(ctx, eventAuditLogLevel(event), "Post-action effect audit", attributes...)
}

// Observe records correlation in logs and traces while keeping metrics low-cardinality.
func (o *OperationalObserver) Observe(ctx context.Context, event Event) {
	if o == nil {
		return
	}

	if o.states != nil {
		o.states.WithLabelValues(string(event.State), string(event.Phase), string(event.Boundary)).Inc()
	}

	span := trace.SpanFromContext(ctx)
	span.AddEvent("policy.effect."+string(event.State), trace.WithAttributes(eventTraceAttributes(event)...))

	if o.audit != nil {
		o.audit.RecordEffect(ctx, event)
	}

	if o.logger != nil {
		o.logger.LogAttrs(ctx, eventLogLevel(event), "Post-action supervisor state changed", eventLogAttributes(event)...)
	}
}

// eventTraceAttributes returns redacted correlation attributes for one transition.
func eventTraceAttributes(event Event) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("nauthilus.policy.decision_id", event.DecisionID),
		attribute.Int64("nauthilus.policy.effect_ordinal", int64(event.EffectOrdinal)),
		attribute.String("nauthilus.policy.target", event.Target),
		attribute.String("nauthilus.policy.provider", event.Provider),
		attribute.String("nauthilus.policy.effect_state", string(event.State)),
		attribute.String("nauthilus.policy.effect_phase", string(event.Phase)),
		attribute.String("nauthilus.policy.finalization_boundary", string(event.Boundary)),
		attribute.String("nauthilus.policy.effect_error_class", event.ErrorClass),
		attribute.Int64("nauthilus.policy.runtime_generation", int64(event.RuntimeGeneration)),
	}
}

// eventLogAttributes returns the same redacted fields for structured logs.
func eventLogAttributes(event Event) []slog.Attr {
	return []slog.Attr{
		slog.String("decision_id", event.DecisionID),
		slog.Uint64("effect_ordinal", uint64(event.EffectOrdinal)),
		slog.String("target", event.Target),
		slog.String("provider", event.Provider),
		slog.String("effect_state", string(event.State)),
		slog.String("effect_phase", string(event.Phase)),
		slog.String("finalization_boundary", string(event.Boundary)),
		slog.String("error_class", event.ErrorClass),
		slog.Uint64("runtime_generation", event.RuntimeGeneration),
		slog.String("source", event.Source),
	}
}

// eventLogLevel raises rejected or unsuccessful states above debug.
func eventLogLevel(event Event) slog.Level {
	if event.State == StateFailed || event.State == StateOutcomeUnknown {
		return slog.LevelWarn
	}

	return slog.LevelDebug
}

// eventAuditLogLevel keeps successful controlled-audit transitions visible at the default level.
func eventAuditLogLevel(event Event) slog.Level {
	if event.State == StateFailed || event.State == StateOutcomeUnknown {
		return slog.LevelWarn
	}

	return slog.LevelInfo
}
