// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package observability

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/decision"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// DecisionSpanName is the stable generic evaluation span name.
	DecisionSpanName = "nauthilus.policy.evaluate"
	// KeyRequestID is the stable correlation field for the caller request identity.
	KeyRequestID = decision.RequestIDAttributeName
	// KeyDecisionID is the stable correlation field for the generated decision identity.
	KeyDecisionID  = decision.DecisionIDAttributeName
	keyNamespace   = "nauthilus.policy.namespace"
	keyAction      = "nauthilus.policy.action"
	keyTransport   = "nauthilus.policy.transport"
	keyGeneration  = "nauthilus.policy.runtime_generation"
	keyEffect      = "nauthilus.policy.effect"
	keyStatusCode  = "nauthilus.policy.status_code"
	keyResultClass = "nauthilus.policy.result_class"
	unadmitted     = "unadmitted"
)

// DecisionServiceObserver emits correlated logs, controlled audit, spans, and bounded metrics.
type DecisionServiceObserver struct {
	logger    *slog.Logger
	decisions *prometheus.CounterVec
}

// NewDecisionServiceObserver constructs and registers one generic Decision observer.
func NewDecisionServiceObserver(
	logger *slog.Logger,
	registerer prometheus.Registerer,
) (*DecisionServiceObserver, error) {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	decisions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nauthilus_policy_service_decisions_total",
		Help: "Generic Policy Decision Service outcomes by bounded registered dimensions.",
	}, []string{"namespace", "action", "transport", "effect", "status_code", "result_class"})
	if err := registerer.Register(decisions); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, fmt.Errorf("register Policy Decision observer metrics: %w", err)
		}

		existing, compatible := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
		if !compatible {
			return nil, fmt.Errorf("register Policy Decision observer metrics: incompatible existing collector")
		}

		decisions = existing
	}

	return &DecisionServiceObserver{logger: logger, decisions: decisions}, nil
}

// Start begins one correlated evaluation span and returns its terminal recorder.
func (o *DecisionServiceObserver) Start(
	ctx context.Context,
	observation decision.Observation,
) (context.Context, func(decision.ObservationResult)) {
	started := time.Now()
	ctx, span := NewTracer().Start(ctx, DecisionSpanName,
		attribute.String(keyTransport, observation.Transport),
		attribute.String("nauthilus.policy.authentication_kind", observation.AuthenticationKind),
		attribute.Int64(keyGeneration, int64(observation.Generation)),
		attribute.Bool("nauthilus.policy.diagnostics_requested", observation.DiagnosticsRequested),
	)

	return ctx, func(result decision.ObservationResult) {
		o.finish(ctx, span, started, observation, result)
	}
}

// finish emits only bounded decisions and correlation fields.
func (o *DecisionServiceObserver) finish(
	ctx context.Context,
	span trace.Span,
	started time.Time,
	observation decision.Observation,
	result decision.ObservationResult,
) {
	projection := newDecisionObservationProjection(result)
	span.SetAttributes(
		attribute.String(keyNamespace, projection.namespace),
		attribute.String(keyAction, projection.action),
		attribute.String(keyEffect, result.Effect),
		attribute.String(keyStatusCode, result.StatusCode),
		attribute.String(keyResultClass, string(result.Class)),
		attribute.Bool("nauthilus.policy.admitted", result.Admitted),
	)

	if projection.requestID != "" {
		span.SetAttributes(attribute.String(KeyRequestID, projection.requestID))
	}

	if projection.decisionID != "" {
		span.SetAttributes(attribute.String(KeyDecisionID, projection.decisionID))
	}

	if result.Class != decision.ObservationResultCompleted {
		span.SetStatus(codes.Error, string(result.Class))
	}

	span.End()

	if o.decisions != nil {
		o.decisions.WithLabelValues(
			projection.namespace, projection.action, observation.Transport,
			result.Effect, result.StatusCode, string(result.Class),
		).Inc()
	}

	if o.logger == nil {
		return
	}

	attributes := decisionLogAttributes(started, observation, result, projection)
	o.logger.LogAttrs(ctx, slog.LevelInfo, "Policy decision evaluated", attributes...)
	auditAttributes := append(
		[]slog.Attr{slog.String("audit_class", "policy_decision")},
		append(attributes, decisionAuditAttributes(observation, result)...)...,
	)
	o.logger.LogAttrs(ctx, slog.LevelInfo, "Policy decision audit", auditAttributes...)
}

type decisionObservationProjection struct {
	requestID  string
	decisionID string
	namespace  string
	action     string
}

// newDecisionObservationProjection exposes admitted typed values or bounded rejection dimensions.
func newDecisionObservationProjection(result decision.ObservationResult) decisionObservationProjection {
	projection := decisionObservationProjection{
		requestID: result.RequestID.String(), decisionID: result.DecisionID.String(),
		namespace: unadmitted, action: unadmitted,
	}
	if result.Admitted && result.Target.Namespace() != "" && result.Target.Action() != "" {
		projection.namespace = result.Target.Namespace()
		projection.action = result.Target.Action()
	}

	return projection
}

// decisionLogAttributes constructs the safe normal-log projection.
func decisionLogAttributes(
	started time.Time,
	observation decision.Observation,
	result decision.ObservationResult,
	projection decisionObservationProjection,
) []slog.Attr {
	attributes := []slog.Attr{
		slog.String(keyNamespace, projection.namespace),
		slog.String(keyAction, projection.action),
		slog.String(keyTransport, observation.Transport),
		slog.Uint64(keyGeneration, observation.Generation),
		slog.String(keyEffect, result.Effect),
		slog.String(keyStatusCode, result.StatusCode),
		slog.String(keyResultClass, string(result.Class)),
		slog.Bool("nauthilus.policy.retryable", result.Retryable),
		slog.Int64("nauthilus.policy.duration_ms", time.Since(started).Milliseconds()),
	}
	if projection.requestID != "" {
		attributes = append(attributes, slog.String(KeyRequestID, projection.requestID))
	}

	if projection.decisionID != "" {
		attributes = append(attributes, slog.String(KeyDecisionID, projection.decisionID))
	}

	return attributes
}

// decisionAuditAttributes adds identity and admission fields only to controlled audit.
func decisionAuditAttributes(
	observation decision.Observation,
	result decision.ObservationResult,
) []slog.Attr {
	return []slog.Attr{
		slog.String("nauthilus.policy.authentication_kind", observation.AuthenticationKind),
		slog.String("nauthilus.policy.principal", result.Principal),
		slog.String("nauthilus.policy.policy_id", result.PolicyID),
		slog.Bool("nauthilus.policy.admitted", result.Admitted),
		slog.Bool("nauthilus.policy.diagnostics_requested", observation.DiagnosticsRequested),
		slog.Bool("nauthilus.policy.diagnostics_released", result.DiagnosticsReleased),
	}
}
