// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/observability"
	"github.com/croessner/nauthilus/v4/server/testing/tracetest"

	"github.com/prometheus/client_golang/prometheus"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestRejectedTargetsUseBoundedMetricDimensions(t *testing.T) {
	tests := []struct {
		name              string
		authenticationErr error
		admissionErr      error
	}{
		{name: "pre-authentication", authenticationErr: errors.New("rejected")},
		{name: "authenticated but unadmitted", admissionErr: errors.New("unadmitted")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()

			observer, err := observability.NewDecisionServiceObserver(nil, registry)
			if err != nil {
				t.Fatalf("NewDecisionServiceObserver() error = %v", err)
			}

			target, err := decision.NewTarget("attacker_namespace_491", "attacker_action_917")
			if err != nil {
				t.Fatalf("NewTarget() error = %v", err)
			}

			invocation := mustAuthorityInvocation(t, false)
			invocation.Request.Target = target
			authenticator := &recordingCallerAuthenticator{
				caller: mustAuthorityCaller(t, false), err: test.authenticationErr,
			}
			generation := mustRuntimeGeneration(t, 51, authenticator,
				&recordingAdmissionAuthority{err: test.admissionErr}, &recordingCheckpointEvaluator{})
			service := mustObservedDecisionService(t, &replaceableGenerationSource{generation: generation}, observer)

			_, _ = service.Evaluate(t.Context(), invocation)

			metrics := gatherDecisionMetrics(t, registry)
			if strings.Contains(metrics, "attacker_namespace_491") || strings.Contains(metrics, "attacker_action_917") {
				t.Fatalf("rejected target reached metric labels: %s", metrics)
			}

			if strings.Count(metrics, `value:"unadmitted"`) != 2 {
				t.Fatalf("bounded rejection dimensions are missing: %s", metrics)
			}
		})
	}
}

func TestInvalidRequestIDNeverReachesObserverSurfaces(t *testing.T) {
	var logs bytes.Buffer

	collector := tracetest.Setup(t)

	observer, err := observability.NewDecisionServiceObserver(
		slog.New(slog.NewJSONHandler(&logs, nil)), prometheus.NewRegistry(),
	)
	if err != nil {
		t.Fatalf("NewDecisionServiceObserver() error = %v", err)
	}

	generation := mustRuntimeGeneration(t, 52,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)},
		&recordingAdmissionAuthority{}, &recordingCheckpointEvaluator{})
	service := mustObservedDecisionService(t, &replaceableGenerationSource{generation: generation}, observer)

	invalidRequestIDs := []string{
		"invalid request identifier with spaces",
		strings.Repeat("x", 129),
	}
	for _, invalidRequestID := range invalidRequestIDs {
		invocation := mustAuthorityInvocation(t, false)
		invocation.Request.RequestID = invalidRequestID

		_, err = service.Evaluate(t.Context(), invocation)
		if !errors.Is(err, decision.ErrInvalidRequest) {
			t.Fatalf("Evaluate() error = %v, want ErrInvalidRequest", err)
		}

		if strings.Contains(logs.String(), invalidRequestID) ||
			spansContainValue(collector.Spans(), invalidRequestID) {
			t.Fatalf("invalid request ID reached observer surfaces: %s", logs.String())
		}
	}

	if !strings.Contains(logs.String(), string(decision.ObservationResultRequestValidationFailure)) {
		t.Fatalf("bounded validation outcome is missing: %s", logs.String())
	}
}

// spansContainValue reports whether any span attribute contains exact caller text.
func spansContainValue(spans []sdktrace.ReadOnlySpan, value string) bool {
	for _, span := range spans {
		for _, field := range span.Attributes() {
			if fmt.Sprint(field.Value.AsInterface()) == value {
				return true
			}
		}
	}

	return false
}

// gatherDecisionMetrics serializes one isolated observer registry.
func gatherDecisionMetrics(t *testing.T, registry *prometheus.Registry) string {
	t.Helper()

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	return fmt.Sprint(families)
}

func TestDecisionServiceObservesCorrelationAndFailureClasses(t *testing.T) {
	tests := []decisionObservationCase{
		{name: "completed decision", wantClass: decision.ObservationResultCompleted, wantDecision: "decision-observed", wantAdmitted: true},
		{name: "authentication failure", authenticationErr: errors.New("private authentication detail"), wantClass: decision.ObservationResultAuthenticationFailure},
		{name: "admission failure", admissionErr: errors.New("private admission detail"), wantClass: decision.ObservationResultAdmissionFailure},
		{name: "evaluation failure", evaluationErr: errors.New("private evaluation detail"), wantClass: decision.ObservationResultEvaluationFailure, wantAdmitted: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runDecisionObservationCase(t, test)
		})
	}
}

type decisionObservationCase struct {
	name              string
	authenticationErr error
	admissionErr      error
	evaluationErr     error
	wantClass         decision.ObservationResultClass
	wantDecision      string
	wantAdmitted      bool
}

// runDecisionObservationCase verifies one service result classification.
func runDecisionObservationCase(t *testing.T, test decisionObservationCase) {
	t.Helper()

	observer := &recordingDecisionObserver{}
	authenticator := &recordingCallerAuthenticator{
		caller: mustAuthorityCaller(t, false), err: test.authenticationErr,
	}
	admission := &recordingAdmissionAuthority{err: test.admissionErr}
	evaluator := &recordingCheckpointEvaluator{
		outcome: mustRuntimeEvaluation(t, 41, "decision-observed"), err: test.evaluationErr,
	}
	generation := mustRuntimeGeneration(t, 41, authenticator, admission, evaluator)
	service := mustObservedDecisionService(t, &replaceableGenerationSource{generation: generation}, observer)

	_, _ = service.Evaluate(context.Background(), mustAuthorityInvocation(t, false))

	observation, result := observer.single(t)
	if observation.Generation != 41 || result.Class != test.wantClass ||
		result.DecisionID.String() != test.wantDecision {
		t.Fatalf("observation/result = %#v/%#v", observation, result)
	}

	if result.Admitted != test.wantAdmitted {
		t.Fatalf("admitted = %v, want %v", result.Admitted, test.wantAdmitted)
	}

	if test.wantAdmitted && result.Principal != "test-authority" {
		t.Fatalf("successful audit fields = %#v", result)
	}

	if test.wantAdmitted && (result.RequestID.String() != "request-authority" ||
		result.Target.Namespace() != "dkim2" || result.Target.Action() != "sign-message-instance") {
		t.Fatalf("admitted correlation = %#v", result)
	}

	if test.wantDecision != "" && result.PolicyID != "authn/standard_auth" {
		t.Fatalf("completed policy = %q, want authn/standard_auth", result.PolicyID)
	}
}

func TestDecisionServiceObserverFailureCannotChangeDecision(t *testing.T) {
	for _, panicAtFinish := range []bool{false, true} {
		observer := panickingDecisionObserver{panicAtFinish: panicAtFinish}
		authenticator := &recordingCallerAuthenticator{caller: mustAuthorityCaller(t, false)}
		admission := &recordingAdmissionAuthority{}
		evaluator := &recordingCheckpointEvaluator{outcome: mustRuntimeEvaluation(t, 42, "decision-observer-safe")}
		generation := mustRuntimeGeneration(t, 42, authenticator, admission, evaluator)
		service := mustObservedDecisionService(t, &replaceableGenerationSource{generation: generation}, observer)

		response, err := service.Evaluate(context.Background(), mustAuthorityInvocation(t, false))
		if err != nil || response.DecisionID().String() != "decision-observer-safe" {
			t.Fatalf("Evaluate() = %q/%v", response.DecisionID(), err)
		}
	}
}

type panickingDecisionObserver struct {
	panicAtFinish bool
}

// Start panics at one configured observer boundary.
func (o panickingDecisionObserver) Start(
	ctx context.Context,
	_ decision.Observation,
) (context.Context, func(decision.ObservationResult)) {
	if !o.panicAtFinish {
		panic("observer start failure")
	}

	return ctx, func(decision.ObservationResult) {
		panic("observer finish failure")
	}
}

type recordingDecisionObserver struct {
	observations []decision.Observation
	results      []decision.ObservationResult
}

// Start records one observation and captures its terminal result.
func (o *recordingDecisionObserver) Start(
	ctx context.Context,
	observation decision.Observation,
) (context.Context, func(decision.ObservationResult)) {
	o.observations = append(o.observations, observation)

	return ctx, func(result decision.ObservationResult) {
		o.results = append(o.results, result)
	}
}

// single returns the only complete observation pair.
func (o *recordingDecisionObserver) single(t *testing.T) (decision.Observation, decision.ObservationResult) {
	t.Helper()

	if len(o.observations) != 1 || len(o.results) != 1 {
		t.Fatalf("observations/results = %d/%d, want 1/1", len(o.observations), len(o.results))
	}

	return o.observations[0], o.results[0]
}

// mustObservedDecisionService constructs one service with an explicit observer.
func mustObservedDecisionService(
	t *testing.T,
	source GenerationSource,
	observer decision.Observer,
) *DecisionService {
	t.Helper()

	service, err := NewDecisionService(source, WithDecisionObserver(observer))
	if err != nil {
		t.Fatalf("NewDecisionService() error = %v", err)
	}

	return service
}
