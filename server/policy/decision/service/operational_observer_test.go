// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

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
	if observation.RequestID != "request-authority" || observation.Namespace != "dkim2" ||
		observation.Action != "sign-message-instance" ||
		observation.Generation != 41 || result.Class != test.wantClass || result.DecisionID != test.wantDecision {
		t.Fatalf("observation/result = %#v/%#v", observation, result)
	}

	if result.Admitted != test.wantAdmitted {
		t.Fatalf("admitted = %v, want %v", result.Admitted, test.wantAdmitted)
	}

	if test.wantAdmitted && result.Principal != "test-authority" {
		t.Fatalf("successful audit fields = %#v", result)
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
