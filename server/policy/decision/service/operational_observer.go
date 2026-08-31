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

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

type nopDecisionObserver struct{}

// Start preserves the caller context and returns a no-op completion callback.
func (nopDecisionObserver) Start(
	ctx context.Context,
	_ decision.Observation,
) (context.Context, func(decision.ObservationResult)) {
	return ctx, func(decision.ObservationResult) {}
}

// DecisionServiceOption configures one optional application observer.
type DecisionServiceOption func(*DecisionService) error

// WithDecisionObserver installs one operational observer without changing authority semantics.
func WithDecisionObserver(observer decision.Observer) DecisionServiceOption {
	return func(service *DecisionService) error {
		if nilDependency(observer) {
			return ErrDecisionServiceDependencyMissing
		}

		service.observer = observer

		return nil
	}
}

// startDecisionObservation isolates evaluation correctness from observer failures.
func startDecisionObservation(
	ctx context.Context,
	observer decision.Observer,
	observation decision.Observation,
) (observed context.Context, finish func(decision.ObservationResult)) {
	observed = ctx
	finish = func(decision.ObservationResult) {}

	defer func() {
		if recover() != nil {
			observed = ctx
			finish = func(decision.ObservationResult) {}
		}
	}()

	observed, callback := observer.Start(ctx, observation)
	if observed == nil {
		observed = ctx
	}

	if callback != nil {
		finish = func(result decision.ObservationResult) {
			defer func() { _ = recover() }()

			callback(result)
		}
	}

	return observed, finish
}

// decisionObservationResult maps response or service error into bounded telemetry.
func decisionObservationResult(
	response decision.DecisionResponse,
	err error,
	details decision.ObservationResult,
) decision.ObservationResult {
	if response.Status().Code() != "" {
		details.DecisionID = response.DecisionID().String()
		details.PolicyID = response.Policy().PolicySet()
		details.Effect = string(response.Effect())
		details.StatusCode = string(response.Status().Code())
		details.Class = decision.ObservationResultCompleted
		details.Retryable = response.Status().Retryable()
		details.DiagnosticsReleased = response.Diagnostics() != nil

		return details
	}

	resultClass := decision.ObservationResultEvaluationFailure
	if errors.Is(err, ErrDecisionAuthentication) {
		resultClass = decision.ObservationResultAuthenticationFailure
	} else if errors.Is(err, ErrDecisionAdmission) {
		resultClass = decision.ObservationResultAdmissionFailure
	}

	details.Class = resultClass

	return details
}
