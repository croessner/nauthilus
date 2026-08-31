// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package decision

import "context"

// ObservationResultClass is the bounded operational outcome of one service invocation.
type ObservationResultClass string

const (
	// ObservationResultCompleted identifies one public Decision response.
	ObservationResultCompleted ObservationResultClass = "completed"
	// ObservationResultAuthenticationFailure identifies rejected credential evidence.
	ObservationResultAuthenticationFailure ObservationResultClass = "authentication_failure"
	// ObservationResultAdmissionFailure identifies rejected caller or request authority.
	ObservationResultAdmissionFailure ObservationResultClass = "admission_failure"
	// ObservationResultEvaluationFailure identifies an internal evaluation failure without a response.
	ObservationResultEvaluationFailure ObservationResultClass = "evaluation_failure"
)

// Observation contains bounded correlation known before evaluation.
type Observation struct {
	RequestID            string
	Namespace            string
	Action               string
	Transport            string
	AuthenticationKind   string
	Generation           uint64
	DiagnosticsRequested bool
}

// ObservationResult contains bounded terminal correlation and status.
type ObservationResult struct {
	DecisionID          string
	Principal           string
	PolicyID            string
	Effect              string
	StatusCode          string
	Class               ObservationResultClass
	Retryable           bool
	Admitted            bool
	DiagnosticsReleased bool
}

// Observer instruments one complete generic Decision invocation.
type Observer interface {
	Start(context.Context, Observation) (context.Context, func(ObservationResult))
}
