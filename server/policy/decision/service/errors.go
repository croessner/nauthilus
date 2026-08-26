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

package service

import "errors"

var (
	// ErrDecisionServiceDependencyMissing identifies an incomplete authority or generation.
	ErrDecisionServiceDependencyMissing = errors.New("decision service dependency missing")

	// ErrDecisionGenerationUnavailable identifies failed or invalid generation capture.
	ErrDecisionGenerationUnavailable = errors.New("decision runtime generation unavailable")

	// ErrDecisionAuthentication identifies rejected credential evidence.
	ErrDecisionAuthentication = errors.New("decision caller authentication failed")

	// ErrDecisionAdmission identifies rejected caller or invocation authority.
	ErrDecisionAdmission = errors.New("decision caller admission failed")

	// ErrDecisionEvaluation identifies an invalid or failed checkpoint evaluation.
	ErrDecisionEvaluation = errors.New("decision checkpoint evaluation failed")

	// ErrDecisionRouteUnavailable identifies a transport disabled by the captured generation.
	ErrDecisionRouteUnavailable = errors.New("decision route unavailable")
)

type decisionAdmissionError struct {
	cause error
}

// Error returns the stable secret-free application-boundary description.
func (e *decisionAdmissionError) Error() string {
	return "decision caller admission failed: caller or invocation was rejected"
}

// Unwrap preserves both the service boundary and admission category for later status mapping.
func (e *decisionAdmissionError) Unwrap() []error {
	return []error{ErrDecisionAdmission, e.cause}
}

// newDecisionAdmissionError preserves a safe admission category without rendering its detail.
func newDecisionAdmissionError(cause error) error {
	return &decisionAdmissionError{cause: cause}
}
