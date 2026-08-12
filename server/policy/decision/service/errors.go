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
)
