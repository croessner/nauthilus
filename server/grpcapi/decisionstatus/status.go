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


// Package decisionstatus maps shared decision-service failures to safe gRPC statuses.
package decisionstatus

import (
	"errors"

	"github.com/croessner/nauthilus/v4/server/policy/admission"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FromError recognizes decision-service failures without exposing wrapped error details.
// Unknown failures remain the responsibility of the calling transport adapter.
func FromError(err error) error {
	switch {
	case errors.Is(err, decisionservice.ErrDecisionRouteUnavailable):
		return status.Error(codes.Unimplemented, "policy endpoint is disabled")
	case errors.Is(err, decisionservice.ErrDecisionAuthentication):
		return status.Error(codes.Unauthenticated, "policy credentials rejected")
	case errors.Is(err, decisionservice.ErrDecisionAdmission):
		if errors.Is(err, admission.ErrRequestLimitExceeded) || errors.Is(err, admission.ErrCapacityLimitExceeded) {
			return status.Error(codes.ResourceExhausted, "policy request exceeds admitted limits")
		}

		return status.Error(codes.PermissionDenied, "policy request is not permitted")
	case errors.Is(err, decisionservice.ErrDecisionGenerationUnavailable), errors.Is(err, decisionservice.ErrDecisionServiceDependencyMissing):
		return status.Error(codes.Unavailable, "policy service unavailable")
	default:
		return nil
	}
}
