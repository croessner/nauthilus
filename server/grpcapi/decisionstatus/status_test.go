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


package decisionstatus

import (
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/admission"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFromErrorPreservesCategoriesWithoutPrivateDetails(t *testing.T) {
	cases := []struct {
		err  error
		code codes.Code
	}{
		{decisionservice.ErrDecisionRouteUnavailable, codes.Unimplemented},
		{decisionservice.ErrDecisionAuthentication, codes.Unauthenticated},
		{decisionservice.ErrDecisionAdmission, codes.PermissionDenied},
		{errors.Join(decisionservice.ErrDecisionAdmission, admission.ErrRequestLimitExceeded), codes.ResourceExhausted},
		{errors.Join(decisionservice.ErrDecisionAdmission, admission.ErrCapacityLimitExceeded), codes.ResourceExhausted},
		{decisionservice.ErrDecisionGenerationUnavailable, codes.Unavailable},
		{decisionservice.ErrDecisionServiceDependencyMissing, codes.Unavailable},
	}

	for _, test := range cases {
		t.Run(test.err.Error(), func(t *testing.T) {
			mapped := FromError(errors.Join(test.err, errors.New("private diagnostic detail")))
			if mapped == nil || status.Code(mapped) != test.code {
				t.Fatalf("FromError() = %v; want %s", mapped, test.code)
			}

			if strings.Contains(mapped.Error(), "private diagnostic detail") {
				t.Fatal("status exposed private error details")
			}
		})
	}
}

func TestFromErrorLeavesUnrecognizedFailuresToAdapter(t *testing.T) {
	for _, err := range []error{nil, errors.New("unrelated"), admission.ErrCapacityLimitExceeded} {
		if mapped := FromError(err); mapped != nil {
			t.Fatalf("FromError(%v) = %v", err, mapped)
		}
	}
}
