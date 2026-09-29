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

package grpcauthority

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/monitoring/authmetrics"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errGRPCApplicationFailure mirrors an unexpected host-provider failure below the application boundary.
var errGRPCApplicationFailure = errors.New(
	`authn Policy decision session: execute authn host provider "plugin_subject": LDAP request dropped from the queue`,
)

// grpcApplicationErrorCount reads the gRPC application error counter.
func grpcApplicationErrorCount() float64 {
	return testutil.ToFloat64(stats.GetMetrics().GetAuthApplicationErrorsTotal().WithLabelValues(authmetrics.TransportGRPC))
}

// newApplicationErrorGRPCHandler builds one authority handler whose application fails every operation with err.
func newApplicationErrorGRPCHandler(err error, logs *bytes.Buffer) *Handler {
	service := &recordingService{authErr: err, lookupErr: err, listErr: err}

	return New(service).withLogger(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

func TestGRPCUnexpectedApplicationErrorAnswersTempFail(t *testing.T) {
	var logs bytes.Buffer

	handler := newApplicationErrorGRPCHandler(errGRPCApplicationFailure, &logs)
	before := grpcApplicationErrorCount()
	ctx := context.Background()

	authResponse, err := handler.Authenticate(ctx, grpcBoundaryAuthRequest())
	assertGRPCTempFailResponse(t, "Authenticate", authResponse, err)

	lookupResponse, err := handler.LookupIdentity(ctx, grpcBoundaryLookupIdentityRequest())
	assertGRPCTempFailResponse(t, "LookupIdentity", lookupResponse, err)

	listResponse, err := handler.ListAccounts(ctx, grpcBoundaryListAccountsRequest())
	assertGRPCListAccountsTempFail(t, listResponse, err)

	if delta := grpcApplicationErrorCount() - before; delta != 3 {
		t.Fatalf("gRPC application error counter delta = %v, want 3", delta)
	}

	for _, want := range []string{
		"level=ERROR", "Authentication application failed", "LDAP request dropped from the queue",
		"transport=" + authmetrics.TransportGRPC,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("application failure log = %q, want %q", logs.String(), want)
		}
	}
}

func TestGRPCTypedApplicationErrorsKeepTheirStatus(t *testing.T) {
	tests := []struct {
		err  error
		name string
		code codes.Code
	}{
		{name: "input", err: &core.AuthInputError{Field: "username", Reason: "required"}, code: codes.InvalidArgument},
		{name: "permission", err: &core.AuthPermissionDeniedError{Reason: "scope"}, code: codes.PermissionDenied},
		{name: "preprocess", err: &core.AuthPreprocessRejectedError{}, code: codes.PermissionDenied},
		{name: "canceled", err: context.Canceled, code: codes.Canceled},
		{name: "deadline", err: context.DeadlineExceeded, code: codes.DeadlineExceeded},
		{name: "decision admission", err: decisionservice.ErrDecisionAdmission, code: codes.PermissionDenied},
		{name: "decision generation", err: decisionservice.ErrDecisionGenerationUnavailable, code: codes.Unavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer

			handler := newApplicationErrorGRPCHandler(test.err, &logs)
			before := grpcApplicationErrorCount()
			ctx := context.Background()

			_, authErr := handler.Authenticate(ctx, grpcBoundaryAuthRequest())
			_, lookupErr := handler.LookupIdentity(ctx, grpcBoundaryLookupIdentityRequest())
			_, listErr := handler.ListAccounts(ctx, grpcBoundaryListAccountsRequest())

			for method, err := range map[string]error{
				"Authenticate": authErr, "LookupIdentity": lookupErr, "ListAccounts": listErr,
			} {
				if status.Code(err) != test.code {
					t.Fatalf("%s() code = %v, want %v", method, status.Code(err), test.code)
				}
			}

			if delta := grpcApplicationErrorCount() - before; delta != 0 {
				t.Fatalf("gRPC application error counter delta = %v, want 0 for typed errors", delta)
			}

			if logs.Len() != 0 {
				t.Fatalf("typed application error logged as internal failure: %q", logs.String())
			}
		})
	}
}
