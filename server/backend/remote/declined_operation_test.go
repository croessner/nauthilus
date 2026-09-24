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

package remote

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"log/slog"
	"strings"
	"testing"

	commonv1 "github.com/croessner/nauthilus/v4/api/common/v1"
	"github.com/croessner/nauthilus/v4/server/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRemoteOperationDeniedIsADeclineNotAFailure pins how the password pipeline
// reads this error.
//
// allowed_operations omitting an operation means this backend was never meant
// to serve the request, so the remaining backends still decide it. Were it read
// as a failure, it would suppress their verdict and turn every unknown user on
// such a deployment into a temporary failure, while a known user with a wrong
// password still got a rejection - a difference an attacker can measure.
func TestRemoteOperationDeniedIsADeclineNotAFailure(t *testing.T) {
	if !errors.IsBackendNotResponsible(ErrRemoteOperationDenied) {
		t.Fatal("a denied operation must be recognised as a declining backend")
	}

	if errors.IsBackendTechnicalFailure(ErrRemoteOperationDenied) {
		t.Fatal("a denied operation is a configuration choice, not a technical failure")
	}

	// Existing callers match on this sentinel; wrapping must not break them.
	if !stderrors.Is(ErrRemoteOperationDenied, ErrRemoteOperationDenied) {
		t.Fatal("the sentinel must stay matchable for its existing callers")
	}
}

// TestRemoteAuthorityRejectedIsAClassifiedTemporaryFailure pins that a refused request is answered as a
// classified temporary failure: it says nothing about the credentials, so it is neither a decline nor counted.
func TestRemoteAuthorityRejectedIsAClassifiedTemporaryFailure(t *testing.T) {
	for _, code := range []codes.Code{codes.FailedPrecondition, codes.InvalidArgument, codes.AlreadyExists} {
		err := classifyAuthorityError(status.Error(code, "refused"))

		if !stderrors.Is(err, ErrRemoteAuthorityRejected) {
			t.Fatalf("%s mapped to %v, want ErrRemoteAuthorityRejected", code, err)
		}

		if !errors.IsBackendTechnicalFailure(err) || errors.IsBackendNotResponsible(err) {
			t.Fatalf("%s must be a classified temporary failure and not a decline: %v", code, err)
		}
	}

	conflict := operationStatusError(&commonv1.OperationStatus{Result: commonv1.OperationResult_OPERATION_RESULT_CONFLICT})
	if !stderrors.Is(conflict, ErrRemoteAuthorityRejected) || !errors.IsBackendTechnicalFailure(conflict) {
		t.Fatalf("conflict status = %v, want a classified ErrRemoteAuthorityRejected", conflict)
	}
}

// TestRemoteCallerRejectionStaysADecline pins that rejected edge caller credentials (UNAUTHENTICATED) decline
// like a denied operation, while the distinct sentinel keeps them visible in logs.
func TestRemoteCallerRejectionStaysADecline(t *testing.T) {
	err := classifyAuthorityError(status.Error(codes.Unauthenticated, "caller rejected"))

	if !stderrors.Is(err, ErrRemoteCallerRejected) || !stderrors.Is(err, ErrRemoteOperationDenied) {
		t.Fatalf("UNAUTHENTICATED mapped to %v, want ErrRemoteCallerRejected wrapping ErrRemoteOperationDenied", err)
	}

	if !errors.IsBackendNotResponsible(err) || errors.IsBackendTechnicalFailure(err) {
		t.Fatalf("UNAUTHENTICATED must stay a decline: %v", err)
	}
}

// TestRemotePermissionDeniedIsAnOperationDenial pins that PERMISSION_DENIED is a plain decline. The authority also
// answers it for user-level results (denied identity lookup, principal mismatch, pre-authentication rejection),
// so it must not be reported as rejected edge caller credentials.
func TestRemotePermissionDeniedIsAnOperationDenial(t *testing.T) {
	err := classifyAuthorityError(status.Error(codes.PermissionDenied, "identity lookup was denied"))

	if !stderrors.Is(err, ErrRemoteOperationDenied) || stderrors.Is(err, ErrRemoteCallerRejected) {
		t.Fatalf("PERMISSION_DENIED mapped to %v, want ErrRemoteOperationDenied without ErrRemoteCallerRejected", err)
	}

	if !errors.IsBackendNotResponsible(err) || errors.IsBackendTechnicalFailure(err) {
		t.Fatalf("PERMISSION_DENIED must stay a decline: %v", err)
	}
}

// TestMapAuthorityErrorLogLevels pins that only rejected caller credentials warn, while a denied operation is
// logged at debug level with the authority status message.
func TestMapAuthorityErrorLogLevels(t *testing.T) {
	for name, tc := range map[string]struct {
		code      codes.Code
		wantLevel string
	}{
		"unauthenticated":   {code: codes.Unauthenticated, wantLevel: "WARN"},
		"permission denied": {code: codes.PermissionDenied, wantLevel: "DEBUG"},
	} {
		t.Run(name, func(t *testing.T) {
			var buffer bytes.Buffer

			manager := &Manager{
				logger:        slog.New(slog.NewJSONHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug})),
				backendName:   "remote",
				authorityName: "authority",
			}

			_ = manager.mapAuthorityError(status.Error(tc.code, "authority status text"))

			var record map[string]any
			if err := json.Unmarshal(buffer.Bytes(), &record); err != nil {
				t.Fatalf("decode log record %q: %v", buffer.String(), err)
			}

			if record["level"] != tc.wantLevel {
				t.Fatalf("log level = %v, want %s", record["level"], tc.wantLevel)
			}

			if !strings.Contains(buffer.String(), "authority status text") {
				t.Fatalf("log record %q misses the authority status message", buffer.String())
			}
		})
	}
}
