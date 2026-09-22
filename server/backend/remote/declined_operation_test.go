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
	stderrors "errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/errors"
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
