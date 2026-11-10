// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
)

// TestRequestSnapshotDefaultFailureUsesOperatorText pins that the default failure text of a post-action snapshot is
// the configured auth.response.failure_message the client receives, not the built-in text.
func TestRequestSnapshotDefaultFailureUsesOperatorText(t *testing.T) {
	const operatorText = "Login rejected at example.test"

	auth := newBackendTestAuthWithDeps(t, core.AuthDeps{})
	auth.Cfg().(*config.FileSettings).Server.AuthResponse = config.AuthResponseSection{FailureMessage: operatorText}
	auth.Runtime.StatusCodeFail = 401

	if got := NewRequestSnapshotFromAuthState(auth).Diagnostics.StatusMessage; got != operatorText {
		t.Fatalf("snapshot status message = %q, want operator text %q", got, operatorText)
	}
}
