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

package core

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/gin-gonic/gin"
)

const authClientStatusTestFailure = "Login rejected at example.test"

// TestTerminalStatusMessageIsClientText pins that a configured auth.response text replaces the built-in default in
// the request state itself, so the summary log line, the captured outcome, and post-action snapshots report the
// message the client receives instead of the built-in text.
func TestTerminalStatusMessageIsClientText(t *testing.T) {
	tests := []struct {
		terminate func(*AuthState, *gin.Context)
		name      string
		want      string
	}{
		{name: "fail", want: authClientStatusTestFailure, terminate: func(auth *AuthState, ctx *gin.Context) {
			auth.AuthFail(ctx)
		}},
		{name: "tempfail", want: authResponseTestTempFail, terminate: func(auth *AuthState, ctx *gin.Context) {
			auth.AuthTempFail(ctx, definitions.TempFailDefault)
		}},
		{name: "specific tempfail text stays", want: definitions.TempFailNoTLS,
			terminate: func(auth *AuthState, ctx *gin.Context) {
				auth.AuthTempFail(ctx, definitions.TempFailNoTLS)
			}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer

			capture := NewCaptureResponseWriter(slog.New(slog.NewTextHandler(&logs, nil)))
			auth, ctx, _ := newCaptureWriterTestState(t, "/api/v1/auth/nginx", capture)
			auth.Cfg().(*config.FileSettings).Server.AuthResponse = config.AuthResponseSection{
				FailureMessage: authClientStatusTestFailure, TempFailMessage: authResponseTestTempFail,
			}

			test.terminate(auth, ctx)

			if auth.Runtime.StatusMessage != test.want {
				t.Fatalf("runtime status message = %q, want %q", auth.Runtime.StatusMessage, test.want)
			}

			if outcome := capture.Outcome(); outcome.StatusMessage != test.want {
				t.Fatalf("captured status message = %q, want %q", outcome.StatusMessage, test.want)
			}

			if line := logs.String(); !strings.Contains(line, `status_message="`+test.want+`"`) {
				t.Fatalf("summary log does not report the client text %q:\n%s", test.want, line)
			}
		})
	}
}
