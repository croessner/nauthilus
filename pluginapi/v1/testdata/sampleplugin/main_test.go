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

package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

func TestSampleTextmapHookServe(t *testing.T) {
	hook := sampleTextmapHook{}
	request := pluginapi.HookRequest{
		Path:  "/sample/textmap",
		Query: map[string][]string{"version": {"7"}},
	}

	tests := []struct {
		name       string
		method     string
		wantStatus int
		wantBody   string
		wantAllow  string
	}{
		{name: "get", method: http.MethodGet, wantStatus: http.StatusOK, wantBody: "rotate-7.example\n"},
		{name: "head", method: http.MethodHead, wantStatus: http.StatusOK},
		{name: "unsupported", method: http.MethodPost, wantStatus: http.StatusMethodNotAllowed, wantBody: "Method Not Allowed\n", wantAllow: "GET, HEAD"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request.Method = tt.method

			response, err := hook.Serve(context.Background(), request)
			if err != nil {
				t.Fatalf("Serve() error = %v", err)
			}

			if response.StatusCode != tt.wantStatus {
				t.Fatalf("StatusCode = %d, want %d", response.StatusCode, tt.wantStatus)
			}

			if got := response.Headers["Content-Type"]; len(got) != 1 || got[0] != "text/plain; charset=utf-8" {
				t.Fatalf("Content-Type = %#v, want text/plain", got)
			}

			if got := response.Headers["ETag"]; len(got) != 1 || !strings.HasPrefix(got[0], "W/\"sample-") {
				t.Fatalf("ETag = %#v, want sample weak validator", got)
			}

			if tt.wantBody == "" {
				if len(response.Body) != 0 {
					t.Fatalf("Body = %q, want empty", response.Body)
				}
			} else if !strings.Contains(string(response.Body), tt.wantBody) {
				t.Fatalf("Body = %q, want substring %q", response.Body, tt.wantBody)
			}

			if tt.wantAllow != "" {
				if got := response.Headers["Allow"]; len(got) != 1 || got[0] != tt.wantAllow {
					t.Fatalf("Allow = %#v, want %q", got, tt.wantAllow)
				}
			}
		})
	}
}
