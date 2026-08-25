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
	"context"
	"net/http"
	"testing"
)

func TestLegacyAuthApplicationExecutorPreservesHTTPMethod(t *testing.T) {
	tests := []struct {
		name      string
		transport AuthTransportContext
		want      string
	}{
		{
			name: "HTTP GET",
			transport: AuthTransportContext{
				Kind:       requestPolicyTransportHTTP,
				HTTPMethod: http.MethodGet,
			},
			want: http.MethodGet,
		},
		{
			name: "HTTP POST",
			transport: AuthTransportContext{
				Kind:       requestPolicyTransportHTTP,
				HTTPMethod: http.MethodPost,
			},
			want: http.MethodPost,
		},
		{
			name: "gRPC remains POST",
			transport: AuthTransportContext{
				Kind:       requestPolicyTransportGRPC,
				HTTPMethod: http.MethodGet,
			},
			want: http.MethodPost,
		},
		{
			name:      "unspecified transport remains POST",
			transport: AuthTransportContext{},
			want:      http.MethodPost,
		},
	}

	executor := newLegacyAuthApplicationExecutor()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ginCtx, err := executor.newContext(context.Background(), AuthInput{
				Context: AuthContext{Transport: test.transport},
			})
			if err != nil {
				t.Fatalf("newContext returned error: %v", err)
			}

			if got := ginCtx.Request.Method; got != test.want {
				t.Fatalf("request method = %q, want %q", got, test.want)
			}
		})
	}
}
