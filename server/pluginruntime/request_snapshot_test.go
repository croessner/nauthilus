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
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/secret"
)

const requestSnapshotUsername = "demo"

func TestRequestSnapshotRedactsSensitiveHeaders(t *testing.T) {
	request := httptest.NewRequest("POST", "/auth", strings.NewReader("body-secret"))
	request.Header.Set(requestHeaderAuthorization, "Bearer token")
	request.Header.Set(requestHeaderCookie, "session=value")
	request.Header.Set("x-api-key", "key-secret")
	request.Header.Set("x-safe-header", "visible")

	auth := &core.AuthState{}
	auth.Request.HTTPClientRequest = request
	auth.Request.Username = requestSnapshotUsername
	auth.Request.Password = secret.New("password-secret")

	snapshot := NewRequestSnapshotFromAuthState(auth, WithSnapshotSecretHeaders("X-Api-Key"))

	for _, header := range []string{requestHeaderAuthorization, requestHeaderCookie, "X-Api-Key"} {
		if _, ok := snapshot.Headers[header]; ok {
			t.Fatalf("snapshot header %q was not redacted: %#v", header, snapshot.Headers)
		}
	}

	if got := snapshot.Headers["X-Safe-Header"]; len(got) != 1 || got[0] != "visible" {
		t.Fatalf("snapshot safe header = %#v, want visible", got)
	}
}

func TestRequestSnapshotExcludesPasswordAndBody(t *testing.T) {
	request := httptest.NewRequest("POST", "/auth", strings.NewReader("body-secret"))
	auth := &core.AuthState{}
	auth.Request.HTTPClientRequest = request
	auth.Request.Username = requestSnapshotUsername
	auth.Request.Password = secret.New("password-secret")

	snapshot := NewRequestSnapshotFromAuthState(auth)
	rendered := fmt.Sprintf("%#v", snapshot)

	for _, secretValue := range []string{"password-secret", "body-secret"} {
		if strings.Contains(rendered, secretValue) {
			t.Fatalf("request snapshot exposed %q in %#v", secretValue, snapshot)
		}
	}
}
