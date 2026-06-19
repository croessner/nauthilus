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
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/secret"
)

const (
	requestSnapshotAuthLoginAttempt  = uint(4)
	requestSnapshotBruteForceName    = "login"
	requestSnapshotClientDN          = "CN=client1,OU=mail"
	requestSnapshotClientHost        = "client.example.test"
	requestSnapshotClientID          = "client-123"
	requestSnapshotClientIssuerDN    = "CN=client-issuer"
	requestSnapshotClientNet         = "203.0.113.0/24"
	requestSnapshotDisplayName       = "Demo User"
	requestSnapshotDisplayNameField  = "display_name"
	requestSnapshotFingerprint       = "aa:bb:cc"
	requestSnapshotGrantTypeAuthCode = "authorization_code"
	requestSnapshotHookClientID      = "hook-client-id"
	requestSnapshotHookDisplayName   = "Caller Example"
	requestSnapshotHookUniqueUserID  = "user-uuid"
	requestSnapshotLocalIP           = "127.0.0.1"
	requestSnapshotLocalPort         = "9444"
	requestSnapshotOIDCClientName    = "OIDC Test Client"
	requestSnapshotSerial            = "serial-1"
	requestSnapshotScopeOpenID       = "openid"
	requestSnapshotScopeProfile      = "profile"
	requestSnapshotStatusOK          = "OK"
	requestSnapshotTLSNotAfter       = "2026-12-31T23:59:59Z"
	requestSnapshotTLSNotBefore      = "2026-01-01T00:00:00Z"
	requestSnapshotTLSSessionID      = "ssl-session-1"
	requestSnapshotTLSVersion        = "TLSv1.3"
	requestSnapshotUniqueUserID      = "uid-123"
	requestSnapshotUsername          = "demo"
)

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

func TestRequestSnapshotPopulatesLuaParityFieldsFromAuthState(t *testing.T) {
	auth := newSnapshotParityAuthState()
	snapshot := NewRequestSnapshotFromAuthState(auth)

	assertSnapshotTransport(t, snapshot)
	assertSnapshotIdentity(t, snapshot)
	assertSnapshotRuntime(t, snapshot)
	assertSnapshotDiagnostics(t, snapshot)
	assertSnapshotTLS(t, snapshot)
}

// newSnapshotParityAuthState builds an auth state with every safe parity surface populated.
func newSnapshotParityAuthState() *core.AuthState {
	auth := &core.AuthState{}
	populateSnapshotParityRequest(auth)
	populateSnapshotParityRuntime(auth)
	populateSnapshotParitySecurity(auth)

	return auth
}

// populateSnapshotParityRequest fills safe request-bound metadata for snapshot tests.
func populateSnapshotParityRequest(auth *core.AuthState) {
	protocol := config.NewProtocol("imap")
	auth.Request.Protocol = protocol
	auth.Request.Service = "auth"
	auth.Request.Method = "plain"
	auth.Request.Username = requestSnapshotUsername
	auth.Request.ExternalSessionID = "external-session"
	auth.Request.ClientIP = "203.0.113.10"
	auth.Request.XClientPort = "4143"
	auth.Request.ClientHost = requestSnapshotClientHost
	auth.Request.XClientID = requestSnapshotClientID
	auth.Request.UserAgent = "imap-client/1.0"
	auth.Request.XLocalIP = requestSnapshotLocalIP
	auth.Request.XPort = requestSnapshotLocalPort
	auth.Request.OIDCCID = "oidc-client-1"
	auth.Request.AuthLoginAttempt = requestSnapshotAuthLoginAttempt
	auth.Request.NoAuth = true
	auth.Request.XSSL = "on"
	auth.Request.XSSLSessionID = requestSnapshotTLSSessionID
	auth.Request.XSSLClientVerify = "SUCCESS"
	auth.Request.XSSLClientDN = requestSnapshotClientDN
	auth.Request.XSSLClientCN = "client1"
	auth.Request.XSSLIssuer = "CN=issuer"
	auth.Request.XSSLClientNotBefore = requestSnapshotTLSNotBefore
	auth.Request.XSSLClientNotAfter = requestSnapshotTLSNotAfter
	auth.Request.XSSLSubjectDN = "CN=subject"
	auth.Request.XSSLIssuerDN = "CN=issuer-dn"
	auth.Request.XSSLClientSubjectDN = "CN=client-subject"
	auth.Request.XSSLClientIssuerDN = requestSnapshotClientIssuerDN
	auth.Request.XSSLProtocol = requestSnapshotTLSVersion
	auth.Request.XSSLCipher = "TLS_AES_256_GCM_SHA384"
	auth.Request.SSLSerial = requestSnapshotSerial
	auth.Request.SSLFingerprint = requestSnapshotFingerprint
}

// populateSnapshotParityRuntime fills safe runtime metadata for snapshot tests.
func populateSnapshotParityRuntime(auth *core.AuthState) {
	auth.Runtime.StartTime = time.Now().Add(-2 * time.Second)
	auth.Runtime.AccountField = backendTestMailAttr
	auth.Runtime.AccountName = "account@example.test"
	auth.Runtime.UniqueUserIDField = backendTestUIDAttr
	auth.Runtime.DisplayNameField = requestSnapshotDisplayNameField
	auth.Runtime.BFClientNet = requestSnapshotClientNet
	auth.Runtime.UserFound = true
	auth.Runtime.Authenticated = true
	auth.Runtime.Authorized = true
	auth.Runtime.BFRepeating = true
	auth.Runtime.BFRWP = true
	auth.Runtime.EnvironmentName = testRuntimeModuleName
	auth.Runtime.StatusMessage = requestSnapshotStatusOK
	auth.Runtime.StatusCodeOK = 200
}

// populateSnapshotParitySecurity fills safe security and attribute metadata for snapshot tests.
func populateSnapshotParitySecurity(auth *core.AuthState) {
	auth.Security.BruteForceName = requestSnapshotBruteForceName
	auth.Security.BruteForceCounter = map[string]uint{requestSnapshotBruteForceName: 7}
	auth.Attributes.Attributes = bktype.AttributeMapping{
		backendTestUIDAttr:              {definitions.LDAPSingleValue: requestSnapshotUniqueUserID},
		requestSnapshotDisplayNameField: {definitions.SliceWithOneElement: requestSnapshotDisplayName},
	}
}

// assertSnapshotTransport checks transport parity fields on a request snapshot.
func assertSnapshotTransport(t *testing.T, snapshot pluginapi.RequestSnapshot) {
	t.Helper()

	assertString(t, snapshot.LocalIP, requestSnapshotLocalIP, "local IP")
	assertString(t, snapshot.LocalPort, requestSnapshotLocalPort, "local port")
	assertString(t, snapshot.ClientNet, requestSnapshotClientNet, "client net")
	assertString(t, snapshot.ClientID, requestSnapshotClientID, "client ID")

	if snapshot.AuthLoginAttempt != requestSnapshotAuthLoginAttempt {
		t.Fatalf("auth login attempt = %d, want %d", snapshot.AuthLoginAttempt, requestSnapshotAuthLoginAttempt)
	}
}

// assertSnapshotIdentity checks safe identity fields on a request snapshot.
func assertSnapshotIdentity(t *testing.T, snapshot pluginapi.RequestSnapshot) {
	t.Helper()

	assertString(t, snapshot.AccountField, backendTestMailAttr, "account field")
	assertString(t, snapshot.UniqueUserID, requestSnapshotUniqueUserID, "unique user ID")
	assertString(t, snapshot.DisplayName, requestSnapshotDisplayName, "display name")
}

// assertSnapshotRuntime checks request outcome flags on a request snapshot.
func assertSnapshotRuntime(t *testing.T, snapshot pluginapi.RequestSnapshot) {
	t.Helper()

	assertTrue(t, snapshot.Runtime.NoAuth, "runtime no-auth")
	assertTrue(t, snapshot.Runtime.UserFound, "runtime user-found")
	assertTrue(t, snapshot.Runtime.Authenticated, "runtime authenticated")
	assertTrue(t, snapshot.Runtime.Authorized, "runtime authorized")
	assertTrue(t, snapshot.Runtime.LocalRequest, "runtime local request")
	assertTrue(t, snapshot.Runtime.Repeating, "runtime repeating")
	assertTrue(t, snapshot.Runtime.RWP, "runtime rwp")
}

// assertSnapshotDiagnostics checks bounded diagnostic values on a request snapshot.
func assertSnapshotDiagnostics(t *testing.T, snapshot pluginapi.RequestSnapshot) {
	t.Helper()

	assertString(t, snapshot.Diagnostics.BruteForceName, requestSnapshotBruteForceName, "brute-force name")
	assertString(t, snapshot.Diagnostics.EnvironmentName, testRuntimeModuleName, "environment name")
	assertString(t, snapshot.Diagnostics.StatusMessage, requestSnapshotStatusOK, "status message")

	if snapshot.Diagnostics.BruteForceCounter != 7 {
		t.Fatalf("brute-force counter = %d, want 7", snapshot.Diagnostics.BruteForceCounter)
	}

	if snapshot.Diagnostics.HTTPStatus != 200 {
		t.Fatalf("HTTP status = %d, want 200", snapshot.Diagnostics.HTTPStatus)
	}

	if snapshot.Diagnostics.LatencyMillis <= 0 {
		t.Fatalf("latency = %d, want positive", snapshot.Diagnostics.LatencyMillis)
	}
}

// assertSnapshotTLS checks normalized and legacy TLS compatibility metadata.
func assertSnapshotTLS(t *testing.T, snapshot pluginapi.RequestSnapshot) {
	t.Helper()

	assertTrue(t, snapshot.TLS.Enabled, "TLS enabled")
	assertTrue(t, snapshot.TLS.Mutual, "TLS mutual")
	assertString(t, snapshot.TLS.Version, requestSnapshotTLSVersion, "TLS version")
	assertString(t, snapshot.TLS.Legacy.SessionID, requestSnapshotTLSSessionID, "TLS session ID")
	assertString(t, snapshot.TLS.Legacy.ClientDN, requestSnapshotClientDN, "TLS client DN")
	assertString(t, snapshot.TLS.Legacy.ClientNotBefore, requestSnapshotTLSNotBefore, "TLS client not before")
	assertString(t, snapshot.TLS.Legacy.ClientNotAfter, requestSnapshotTLSNotAfter, "TLS client not after")
	assertString(t, snapshot.TLS.Legacy.ClientIssuerDN, requestSnapshotClientIssuerDN, "TLS client issuer DN")
	assertString(t, snapshot.TLS.Legacy.Serial, requestSnapshotSerial, "TLS serial")
	assertString(t, snapshot.TLS.Legacy.Fingerprint, requestSnapshotFingerprint, "TLS fingerprint")
}

// assertString compares a snapshot string value against its expected value.
func assertString(t *testing.T, got string, want string, label string) {
	t.Helper()

	if got != want {
		t.Fatalf("%s = %q, want %q", label, got, want)
	}
}

// assertTrue verifies a required boolean snapshot flag.
func assertTrue(t *testing.T, got bool, label string) {
	t.Helper()

	if !got {
		t.Fatalf("%s = false, want true", label)
	}
}
