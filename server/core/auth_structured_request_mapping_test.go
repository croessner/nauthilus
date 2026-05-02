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

package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/fxamacker/cbor/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestApplyStructuredAuthRequestMapsAllFields(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	auth := &AuthState{
		deps: setupAuthDeps(),
		Request: AuthRequest{
			HTTPClientContext: ctx,
		},
	}

	request := fullStructuredRequestFixture()
	expected := request

	ApplyStructuredAuthRequest(auth, &request)

	assertAuthStateMatchesStructuredRequest(t, auth, expected)
	assert.Empty(t, request.Password, "password should be cleared after mapping")
}

// TestNewAuthStateWithSetupWithDepsMapsAllJSONFields verifies that the JSON
// request setup path still maps all structured fields into AuthState.
func TestNewAuthStateWithSetupWithDepsMapsAllJSONFields(t *testing.T) {
	request := fullStructuredRequestFixture()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal JSON payload: %v", err)
	}

	auth := setupStructuredAuthStateFromPayload(t, definitions.ServJSON, "application/json", payload)

	assertAuthStateMatchesStructuredRequest(t, auth, request)
}

// TestNewAuthStateWithSetupWithDepsMapsAllCBORFields verifies that the CBOR
// request setup path still maps all structured fields into AuthState.
func TestNewAuthStateWithSetupWithDepsMapsAllCBORFields(t *testing.T) {
	request := fullStructuredRequestFixture()
	payload, err := cbor.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal CBOR payload: %v", err)
	}

	auth := setupStructuredAuthStateFromPayload(t, definitions.ServCBOR, "application/cbor", payload)

	assertAuthStateMatchesStructuredRequest(t, auth, request)
}

// setupStructuredAuthStateFromPayload builds an auth state through the normal
// setup pipeline using the provided encoded request body.
func setupStructuredAuthStateFromPayload(
	t *testing.T,
	service string,
	contentType string,
	payload []byte,
) *AuthState {
	t.Helper()

	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)

	endpoint := "/api/v1/auth/json"
	if service == definitions.ServCBOR {
		endpoint = "/api/v1/auth/cbor"
	}

	ctx.Request = httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", contentType)
	ctx.Set(definitions.CtxServiceKey, service)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	auth := NewAuthStateWithSetupWithDeps(ctx, setupAuthDeps())
	if auth == nil {
		t.Fatal("expected auth state, got nil")
	}

	authState, ok := auth.(*AuthState)
	if !ok {
		t.Fatalf("expected *AuthState, got %T", auth)
	}

	return authState
}

// fullStructuredRequestFixture returns a request with all structured fields
// populated for transport mapping coverage tests.
func fullStructuredRequestFixture() authdto.Request {
	return authdto.Request{
		Username:            "user@example.test",
		Password:            "secret",
		ClientIP:            "203.0.113.10",
		ClientPort:          "4143",
		ClientHostname:      "client.example.test",
		ClientID:            "client-123",
		ExternalSessionID:   "external-session-123",
		UserAgent:           "imap-client/1.0",
		LocalIP:             "127.0.0.1",
		LocalPort:           "9444",
		Protocol:            "imap",
		Method:              "plain",
		XSSL:                "on",
		XSSLSessionID:       "ssl-session-1",
		XSSLClientVerify:    "SUCCESS",
		XSSLClientDN:        "CN=client1,OU=mail",
		XSSLClientCN:        "client1",
		XSSLIssuer:          "CN=issuer",
		XSSLClientNotBefore: "2026-01-01T00:00:00Z",
		XSSLClientNotAfter:  "2026-12-31T23:59:59Z",
		XSSLSubjectDN:       "CN=subject",
		XSSLIssuerDN:        "CN=issuer-dn",
		XSSLClientSubjectDN: "CN=client-subject",
		XSSLClientIssuerDN:  "CN=client-issuer",
		XSSLProtocol:        "TLSv1.3",
		XSSLCipher:          "TLS_AES_256_GCM_SHA384",
		SSLSerial:           "serial-1",
		SSLFingerprint:      "aa:bb:cc",
		OIDCCID:             "oidc-client-1",
		AuthLoginAttempt:    4,
	}
}

// assertAuthStateMatchesStructuredRequest validates that every structured DTO
// field is reflected in the resulting AuthState.
func assertAuthStateMatchesStructuredRequest(t *testing.T, auth *AuthState, expected authdto.Request) {
	t.Helper()

	if auth == nil {
		t.Fatal("auth state must not be nil")
	}

	assert.Equal(t, expected.Username, auth.GetUsername())
	assert.Equal(t, expected.ClientIP, auth.Request.ClientIP)
	assert.Equal(t, expected.ClientPort, auth.Request.XClientPort)
	assert.Equal(t, expected.ClientHostname, auth.Request.ClientHost)
	assert.Equal(t, expected.ClientID, auth.Request.XClientID)
	assert.Equal(t, expected.ExternalSessionID, auth.Request.ExternalSessionID)
	assert.Equal(t, expected.UserAgent, auth.Request.UserAgent)
	assert.Equal(t, expected.LocalIP, auth.Request.XLocalIP)
	assert.Equal(t, expected.LocalPort, auth.Request.XPort)
	assert.Equal(t, expected.Protocol, auth.GetProtocol().Get())
	assert.Equal(t, expected.Method, auth.Request.Method)
	assert.Equal(t, expected.XSSL, auth.Request.XSSL)
	assert.Equal(t, expected.XSSLSessionID, auth.Request.XSSLSessionID)
	assert.Equal(t, expected.XSSLClientVerify, auth.Request.XSSLClientVerify)
	assert.Equal(t, expected.XSSLClientDN, auth.Request.XSSLClientDN)
	assert.Equal(t, expected.XSSLClientCN, auth.Request.XSSLClientCN)
	assert.Equal(t, expected.XSSLIssuer, auth.Request.XSSLIssuer)
	assert.Equal(t, expected.XSSLClientNotBefore, auth.Request.XSSLClientNotBefore)
	assert.Equal(t, expected.XSSLClientNotAfter, auth.Request.XSSLClientNotAfter)
	assert.Equal(t, expected.XSSLSubjectDN, auth.Request.XSSLSubjectDN)
	assert.Equal(t, expected.XSSLIssuerDN, auth.Request.XSSLIssuerDN)
	assert.Equal(t, expected.XSSLClientSubjectDN, auth.Request.XSSLClientSubjectDN)
	assert.Equal(t, expected.XSSLClientIssuerDN, auth.Request.XSSLClientIssuerDN)
	assert.Equal(t, expected.XSSLProtocol, auth.Request.XSSLProtocol)
	assert.Equal(t, expected.XSSLCipher, auth.Request.XSSLCipher)
	assert.Equal(t, expected.SSLSerial, auth.Request.SSLSerial)
	assert.Equal(t, expected.SSLFingerprint, auth.Request.SSLFingerprint)
	assert.Equal(t, expected.OIDCCID, auth.Request.OIDCCID)
	assert.Equal(t, expected.AuthLoginAttempt, auth.Request.AuthLoginAttempt)

	var password string
	auth.GetPassword().WithString(func(value string) {
		password = value
	})

	assert.Equal(t, expected.Password, password)

	if expected.AuthLoginAttempt > 0 {
		assert.Equal(t, expected.AuthLoginAttempt-1, auth.GetFailCount())
	}

	if auth.Request.HTTPClientContext != nil {
		assert.Equal(
			t,
			expected.ExternalSessionID,
			auth.Request.HTTPClientContext.GetString(definitions.CtxExternalSessionKey),
		)
	}
}
