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

package auth

import (
	"encoding/base64"
	stdjson "encoding/json"
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/encoding/cborcodec"
	"github.com/croessner/nauthilus/v4/server/model/authdto"

	"github.com/gin-gonic/gin"
)

// TestHTTPAuthInputBuilderMapsEveryStructuredField pins that JSON and CBOR auth bodies map every DTO field into the
// transport-neutral auth input.
func TestHTTPAuthInputBuilderMapsEveryStructuredField(t *testing.T) {
	gin.SetMode(gin.TestMode)

	request := fullStructuredAuthRequest()
	encoders := map[string]struct {
		contentType string
		encode      func(any) ([]byte, error)
	}{
		definitions.ServJSON: {contentType: "application/json", encode: stdjson.Marshal},
		definitions.ServCBOR: {contentType: "application/cbor", encode: cborcodec.Marshal},
	}

	for service, encoder := range encoders {
		t.Run(service, func(t *testing.T) {
			payload, err := encoder.encode(request)
			if err != nil {
				t.Fatalf("encode request: %v", err)
			}

			ctx, recorder := newHTTPAuthAdapterTestContext(http.MethodPost, "/api/v1/auth/"+service, string(payload),
				encoder.contentType, service)

			input, ok := newHTTPAuthInputBuilder(applicationBoundaryDeps()).Build(ctx)
			if !ok {
				t.Fatalf("Build() rejected the full request: status %d body %q", recorder.Code, recorder.Body.String())
			}

			assertStructuredAuthInput(t, input, request)
		})
	}
}

// TestHTTPAuthInputBuilderDecodesHeaderPasswords pins URL partial decoding and the legacy URL-safe base64 form of
// header passwords.
func TestHTTPAuthInputBuilderDecodesHeaderPasswords(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		header  string
		encoded bool
		want    string
	}{
		{name: "plain", header: "password123", want: "password123"},
		{name: "url encoded ampersand", header: "pass%26word", want: "pass&word"},
		{name: "url encoded percent", header: "100%25percent", want: "100%percent"},
		{name: "url encoded space", header: "my%20password", want: "my password"},
		{name: "mixed url encoding", header: "pass%20word%26100%25", want: "pass word&100%"},
		{name: "unpadded url-safe base64", header: base64.RawURLEncoding.EncodeToString([]byte("pass word?")),
			encoded: true, want: "pass word?"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, _ := newHTTPAuthAdapterTestContext(http.MethodGet, "/api/v1/auth/nginx", "", "", definitions.ServNginx)
			ctx.Request.Header.Set("Auth-User", "alice@example.test")
			ctx.Request.Header.Set("Auth-Pass", test.header)

			if test.encoded {
				ctx.Request.Header.Set("Auth-Pass-Encoded", "1")
			}

			input, ok := newHTTPAuthInputBuilder(applicationBoundaryDeps()).Build(ctx)
			if !ok {
				t.Fatal("Build() rejected the header password")
			}

			if got := input.Credentials.Password.String(); got != test.want {
				t.Fatalf("password = %q, want %q", got, test.want)
			}
		})
	}
}

// assertStructuredAuthInput compares every mapped auth input field with its DTO source.
func assertStructuredAuthInput(t *testing.T, input core.AuthInput, want authdto.Request) {
	t.Helper()

	fields := []struct {
		name string
		got  string
		want string
	}{
		{"username", input.Credentials.Username, want.Username},
		{"password", input.Credentials.Password.String(), want.Password},
		{"client_ip", input.Context.ClientIP, want.ClientIP},
		{"client_port", input.Context.ClientPort, want.ClientPort},
		{"client_hostname", input.Context.ClientHostname, want.ClientHostname},
		{"client_id", input.Context.ClientID, want.ClientID},
		{"external_session_id", input.Context.ExternalSessionID, want.ExternalSessionID},
		{"user_agent", input.Context.UserAgent, want.UserAgent},
		{"local_ip", input.Context.LocalIP, want.LocalIP},
		{"local_port", input.Context.LocalPort, want.LocalPort},
		{"protocol", input.Context.Protocol, want.Protocol},
		{"method", input.Context.Method, want.Method},
		{"ssl", input.Context.XSSL, want.XSSL},
		{"ssl_session_id", input.Context.XSSLSessionID, want.XSSLSessionID},
		{"ssl_client_verify", input.Context.XSSLClientVerify, want.XSSLClientVerify},
		{"ssl_client_dn", input.Context.XSSLClientDN, want.XSSLClientDN},
		{"ssl_client_cn", input.Context.XSSLClientCN, want.XSSLClientCN},
		{"ssl_issuer", input.Context.XSSLIssuer, want.XSSLIssuer},
		{"ssl_client_notbefore", input.Context.XSSLClientNotBefore, want.XSSLClientNotBefore},
		{"ssl_client_notafter", input.Context.XSSLClientNotAfter, want.XSSLClientNotAfter},
		{"ssl_subject_dn", input.Context.XSSLSubjectDN, want.XSSLSubjectDN},
		{"ssl_issuer_dn", input.Context.XSSLIssuerDN, want.XSSLIssuerDN},
		{"ssl_client_subject_dn", input.Context.XSSLClientSubjectDN, want.XSSLClientSubjectDN},
		{"ssl_client_issuer_dn", input.Context.XSSLClientIssuerDN, want.XSSLClientIssuerDN},
		{"ssl_protocol", input.Context.XSSLProtocol, want.XSSLProtocol},
		{"ssl_cipher", input.Context.XSSLCipher, want.XSSLCipher},
		{"ssl_serial", input.Context.SSLSerial, want.SSLSerial},
		{"ssl_fingerprint", input.Context.SSLFingerprint, want.SSLFingerprint},
		{"oidc_cid", input.Context.OIDCCID, want.OIDCCID},
	}

	for _, field := range fields {
		if field.got != field.want {
			t.Errorf("%s = %q, want %q", field.name, field.got, field.want)
		}
	}

	if input.AuthLoginAttempt != want.AuthLoginAttempt {
		t.Errorf("auth_login_attempt = %d, want %d", input.AuthLoginAttempt, want.AuthLoginAttempt)
	}
}

// fullStructuredAuthRequest returns a structured auth request with every DTO field populated.
func fullStructuredAuthRequest() authdto.Request {
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
