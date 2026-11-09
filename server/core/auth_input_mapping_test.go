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
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/model/authdto/authdtotest"
	"github.com/gin-gonic/gin"
)

// TestApplyAuthInputMapsEveryStructuredField pins that every structured DTO field reaches the request-owned auth state
// through the single auth-input applier used by the auth host.
func TestApplyAuthInputMapsEveryStructuredField(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	auth := &AuthState{deps: setupAuthDeps(), Request: AuthRequest{HTTPClientContext: ctx}}
	want := authdtotest.FullRequest()

	auth.applyAuthInput(NewAuthInputFromStructuredRequest(definitions.ServJSON, AuthModeAuthenticate, want))

	fields := []struct {
		name string
		got  string
		want string
	}{
		{"username", auth.GetUsername(), want.Username},
		{"password", auth.GetPassword().String(), want.Password},
		{"client_ip", auth.Request.ClientIP, want.ClientIP},
		{"client_port", auth.Request.XClientPort, want.ClientPort},
		{"client_hostname", auth.Request.ClientHost, want.ClientHostname},
		{"client_id", auth.Request.XClientID, want.ClientID},
		{"external_session_id", auth.Request.ExternalSessionID, want.ExternalSessionID},
		{"user_agent", auth.Request.UserAgent, want.UserAgent},
		{"local_ip", auth.Request.XLocalIP, want.LocalIP},
		{"local_port", auth.Request.XPort, want.LocalPort},
		{"protocol", auth.GetProtocol().Get(), want.Protocol},
		{"method", auth.Request.Method, want.Method},
		{"ssl", auth.Request.XSSL, want.XSSL},
		{"ssl_session_id", auth.Request.XSSLSessionID, want.XSSLSessionID},
		{"ssl_client_verify", auth.Request.XSSLClientVerify, want.XSSLClientVerify},
		{"ssl_client_dn", auth.Request.XSSLClientDN, want.XSSLClientDN},
		{"ssl_client_cn", auth.Request.XSSLClientCN, want.XSSLClientCN},
		{"ssl_issuer", auth.Request.XSSLIssuer, want.XSSLIssuer},
		{"ssl_client_notbefore", auth.Request.XSSLClientNotBefore, want.XSSLClientNotBefore},
		{"ssl_client_notafter", auth.Request.XSSLClientNotAfter, want.XSSLClientNotAfter},
		{"ssl_subject_dn", auth.Request.XSSLSubjectDN, want.XSSLSubjectDN},
		{"ssl_issuer_dn", auth.Request.XSSLIssuerDN, want.XSSLIssuerDN},
		{"ssl_client_subject_dn", auth.Request.XSSLClientSubjectDN, want.XSSLClientSubjectDN},
		{"ssl_client_issuer_dn", auth.Request.XSSLClientIssuerDN, want.XSSLClientIssuerDN},
		{"ssl_protocol", auth.Request.XSSLProtocol, want.XSSLProtocol},
		{"ssl_cipher", auth.Request.XSSLCipher, want.XSSLCipher},
		{"ssl_serial", auth.Request.SSLSerial, want.SSLSerial},
		{"ssl_fingerprint", auth.Request.SSLFingerprint, want.SSLFingerprint},
		{"oidc_cid", auth.Request.OIDCCID, want.OIDCCID},
	}

	for _, field := range fields {
		if field.got != field.want {
			t.Errorf("%s = %q, want %q", field.name, field.got, field.want)
		}
	}

	if auth.Request.AuthLoginAttempt != want.AuthLoginAttempt || auth.GetFailCount() != want.AuthLoginAttempt-1 {
		t.Errorf("login attempt/fail count = %d/%d, want %d/%d", auth.Request.AuthLoginAttempt, auth.GetFailCount(),
			want.AuthLoginAttempt, want.AuthLoginAttempt-1)
	}
}
