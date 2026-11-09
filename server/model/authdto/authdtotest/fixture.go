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

// Package authdtotest provides shared structured auth request fixtures for tests.
package authdtotest

import "github.com/croessner/nauthilus/v4/server/model/authdto"

// FullRequest returns a structured auth request with every DTO field populated with distinct values.
func FullRequest() authdto.Request {
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
