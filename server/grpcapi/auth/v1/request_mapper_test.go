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

package authv1

import (
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/server/model/authdto"
)

func TestAuthRequestToDTOMapsEveryField(t *testing.T) {
	t.Parallel()

	got := AuthRequestToDTO(newPopulatedAuthRequest())
	expected := expectedAuthDTO()
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected DTO mapping:\n got: %+v\nwant: %+v", got, expected)
	}
}

// TestListAccountsRequestToDTOMapsEveryField verifies field-complete mapping
// for the list-accounts RPC request payload.
func TestListAccountsRequestToDTOMapsEveryField(t *testing.T) {
	t.Parallel()

	request := &ListAccountsRequest{
		Username:          "user@example.test",
		ClientIp:          "203.0.113.10",
		ClientPort:        "40123",
		ClientHostname:    "client.example.test",
		ClientId:          "cid-1",
		ExternalSessionId: "ext-123",
		UserAgent:         "grpc-client/1.0",
		LocalIp:           "127.0.0.1",
		LocalPort:         "9444",
		Protocol:          "account-provider",
		Method:            "list-accounts",
		OidcCid:           "oidc-client",
	}

	expected := authdto.Request{
		Username:          "user@example.test",
		ClientIP:          "203.0.113.10",
		ClientPort:        "40123",
		ClientHostname:    "client.example.test",
		ClientID:          "cid-1",
		ExternalSessionID: "ext-123",
		UserAgent:         "grpc-client/1.0",
		LocalIP:           "127.0.0.1",
		LocalPort:         "9444",
		Protocol:          "account-provider",
		Method:            "list-accounts",
		OIDCCID:           "oidc-client",
	}

	got := ListAccountsRequestToDTO(request)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected DTO mapping:\n got: %+v\nwant: %+v", got, expected)
	}
}

func TestLookupIdentityRequestToDTOMapsEveryField(t *testing.T) {
	t.Parallel()

	request := &LookupIdentityRequest{
		Username:           "user@example.test",
		ClientIp:           "203.0.113.10",
		ClientPort:         "40123",
		ClientHostname:     "client.example.test",
		ClientId:           "cid-1",
		ExternalSessionId:  "ext-123",
		UserAgent:          "grpc-client/1.0",
		LocalIp:            "127.0.0.1",
		LocalPort:          "9444",
		Protocol:           "imap",
		Method:             "lookup",
		Ssl:                "on",
		SslSessionId:       "sess-1",
		SslClientVerify:    "SUCCESS",
		SslClientDn:        "CN=test",
		SslClientCn:        "test",
		SslIssuer:          "issuer",
		SslClientNotbefore: "2026-01-01T00:00:00Z",
		SslClientNotafter:  "2026-12-31T23:59:59Z",
		SslSubjectDn:       "subject-dn",
		SslIssuerDn:        "issuer-dn",
		SslClientSubjectDn: "client-subject-dn",
		SslClientIssuerDn:  "client-issuer-dn",
		SslProtocol:        "TLSv1.3",
		SslCipher:          "TLS_AES_256_GCM_SHA384",
		SslSerial:          "01",
		SslFingerprint:     "ab:cd",
		OidcCid:            "oidc-client",
	}

	expected := expectedAuthDTO()
	expected.Password = ""
	expected.Method = "lookup"
	expected.AuthLoginAttempt = 0

	got := LookupIdentityRequestToDTO(request)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected DTO mapping:\n got: %+v\nwant: %+v", got, expected)
	}
}

// TestRequestMappersHandleNilInput ensures all mappers are nil-safe and
// return a zero DTO value when no request is provided.
func TestRequestMappersHandleNilInput(t *testing.T) {
	t.Parallel()

	if got := AuthRequestToDTO(nil); !reflect.DeepEqual(got, authdto.Request{}) {
		t.Fatalf("AuthRequestToDTO(nil) should return zero request, got %+v", got)
	}

	if got := ListAccountsRequestToDTO(nil); !reflect.DeepEqual(got, authdto.Request{}) {
		t.Fatalf("ListAccountsRequestToDTO(nil) should return zero request, got %+v", got)
	}

	if got := LookupIdentityRequestToDTO(nil); !reflect.DeepEqual(got, authdto.Request{}) {
		t.Fatalf("LookupIdentityRequestToDTO(nil) should return zero request, got %+v", got)
	}
}

// newPopulatedAuthRequest creates a fully populated auth request used by
// mapping tests to cover every field.
func newPopulatedAuthRequest() *AuthRequest {
	return &AuthRequest{
		Username:           "user@example.test",
		Password:           "secret",
		ClientIp:           "203.0.113.10",
		ClientPort:         "40123",
		ClientHostname:     "client.example.test",
		ClientId:           "cid-1",
		ExternalSessionId:  "ext-123",
		UserAgent:          "grpc-client/1.0",
		LocalIp:            "127.0.0.1",
		LocalPort:          "9444",
		Protocol:           "imap",
		Method:             "plain",
		Ssl:                "on",
		SslSessionId:       "sess-1",
		SslClientVerify:    "SUCCESS",
		SslClientDn:        "CN=test",
		SslClientCn:        "test",
		SslIssuer:          "issuer",
		SslClientNotbefore: "2026-01-01T00:00:00Z",
		SslClientNotafter:  "2026-12-31T23:59:59Z",
		SslSubjectDn:       "subject-dn",
		SslIssuerDn:        "issuer-dn",
		SslClientSubjectDn: "client-subject-dn",
		SslClientIssuerDn:  "client-issuer-dn",
		SslProtocol:        "TLSv1.3",
		SslCipher:          "TLS_AES_256_GCM_SHA384",
		SslSerial:          "01",
		SslFingerprint:     "ab:cd",
		OidcCid:            "oidc-client",
		AuthLoginAttempt:   7,
	}
}

// expectedAuthDTO returns the canonical DTO representation for the populated
// auth request fixture.
func expectedAuthDTO() authdto.Request {
	return authdto.Request{
		Username:            "user@example.test",
		Password:            "secret",
		ClientIP:            "203.0.113.10",
		ClientPort:          "40123",
		ClientHostname:      "client.example.test",
		ClientID:            "cid-1",
		ExternalSessionID:   "ext-123",
		UserAgent:           "grpc-client/1.0",
		LocalIP:             "127.0.0.1",
		LocalPort:           "9444",
		Protocol:            "imap",
		Method:              "plain",
		XSSL:                "on",
		XSSLSessionID:       "sess-1",
		XSSLClientVerify:    "SUCCESS",
		XSSLClientDN:        "CN=test",
		XSSLClientCN:        "test",
		XSSLIssuer:          "issuer",
		XSSLClientNotBefore: "2026-01-01T00:00:00Z",
		XSSLClientNotAfter:  "2026-12-31T23:59:59Z",
		XSSLSubjectDN:       "subject-dn",
		XSSLIssuerDN:        "issuer-dn",
		XSSLClientSubjectDN: "client-subject-dn",
		XSSLClientIssuerDN:  "client-issuer-dn",
		XSSLProtocol:        "TLSv1.3",
		XSSLCipher:          "TLS_AES_256_GCM_SHA384",
		SSLSerial:           "01",
		SSLFingerprint:      "ab:cd",
		OIDCCID:             "oidc-client",
		AuthLoginAttempt:    7,
	}
}
