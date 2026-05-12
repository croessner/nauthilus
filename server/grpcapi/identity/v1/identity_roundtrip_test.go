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

package identityv1

import (
	"testing"
	"time"

	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testAttestationTypeNone  = "none"
	testCredentialName       = "security key"
	testCredentialRawJSON    = `{"id":"AQID","signCount":42}`
	testIdentityUsername     = "user@example.test"
	testIdentityProtocolOIDC = "oidc"
)

func TestIdentityMessagesRoundTrip(t *testing.T) {
	t.Parallel()

	lastUsed := time.Date(2026, 5, 12, 10, 15, 30, 0, time.UTC)
	credential := &WebAuthnCredential{
		CredentialId:    []byte{0x01, 0x02, 0x03},
		PublicKey:       []byte{0x04, 0x05, 0x06},
		SignCount:       42,
		Transports:      []string{"usb", "internal"},
		BackupEligible:  true,
		BackupState:     true,
		AttestationType: testAttestationTypeNone,
		Name:            testCredentialName,
		LastUsed:        timestamppb.New(lastUsed),
		RawJson:         testCredentialRawJSON,
	}

	cases := []struct {
		name       string
		message    proto.Message
		newMessage func() proto.Message
	}{
		{name: "request context", message: newRoundTripRequestContext(), newMessage: func() proto.Message { return &RequestContext{} }},
		{name: "user snapshot", message: newRoundTripUserSnapshot(credential), newMessage: func() proto.Message { return &UserSnapshot{} }},
		{name: "mfa state", message: newRoundTripMFAState(credential), newMessage: func() proto.Message { return &MFAState{} }},
		{name: "webauthn credential", message: credential, newMessage: func() proto.Message { return &WebAuthnCredential{} }},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			data, err := proto.Marshal(testCase.message)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			roundTripped := testCase.newMessage()
			if err := proto.Unmarshal(data, roundTripped); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if !proto.Equal(testCase.message, roundTripped) {
				t.Fatalf("roundtrip mismatch:\n got: %v\nwant: %v", roundTripped, testCase.message)
			}
		})
	}
}

func newRoundTripRequestContext() *RequestContext {
	return &RequestContext{
		Username:           testIdentityUsername,
		ClientIp:           "203.0.113.10",
		ClientPort:         "40123",
		ClientHostname:     "client.example.test",
		ClientId:           "client-id",
		ExternalSessionId:  "external-session",
		UserAgent:          "browser",
		LocalIp:            "127.0.0.1",
		LocalPort:          "9444",
		Protocol:           testIdentityProtocolOIDC,
		Method:             "lookup_identity",
		Ssl:                "on",
		SslSessionId:       "ssl-session",
		SslClientVerify:    "SUCCESS",
		SslClientDn:        "CN=edge",
		SslClientCn:        "edge",
		SslIssuer:          "issuer",
		SslClientNotbefore: "2026-01-01T00:00:00Z",
		SslClientNotafter:  "2026-12-31T23:59:59Z",
		SslSubjectDn:       "subject",
		SslIssuerDn:        "issuer-dn",
		SslClientSubjectDn: "client-subject",
		SslClientIssuerDn:  "client-issuer",
		SslProtocol:        "TLSv1.3",
		SslCipher:          "TLS_AES_256_GCM_SHA384",
		SslSerial:          "serial",
		SslFingerprint:     "fingerprint",
		OidcCid:            "oidc-client",
		SamlEntityId:       "saml-entity",
		AuthLoginAttempt:   3,
		Metadata: map[string]*commonv1.AttributeValues{
			"request.header.x-correlation-id": {Values: []string{"corr-1"}},
		},
		EdgeInstance:      "edge-a",
		EdgeRequestId:     "edge-request",
		RequestedLanguage: "en",
	}
}

func newRoundTripUserSnapshot(credential *WebAuthnCredential) *UserSnapshot {
	return &UserSnapshot{
		Username:     testIdentityUsername,
		Account:      "account",
		UniqueUserId: "unique-id",
		DisplayName:  "User Example",
		Attributes: map[string]*commonv1.AttributeValues{
			"mail": {Values: []string{testIdentityUsername}},
		},
		Groups:   []string{"users"},
		GroupDns: []string{"cn=users,dc=example,dc=test"},
		Backend:  newRoundTripBackendRef(),
		Mfa:      newRoundTripMFAState(credential),
	}
}

func newRoundTripMFAState(credential *WebAuthnCredential) *MFAState {
	return &MFAState{
		HasTotp:             true,
		RecoveryCodeCount:   4,
		HasWebauthn:         true,
		WebauthnCredentials: []*WebAuthnCredential{credential},
		PreferredMethod:     "webauthn",
	}
}

func newRoundTripBackendRef() *commonv1.BackendRef {
	return &commonv1.BackendRef{
		Type:        "ldap",
		Name:        "default",
		Protocol:    testIdentityProtocolOIDC,
		Authority:   "authority-a",
		OpaqueToken: "opaque-ref",
	}
}
