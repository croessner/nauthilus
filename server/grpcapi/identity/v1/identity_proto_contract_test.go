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

	"github.com/croessner/nauthilus/server/grpcapi/internal/prototest"

	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	identityProtoPackage = "nauthilus.identity.v1"
	identityServiceName  = "IdentityBackendService"
)

const (
	rpcResolveUser              = "ResolveUser"
	rpcGetMFAState              = "GetMFAState"
	rpcBeginTOTPRegistration    = "BeginTOTPRegistration"
	rpcFinishTOTPRegistration   = "FinishTOTPRegistration"
	rpcVerifyTOTP               = "VerifyTOTP"
	rpcDeleteTOTP               = "DeleteTOTP"
	rpcGenerateRecoveryCodes    = "GenerateRecoveryCodes"
	rpcUseRecoveryCode          = "UseRecoveryCode"
	rpcDeleteRecoveryCodes      = "DeleteRecoveryCodes"
	rpcGetWebAuthnCredentials   = "GetWebAuthnCredentials"
	rpcSaveWebAuthnCredential   = "SaveWebAuthnCredential"
	rpcUpdateWebAuthnCredential = "UpdateWebAuthnCredential"
	rpcDeleteWebAuthnCredential = "DeleteWebAuthnCredential"
)

const (
	backendRefFullName       protoreflect.FullName = "nauthilus.common.v1.BackendRef"
	operationStatusFullName  protoreflect.FullName = "nauthilus.common.v1.OperationStatus"
	attributeValuesFullName  protoreflect.FullName = "nauthilus.common.v1.AttributeValues"
	requestContextFullName   protoreflect.FullName = "nauthilus.identity.v1.RequestContext"
	attributeRequestFullName protoreflect.FullName = "nauthilus.identity.v1.AttributeRequest"
	userSnapshotFullName     protoreflect.FullName = "nauthilus.identity.v1.UserSnapshot"
	mfaStateFullName         protoreflect.FullName = "nauthilus.identity.v1.MFAState"
	credentialFullName       protoreflect.FullName = "nauthilus.identity.v1.WebAuthnCredential"
)

const (
	messageMFAWriteResponse           protoreflect.Name = "MFAWriteResponse"
	messageDeleteTOTPRequest          protoreflect.Name = "DeleteTOTPRequest"
	messageDeleteRecoveryCodesRequest protoreflect.Name = "DeleteRecoveryCodesRequest"
)

func TestIdentityProtoContract(t *testing.T) {
	t.Parallel()

	fileDescriptor := File_server_grpcapi_identity_v1_identity_backend_proto

	prototest.AssertPackage(t, fileDescriptor, identityProtoPackage)
	assertIdentityServiceShape(t, fileDescriptor)
	assertRequestContextShape(t, fileDescriptor)
	assertUserSnapshotShape(t, fileDescriptor)
	assertMFAShapes(t, fileDescriptor)
	assertWebAuthnShapes(t, fileDescriptor)
}

func assertIdentityServiceShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	service := prototest.Service(t, fileDescriptor, identityServiceName)
	methods := service.Methods()

	cases := []struct {
		name       string
		inputType  protoreflect.Name
		outputType protoreflect.Name
	}{
		{name: rpcResolveUser, inputType: "ResolveUserRequest", outputType: "UserSnapshotResponse"},
		{name: rpcGetMFAState, inputType: "GetMFAStateRequest", outputType: "MFAStateResponse"},
		{name: rpcBeginTOTPRegistration, inputType: "BeginTOTPRegistrationRequest", outputType: "BeginTOTPRegistrationResponse"},
		{name: rpcFinishTOTPRegistration, inputType: "FinishTOTPRegistrationRequest", outputType: messageMFAWriteResponse},
		{name: rpcVerifyTOTP, inputType: "VerifyTOTPRequest", outputType: "VerifyTOTPResponse"},
		{name: rpcDeleteTOTP, inputType: messageDeleteTOTPRequest, outputType: messageMFAWriteResponse},
		{name: rpcGenerateRecoveryCodes, inputType: "GenerateRecoveryCodesRequest", outputType: "GenerateRecoveryCodesResponse"},
		{name: rpcUseRecoveryCode, inputType: "UseRecoveryCodeRequest", outputType: "UseRecoveryCodeResponse"},
		{name: rpcDeleteRecoveryCodes, inputType: messageDeleteRecoveryCodesRequest, outputType: messageMFAWriteResponse},
		{name: rpcGetWebAuthnCredentials, inputType: "GetWebAuthnCredentialsRequest", outputType: "WebAuthnCredentialsResponse"},
		{name: rpcSaveWebAuthnCredential, inputType: "SaveWebAuthnCredentialRequest", outputType: messageMFAWriteResponse},
		{name: rpcUpdateWebAuthnCredential, inputType: "UpdateWebAuthnCredentialRequest", outputType: messageMFAWriteResponse},
		{name: rpcDeleteWebAuthnCredential, inputType: "DeleteWebAuthnCredentialRequest", outputType: messageMFAWriteResponse},
	}

	if got, want := methods.Len(), len(cases); got != want {
		t.Fatalf("unexpected method count: got %d want %d", got, want)
	}

	for index, testCase := range cases {
		method := methods.Get(index)

		if got := string(method.Name()); got != testCase.name {
			t.Fatalf("unexpected method at index %d: got %q want %q", index, got, testCase.name)
		}

		if got := method.Input().Name(); got != testCase.inputType {
			t.Fatalf("%s input type = %q, want %q", testCase.name, got, testCase.inputType)
		}

		if got := method.Output().Name(); got != testCase.outputType {
			t.Fatalf("%s output type = %q, want %q", testCase.name, got, testCase.outputType)
		}
	}
}

func assertRequestContextShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	message := prototest.Message(t, fileDescriptor, "RequestContext")
	cases := []struct {
		name   protoreflect.Name
		number protoreflect.FieldNumber
	}{
		{name: "username", number: 1},
		{name: "client_ip", number: 2},
		{name: "client_port", number: 3},
		{name: "client_hostname", number: 4},
		{name: "client_id", number: 5},
		{name: "external_session_id", number: 6},
		{name: "user_agent", number: 7},
		{name: "local_ip", number: 8},
		{name: "local_port", number: 9},
		{name: "protocol", number: 10},
		{name: "method", number: 11},
		{name: "ssl", number: 12},
		{name: "ssl_session_id", number: 13},
		{name: "ssl_client_verify", number: 14},
		{name: "ssl_client_dn", number: 15},
		{name: "ssl_client_cn", number: 16},
		{name: "ssl_issuer", number: 17},
		{name: "ssl_client_notbefore", number: 18},
		{name: "ssl_client_notafter", number: 19},
		{name: "ssl_subject_dn", number: 20},
		{name: "ssl_issuer_dn", number: 21},
		{name: "ssl_client_subject_dn", number: 22},
		{name: "ssl_client_issuer_dn", number: 23},
		{name: "ssl_protocol", number: 24},
		{name: "ssl_cipher", number: 25},
		{name: "ssl_serial", number: 26},
		{name: "ssl_fingerprint", number: 27},
		{name: "oidc_cid", number: 28},
		{name: "saml_entity_id", number: 29},
		{name: "auth_login_attempt", number: 30},
		{name: "edge_instance", number: 32},
		{name: "edge_request_id", number: 33},
		{name: "requested_language", number: 34},
	}

	for _, testCase := range cases {
		prototest.AssertFieldNumber(t, message, testCase.name, testCase.number)
	}

	prototest.AssertMapValueMessage(t, message, "metadata", 31, attributeValuesFullName)
}

func assertUserSnapshotShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	attributeRequest := prototest.Message(t, fileDescriptor, "AttributeRequest")
	prototest.AssertFieldNumber(t, attributeRequest, "names", 1)
	prototest.AssertFieldNumber(t, attributeRequest, "include_standard_identity", 2)
	prototest.AssertFieldNumber(t, attributeRequest, "include_groups", 3)
	prototest.AssertFieldNumber(t, attributeRequest, "include_group_dns", 4)
	prototest.AssertFieldNumber(t, attributeRequest, "report_missing", 5)

	user := prototest.Message(t, fileDescriptor, "UserSnapshot")
	prototest.AssertFieldNumber(t, user, "username", 1)
	prototest.AssertFieldNumber(t, user, "account", 2)
	prototest.AssertFieldNumber(t, user, "unique_user_id", 3)
	prototest.AssertFieldNumber(t, user, "display_name", 4)
	prototest.AssertMapValueMessage(t, user, "attributes", 5, attributeValuesFullName)
	prototest.AssertFieldNumber(t, user, "groups", 6)
	prototest.AssertFieldNumber(t, user, "group_dns", 7)
	prototest.AssertMessageField(t, user, "backend", 8, backendRefFullName)
	prototest.AssertMessageField(t, user, "mfa", 9, mfaStateFullName)

	resolve := prototest.Message(t, fileDescriptor, "ResolveUserRequest")
	prototest.AssertMessageField(t, resolve, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, resolve, "username", 2)
	prototest.AssertMessageField(t, resolve, "backend", 3, backendRefFullName)
	prototest.AssertMessageField(t, resolve, "attributes", 4, attributeRequestFullName)
	prototest.AssertFieldNumber(t, resolve, "include_mfa_state", 5)
	prototest.AssertFieldNumber(t, resolve, "include_webauthn_credentials", 6)

	response := prototest.Message(t, fileDescriptor, "UserSnapshotResponse")
	prototest.AssertMessageField(t, response, "status", 1, operationStatusFullName)
	prototest.AssertMessageField(t, response, "user", 2, userSnapshotFullName)
	prototest.AssertFieldNumber(t, response, "missing_attributes", 3)
	prototest.AssertFieldNumber(t, response, "denied_attributes", 4)
}

func assertMFAShapes(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	mfa := prototest.Message(t, fileDescriptor, "MFAState")
	prototest.AssertFieldNumber(t, mfa, "has_totp", 1)
	prototest.AssertFieldNumber(t, mfa, "recovery_code_count", 2)
	prototest.AssertFieldNumber(t, mfa, "has_webauthn", 3)
	prototest.AssertMessageField(t, mfa, "webauthn_credentials", 4, credentialFullName)
	prototest.AssertFieldNumber(t, mfa, "preferred_method", 5)

	getMFA := prototest.Message(t, fileDescriptor, "GetMFAStateRequest")
	prototest.AssertMessageField(t, getMFA, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, getMFA, "username", 2)
	prototest.AssertMessageField(t, getMFA, "backend", 3, backendRefFullName)
	prototest.AssertFieldNumber(t, getMFA, "include_webauthn_credentials", 4)

	getMFAResponse := prototest.Message(t, fileDescriptor, "MFAStateResponse")
	prototest.AssertMessageField(t, getMFAResponse, "status", 1, operationStatusFullName)
	prototest.AssertMessageField(t, getMFAResponse, "mfa", 2, mfaStateFullName)
	prototest.AssertMessageField(t, getMFAResponse, "backend", 3, backendRefFullName)

	assertTOTPAndRecoveryShapes(t, fileDescriptor)
}

func assertTOTPAndRecoveryShapes(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	begin := prototest.Message(t, fileDescriptor, "BeginTOTPRegistrationRequest")
	prototest.AssertMessageField(t, begin, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, begin, "username", 2)
	prototest.AssertMessageField(t, begin, "backend", 3, backendRefFullName)
	prototest.AssertFieldNumber(t, begin, "idempotency_key", 4)

	beginResponse := prototest.Message(t, fileDescriptor, "BeginTOTPRegistrationResponse")
	prototest.AssertMessageField(t, beginResponse, "status", 1, operationStatusFullName)
	prototest.AssertFieldNumber(t, beginResponse, "pending_registration_id", 2)
	prototest.AssertFieldNumber(t, beginResponse, "totp_secret", 3)
	prototest.AssertFieldNumber(t, beginResponse, "otpauth_url", 4)
	prototest.AssertMessageField(t, beginResponse, "expires_at", 5, "google.protobuf.Timestamp")
	prototest.AssertMessageField(t, beginResponse, "backend", 6, backendRefFullName)

	finish := prototest.Message(t, fileDescriptor, "FinishTOTPRegistrationRequest")
	prototest.AssertMessageField(t, finish, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, finish, "username", 2)
	prototest.AssertMessageField(t, finish, "backend", 3, backendRefFullName)
	prototest.AssertFieldNumber(t, finish, "pending_registration_id", 4)
	prototest.AssertFieldNumber(t, finish, "code", 5)
	prototest.AssertFieldNumber(t, finish, "idempotency_key", 6)

	verify := prototest.Message(t, fileDescriptor, "VerifyTOTPRequest")
	prototest.AssertMessageField(t, verify, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, verify, "username", 2)
	prototest.AssertMessageField(t, verify, "backend", 3, backendRefFullName)
	prototest.AssertFieldNumber(t, verify, "code", 4)

	verifyResponse := prototest.Message(t, fileDescriptor, "VerifyTOTPResponse")
	prototest.AssertMessageField(t, verifyResponse, "status", 1, operationStatusFullName)
	prototest.AssertFieldNumber(t, verifyResponse, "valid", 2)
	prototest.AssertMessageField(t, verifyResponse, "backend", 3, backendRefFullName)

	assertRecoveryShapes(t, fileDescriptor)
}

func assertRecoveryShapes(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	for _, name := range []protoreflect.Name{messageDeleteTOTPRequest, messageDeleteRecoveryCodesRequest} {
		message := prototest.Message(t, fileDescriptor, name)
		prototest.AssertMessageField(t, message, "context", 1, requestContextFullName)
		prototest.AssertFieldNumber(t, message, "username", 2)
		prototest.AssertMessageField(t, message, "backend", 3, backendRefFullName)
		prototest.AssertFieldNumber(t, message, "idempotency_key", 4)
	}

	generate := prototest.Message(t, fileDescriptor, "GenerateRecoveryCodesRequest")
	prototest.AssertMessageField(t, generate, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, generate, "username", 2)
	prototest.AssertMessageField(t, generate, "backend", 3, backendRefFullName)
	prototest.AssertFieldNumber(t, generate, "count", 4)
	prototest.AssertFieldNumber(t, generate, "idempotency_key", 5)

	generateResponse := prototest.Message(t, fileDescriptor, "GenerateRecoveryCodesResponse")
	prototest.AssertMessageField(t, generateResponse, "status", 1, operationStatusFullName)
	prototest.AssertFieldNumber(t, generateResponse, "codes", 2)
	prototest.AssertFieldNumber(t, generateResponse, "recovery_code_count", 3)
	prototest.AssertMessageField(t, generateResponse, "backend", 4, backendRefFullName)

	use := prototest.Message(t, fileDescriptor, "UseRecoveryCodeRequest")
	prototest.AssertMessageField(t, use, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, use, "username", 2)
	prototest.AssertMessageField(t, use, "backend", 3, backendRefFullName)
	prototest.AssertFieldNumber(t, use, "code", 4)
	prototest.AssertFieldNumber(t, use, "idempotency_key", 5)

	useResponse := prototest.Message(t, fileDescriptor, "UseRecoveryCodeResponse")
	prototest.AssertMessageField(t, useResponse, "status", 1, operationStatusFullName)
	prototest.AssertFieldNumber(t, useResponse, "valid", 2)
	prototest.AssertFieldNumber(t, useResponse, "remaining_recovery_code_count", 3)
	prototest.AssertMessageField(t, useResponse, "backend", 4, backendRefFullName)
}

func assertWebAuthnShapes(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	assertWebAuthnCredentialShape(t, fileDescriptor)
	assertWebAuthnReadShapes(t, fileDescriptor)
	assertWebAuthnWriteShapes(t, fileDescriptor)
}

func assertWebAuthnCredentialShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	credential := prototest.Message(t, fileDescriptor, "WebAuthnCredential")
	prototest.AssertFieldNumber(t, credential, "credential_id", 1)
	prototest.AssertFieldNumber(t, credential, "public_key", 2)
	prototest.AssertFieldNumber(t, credential, "sign_count", 3)
	prototest.AssertFieldNumber(t, credential, "transports", 4)
	prototest.AssertFieldNumber(t, credential, "backup_eligible", 5)
	prototest.AssertFieldNumber(t, credential, "backup_state", 6)
	prototest.AssertFieldNumber(t, credential, "attestation_type", 7)
	prototest.AssertFieldNumber(t, credential, "name", 8)
	prototest.AssertMessageField(t, credential, "last_used", 9, "google.protobuf.Timestamp")
	prototest.AssertFieldNumber(t, credential, "raw_json", 10)
}

func assertWebAuthnReadShapes(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	get := prototest.Message(t, fileDescriptor, "GetWebAuthnCredentialsRequest")
	prototest.AssertMessageField(t, get, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, get, "username", 2)
	prototest.AssertMessageField(t, get, "backend", 3, backendRefFullName)

	response := prototest.Message(t, fileDescriptor, "WebAuthnCredentialsResponse")
	prototest.AssertMessageField(t, response, "status", 1, operationStatusFullName)
	prototest.AssertMessageField(t, response, "credentials", 2, credentialFullName)
	prototest.AssertMessageField(t, response, "backend", 3, backendRefFullName)
}

func assertWebAuthnWriteShapes(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	save := prototest.Message(t, fileDescriptor, "SaveWebAuthnCredentialRequest")
	prototest.AssertMessageField(t, save, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, save, "username", 2)
	prototest.AssertMessageField(t, save, "backend", 3, backendRefFullName)
	prototest.AssertMessageField(t, save, "credential", 4, credentialFullName)
	prototest.AssertFieldNumber(t, save, "idempotency_key", 5)

	update := prototest.Message(t, fileDescriptor, "UpdateWebAuthnCredentialRequest")
	prototest.AssertMessageField(t, update, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, update, "username", 2)
	prototest.AssertMessageField(t, update, "backend", 3, backendRefFullName)
	prototest.AssertMessageField(t, update, "old_credential", 4, credentialFullName)
	prototest.AssertMessageField(t, update, "new_credential", 5, credentialFullName)
	prototest.AssertFieldNumber(t, update, "idempotency_key", 6)

	deleteRequest := prototest.Message(t, fileDescriptor, "DeleteWebAuthnCredentialRequest")
	prototest.AssertMessageField(t, deleteRequest, "context", 1, requestContextFullName)
	prototest.AssertFieldNumber(t, deleteRequest, "username", 2)
	prototest.AssertMessageField(t, deleteRequest, "backend", 3, backendRefFullName)
	prototest.AssertFieldNumber(t, deleteRequest, "credential_id", 4)
	prototest.AssertFieldNumber(t, deleteRequest, "idempotency_key", 5)

	writeResponse := prototest.Message(t, fileDescriptor, messageMFAWriteResponse)
	prototest.AssertMessageField(t, writeResponse, "status", 1, operationStatusFullName)
	prototest.AssertFieldNumber(t, writeResponse, "changed", 2)
	prototest.AssertMessageField(t, writeResponse, "mfa", 3, mfaStateFullName)
	prototest.AssertMessageField(t, writeResponse, "backend", 4, backendRefFullName)
}
