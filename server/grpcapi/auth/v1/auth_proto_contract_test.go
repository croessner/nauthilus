package authv1

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	authProtoPackage                 = "nauthilus.auth.v1"
	authServiceName                  = "AuthService"
	authMethodAuthenticate           = "Authenticate"
	authMethodLookupIdentity         = "LookupIdentity"
	authMethodListAccounts           = "ListAccounts"
	authMessageAuthRequest           = "AuthRequest"
	authMessageLookupIdentityRequest = "LookupIdentityRequest"
	authMessageListAccountsRequest   = "ListAccountsRequest"
	authMessageAuthResponse          = "AuthResponse"
	authMessageListAccountsResponse  = "ListAccountsResponse"
	authDecisionNameUnspecified      = "unspecified"
	authDecisionNameOK               = "ok"
	authDecisionNameFail             = "fail"
	authDecisionNameTempfail         = "tempfail"
)

const (
	authFieldOK               protoreflect.Name = authDecisionNameOK
	authFieldUsername         protoreflect.Name = "username"
	authFieldPassword         protoreflect.Name = "password"
	authFieldOIDCCID          protoreflect.Name = "oidc_cid"
	authFieldAuthLoginAttempt protoreflect.Name = "auth_login_attempt"
	authFieldClientIP         protoreflect.Name = "client_ip"
	authFieldSSLFingerprint   protoreflect.Name = "ssl_fingerprint"
	authFieldMethod           protoreflect.Name = "method"
	authFieldDecision         protoreflect.Name = "decision"
	authFieldSession          protoreflect.Name = "session"
	authFieldAccountField     protoreflect.Name = "account_field"
	authFieldTOTPSecretField  protoreflect.Name = "totp_secret_field"
	authFieldBackend          protoreflect.Name = "backend"
	authFieldAttributes       protoreflect.Name = "attributes"
	authFieldStatusMessage    protoreflect.Name = "status_message"
	authFieldError            protoreflect.Name = "error"
	authFieldBackendRef       protoreflect.Name = "backend_ref"
)

const (
	commonAttributeValuesFullName protoreflect.FullName = "nauthilus.common.v1.AttributeValues"
	commonBackendRefFullName      protoreflect.FullName = "nauthilus.common.v1.BackendRef"
)

func TestAuthProtoContract(t *testing.T) {
	t.Parallel()

	fileDescriptor := File_server_grpcapi_auth_v1_auth_proto

	if got, want := string(fileDescriptor.Package()), authProtoPackage; got != want {
		t.Fatalf("unexpected proto package: got %q want %q", got, want)
	}

	assertAuthServiceShape(t, fileDescriptor)
	assertAuthRequestFieldNumbers(t, fileDescriptor)
	assertLookupIdentityRequestFieldNumbers(t, fileDescriptor)
	assertListAccountsRequestFieldNumbers(t, fileDescriptor)
	assertAuthResponseFieldNumbers(t, fileDescriptor)
	assertAuthDecisionValues(t)
}

func assertAuthServiceShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	services := fileDescriptor.Services()

	if got, want := services.Len(), 1; got != want {
		t.Fatalf("unexpected service count: got %d want %d", got, want)
	}

	service := services.Get(0)

	if got, want := string(service.Name()), authServiceName; got != want {
		t.Fatalf("unexpected service name: got %q want %q", got, want)
	}

	methods := service.Methods()

	if got, want := methods.Len(), 3; got != want {
		t.Fatalf("unexpected method count: got %d want %d", got, want)
	}

	cases := []struct {
		name       string
		inputType  string
		outputType string
	}{
		{name: authMethodAuthenticate, inputType: authMessageAuthRequest, outputType: authMessageAuthResponse},
		{name: authMethodLookupIdentity, inputType: authMessageLookupIdentityRequest, outputType: authMessageAuthResponse},
		{name: authMethodListAccounts, inputType: authMessageListAccountsRequest, outputType: authMessageListAccountsResponse},
	}

	for index, testCase := range cases {
		method := methods.Get(index)

		if got := string(method.Name()); got != testCase.name {
			t.Fatalf("unexpected method at index %d: got %q want %q", index, got, testCase.name)
		}

		if got := string(method.Input().Name()); got != testCase.inputType {
			t.Fatalf("%s input type = %q, want %q", testCase.name, got, testCase.inputType)
		}

		if got := string(method.Output().Name()); got != testCase.outputType {
			t.Fatalf("%s output type = %q, want %q", testCase.name, got, testCase.outputType)
		}
	}
}

func assertAuthRequestFieldNumbers(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	messages := fileDescriptor.Messages()
	requestMessage := messages.ByName(authMessageAuthRequest)

	if requestMessage == nil {
		t.Fatal("AuthRequest message not found in descriptor")
	}

	assertFieldNumber(t, requestMessage, authFieldUsername, 1)
	assertFieldNumber(t, requestMessage, authFieldPassword, 2)
	assertFieldNumber(t, requestMessage, authFieldOIDCCID, 29)
	assertFieldNumber(t, requestMessage, authFieldAuthLoginAttempt, 30)
}

func assertLookupIdentityRequestFieldNumbers(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	messages := fileDescriptor.Messages()
	requestMessage := messages.ByName(authMessageLookupIdentityRequest)

	if requestMessage == nil {
		t.Fatal("LookupIdentityRequest message not found in descriptor")
	}

	assertFieldNumber(t, requestMessage, authFieldUsername, 1)
	assertFieldNumber(t, requestMessage, authFieldClientIP, 2)
	assertFieldNumber(t, requestMessage, authFieldSSLFingerprint, 27)
	assertFieldNumber(t, requestMessage, authFieldOIDCCID, 28)

	if field := requestMessage.Fields().ByName(authFieldPassword); field != nil {
		t.Fatal("LookupIdentityRequest must not expose a password field")
	}
}

func assertListAccountsRequestFieldNumbers(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	messages := fileDescriptor.Messages()
	requestMessage := messages.ByName(authMessageListAccountsRequest)

	if requestMessage == nil {
		t.Fatal("ListAccountsRequest message not found in descriptor")
	}

	assertFieldNumber(t, requestMessage, authFieldUsername, 1)
	assertFieldNumber(t, requestMessage, authFieldClientIP, 2)
	assertFieldNumber(t, requestMessage, authFieldMethod, 11)
	assertFieldNumber(t, requestMessage, authFieldOIDCCID, 12)
}

func assertAuthResponseFieldNumbers(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	messages := fileDescriptor.Messages()
	responseMessage := messages.ByName(authMessageAuthResponse)

	if responseMessage == nil {
		t.Fatal("AuthResponse message not found in descriptor")
	}

	cases := []struct {
		fieldName protoreflect.Name
		number    protoreflect.FieldNumber
	}{
		{fieldName: authFieldOK, number: 1},
		{fieldName: authFieldDecision, number: 2},
		{fieldName: authFieldSession, number: 3},
		{fieldName: authFieldAccountField, number: 4},
		{fieldName: authFieldTOTPSecretField, number: 5},
		{fieldName: authFieldBackend, number: 6},
		{fieldName: authFieldAttributes, number: 7},
		{fieldName: authFieldStatusMessage, number: 8},
		{fieldName: authFieldError, number: 9},
		{fieldName: authFieldBackendRef, number: 10},
	}

	for _, testCase := range cases {
		assertFieldNumber(t, responseMessage, testCase.fieldName, testCase.number)
	}

	assertAuthResponseSharedCommonTypes(t, fileDescriptor, responseMessage)
}

func assertAuthResponseSharedCommonTypes(
	t *testing.T,
	fileDescriptor protoreflect.FileDescriptor,
	responseMessage protoreflect.MessageDescriptor,
) {
	t.Helper()

	if message := fileDescriptor.Messages().ByName("AttributeValues"); message != nil {
		t.Fatal("auth-local AttributeValues must be replaced by nauthilus.common.v1.AttributeValues")
	}

	attributesField := responseMessage.Fields().ByName(authFieldAttributes)
	if attributesField == nil || !attributesField.IsMap() {
		t.Fatal("AuthResponse.attributes must be a map field")
	}

	valueField := attributesField.Message().Fields().ByName("value")
	if valueField == nil || valueField.Message() == nil {
		t.Fatal("AuthResponse.attributes map value must be a message")
	}

	if got := valueField.Message().FullName(); got != commonAttributeValuesFullName {
		t.Fatalf("AuthResponse.attributes value type = %q, want %q", got, commonAttributeValuesFullName)
	}

	backendRefField := responseMessage.Fields().ByName(authFieldBackendRef)
	if backendRefField == nil || backendRefField.Message() == nil {
		t.Fatal("AuthResponse.backend_ref must be a message field")
	}

	if got := backendRefField.Message().FullName(); got != commonBackendRefFullName {
		t.Fatalf("AuthResponse.backend_ref type = %q, want %q", got, commonBackendRefFullName)
	}
}

func assertFieldNumber(
	t *testing.T,
	message protoreflect.MessageDescriptor,
	fieldName protoreflect.Name,
	expectedNumber protoreflect.FieldNumber,
) {
	t.Helper()

	field := message.Fields().ByName(fieldName)
	if field == nil {
		t.Fatalf("%s field not found in %s", fieldName, message.Name())
	}

	if got := field.Number(); got != expectedNumber {
		t.Fatalf(
			"unexpected field number for %s.%s: got %d want %d",
			message.Name(),
			fieldName,
			got,
			expectedNumber,
		)
	}
}

func assertAuthDecisionValues(t *testing.T) {
	t.Helper()

	cases := []struct {
		name  string
		value AuthDecision
		want  int32
	}{
		{name: authDecisionNameUnspecified, value: AuthDecision_AUTH_DECISION_UNSPECIFIED, want: 0},
		{name: authDecisionNameOK, value: AuthDecision_AUTH_DECISION_OK, want: 1},
		{name: authDecisionNameFail, value: AuthDecision_AUTH_DECISION_FAIL, want: 2},
		{name: authDecisionNameTempfail, value: AuthDecision_AUTH_DECISION_TEMPFAIL, want: 3},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := int32(testCase.value); got != testCase.want {
				t.Fatalf("unexpected enum value: got %d want %d", got, testCase.want)
			}
		})
	}
}
