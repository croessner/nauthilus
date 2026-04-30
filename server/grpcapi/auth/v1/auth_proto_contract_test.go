package authv1

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestAuthProtoContract(t *testing.T) {
	t.Parallel()

	fileDescriptor := File_server_grpcapi_auth_v1_auth_proto

	if got, want := string(fileDescriptor.Package()), "nauthilus.auth.v1"; got != want {
		t.Fatalf("unexpected proto package: got %q want %q", got, want)
	}

	assertAuthServiceShape(t, fileDescriptor)
	assertAuthRequestFieldNumbers(t, fileDescriptor)
	assertLookupIdentityRequestFieldNumbers(t, fileDescriptor)
	assertAuthDecisionValues(t)
}

func assertAuthServiceShape(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	services := fileDescriptor.Services()

	if got, want := services.Len(), 1; got != want {
		t.Fatalf("unexpected service count: got %d want %d", got, want)
	}

	service := services.Get(0)

	if got, want := string(service.Name()), "AuthService"; got != want {
		t.Fatalf("unexpected service name: got %q want %q", got, want)
	}

	methods := service.Methods()

	if got, want := methods.Len(), 3; got != want {
		t.Fatalf("unexpected method count: got %d want %d", got, want)
	}

	if got, want := string(methods.Get(0).Name()), "Authenticate"; got != want {
		t.Fatalf("unexpected first method: got %q want %q", got, want)
	}

	if got, want := string(methods.Get(1).Name()), "LookupIdentity"; got != want {
		t.Fatalf("unexpected second method: got %q want %q", got, want)
	}

	if got, want := string(methods.Get(2).Name()), "ListAccounts"; got != want {
		t.Fatalf("unexpected third method: got %q want %q", got, want)
	}
}

func assertAuthRequestFieldNumbers(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	messages := fileDescriptor.Messages()
	requestMessage := messages.ByName("AuthRequest")

	if requestMessage == nil {
		t.Fatal("AuthRequest message not found in descriptor")
	}

	assertFieldNumber(t, requestMessage, "username", 1)
	assertFieldNumber(t, requestMessage, "password", 2)
	assertFieldNumber(t, requestMessage, "oidc_cid", 29)
	assertFieldNumber(t, requestMessage, "auth_login_attempt", 30)
}

func assertLookupIdentityRequestFieldNumbers(t *testing.T, fileDescriptor protoreflect.FileDescriptor) {
	t.Helper()

	messages := fileDescriptor.Messages()
	requestMessage := messages.ByName("LookupIdentityRequest")

	if requestMessage == nil {
		t.Fatal("LookupIdentityRequest message not found in descriptor")
	}

	assertFieldNumber(t, requestMessage, "username", 1)
	assertFieldNumber(t, requestMessage, "client_ip", 2)
	assertFieldNumber(t, requestMessage, "ssl_fingerprint", 27)
	assertFieldNumber(t, requestMessage, "oidc_cid", 28)

	if field := requestMessage.Fields().ByName("password"); field != nil {
		t.Fatal("LookupIdentityRequest must not expose a password field")
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
		{name: "unspecified", value: AuthDecision_AUTH_DECISION_UNSPECIFIED, want: 0},
		{name: "ok", value: AuthDecision_AUTH_DECISION_OK, want: 1},
		{name: "fail", value: AuthDecision_AUTH_DECISION_FAIL, want: 2},
		{name: "tempfail", value: AuthDecision_AUTH_DECISION_TEMPFAIL, want: 3},
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
