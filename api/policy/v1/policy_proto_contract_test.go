package policyv1

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestPolicyDescriptorRemainsUnaryAndHasNoForbiddenSurface(t *testing.T) {
	services := File_api_policy_v1_policy_proto.Services()
	if services.Len() != 1 {
		t.Fatalf("service count = %d, want 1", services.Len())
	}

	service := services.Get(0)
	if service.Name() != "PolicyDecisionService" || service.Methods().Len() != 1 {
		t.Fatalf("service shape = %s/%d, want PolicyDecisionService/1", service.Name(), service.Methods().Len())
	}

	method := service.Methods().Get(0)
	if method.Name() != "Evaluate" || method.IsStreamingClient() || method.IsStreamingServer() {
		t.Fatalf("method shape = %s client=%t server=%t, want unary Evaluate", method.Name(), method.IsStreamingClient(), method.IsStreamingServer())
	}

	assertNoForbiddenPolicyDescriptorSurface(t, File_api_policy_v1_policy_proto)
}

func TestPolicyResponseValueContractsExcludeRecords(t *testing.T) {
	for _, contract := range []struct {
		message string
		field   string
	}{
		{message: "Obligation", field: "parameters"},
		{message: "Advice", field: "parameters"},
		{message: "Diagnostics", field: "entries"},
	} {
		message := File_api_policy_v1_policy_proto.Messages().ByName(protoreflect.Name(contract.message))
		field := message.Fields().ByName(protoreflect.Name(contract.field))
		value := field.MapValue().Message()

		if value == nil || value.Name() == "Value" || value.Fields().ByName("records") != nil {
			t.Fatalf("%s.%s admits fact-only records through %v", contract.message, contract.field, value)
		}
	}
}

func assertNoForbiddenPolicyDescriptorSurface(t *testing.T, file protoreflect.FileDescriptor) {
	t.Helper()

	forbidden := []string{"batch", "outcome", "cache", "replay", "idempot", "deduplic", "ttl", "vary"}

	for index := 0; index < file.Messages().Len(); index++ {
		assertMessageSurface(t, file.Messages().Get(index), forbidden)
	}

	for index := 0; index < file.Enums().Len(); index++ {
		assertAllowedPolicyName(t, "enum", file.Enums().Get(index).Name(), forbidden)
	}
}

// assertMessageSurface recursively checks message, nested message, enum, and field names for forbidden API surfaces.
func assertMessageSurface(t *testing.T, message protoreflect.MessageDescriptor, forbidden []string) {
	t.Helper()
	assertAllowedPolicyName(t, "message", message.Name(), forbidden)

	for fieldIndex := 0; fieldIndex < message.Fields().Len(); fieldIndex++ {
		field := message.Fields().Get(fieldIndex)
		if field.Name() != "retryable" || message.Name() != "Status" {
			assertAllowedPolicyName(t, "field", field.Name(), forbidden)
		}
	}

	for index := 0; index < message.Messages().Len(); index++ {
		assertMessageSurface(t, message.Messages().Get(index), forbidden)
	}

	for index := 0; index < message.Enums().Len(); index++ {
		assertAllowedPolicyName(t, "enum", message.Enums().Get(index).Name(), forbidden)
	}
}

// assertAllowedPolicyName rejects a forbidden public contract term in one descriptor name.
func assertAllowedPolicyName(t *testing.T, kind string, name protoreflect.Name, forbidden []string) {
	t.Helper()

	normalized := strings.ToLower(string(name))
	for _, term := range forbidden {
		if strings.Contains(normalized, term) {
			t.Fatalf("forbidden %s %q", kind, name)
		}
	}
}
