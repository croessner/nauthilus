// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package testsupport shares sealed Policy fixtures across transport tests.
package testsupport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	management "github.com/croessner/nauthilus/v3/server/openapi/generated/management"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

const (
	trackedDKIM2RequestID  = "019d10c4-3858-7c2a-a5d1-2b3d57e641f2"
	trackedDKIM2Rule       = "permit_strict_pass"
	trackedDKIM2DecisionID = "decision-dkim2-rspamd"
	protoJSONRecords       = "records"
)

var trackedDKIM2ChainFields = []string{
	"sequence", "message_instance", "hop_binding", "signer_domain", "signature_algorithms",
	"signature_state", "custody_transition", "do_not_modify", "do_not_explode", "feedback",
	"feed_here", "exploded", "recipe_mode", "recipe_has_header_changes", "recipe_body_mode",
	"recipe_digest", "change_classes", "affected_headers", "history_header_state", "history_body_state",
	"body_availability", "change_count", "affected_header_count",
}

// TrackedDKIM2RequestBytes reads the sealed documentation request independently of the caller package directory.
func TrackedDKIM2RequestBytes(t testing.TB) []byte {
	t.Helper()

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve DKIM2 test fixture helper source")
	}

	path := filepath.Join(filepath.Dir(source), "..", "..", "docs", "policy-layer", "dkim2_rspamd_policy_request_v1.example.json")

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tracked DKIM2 request: %v", err)
	}

	return payload
}

// TrackedDKIM2ManagementRequest decodes the sealed request through the generated OpenAPI DTO.
func TrackedDKIM2ManagementRequest(t testing.TB) management.PolicyDecisionRequest {
	t.Helper()

	var request management.PolicyDecisionRequest
	if err := json.Unmarshal(TrackedDKIM2RequestBytes(t), &request); err != nil {
		t.Fatalf("decode tracked DKIM2 management request: %v", err)
	}

	return request
}

// TrackedDKIM2ProtoJSON adapts only the OpenAPI array wrappers to protobuf JSON wrappers.
func TrackedDKIM2ProtoJSON(t testing.TB) []byte {
	t.Helper()

	var document any
	if err := json.Unmarshal(TrackedDKIM2RequestBytes(t), &document); err != nil {
		t.Fatalf("decode tracked DKIM2 JSON for protobuf adaptation: %v", err)
	}

	adapted := adaptProtoJSONCollections(document)

	payload, err := json.Marshal(adapted)
	if err != nil {
		t.Fatalf("encode tracked DKIM2 protobuf JSON: %v", err)
	}

	return payload
}

// AssertTrackedDKIM2RequestInput proves a transport retained the complete sealed request semantics.
func AssertTrackedDKIM2RequestInput(t testing.TB, request decision.DecisionRequestInput) {
	t.Helper()

	assertTrackedDKIM2Identity(t, request)

	resource := request.Resource.Attributes().Values()

	environment := request.Environment.Attributes().Values()
	assertTrackedDKIM2Resource(t, request.Resource, resource)
	assertTrackedDKIM2Environment(t, request.Environment, environment)
	assertTrackedDKIM2Chain(t, resource)
}

// assertTrackedDKIM2Identity verifies the sealed contract and correlation identity.
func assertTrackedDKIM2Identity(t testing.TB, request decision.DecisionRequestInput) {
	t.Helper()

	if request.Version != decision.ContractVersion || request.RequestID != trackedDKIM2RequestID ||
		request.Target.String() != "dkim2/accept-message-instance" {
		t.Fatalf("tracked request identity = %q/%q/%q", request.Version, request.RequestID, request.Target.String())
	}
}

// assertTrackedDKIM2Resource verifies the complete verifier-owned aggregate surface.
func assertTrackedDKIM2Resource(t testing.TB, resource decision.Entity, values map[string]decision.Value) {
	t.Helper()

	if resource.Type() != "dkim2-message-instance" || len(values) != 24 {
		t.Fatalf("tracked resource = %q with %d attributes, want complete 24-attribute projection", resource.Type(), len(values))
	}

	assertTrackedDKIM2String(t, values, "dkim2.projection_schema", "dkim2.verifier-projection.v1")
}

// assertTrackedDKIM2Environment verifies the complete Rspamd and SMTP observation surface.
func assertTrackedDKIM2Environment(t testing.TB, environment decision.Environment, values map[string]decision.Value) {
	t.Helper()

	if environment.Service() != "rspamd" || environment.Instance() != "mx01.example.net" ||
		environment.Protocol() != "milter" || len(values) != 13 {
		t.Fatalf("tracked environment = %q/%q/%q with %d attributes", environment.Service(), environment.Instance(), environment.Protocol(), len(values))
	}

	assertTrackedDKIM2String(t, values, "rspamd.smtp_client_ip", "203.0.113.7")
	assertTrackedDKIM2String(t, values, "rspamd.scan_action_before_policy", "greylist")
}

// assertTrackedDKIM2Chain verifies all ordered fields in the sealed verifier hop.
func assertTrackedDKIM2Chain(t testing.TB, resource map[string]decision.Value) {
	t.Helper()

	chain, ok := resource["dkim2.chain"].Records()
	if !ok || len(chain.Records()) != 1 {
		t.Fatalf("tracked chain = %#v, want one complete record", resource["dkim2.chain"])
	}

	fields := chain.Records()[0].Fields()

	names := make([]string, 0, len(fields))
	for _, field := range fields {
		names = append(names, field.Name())
	}

	if !reflect.DeepEqual(names, trackedDKIM2ChainFields) {
		t.Fatalf("tracked chain fields = %v, want %v", names, trackedDKIM2ChainFields)
	}
}

// DirectPermitResponse constructs the public semantics selected by the real direct-service fixture.
func DirectPermitResponse(t testing.TB) decision.DecisionResponse {
	t.Helper()

	status, err := decision.NewStatus(decision.StatusCodePermit, "permitted", nil)
	if err != nil {
		t.Fatalf("construct tracked permit status: %v", err)
	}

	metadata, err := decision.NewPolicyMetadata("dkim2/verifier", "v1", trackedDKIM2Rule, 1)
	if err != nil {
		t.Fatalf("construct tracked policy metadata: %v", err)
	}

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID: trackedDKIM2RequestID, DecisionID: trackedDKIM2DecisionID,
		Effect: decision.EffectPermit, Status: status, Policy: metadata,
	})
	if err != nil {
		t.Fatalf("construct tracked direct-service response: %v", err)
	}

	return response
}

// ManagementPermitResponse returns the transport-visible subset of the direct-service permit.
func ManagementPermitResponse() management.PolicyDecisionResponse {
	return management.PolicyDecisionResponse{
		DecisionId: trackedDKIM2DecisionID, Effect: management.Permit,
		Status: management.PolicyStatus{Code: "permit", Message: "permitted", Retryable: false},
	}
}

// AssertManagementPermitResponse compares one public result with the direct-service permit projection.
func AssertManagementPermitResponse(t testing.TB, response management.PolicyDecisionResponse) {
	t.Helper()

	want := ManagementPermitResponse()
	if !reflect.DeepEqual(response, want) {
		t.Fatalf("Policy response semantics = %#v, want %#v", response, want)
	}
}

// assertTrackedDKIM2String verifies one exact string member in a normalized value map.
func assertTrackedDKIM2String(t testing.TB, values map[string]decision.Value, name string, want string) {
	t.Helper()

	value, exists := values[name]
	if !exists {
		t.Fatalf("tracked request is missing %s", name)
	}

	got, ok := value.StringValue()
	if !ok || got != want {
		t.Fatalf("tracked request %s = %q/%t, want %q/true", name, got, ok, want)
	}
}

// adaptProtoJSONCollections converts the two protobuf wrapper-message collections without changing leaf values.
func adaptProtoJSONCollections(value any) any {
	switch typed := value.(type) {
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = adaptProtoJSONCollections(item)
		}

		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for name, item := range typed {
			adapted := adaptProtoJSONCollections(item)

			switch name {
			case "strings":
				if _, ok := adapted.([]any); ok {
					adapted = map[string]any{"values": adapted}
				}
			case protoJSONRecords:
				if _, ok := adapted.([]any); ok {
					adapted = map[string]any{protoJSONRecords: adapted}
				}
			}

			result[name] = adapted
		}

		return result
	default:
		return value
	}
}
