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

	management "github.com/croessner/nauthilus/v4/server/openapi/generated/management"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

const (
	trackedRecordRequestID  = "019d10c4-3858-7c2a-a5d1-2b3d57e641f2"
	trackedRecordRule       = "permit_current_trusted_carrier"
	trackedRecordDecisionID = "decision-inventory-inspection"
	trackedRecordRequest    = "record_request_v1.json"
	trackedRecordPolicy     = "record_reference_policy.yml"
	protoJSONRecords        = "records"
)

var trackedRecordLegFields = []string{"sequence", "leg_binding", "carrier", "change_classes", "sealed"}

// trackedFixtureBytes reads one sealed fixture independently of the caller package directory.
func trackedFixtureBytes(t testing.TB, name string) []byte {
	t.Helper()

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Policy test fixture helper source")
	}

	path := filepath.Join(filepath.Dir(source), "testdata", name)

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tracked Policy fixture %s: %v", name, err)
	}

	return payload
}

// TrackedRecordRequestBytes reads the sealed generic record request.
func TrackedRecordRequestBytes(t testing.TB) []byte {
	t.Helper()

	return trackedFixtureBytes(t, trackedRecordRequest)
}

// TrackedRecordPolicyBytes reads the executable generic record-collection Policy configuration.
func TrackedRecordPolicyBytes(t testing.TB) []byte {
	t.Helper()

	return trackedFixtureBytes(t, trackedRecordPolicy)
}

// TrackedRecordManagementRequest decodes the sealed request through the generated OpenAPI DTO.
func TrackedRecordManagementRequest(t testing.TB) management.PolicyDecisionRequest {
	t.Helper()

	var request management.PolicyDecisionRequest
	if err := json.Unmarshal(TrackedRecordRequestBytes(t), &request); err != nil {
		t.Fatalf("decode tracked record management request: %v", err)
	}

	return request
}

// TrackedRecordProtoJSON adapts only the OpenAPI array wrappers to protobuf JSON wrappers.
func TrackedRecordProtoJSON(t testing.TB) []byte {
	t.Helper()

	var document any
	if err := json.Unmarshal(TrackedRecordRequestBytes(t), &document); err != nil {
		t.Fatalf("decode tracked record JSON for protobuf adaptation: %v", err)
	}

	adapted := adaptProtoJSONCollections(document)

	payload, err := json.Marshal(adapted)
	if err != nil {
		t.Fatalf("encode tracked record protobuf JSON: %v", err)
	}

	return payload
}

// AssertTrackedRecordRequestInput proves a transport retained the complete sealed request semantics.
func AssertTrackedRecordRequestInput(t testing.TB, request decision.DecisionRequestInput) {
	t.Helper()

	assertTrackedRecordIdentity(t, request)

	resource := request.Resource.Attributes().Values()

	environment := request.Environment.Attributes().Values()
	assertTrackedRecordResource(t, request.Resource, resource)
	assertTrackedRecordEnvironment(t, request.Environment, environment)
	assertTrackedRecordLegs(t, resource)
}

// assertTrackedRecordIdentity verifies the sealed contract and correlation identity.
func assertTrackedRecordIdentity(t testing.TB, request decision.DecisionRequestInput) {
	t.Helper()

	if request.Version != decision.ContractVersion || request.RequestID != trackedRecordRequestID ||
		request.Target.String() != "inventory/inspect-shipment" {
		t.Fatalf("tracked request identity = %q/%q/%q", request.Version, request.RequestID, request.Target.String())
	}
}

// assertTrackedRecordResource verifies the complete caller-owned resource surface.
func assertTrackedRecordResource(t testing.TB, resource decision.Entity, values map[string]decision.Value) {
	t.Helper()

	if resource.Type() != "inventory-shipment" || len(values) != 5 {
		t.Fatalf("tracked resource = %q with %d attributes, want complete 5-attribute resource", resource.Type(), len(values))
	}

	assertTrackedRecordString(t, values, "inventory.manifest_schema", "inventory.manifest.v1")
}

// assertTrackedRecordEnvironment verifies the complete caller environment surface.
func assertTrackedRecordEnvironment(t testing.TB, environment decision.Environment, values map[string]decision.Value) {
	t.Helper()

	if environment.Service() != "warehouse" || environment.Instance() != "wh01.example.net" ||
		environment.Protocol() != "http" || len(values) != 5 {
		t.Fatalf("tracked environment = %q/%q/%q with %d attributes", environment.Service(), environment.Instance(), environment.Protocol(), len(values))
	}

	assertTrackedRecordString(t, values, "warehouse.dock_ip", "203.0.113.7")
}

// assertTrackedRecordLegs verifies all ordered fields in the sealed record.
func assertTrackedRecordLegs(t testing.TB, resource map[string]decision.Value) {
	t.Helper()

	legs, ok := resource["inventory.legs"].Records()
	if !ok || len(legs.Records()) != 1 {
		t.Fatalf("tracked legs = %#v, want one complete record", resource["inventory.legs"])
	}

	fields := legs.Records()[0].Fields()

	names := make([]string, 0, len(fields))
	for _, field := range fields {
		names = append(names, field.Name())
	}

	if !reflect.DeepEqual(names, trackedRecordLegFields) {
		t.Fatalf("tracked leg fields = %v, want %v", names, trackedRecordLegFields)
	}
}

// DirectPermitResponse constructs the public semantics selected by the real direct-service fixture.
func DirectPermitResponse(t testing.TB) decision.DecisionResponse {
	return PermitResponseWithRequestID(t, trackedRecordRequestID)
}

// PermitResponseWithRequestID constructs generic public permit semantics with exact request correlation.
func PermitResponseWithRequestID(t testing.TB, requestID string) decision.DecisionResponse {
	t.Helper()

	status, err := decision.NewStatus(decision.StatusCodePermit, "permitted", nil)
	if err != nil {
		t.Fatalf("construct tracked permit status: %v", err)
	}

	metadata, err := decision.NewPolicyMetadata("inventory/inspection", "v1", trackedRecordRule, 1)
	if err != nil {
		t.Fatalf("construct tracked policy metadata: %v", err)
	}

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID: requestID, DecisionID: trackedRecordDecisionID,
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
		RequestId: trackedRecordRequestID, DecisionId: trackedRecordDecisionID, Effect: management.Permit,
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

// assertTrackedRecordString verifies one exact string member in a normalized value map.
func assertTrackedRecordString(t testing.TB, values map[string]decision.Value, name string, want string) {
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
