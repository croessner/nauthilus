// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyhttp

import (
	"encoding/json"
	"net/http"
	"testing"

	management "github.com/croessner/nauthilus/v4/server/openapi/generated/management"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/testsupport"
)

func TestTrackedRecordHTTPParityWithDirectDecisionFixture(t *testing.T) {
	payload := testsupport.TrackedRecordRequestBytes(t)
	service := &recordingService{response: testsupport.DirectPermitResponse(t)}

	wireResponse := servePolicyRequest(policyEngine(service), string(payload), "Basic aW52ZW50b3J5LXNjYW5uZXI6dGVzdA==")
	if wireResponse.Code != http.StatusOK || service.calls != 1 {
		t.Fatalf("HTTP route status/service calls = %d/%d, want 200/1", wireResponse.Code, service.calls)
	}

	var response management.PolicyDecisionResponse
	if err := json.Unmarshal(wireResponse.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode tracked HTTP response: %v", err)
	}

	testsupport.AssertManagementPermitResponse(t, response)
	testsupport.AssertTrackedRecordRequestInput(t, service.invocation.Request)
}

func TestPolicyHTTPResponseReturnsInternalRequestCorrelation(t *testing.T) {
	for _, test := range []struct {
		name      string
		requestID string
		body      string
	}{
		{name: "supplied request ID", requestID: "caller-request", body: `{"version":"1","request_id":"caller-request","target":{"namespace":"mail","action":"submit"}}`},
		{name: "omitted request ID", requestID: "generated-request", body: `{"version":"1","target":{"namespace":"mail","action":"submit"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &recordingService{response: testsupport.PermitResponseWithRequestID(t, test.requestID)}

			wireResponse := servePolicyRequest(policyEngine(service), test.body, "Bearer opaque")
			if wireResponse.Code != http.StatusOK || service.calls != 1 {
				t.Fatalf("HTTP route status/service calls = %d/%d, want 200/1", wireResponse.Code, service.calls)
			}

			var payload map[string]any
			if err := json.Unmarshal(wireResponse.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode Policy HTTP response: %v", err)
			}

			if payload["request_id"] != service.response.RequestID().String() {
				t.Fatalf("HTTP response request_id = %#v, want internal correlation %q", payload["request_id"], service.response.RequestID())
			}
		})
	}
}

func TestPolicyHTTPActualInvocationPreservesPresentEmptyStringsAndBytes(t *testing.T) {
	service := &recordingService{response: testsupport.DirectPermitResponse(t)}
	body := `{"version":"1","target":{"namespace":"mail","action":"submit"},"attributes":{"empty_strings":{"strings":[]},"empty_bytes":{"bytes":""}}}`

	wireResponse := servePolicyRequest(policyEngine(service), body, "Bearer opaque")
	if wireResponse.Code != http.StatusOK || service.calls != 1 {
		t.Fatalf("HTTP route status/service calls = %d/%d, want 200/1", wireResponse.Code, service.calls)
	}

	stringsValue, exists := service.invocation.Request.Attributes["empty_strings"]
	assertHTTPPresentEmptyStrings(t, stringsValue, exists)

	bytesMember, exists := service.invocation.Request.Attributes["empty_bytes"]
	assertHTTPPresentEmptyBytes(t, bytesMember, exists)
}

// assertHTTPPresentEmptyStrings verifies the transport retained the active empty list member.
func assertHTTPPresentEmptyStrings(t *testing.T, value decision.Value, exists bool) {
	t.Helper()

	if !exists || value.Kind() != "strings" {
		t.Fatalf("empty strings value = %#v/%t, want present strings", value, exists)
	}

	member, ok := value.Strings()
	if !ok || member == nil || len(member) != 0 {
		t.Fatalf("empty strings member = %#v/%t, want present non-nil empty list", member, ok)
	}
}

// assertHTTPPresentEmptyBytes verifies the transport retained the active empty byte member.
func assertHTTPPresentEmptyBytes(t *testing.T, value decision.Value, exists bool) {
	t.Helper()

	if !exists || value.Kind() != "bytes" {
		t.Fatalf("empty bytes value = %#v/%t, want present bytes", value, exists)
	}

	member, ok := value.Bytes()
	if !ok || member == nil || len(member) != 0 {
		t.Fatalf("empty bytes member = %#v/%t, want present non-nil empty bytes", member, ok)
	}
}

func TestRecordHTTPWirePreservesLocalNestedAttributeKeys(t *testing.T) {
	t.Parallel()

	body := `{
  "version":"1",
  "target":{"namespace":"inventory","action":"inspect-shipment"},
  "resource":{"type":"inventory-shipment","attributes":{
    "inventory.manifest_schema":{"string":"inventory.manifest.v1"},
    "inventory.legs":{"records":[{"fields":[
      {"name":"sequence","value":{"integer":"1"}},
      {"name":"carrier","value":{"string":"carrier.example"}}
    ]}]}
  }},
  "environment":{"service":"warehouse","instance":"wh01.example.net","protocol":"http","attributes":{
    "warehouse.dock_ip":{"string":"2001:db8::25"}
  }},
  "options":{"include_diagnostics":false}
}`

	request, err := decodeRequest([]byte(body))
	if err != nil {
		t.Fatalf("decodeRequest() error = %v", err)
	}

	if request.Target.String() != "inventory/inspect-shipment" {
		t.Fatalf("target = %q", request.Target.String())
	}

	resource := request.Resource.Attributes().Values()
	if _, ok := resource["inventory.legs"]; !ok {
		t.Fatalf("resource attributes = %v, want local inventory.legs", resource)
	}

	if _, ok := resource["resource.inventory.legs"]; ok {
		t.Fatal("HTTP wire retained an incorrectly pre-prefixed resource key")
	}

	environment := request.Environment.Attributes().Values()

	ip, ok := environment["warehouse.dock_ip"]
	if !ok {
		t.Fatalf("environment attributes = %v, want local warehouse.dock_ip", environment)
	}

	address, _ := ip.StringValue()
	if address != "2001:db8::25" {
		t.Fatalf("dock address = %q", address)
	}
}

func TestPolicyHTTPRecordRawWireRejection(t *testing.T) {
	tests := map[string]string{
		"duplicate record fields": `{"version":"1","target":{"namespace":"mail","action":"submit"},"attributes":{"chain":{"records":[{"fields":[{"name":"sequence","value":{"integer":"1"}},{"name":"sequence","value":{"integer":"2"}}]}]}}}`,
		"multiple field kinds":    `{"version":"1","target":{"namespace":"mail","action":"submit"},"attributes":{"chain":{"records":[{"fields":[{"name":"sequence","value":{"integer":"1","string":"one"}}]}]}}}`,
		"empty record":            `{"version":"1","target":{"namespace":"mail","action":"submit"},"attributes":{"chain":{"records":[{"fields":[]}]}}}`,
		"recursive record":        `{"version":"1","target":{"namespace":"mail","action":"submit"},"attributes":{"chain":{"records":[{"fields":[{"name":"nested","value":{"records":[]}}]}]}}}`,
		"unknown nested field":    `{"version":"1","target":{"namespace":"mail","action":"submit"},"attributes":{"chain":{"records":[{"fields":[{"name":"sequence","value":{"integer":"1","unknown":true}}]}]}}}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRequest([]byte(body)); err == nil {
				t.Fatal("decodeRequest() accepted invalid record wire")
			}
		})
	}
}

func TestPolicyHTTPRecordRawWireAcceptsOrderedFields(t *testing.T) {
	body := `{"version":"1","target":{"namespace":"mail","action":"submit"},"attributes":{"chain":{"records":[{"fields":[{"name":"digest","value":{"bytes":"dHdv"}},{"name":"sequence","value":{"integer":"1"}}]}]}}}`

	request, err := decodeRequest([]byte(body))
	if err != nil {
		t.Fatalf("decodeRequest() error = %v", err)
	}

	value, ok := request.Attributes["chain"]
	if !ok || value.Kind() != "records" {
		t.Fatalf("record value = %#v, %t", value, ok)
	}
}
