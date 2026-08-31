// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyhttp

import "testing"

func TestDKIM2RspamdHTTPWirePreservesLocalNestedAttributeKeys(t *testing.T) {
	t.Parallel()

	body := `{
  "version":"1",
  "target":{"namespace":"dkim2","action":"accept-message-instance"},
  "resource":{"type":"dkim2-message-instance","attributes":{
    "dkim2.projection_schema":{"string":"dkim2.verifier-projection.v1"},
    "dkim2.chain":{"records":[{"fields":[
      {"name":"sequence","value":{"integer":"1"}},
      {"name":"signer_domain","value":{"string":"origin.example"}}
    ]}]}
  }},
  "environment":{"service":"rspamd","instance":"mx01.example.net","protocol":"milter","attributes":{
    "rspamd.smtp_client_ip":{"string":"2001:db8::25"}
  }},
  "options":{"include_diagnostics":false}
}`

	request, err := decodeRequest([]byte(body))
	if err != nil {
		t.Fatalf("decodeRequest() error = %v", err)
	}

	if request.Target.String() != "dkim2/accept-message-instance" {
		t.Fatalf("target = %q", request.Target.String())
	}

	resource := request.Resource.Attributes().Values()
	if _, ok := resource["dkim2.chain"]; !ok {
		t.Fatalf("resource attributes = %v, want local dkim2.chain", resource)
	}

	if _, ok := resource["resource.dkim2.chain"]; ok {
		t.Fatal("HTTP wire retained an incorrectly pre-prefixed resource key")
	}

	environment := request.Environment.Attributes().Values()

	ip, ok := environment["rspamd.smtp_client_ip"]
	if !ok {
		t.Fatalf("environment attributes = %v, want local rspamd.smtp_client_ip", environment)
	}

	address, _ := ip.StringValue()
	if address != "2001:db8::25" {
		t.Fatalf("SMTP peer = %q", address)
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
