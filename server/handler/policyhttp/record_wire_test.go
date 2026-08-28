// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyhttp

import "testing"

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
