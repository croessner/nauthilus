// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policygrpc

import (
	"testing"

	policyv1 "github.com/croessner/nauthilus/v3/api/policy/v1"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestPolicyGRPCRecordRawWireRejection(t *testing.T) {
	t.Run("absent field oneof", func(t *testing.T) {
		request := policyRequestWithValue(recordValue(&policyv1.RecordFieldValue{}))
		if _, err := requestInput(request); err == nil {
			t.Fatal("requestInput() accepted an absent record-field oneof")
		}
	})

	t.Run("duplicate repeated field names", func(t *testing.T) {
		fieldValue := &policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_Integer{Integer: 1}}

		fieldBytes, err := proto.Marshal(&policyv1.RecordField{Name: "sequence", Value: fieldValue})
		if err != nil {
			t.Fatalf("marshal record field: %v", err)
		}

		recordBytes := protowire.AppendTag(nil, 1, protowire.BytesType)
		recordBytes = protowire.AppendBytes(recordBytes, fieldBytes)
		recordBytes = protowire.AppendTag(recordBytes, 1, protowire.BytesType)
		recordBytes = protowire.AppendBytes(recordBytes, fieldBytes)
		record := &policyv1.Record{}

		if err = proto.Unmarshal(recordBytes, record); err != nil {
			t.Fatalf("unmarshal raw duplicate record fields: %v", err)
		}

		value := recordListValue(&policyv1.RecordList{Records: []*policyv1.Record{record}})

		if _, err := requestInput(policyRequestWithValue(value)); err == nil {
			t.Fatal("requestInput() accepted duplicate repeated record fields")
		}
	})

	for _, testCase := range []struct {
		name  string
		value func(*testing.T) *policyv1.Value
	}{
		{name: "unknown record-list field", value: rawUnknownRecordListValue},
		{name: "unknown record field", value: rawUnknownRecordValue},
		{name: "unknown record-field field", value: rawUnknownRecordFieldValue},
		{name: "unknown record-field-value field", value: rawUnknownRecordLeafValue},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := requestInput(policyRequestWithValue(testCase.value(t))); err == nil {
				t.Fatal("requestInput() accepted an unknown nested record field")
			}
		})
	}
}

func TestPolicyGRPCRecordFieldConflictingOneofUsesCanonicalLastValue(t *testing.T) {
	encoded, err := proto.Marshal(&policyv1.RecordFieldValue{
		Kind: &policyv1.RecordFieldValue_String_{String_: "first"},
	})
	if err != nil {
		t.Fatalf("marshal field value: %v", err)
	}

	encoded = append(encoded, 0x18, 0x02)
	decoded := &policyv1.RecordFieldValue{}

	if err = proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("unmarshal conflicting field value: %v", err)
	}

	request, err := requestInput(policyRequestWithValue(recordValue(decoded)))
	if err != nil {
		t.Fatalf("requestInput() error = %v", err)
	}

	value := request.Attributes["value"]
	records, _ := value.Records()
	integer, ok := records.Records()[0].Fields()[0].Value().Integer()

	if !ok || integer != 1 {
		t.Fatalf("canonical last record-field value = %d, %t, want 1, true", integer, ok)
	}
}

func TestPolicyGRPCRecordRoundTripPreservesRepeatedOrder(t *testing.T) {
	value := &policyv1.Value{Kind: &policyv1.Value_Records{Records: &policyv1.RecordList{
		Records: []*policyv1.Record{{Fields: []*policyv1.RecordField{
			{Name: "digest", Value: &policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_Bytes{Bytes: []byte("two")}}},
			{Name: "sequence", Value: &policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_Integer{Integer: 1}}},
		}}},
	}}}

	request, err := requestInput(policyRequestWithValue(value))
	if err != nil {
		t.Fatalf("requestInput() error = %v", err)
	}

	converted, err := valueProto(request.Attributes["value"])
	if err != nil {
		t.Fatalf("valueProto() error = %v", err)
	}

	fields := converted.GetRecords().GetRecords()[0].GetFields()
	if len(fields) != 2 || fields[0].GetName() != "digest" || fields[1].GetName() != "sequence" {
		t.Fatalf("repeated field order = %#v", fields)
	}
}

func TestDKIM2RspamdGRPCWirePreservesLocalNestedAttributeKeys(t *testing.T) {
	t.Parallel()

	request := &policyv1.DecisionRequest{
		Version: "1",
		Target:  &policyv1.Target{Namespace: "dkim2", Action: "accept-message-instance"},
		Resource: &policyv1.Entity{Type: "dkim2-message-instance", Attributes: map[string]*policyv1.Value{
			"dkim2.projection_schema": {Kind: &policyv1.Value_String_{String_: "dkim2.verifier-projection.v1"}},
			"dkim2.chain": recordListValue(&policyv1.RecordList{Records: []*policyv1.Record{{Fields: []*policyv1.RecordField{
				{Name: "sequence", Value: &policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_Integer{Integer: 1}}},
				{Name: "signer_domain", Value: &policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_String_{String_: "origin.example"}}},
			}}}}),
		}},
		Environment: &policyv1.Environment{
			Service: "rspamd", Instance: "mx01.example.net", Protocol: "milter",
			Attributes: map[string]*policyv1.Value{
				"rspamd.smtp_client_ip": {Kind: &policyv1.Value_String_{String_: "192.0.2.25"}},
			},
		},
	}

	converted, err := requestInput(request)
	if err != nil {
		t.Fatalf("requestInput() error = %v", err)
	}

	resource := converted.Resource.Attributes().Values()
	if _, ok := resource["dkim2.chain"]; !ok {
		t.Fatalf("resource attributes = %v, want local dkim2.chain", resource)
	}

	if _, ok := resource["resource.dkim2.chain"]; ok {
		t.Fatal("gRPC wire retained an incorrectly pre-prefixed resource key")
	}

	environment := converted.Environment.Attributes().Values()

	ip, ok := environment["rspamd.smtp_client_ip"]
	if !ok {
		t.Fatalf("environment attributes = %v, want local rspamd.smtp_client_ip", environment)
	}

	address, _ := ip.StringValue()
	if address != "192.0.2.25" {
		t.Fatalf("SMTP peer = %q", address)
	}
}

// recordValue wraps one field value in the smallest valid repeated record shape.
func recordValue(value *policyv1.RecordFieldValue) *policyv1.Value {
	return recordListValue(&policyv1.RecordList{
		Records: []*policyv1.Record{{Fields: []*policyv1.RecordField{{Name: "sequence", Value: value}}}},
	})
}

// recordListValue wraps one exact raw-decoded collection in the top-level records branch.
func recordListValue(value *policyv1.RecordList) *policyv1.Value {
	return &policyv1.Value{Kind: &policyv1.Value_Records{Records: value}}
}

// rawUnknownRecordListValue injects unknown bytes at the collection message level.
func rawUnknownRecordListValue(t *testing.T) *policyv1.Value {
	t.Helper()

	source := recordValue(&policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_Integer{Integer: 1}}).GetRecords()
	decoded := &policyv1.RecordList{}
	decodeWithRawUnknown(t, source, decoded)

	return recordListValue(decoded)
}

// rawUnknownRecordValue injects unknown bytes at the record message level.
func rawUnknownRecordValue(t *testing.T) *policyv1.Value {
	t.Helper()

	source := recordValue(&policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_Integer{Integer: 1}}).GetRecords().GetRecords()[0]
	decoded := &policyv1.Record{}
	decodeWithRawUnknown(t, source, decoded)

	return recordListValue(&policyv1.RecordList{Records: []*policyv1.Record{decoded}})
}

// rawUnknownRecordFieldValue injects unknown bytes at the named field message level.
func rawUnknownRecordFieldValue(t *testing.T) *policyv1.Value {
	t.Helper()

	source := &policyv1.RecordField{
		Name: "sequence", Value: &policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_Integer{Integer: 1}},
	}
	decoded := &policyv1.RecordField{}
	decodeWithRawUnknown(t, source, decoded)

	return recordListValue(&policyv1.RecordList{Records: []*policyv1.Record{{Fields: []*policyv1.RecordField{decoded}}}})
}

// rawUnknownRecordLeafValue injects unknown bytes at the non-recursive leaf message level.
func rawUnknownRecordLeafValue(t *testing.T) *policyv1.Value {
	t.Helper()

	source := &policyv1.RecordFieldValue{Kind: &policyv1.RecordFieldValue_Integer{Integer: 1}}
	decoded := &policyv1.RecordFieldValue{}
	decodeWithRawUnknown(t, source, decoded)

	return recordValue(decoded)
}

// decodeWithRawUnknown appends one unknown varint field before protobuf decoding.
func decodeWithRawUnknown(t *testing.T, source proto.Message, target proto.Message) {
	t.Helper()

	encoded, err := proto.Marshal(source)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}

	encoded = protowire.AppendTag(encoded, 99, protowire.VarintType)
	encoded = protowire.AppendVarint(encoded, 1)

	if err = proto.Unmarshal(encoded, target); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
}
