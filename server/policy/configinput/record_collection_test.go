// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

const recordCollectionPolicyFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          submit:
            versions:
              v1:
                facts:
                  - attribute: resource.chain
                    category: resource
                    type: records
                    allowed_sources: [caller]
                    record_schema:
                      id: chain
                      version: v1
                      min_records: 0
                      max_records: 8
                      max_fields: 2
                      max_aggregate_bytes: 1024
                      fields:
                        - {name: sequence, type: integer, required: true, expression_visible: true}
                        - {name: result, type: string, max_length: 16, expression_visible: true}
      policy_sets:
        default:
          rules:
            - name: any_pass
              checkpoint: final_decision
              if:
                records:
                  attribute: resource.chain
                  quantifier: any
                  field: result
                  where: {eq: pass}
              then: {decision: permit}
  targets:
    - namespace: mail
      action: submit
      schema: mail/submit/v1
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision:
          policy_sets: [mail/default]
`

func TestPolicyRecordSchemaAndQuantifierCompileTogether(t *testing.T) {
	document, err := policyconfig.Decode("yaml", strings.NewReader(recordCollectionPolicyFixture))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	catalog, err := input.Compile(context.Background(), nil)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	target, _ := decision.NewTarget("mail", "submit")

	compiled, ok := catalog.Lookup(target)
	if !ok {
		t.Fatal("compiled record target is missing")
	}

	setID, _ := registry.NewPolicySetID("mail", "default")

	set, ok := compiled.LookupPolicySet(setID)
	if !ok || len(set.Rules()) != 1 {
		t.Fatalf("compiled policy set = %#v, %t", set, ok)
	}

	expression := set.Rules()[0].Expression()
	if expression.Kind() != registry.ExpressionKindRecordQuantifier ||
		expression.Quantifier() != registry.RecordQuantifierAny || expression.RecordField() != "result" {
		t.Fatalf("compiled record expression = %#v", expression)
	}
}

func TestPolicyRecordQuantifierRejectsDynamicAndNestedPaths(t *testing.T) {
	for name, replacement := range map[string]string{
		"dynamic field":     "field: ${field}",
		"nested quantifier": "field: result\n                  where:\n                    records:\n                      attribute: resource.chain\n                      quantifier: any\n                      field: result\n                      where: {eq: pass}",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := strings.Replace(recordCollectionPolicyFixture, "field: result", replacement, 1)

			document, err := policyconfig.Decode("yaml", strings.NewReader(fixture))
			if err == nil {
				_, err = Normalize(context.Background(), document)
			}

			if err == nil {
				t.Fatal("Normalize() accepted an unsafe record path")
			}
		})
	}
}

func TestPolicyRecordQuantifierCompilerRejectsUnknownHiddenAndWronglyTypedFields(t *testing.T) {
	for name, fixture := range map[string]string{
		"unknown field": strings.Replace(recordCollectionPolicyFixture, "field: result", "field: unknown", 1),
		"hidden field": strings.Replace(
			recordCollectionPolicyFixture,
			"name: result, type: string, max_length: 16, expression_visible: true",
			"name: result, type: string, max_length: 16, expression_visible: false",
			1,
		),
		"wrong field type": strings.Replace(recordCollectionPolicyFixture, "where: {eq: pass}", "where: {eq: 1}", 1),
	} {
		t.Run(name, func(t *testing.T) {
			document, err := policyconfig.Decode("yaml", strings.NewReader(fixture))
			if err != nil {
				t.Fatalf("policyconfig.Decode() error = %v", err)
			}

			input, err := Normalize(context.Background(), document)
			if err == nil {
				_, err = input.Compile(context.Background(), nil)
			}

			if err == nil {
				t.Fatal("Compile() accepted an incompatible record-local field")
			}
		})
	}
}
