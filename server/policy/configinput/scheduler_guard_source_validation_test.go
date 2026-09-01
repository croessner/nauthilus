// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

const unavailableHostSchedulerGuardFixture = `policy:
  namespaces:
    authn:
      providers:
        lua_environment_guarded:
          kind: lua_environment
          script_path: guarded.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          scheduler_guards:
            backend_result:
              if: {attribute: backend.authenticated, is: true}
              on_missing_attribute: run
          checkpoints:
            pre_auth:
              providers:
                - name: guarded
                  use: authn/lua_environment_guarded
                  skip_if: [backend_result]
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
`

const unavailableNauthilusHostSchedulerGuardFixture = `policy:
  namespaces:
    authn:
      providers:
        lua_environment_guarded:
          kind: lua_environment
          script_path: guarded.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          scheduler_guards:
            tls_result:
              if: {attribute: nauthilus.auth.tls.secure, is: true}
              on_missing_attribute: run
          checkpoints:
            pre_auth:
              providers:
                - name: guarded
                  use: authn/lua_environment_guarded
                  skip_if: [tls_result]
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
`

// TestCompiledHostSchedulerGuardRejectsUnavailableFactSource protects candidate preparation.
func TestCompiledHostSchedulerGuardRejectsUnavailableFactSource(t *testing.T) {
	err := compilePolicyFixture(t, unavailableHostSchedulerGuardFixture)
	if err == nil || !strings.Contains(err.Error(), "source backend is unavailable before host scheduling") {
		t.Fatalf("Compile() error = %v, want unavailable backend scheduler fact", err)
	}
}

// TestCompiledHostSchedulerGuardRejectsNauthilusCheckProducedFact protects builtin availability.
func TestCompiledHostSchedulerGuardRejectsNauthilusCheckProducedFact(t *testing.T) {
	err := compilePolicyFixture(t, unavailableNauthilusHostSchedulerGuardFixture)
	if err == nil || !strings.Contains(err.Error(), "nauthilus.auth.tls.secure") {
		t.Fatalf("Compile() error = %v, want unavailable Nauthilus scheduler fact", err)
	}
}

type schedulerGuardSourceTestCase struct {
	name    string
	factID  string
	sources []decision.FactSource
	wantErr bool
}

var schedulerGuardSourceTestCases = []schedulerGuardSourceTestCase{
	{
		name: "caller protocol", factID: "environment.protocol",
		sources: []decision.FactSource{decision.FactSourceCaller},
	},
	{name: "token", sources: []decision.FactSource{decision.FactSourceToken}},
	{name: "transport", sources: []decision.FactSource{decision.FactSourceTransport}},
	{
		name: "authenticator caller principal", factID: decision.FactCallerPrincipal,
		sources: []decision.FactSource{decision.FactSourceNauthilus},
	},
	{
		name: "authenticator caller client ID", factID: decision.FactCallerClientID,
		sources: []decision.FactSource{decision.FactSourceNauthilus},
	},
	{
		name: "authenticator caller kind", factID: decision.FactCallerAuthenticationKind,
		sources: []decision.FactSource{decision.FactSourceNauthilus},
	},
	{
		name: "authenticator caller scopes", factID: decision.FactCallerScopes,
		sources: []decision.FactSource{decision.FactSourceNauthilus},
	},
	{
		name: "Nauthilus check result", factID: policy.AuthnFactTLSSecure,
		sources: []decision.FactSource{decision.FactSourceNauthilus}, wantErr: true,
	},
	{
		name: "Nauthilus operation", factID: policy.AuthnFactOperation,
		sources: []decision.FactSource{decision.FactSourceNauthilus}, wantErr: true,
	},
	{
		name: "Nauthilus service", factID: policy.AuthnFactService,
		sources: []decision.FactSource{decision.FactSourceNauthilus}, wantErr: true,
	},
	{
		name: "Nauthilus later result", factID: policy.AuthnFactCurrentDecision,
		sources: []decision.FactSource{decision.FactSourceNauthilus}, wantErr: true,
	},
	{name: "backend", sources: []decision.FactSource{decision.FactSourceBackend}, wantErr: true},
	{name: "lua", sources: []decision.FactSource{decision.FactSourceLua}, wantErr: true},
	{name: "plugin", sources: []decision.FactSource{decision.FactSourcePlugin}, wantErr: true},
	{
		name: "mixed safe and unavailable",
		sources: []decision.FactSource{
			decision.FactSourceCaller,
			decision.FactSourcePlugin,
		},
		wantErr: true,
	},
}

// TestHostSchedulerGuardRejectsUnavailableFactSources protects the pre-host trust boundary.
func TestHostSchedulerGuardRejectsUnavailableFactSources(t *testing.T) {
	for _, test := range schedulerGuardSourceTestCases {
		t.Run(test.name, func(t *testing.T) {
			assertHostSchedulerGuardSource(t, test)
		})
	}
}

// TestHostSchedulerGuardAllowsPreparedClientIPFacts protects trusted proxy scheduling guards.
func TestHostSchedulerGuardAllowsPreparedClientIPFacts(t *testing.T) {
	for _, factID := range []string{
		policy.AuthnFactRequestClientIP,
		policy.AuthnFactRequestClientIPPresent,
		policy.AuthnFactRequestClientIPTrusted,
	} {
		t.Run(factID, func(t *testing.T) {
			assertHostSchedulerGuardSource(t, schedulerGuardSourceTestCase{
				name: factID, factID: factID,
				sources: []decision.FactSource{decision.FactSourceNauthilus},
			})
		})
	}
}

// assertHostSchedulerGuardSource checks one exact fact-source combination.
func assertHostSchedulerGuardSource(t *testing.T, test schedulerGuardSourceTestCase) {
	t.Helper()

	factID := test.factID
	if factID == "" {
		factID = "environment.protocol_present"
	}

	expression := schedulerGuardSourceExpression(t, factID)
	schema := map[string]registry.FactSchema{
		expression.FactID(): schedulerGuardFactSchema(t, expression.FactID(), test.sources),
	}

	err := validateHostSchedulerGuardSources(expression, schema)
	if (err != nil) != test.wantErr {
		t.Fatalf("validateHostSchedulerGuardSources() error = %v, wantErr %t", err, test.wantErr)
	}
}

// schedulerGuardSourceExpression constructs one strict pre-host fact predicate.
func schedulerGuardSourceExpression(t *testing.T, factID string) registry.PolicyExpression {
	t.Helper()

	expected := true

	value, err := decision.NewValue(decision.ValueInput{Boolean: &expected})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind:     registry.ExpressionKindAttribute,
		FactID:   factID,
		FactKind: decision.ValueKindBoolean,
		Operator: registry.ExpressionOperatorExists,
		Values:   []decision.Value{value},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	return expression
}

// schedulerGuardFactSchema constructs one exact source-owned fact declaration.
func schedulerGuardFactSchema(
	t *testing.T,
	id string,
	sources []decision.FactSource,
) registry.FactSchema {
	t.Helper()

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID: id, AllowedSources: sources, Category: decision.FactCategoryEnvironment,
		Kind: decision.ValueKindBoolean,
	})
	if err != nil {
		t.Fatalf("NewFactSchema() error = %v", err)
	}

	return fact
}
