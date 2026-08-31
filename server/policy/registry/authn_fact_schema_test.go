// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package registry

import (
	"context"
	"testing"

	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestBuiltinAuthnSchemasDeclareAdapterFactsWithExactSources(t *testing.T) {
	contribution, err := NewBuiltinTargetContributor().Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	tests := []struct {
		name          string
		action        policy.Operation
		operationFact string
	}{
		{name: "authenticate", action: policy.OperationAuthenticate, operationFact: policy.AuthnFactAuthenticated},
		{name: "lookup identity", action: policy.OperationLookupIdentity, operationFact: policy.AuthnFactIdentityFound},
		{name: "list accounts", action: policy.OperationListAccounts, operationFact: policy.AuthnFactAccountCount},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema := builtinAuthnSchemaForAction(t, contribution.Schemas(), string(test.action))
			facts := indexAuthnFactSchemas(schema.Facts())

			assertAuthnFactSchema(t, facts, policy.AuthnFactOperation, decision.ValueKindString, decision.FactSourceNauthilus)
			assertAuthnFactSchema(t, facts, policy.AuthnFactUsername, decision.ValueKindString, decision.FactSourceCaller)
			assertAuthnFactSchema(t, facts, policy.AuthnFactProtocol, decision.ValueKindString, decision.FactSourceCaller)
			assertAuthnFactSchema(t, facts, decision.FactTransportGRPCMethod, decision.ValueKindString, decision.FactSourceTransport)
			assertAuthnFactSchema(t, facts, test.operationFact, authnOperationFactKind(test.action), decision.FactSourceBackend)

			if test.action == policy.OperationListAccounts {
				assertAuthnFactSchema(t, facts, policy.AuthnFactAccountProviderCompleted, decision.ValueKindBoolean, decision.FactSourceBackend)
			} else {
				assertAuthnFactSchema(t, facts, policy.AuthnFactBackend, decision.ValueKindString, decision.FactSourceBackend)
				assertAuthnFactSchema(t, facts, policy.AuthnFactGroups, decision.ValueKindStrings, decision.FactSourceBackend)
			}
		})
	}
}

// builtinAuthnSchemaForAction returns one exact builtin schema from a detached contribution.
func builtinAuthnSchemaForAction(t *testing.T, schemas []SchemaDefinition, action string) SchemaDefinition {
	t.Helper()

	want := policy.AuthnNamespace + "/" + action + "/v1"
	for _, schema := range schemas {
		if schema.Identity().String() == want {
			return schema
		}
	}

	t.Fatalf("builtin authn schema %q missing", want)

	return SchemaDefinition{}
}

// indexAuthnFactSchemas indexes exact schema declarations by canonical ID.
func indexAuthnFactSchemas(facts []FactSchema) map[string]FactSchema {
	result := make(map[string]FactSchema, len(facts))
	for _, fact := range facts {
		result[fact.ID()] = fact
	}

	return result
}

// assertAuthnFactSchema verifies one exact value kind and sole provenance source.
func assertAuthnFactSchema(
	t *testing.T,
	facts map[string]FactSchema,
	id string,
	wantKind decision.ValueKind,
	wantSource decision.FactSource,
) {
	t.Helper()

	fact, found := facts[id]
	if !found {
		t.Fatalf("fact schema %q missing", id)
	}

	if fact.Kind() != wantKind {
		t.Fatalf("fact schema %q kind = %q, want %q", id, fact.Kind(), wantKind)
	}

	sources := fact.AllowedSources()
	if len(sources) != 1 || sources[0] != wantSource {
		t.Fatalf("fact schema %q sources = %v, want [%s]", id, sources, wantSource)
	}
}

// authnOperationFactKind returns the strict result kind for one authn action.
func authnOperationFactKind(operation policy.Operation) decision.ValueKind {
	if operation == policy.OperationListAccounts {
		return decision.ValueKindInteger
	}

	return decision.ValueKindBoolean
}
