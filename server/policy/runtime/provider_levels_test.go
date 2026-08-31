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

package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

func TestProviderLevelsCompileDeterministicallyAndRejectUnsafeContinuation(t *testing.T) {
	target, schema := providerLevelTargetSchema(t, false)
	providers := []registry.ProviderDefinition{
		providerLevelDefinition(t, target, "mail/a", nil, "plugin.a.value", registry.ProviderFailureIndeterminate),
		providerLevelDefinition(t, target, "mail/b", nil, "plugin.b.value", registry.ProviderFailureContinue),
		providerLevelDefinition(t, target, "mail/c", []string{"mail/a"}, "plugin.c.value", registry.ProviderFailureIndeterminate),
		providerLevelDefinition(t, target, "mail/d", []string{"mail/b"}, "plugin.d.value", registry.ProviderFailureIndeterminate),
	}
	record := providerLevelRecord(t, target, schema, providers)

	catalog, err := NewTargetCatalog([]TargetCatalogRecord{record})
	if err != nil {
		t.Fatalf("NewTargetCatalog() error = %v", err)
	}

	compiled, ok := catalog.Lookup(target)
	if !ok {
		t.Fatal("compiled target missing")
	}

	checkpoint, ok := compiled.DomainPlan().Checkpoint(decision.CheckpointFinalDecision)
	if !ok {
		t.Fatal("final checkpoint missing")
	}

	levels := checkpoint.ProviderLevels()
	if got := strings.Join(levels[0], ","); got != "mail/a,mail/b" {
		t.Fatalf("provider level 0 = %q", got)
	}

	if got := strings.Join(levels[1], ","); got != "mail/c,mail/d" {
		t.Fatalf("provider level 1 = %q", got)
	}

	_, requiredSchema := providerLevelTargetSchema(t, true)
	record = providerLevelRecord(t, target, requiredSchema, providers)

	if _, err = NewTargetCatalog([]TargetCatalogRecord{record}); err == nil || !strings.Contains(err.Error(), "continue") {
		t.Fatalf("NewTargetCatalog(unsafe continue) error = %v", err)
	}
}

func TestProviderLevelsRejectUnknownAndDuplicateProducedFacts(t *testing.T) {
	target, schema := providerLevelTargetSchema(t, false)

	tests := []struct {
		name      string
		providers []registry.ProviderDefinition
	}{
		{
			name: "unknown output",
			providers: []registry.ProviderDefinition{
				providerLevelDefinition(t, target, "mail/unknown", nil, "plugin.unknown.value", registry.ProviderFailureIndeterminate),
			},
		},
		{
			name: "duplicate output owner",
			providers: []registry.ProviderDefinition{
				providerLevelDefinition(t, target, "mail/first", nil, "plugin.a.value", registry.ProviderFailureIndeterminate),
				providerLevelDefinition(t, target, "mail/second", nil, "plugin.a.value", registry.ProviderFailureIndeterminate),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := providerLevelRecord(t, target, schema, test.providers)

			if _, err := NewTargetCatalog([]TargetCatalogRecord{record}); err == nil {
				t.Fatal("NewTargetCatalog() provider output error = nil")
			}
		})
	}
}

// providerLevelTargetSchema constructs one generic exact schema for scheduler compilation.
func providerLevelTargetSchema(t *testing.T, required bool) (decision.Target, registry.SchemaDefinition) {
	t.Helper()

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity("mail", "submit", "v1")
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	facts := make([]registry.FactSchema, 0, 4)

	for _, id := range []string{"plugin.a.value", "plugin.b.value", "plugin.c.value", "plugin.d.value"} {
		fact, factErr := registry.NewFactSchema(registry.FactSchemaInput{
			ID: id, Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindString,
			AllowedSources: []decision.FactSource{decision.FactSourcePlugin}, MaxLength: 64,
			Required: required && id == "plugin.b.value",
		})
		if factErr != nil {
			t.Fatalf("NewFactSchema(%s) error = %v", id, factErr)
		}

		facts = append(facts, fact)
	}

	schema, err := registry.NewSchemaDefinition(identity, facts)
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	return target, schema
}

// providerLevelDefinition constructs one scheduled generic provider descriptor.
func providerLevelDefinition(
	t *testing.T,
	target decision.Target,
	id string,
	requires []string,
	fact string,
	failure registry.ProviderFailureBehavior,
) registry.ProviderDefinition {
	t.Helper()

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID: id, Targets: []decision.Target{target}, Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
		Requires: requires, ProducedFacts: []string{fact}, Failure: failure, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition(%s) error = %v", id, err)
	}

	return provider
}

// providerLevelRecord constructs one provider-only generic runtime record.
func providerLevelRecord(
	t *testing.T,
	target decision.Target,
	schema registry.SchemaDefinition,
	providers []registry.ProviderDefinition,
) TargetCatalogRecord {
	t.Helper()

	providerIDs := make([]string, 0, len(providers))
	for _, provider := range providers {
		providerIDs = append(providerIDs, provider.ID())
	}

	record := TargetCatalogRecord{
		Target: target, Schema: schema, Providers: providers,
		Checkpoints: []CheckpointRecord{{Name: decision.CheckpointFinalDecision, ProviderIDs: providerIDs}},
		NoMatch:     registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
	}

	return completionRuntimeAuthorizeRecord(t, record)
}
