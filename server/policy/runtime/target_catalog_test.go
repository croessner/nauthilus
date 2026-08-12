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
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestTargetCatalogOwnsCompiledRecords(t *testing.T) {
	record, factSources := newTargetCatalogRecord(t)
	records := []TargetCatalogRecord{record}

	catalog, err := NewTargetCatalog(records)
	if err != nil {
		t.Fatalf("NewTargetCatalog() error = %v", err)
	}

	factSources[0] = decision.FactSourceToken
	records[0] = TargetCatalogRecord{}

	returned, ok := catalog.Lookup(record.Target)
	if !ok {
		t.Fatal("compiled target missing")
	}

	returnedFacts := returned.Schema().Facts()
	returnedFacts[0] = registry.FactSchema{}

	second, ok := catalog.Lookup(record.Target)
	if !ok {
		t.Fatal("compiled target missing on second lookup")
	}

	sources := second.Schema().Facts()[0].AllowedSources()
	if len(sources) != 1 || sources[0] != decision.FactSourceCaller {
		t.Fatalf("compiled fact sources = %v, want immutable caller source", sources)
	}

	clone := catalog.Clone()
	if clone == catalog {
		t.Fatal("Clone() returned the original catalog pointer")
	}

	if _, ok := clone.Lookup(record.Target); !ok {
		t.Fatal("cloned catalog lost target")
	}
}

// newTargetCatalogRecord constructs one mutable input record for ownership tests.
func newTargetCatalogRecord(t *testing.T) (TargetCatalogRecord, []decision.FactSource) {
	t.Helper()

	factSources := []decision.FactSource{decision.FactSourceCaller}

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID:             "input.value",
		Category:       decision.FactCategoryEnvironment,
		Kind:           decision.ValueKindString,
		AllowedSources: factSources,
		Required:       true,
		MaxLength:      32,
	})
	if err != nil {
		t.Fatalf("registry.NewFactSchema() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity("dkim2", "sign", "v1")
	if err != nil {
		t.Fatalf("registry.NewSchemaIdentity() error = %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, []registry.FactSchema{fact})
	if err != nil {
		t.Fatalf("registry.NewSchemaDefinition() error = %v", err)
	}

	target, err := decision.NewTarget("dkim2", "sign")
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	return TargetCatalogRecord{Target: target, Schema: schema}, factSources
}
