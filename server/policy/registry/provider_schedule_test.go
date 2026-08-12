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

package registry_test

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestProviderDefinitionOwnsGenericSchedulingContract(t *testing.T) {
	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:            "mail/reputation",
		Targets:       []decision.Target{target},
		Executions:    []registry.ExecutionClass{registry.ExecutionHostSync},
		Requires:      []string{"mail/identity"},
		ProducedFacts: []string{"plugin.reputation.score"},
		Failure:       registry.ProviderFailureContinue,
		Timeout:       125 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	if got := provider.Requires(); len(got) != 1 || got[0] != "mail/identity" {
		t.Fatalf("Requires() = %#v", got)
	}

	if got := provider.ProducedFacts(); len(got) != 1 || got[0] != "plugin.reputation.score" {
		t.Fatalf("ProducedFacts() = %#v", got)
	}

	if provider.Failure() != registry.ProviderFailureContinue || provider.Timeout() != 125*time.Millisecond {
		t.Fatalf("failure/timeout = %q/%s", provider.Failure(), provider.Timeout())
	}

	for _, failure := range []registry.ProviderFailureBehavior{"", "ignore", "best_effort"} {
		_, err = registry.NewProviderDefinition(registry.ProviderDefinitionInput{
			ID:            "mail/invalid",
			Targets:       []decision.Target{target},
			Executions:    []registry.ExecutionClass{registry.ExecutionHostSync},
			ProducedFacts: []string{"plugin.invalid.value"},
			Failure:       failure,
			Timeout:       time.Second,
		})
		if err == nil {
			t.Fatalf("NewProviderDefinition(failure=%q) error = nil", failure)
		}
	}
}
