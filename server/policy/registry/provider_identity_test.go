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

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

func TestProviderDefinitionAcceptsCanonicalProviderIdentities(t *testing.T) {
	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	tests := []string{
		"authn/builtin/brute_force",
		"authn/plugin.example.environment",
		"authn/plugin.example.subject.local",
		"authn/lua_environment_name",
	}

	for _, identity := range tests {
		t.Run(identity, func(t *testing.T) {
			_, definitionErr := NewProviderDefinition(ProviderDefinitionInput{
				ID:         identity,
				Targets:    []decision.Target{target},
				Executions: []ExecutionClass{ExecutionHostSync},
			})
			if definitionErr != nil {
				t.Fatalf("NewProviderDefinition(%q) error = %v", identity, definitionErr)
			}

			if _, checkpointErr := NewCheckpointDefinition("pre_auth", nil, []string{identity}); checkpointErr != nil {
				t.Fatalf("NewCheckpointDefinition(%q) error = %v", identity, checkpointErr)
			}
		})
	}
}

func TestBuiltinAuthnProviderUseIdentitiesResolveExactly(t *testing.T) {
	contribution, err := NewBuiltinTargetContributor().Contribute(context.Background())
	if err != nil {
		t.Fatalf("NewBuiltinTargetContributor().Contribute() error = %v", err)
	}

	providers := make(map[string]struct{}, len(contribution.Providers()))
	for _, provider := range contribution.Providers() {
		providers[provider.ID()] = struct{}{}
	}

	want := []string{
		policy.AuthnProviderBruteForce,
		policy.AuthnProviderTLSEncryption,
		policy.AuthnProviderRelayDomains,
		policy.AuthnProviderRBL,
		policy.AuthnProviderLDAPBackend,
		policy.AuthnProviderLuaBackend,
		policy.AuthnProviderPluginBackendOrder,
		policy.AuthnProviderAccount,
	}

	for _, identity := range want {
		if _, exists := providers[identity]; !exists {
			t.Errorf("builtin provider %q is unresolved", identity)
		}

		if !IsBuiltinAuthProviderID(identity) {
			t.Errorf("builtin provider %q is not reserved", identity)
		}
	}

	if IsBuiltinAuthProviderID("authn/lua_environment_risk") {
		t.Error("configured Lua environment identity is reserved as builtin")
	}
}

func TestPolicyRuleAcceptsProviderIdentitiesAndInstanceNames(t *testing.T) {
	expression, err := NewPolicyExpression(PolicyExpressionInput{Kind: ExpressionKindAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	for _, reference := range []string{"dependent", policy.AuthnProviderBruteForce} {
		t.Run(reference, func(t *testing.T) {
			rule, ruleErr := NewPolicyRule(PolicyRuleInput{
				Name: "allow", Checkpoint: string(policy.StagePreAuth), RequiredProviders: []string{reference},
				Expression: expression, Decision: decision.EffectPermit,
			})
			if ruleErr != nil {
				t.Fatalf("NewPolicyRule(%q) error = %v", reference, ruleErr)
			}

			if got := rule.RequiredProviders(); len(got) != 1 || got[0] != reference {
				t.Fatalf("RequiredProviders() = %v, want [%q]", got, reference)
			}
		})
	}
}

func TestNewAuthnDomainPlanDefinitionPreservesFallbackProvenance(t *testing.T) {
	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	checkpoint, err := NewCheckpointDefinition(string(policy.StagePreAuth), nil, []string{policy.AuthnProviderBruteForce})
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	plan, err := NewAuthnDomainPlanDefinition(target, []CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("NewAuthnDomainPlanDefinition() error = %v", err)
	}

	if !plan.IsBuiltinAuth() {
		t.Fatal("authn domain plan lost builtin fallback provenance")
	}

	generic, err := NewDomainPlanDefinition(target, []CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition() error = %v", err)
	}

	if generic.IsBuiltinAuth() {
		t.Fatal("generic domain-plan constructor forged builtin fallback provenance")
	}
}

func TestNewAuthnDomainPlanDefinitionAcceptsEveryAuthnCheckpoint(t *testing.T) {
	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	stages := []policy.Stage{
		policy.StagePreAuth,
		policy.StageAuthBackend,
		policy.StageSubjectAnalysis,
		policy.StageAccountProvider,
		policy.StageAuthDecision,
	}

	for _, stage := range stages {
		t.Run(string(stage), func(t *testing.T) {
			checkpoint, checkpointErr := NewCheckpointDefinition(string(stage), nil, nil)
			if checkpointErr != nil {
				t.Fatalf("NewCheckpointDefinition() error = %v", checkpointErr)
			}

			if _, planErr := NewAuthnDomainPlanDefinition(target, []CheckpointDefinition{checkpoint}); planErr != nil {
				t.Fatalf("NewAuthnDomainPlanDefinition() error = %v", planErr)
			}
		})
	}
}

func TestNewAuthnDomainPlanDefinitionRejectsNonAuthnTargets(t *testing.T) {
	checkpoint, err := NewCheckpointDefinition(string(policy.StagePreAuth), nil, nil)
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	tests := []struct {
		namespace string
		action    string
	}{
		{namespace: "shared", action: string(policy.OperationAuthenticate)},
		{namespace: policy.AuthnNamespace, action: "sign"},
	}

	for _, test := range tests {
		t.Run(test.namespace+"/"+test.action, func(t *testing.T) {
			target, targetErr := decision.NewTarget(test.namespace, test.action)
			if targetErr != nil {
				t.Fatalf("decision.NewTarget() error = %v", targetErr)
			}

			if _, planErr := NewAuthnDomainPlanDefinition(target, []CheckpointDefinition{checkpoint}); planErr == nil {
				t.Fatal("NewAuthnDomainPlanDefinition() error = nil")
			}
		})
	}
}

func TestNewAuthnDomainPlanDefinitionRejectsGenericCheckpoint(t *testing.T) {
	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	checkpoint, err := NewCheckpointDefinition(decision.CheckpointFinalDecision, nil, nil)
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	if _, planErr := NewAuthnDomainPlanDefinition(target, []CheckpointDefinition{checkpoint}); planErr == nil {
		t.Fatal("NewAuthnDomainPlanDefinition() error = nil")
	}
}
