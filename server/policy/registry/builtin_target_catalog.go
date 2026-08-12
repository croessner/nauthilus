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
	"fmt"
	"slices"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

const builtinTargetContributorID = "builtin.authn"

const (
	builtinBruteForceProvider   = "authn/brute_force"
	builtinLuaActionProvider    = "authn/lua_action"
	builtinPostActionProvider   = "authn/post_action"
	builtinBruteForceEffect     = "authn/brute_force_update"
	builtinLuaActionEffect      = "authn/lua_action_dispatch"
	builtinPostActionEffect     = "authn/lua_post_action_enqueue"
	builtinActionListAccounts   = string(policy.OperationListAccounts)
	builtinActionAuthenticate   = string(policy.OperationAuthenticate)
	builtinActionLookupIdentity = string(policy.OperationLookupIdentity)
	builtinCheckpointDecision   = string(policy.StageAuthDecision)
	builtinCheckpointPreAuth    = string(policy.StagePreAuth)
	builtinEnvironmentProvider  = "authn/environment"
	builtinTLSProvider          = "authn/tls_encryption"
	builtinRelayProvider        = "authn/relay_domains"
	builtinRBLProvider          = "authn/rbl"
	builtinAuthBackendProvider  = "authn/auth_backend"
	builtinSubjectProvider      = "authn/subject"
	builtinAccountProvider      = "authn/account_provider"
)

type builtinTargetContributor struct {
	postActionAcceptance effectsupervisor.Acceptor
}

// NewBuiltinTargetContributor returns the internal authn definition contributor.
func NewBuiltinTargetContributor(postActionAcceptance ...effectsupervisor.Acceptor) Contributor {
	var capability effectsupervisor.Acceptor
	if len(postActionAcceptance) > 0 {
		capability = postActionAcceptance[0]
	}

	return builtinTargetContributor{postActionAcceptance: capability}
}

// Contribute returns inactive authn target and exact schema definitions.
func (c builtinTargetContributor) Contribute(ctx context.Context) (DefinitionContribution, error) {
	if err := ctx.Err(); err != nil {
		return DefinitionContribution{}, err
	}

	ownership, err := NewNamespaceOwnership(builtinTargetContributorID, []string{"authn"})
	if err != nil {
		return DefinitionContribution{}, err
	}

	targets, schemas, targetValues, plans, err := buildBuiltinAuthnDefinitions()
	if err != nil {
		return DefinitionContribution{}, err
	}

	standardAuth, err := newBuiltinStandardAuthPolicySet()
	if err != nil {
		return DefinitionContribution{}, err
	}

	providers, err := builtinAuthnProviders(targetValues, c.postActionAcceptance)
	if err != nil {
		return DefinitionContribution{}, err
	}

	effects, err := builtinAuthnEffects(targetValues)
	if err != nil {
		return DefinitionContribution{}, err
	}

	contribution, err := NewCompleteDefinitionContribution(DefinitionContributionInput{
		Ownership:  ownership,
		Targets:    targets,
		Schemas:    schemas,
		PolicySets: []PolicySetDefinition{standardAuth},
		Plans:      plans,
		Providers:  providers,
		Effects:    effects,
	})
	if err != nil {
		return DefinitionContribution{}, fmt.Errorf("build builtin target contribution: %w", err)
	}

	return contribution, nil
}

// builtinAuthnActions returns the exact initial authentication action vocabulary.
func builtinAuthnActions() []string {
	return []string{builtinActionAuthenticate, builtinActionLookupIdentity, builtinActionListAccounts}
}

// buildBuiltinAuthnDefinitions constructs target, schema, and checkpoint topology together.
func buildBuiltinAuthnDefinitions() (
	[]TargetDefinition,
	[]SchemaDefinition,
	[]decision.Target,
	[]DomainPlanDefinition,
	error,
) {
	targets := make([]TargetDefinition, 0, len(builtinAuthnActions()))
	schemas := make([]SchemaDefinition, 0, len(builtinAuthnActions()))
	targetValues := make([]decision.Target, 0, len(builtinAuthnActions()))
	plans := make([]DomainPlanDefinition, 0, len(builtinAuthnActions()))

	for _, action := range builtinAuthnActions() {
		target, schema, targetDefinition, plan, err := buildBuiltinAuthnTarget(action)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		targets = append(targets, targetDefinition)
		schemas = append(schemas, schema)
		targetValues = append(targetValues, target)
		plans = append(plans, plan)
	}

	return targets, schemas, targetValues, plans, nil
}

// buildBuiltinAuthnTarget constructs one exact authn target family.
func buildBuiltinAuthnTarget(
	action string,
) (decision.Target, SchemaDefinition, TargetDefinition, DomainPlanDefinition, error) {
	schemaIdentity, err := NewSchemaIdentity("authn", action, "v1")
	if err != nil {
		return decision.Target{}, SchemaDefinition{}, TargetDefinition{}, DomainPlanDefinition{}, err
	}

	schema, err := NewSchemaDefinition(schemaIdentity, nil)
	if err != nil {
		return decision.Target{}, SchemaDefinition{}, TargetDefinition{}, DomainPlanDefinition{}, err
	}

	schema.builtinAuth = true

	target, err := decision.NewTarget("authn", action)
	if err != nil {
		return decision.Target{}, SchemaDefinition{}, TargetDefinition{}, DomainPlanDefinition{}, err
	}

	targetDefinition, err := NewTargetDefinition(target, []SchemaIdentity{schemaIdentity})
	if err != nil {
		return decision.Target{}, SchemaDefinition{}, TargetDefinition{}, DomainPlanDefinition{}, err
	}

	plan, err := builtinAuthnPlan(target)

	return target, schema, targetDefinition, plan, err
}

// builtinAuthnPlan binds the existing evaluator at exact authn checkpoints.
func builtinAuthnPlan(target decision.Target) (DomainPlanDefinition, error) {
	checkpointNames := []string{builtinCheckpointDecision}
	if target.Action() != builtinActionListAccounts {
		checkpointNames = []string{builtinCheckpointPreAuth, builtinCheckpointDecision}
	}

	checkpoints := make([]CheckpointDefinition, 0, len(checkpointNames))
	for _, checkpointName := range checkpointNames {
		binding, err := NewPolicySetImport(
			"builtin.authn."+target.Action()+"."+checkpointName,
			BuiltinStandardAuthPolicySet,
			target,
			checkpointName,
			ExportContract{},
		)
		if err != nil {
			return DomainPlanDefinition{}, err
		}

		checkpoint, err := NewCheckpointDefinition(
			checkpointName,
			[]PolicySetImport{binding},
			builtinCheckpointProviders(target, checkpointName),
		)
		if err != nil {
			return DomainPlanDefinition{}, err
		}

		checkpoints = append(checkpoints, checkpoint)
	}

	plan, err := NewDomainPlanDefinition(target, checkpoints)
	if err != nil {
		return DomainPlanDefinition{}, err
	}

	plan.builtinAuth = true

	return plan, nil
}

// builtinCheckpointProviders preserves the established auth work order before each checkpoint.
func builtinCheckpointProviders(target decision.Target, checkpoint string) []string {
	switch {
	case target.Action() == builtinActionAuthenticate && checkpoint == builtinCheckpointPreAuth:
		return []string{builtinBruteForceProvider}
	case target.Action() == builtinActionAuthenticate && checkpoint == builtinCheckpointDecision:
		return []string{
			builtinEnvironmentProvider,
			builtinTLSProvider,
			builtinRelayProvider,
			builtinRBLProvider,
			builtinAuthBackendProvider,
			builtinSubjectProvider,
		}
	case target.Action() == builtinActionLookupIdentity && checkpoint == builtinCheckpointPreAuth:
		return []string{builtinEnvironmentProvider, builtinTLSProvider, builtinRBLProvider}
	case target.Action() == builtinActionLookupIdentity && checkpoint == builtinCheckpointDecision:
		return []string{builtinAuthBackendProvider, builtinSubjectProvider}
	case target.Action() == builtinActionListAccounts:
		return []string{builtinAccountProvider}
	default:
		return nil
	}
}

// builtinAuthnProviders declares immutable host ownership classes.
func builtinAuthnProviders(
	targets []decision.Target,
	postActionAcceptance effectsupervisor.Acceptor,
) ([]ProviderDefinition, error) {
	authAndLookup := builtinTargetsForActions(targets, builtinActionAuthenticate, builtinActionLookupIdentity)
	authenticate := builtinTargetsForActions(targets, builtinActionAuthenticate)
	listAccounts := builtinTargetsForActions(targets, builtinActionListAccounts)

	inputs := []ProviderDefinitionInput{
		{
			ID:         builtinBruteForceProvider,
			Targets:    authAndLookup,
			Executions: []ExecutionClass{ExecutionHostSync},
		},
		{
			ID:         builtinLuaActionProvider,
			Targets:    authAndLookup,
			Executions: []ExecutionClass{ExecutionHostSync},
		},
		{
			PostActionAcceptance: postActionAcceptance,
			ID:                   builtinPostActionProvider,
			Targets:              authenticate,
			Executions:           []ExecutionClass{ExecutionHostPostAction},
		},
		{ID: builtinEnvironmentProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinTLSProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinRelayProvider, Targets: authenticate, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinRBLProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinAuthBackendProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinSubjectProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinAccountProvider, Targets: listAccounts, Executions: []ExecutionClass{ExecutionHostSync}},
	}

	result := make([]ProviderDefinition, 0, len(inputs))
	for _, input := range inputs {
		provider, err := newProviderDefinition(input, true)
		if err != nil {
			return nil, err
		}

		result = append(result, provider)
	}

	return result, nil
}

// builtinAuthnEffects declares immutable mappings for established auth effects.
func builtinAuthnEffects(targets []decision.Target) ([]EffectDefinition, error) {
	bruteForceParameters, luaParameters, err := builtinEffectParameters()
	if err != nil {
		return nil, err
	}

	inputs := []EffectDefinitionInput{
		{
			ID:         builtinBruteForceEffect,
			Kind:       EffectKindObligation,
			Execution:  ExecutionHostSync,
			Targets:    builtinTargetsForEffectSelection(targets, policy.ObligationBruteForceUpdate),
			Provider:   builtinBruteForceProvider,
			Parameters: bruteForceParameters,
		},
		{
			ID:         builtinLuaActionEffect,
			Kind:       EffectKindObligation,
			Execution:  ExecutionHostSync,
			Targets:    builtinTargetsForEffectSelection(targets, policy.ObligationLuaActionDispatch),
			Provider:   builtinLuaActionProvider,
			Parameters: luaParameters,
		},
		{
			ID:         builtinPostActionEffect,
			Kind:       EffectKindObligation,
			Execution:  ExecutionHostPostAction,
			Targets:    builtinTargetsForEffectSelection(targets, policy.ObligationLuaPostActionEnqueue),
			Provider:   builtinPostActionProvider,
			Parameters: luaParameters,
		},
	}
	selections := []string{
		policy.ObligationBruteForceUpdate,
		policy.ObligationLuaActionDispatch,
		policy.ObligationLuaPostActionEnqueue,
	}

	result := make([]EffectDefinition, 0, len(inputs))
	for index, input := range inputs {
		effect, err := newEffectDefinitionWithSelection(input, true, selections[index])
		if err != nil {
			return nil, err
		}

		result = append(result, effect)
	}

	return result, nil
}

// BuiltinAuthEffectSelectionIDs returns the immutable established selections required by one authn action.
func BuiltinAuthEffectSelectionIDs(action string) []string {
	switch action {
	case builtinActionAuthenticate:
		return []string{
			policy.ObligationBruteForceUpdate,
			policy.ObligationLuaActionDispatch,
			policy.ObligationLuaPostActionEnqueue,
		}
	case builtinActionLookupIdentity:
		return []string{policy.ObligationBruteForceUpdate, policy.ObligationLuaActionDispatch}
	default:
		return nil
	}
}

// builtinTargetsForEffectSelection derives exact target allowlists from the shared requirement owner.
func builtinTargetsForEffectSelection(targets []decision.Target, selection string) []decision.Target {
	result := make([]decision.Target, 0, len(targets))

	for _, target := range targets {
		if slices.Contains(BuiltinAuthEffectSelectionIDs(target.Action()), selection) {
			result = append(result, target)
		}
	}

	return result
}

// builtinTargetsForActions selects exact builtin targets while preserving contribution order.
func builtinTargetsForActions(targets []decision.Target, actions ...string) []decision.Target {
	result := make([]decision.Target, 0, len(actions))

	for _, target := range targets {
		for _, action := range actions {
			if target.Action() == action {
				result = append(result, target)

				break
			}
		}
	}

	return result
}

// builtinEffectParameters preserves the established standard-auth obligation arguments.
func builtinEffectParameters() ([]ParameterSchema, []ParameterSchema, error) {
	optionalFeature, err := NewParameterSchema(ParameterSchemaInput{
		Name: policy.ObligationArgFeature, Kind: decision.ValueKindString, MaxLength: 128, NonEmpty: true,
	})
	if err != nil {
		return nil, nil, err
	}

	optionalEnvironment, err := NewParameterSchema(ParameterSchemaInput{Name: policy.ObligationArgEnvironment, Kind: decision.ValueKindString, MaxLength: 128})
	if err != nil {
		return nil, nil, err
	}

	requiredAction, err := NewParameterSchema(ParameterSchemaInput{
		Name: policy.ObligationArgAction, Kind: decision.ValueKindString, MaxLength: 128, Required: true,
		AllowedStrings: policy.LuaActionDispatchActions(),
	})
	if err != nil {
		return nil, nil, err
	}

	requiredFeature, err := NewParameterSchema(ParameterSchemaInput{
		Name: policy.ObligationArgFeature, Kind: decision.ValueKindString, MaxLength: 128, Required: true, NonEmpty: true,
	})
	if err != nil {
		return nil, nil, err
	}

	optionalWait, err := NewParameterSchema(ParameterSchemaInput{Name: policy.ObligationArgWait, Kind: decision.ValueKindBoolean})
	if err != nil {
		return nil, nil, err
	}

	return []ParameterSchema{optionalFeature, optionalEnvironment},
		[]ParameterSchema{requiredAction, requiredFeature, optionalEnvironment, optionalWait},
		nil
}
