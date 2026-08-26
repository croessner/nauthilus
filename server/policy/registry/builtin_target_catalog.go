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
	builtinAuthnMaximumFactText  = 4096
	builtinAuthnMaximumFactItems = 1024
	builtinBruteForceProvider    = policy.AuthnProviderBruteForce
	// AuthnLuaActionProviderID owns exact configured synchronous authn Lua actions.
	AuthnLuaActionProviderID = "authn/lua_action"
	// AuthnPostActionProviderID owns exact configured authn Lua post-actions.
	AuthnPostActionProviderID    = "authn/post_action"
	builtinLuaActionProvider     = AuthnLuaActionProviderID
	builtinPostActionProvider    = AuthnPostActionProviderID
	builtinBruteForceEffect      = policy.EffectBruteForceUpdate
	builtinActionListAccounts    = string(policy.OperationListAccounts)
	builtinActionAuthenticate    = string(policy.OperationAuthenticate)
	builtinActionLookupIdentity  = string(policy.OperationLookupIdentity)
	builtinCheckpointDecision    = string(policy.StageAuthDecision)
	builtinCheckpointPreAuth     = string(policy.StagePreAuth)
	builtinEnvironmentProvider   = policy.AuthnProviderEnvironment
	builtinTLSProvider           = policy.AuthnProviderTLSEncryption
	builtinRelayProvider         = policy.AuthnProviderRelayDomains
	builtinRBLProvider           = policy.AuthnProviderRBL
	builtinAuthBackendProvider   = policy.AuthnProviderBackend
	builtinSubjectProvider       = policy.AuthnProviderSubject
	builtinLDAPBackendProvider   = policy.AuthnProviderLDAPBackend
	builtinLuaBackendProvider    = policy.AuthnProviderLuaBackend
	builtinPluginBackendProvider = policy.AuthnProviderPluginBackendOrder
	builtinAccountProvider       = policy.AuthnProviderAccount
)

// BuiltinAuthEffectBinding describes one immutable standard-auth execution owner.
type BuiltinAuthEffectBinding struct {
	EffectID  string
	Provider  string
	Execution ExecutionClass
}

var builtinAuthEffectBindings = []BuiltinAuthEffectBinding{
	{
		EffectID:  builtinBruteForceEffect,
		Provider:  builtinBruteForceProvider,
		Execution: ExecutionHostSync,
	},
}

var builtinAuthProviderIDs = map[string]struct{}{
	builtinBruteForceProvider:    {},
	builtinLuaActionProvider:     {},
	builtinPostActionProvider:    {},
	builtinEnvironmentProvider:   {},
	builtinTLSProvider:           {},
	builtinRelayProvider:         {},
	builtinRBLProvider:           {},
	builtinAuthBackendProvider:   {},
	builtinSubjectProvider:       {},
	builtinLDAPBackendProvider:   {},
	builtinLuaBackendProvider:    {},
	builtinPluginBackendProvider: {},
	builtinAccountProvider:       {},
}

// IsBuiltinAuthProviderID reports whether an identity is reserved by the immutable authn host catalog.
func IsBuiltinAuthProviderID(identity string) bool {
	_, exists := builtinAuthProviderIDs[identity]

	return exists
}

// BuiltinAuthEffectBindings returns detached immutable standard-auth owner mappings.
func BuiltinAuthEffectBindings() []BuiltinAuthEffectBinding {
	return append([]BuiltinAuthEffectBinding(nil), builtinAuthEffectBindings...)
}

// BuiltinAuthEffectBindingForEffect resolves a canonical effect to its standard-auth execution owner.
func BuiltinAuthEffectBindingForEffect(effectID string) (BuiltinAuthEffectBinding, bool) {
	for _, binding := range builtinAuthEffectBindings {
		if binding.EffectID == effectID {
			return binding, true
		}
	}

	return BuiltinAuthEffectBinding{}, false
}

type builtinTargetContributor struct {
	postActionAcceptance effectsupervisor.Acceptor
	policyAttributes     map[string]AttributeDefinition
}

// NewBuiltinTargetContributor returns the internal authn definition contributor.
func NewBuiltinTargetContributor(postActionAcceptance ...effectsupervisor.Acceptor) Contributor {
	var capability effectsupervisor.Acceptor
	if len(postActionAcceptance) > 0 {
		capability = postActionAcceptance[0]
	}

	return builtinTargetContributor{postActionAcceptance: capability}
}

// NewBuiltinTargetContributorWithAuthnPolicy binds captured auth attribute definitions to the candidate catalog.
func NewBuiltinTargetContributorWithAuthnPolicy(
	attributes map[string]AttributeDefinition,
	postActionAcceptance ...effectsupervisor.Acceptor,
) Contributor {
	contributor := NewBuiltinTargetContributor(postActionAcceptance...).(builtinTargetContributor)
	contributor.policyAttributes = cloneAuthnPolicyAttributes(attributes)

	return contributor
}

// cloneAuthnPolicyAttributes deeply owns the captured legacy attribute vocabulary.
func cloneAuthnPolicyAttributes(attributes map[string]AttributeDefinition) map[string]AttributeDefinition {
	result := make(map[string]AttributeDefinition, len(attributes))
	for id, definition := range attributes {
		result[id] = CloneDefinition(definition)
	}

	return result
}

// Contribute returns inactive authn target and exact schema definitions.
func (c builtinTargetContributor) Contribute(ctx context.Context) (DefinitionContribution, error) {
	if err := ctx.Err(); err != nil {
		return DefinitionContribution{}, err
	}

	ownership, err := NewNamespaceOwnership(builtinTargetContributorID, []string{policy.AuthnNamespace})
	if err != nil {
		return DefinitionContribution{}, err
	}

	targets, schemas, targetValues, plans, err := buildBuiltinAuthnDefinitions(c.policyAttributes)
	if err != nil {
		return DefinitionContribution{}, err
	}

	standardAuth, err := newBuiltinStandardAuthPolicySet(c.policyAttributes)
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

// builtinAuthnFactSchemas constructs the exact candidate fact contract for one operation.
func builtinAuthnFactSchemas(
	action string,
	policyAttributes map[string]AttributeDefinition,
) ([]FactSchema, error) {
	inputs := builtinAuthnCommonFactSchemaInputs()
	inputs = append(inputs, builtinStandardAuthFactSchemaInputs(action)...)

	dynamic, err := builtinAuthnPolicyFactSchemaInputs(action, policyAttributes)
	if err != nil {
		return nil, err
	}

	inputs = append(inputs, dynamic...)

	switch action {
	case builtinActionAuthenticate:
		inputs = append(inputs, builtinAuthnBackendFactSchemaInputs(policy.AuthnFactAuthenticated)...)
	case builtinActionLookupIdentity:
		inputs = append(inputs, builtinAuthnBackendFactSchemaInputs(policy.AuthnFactIdentityFound)...)
	case builtinActionListAccounts:
		inputs = append(inputs,
			builtinAuthnFactSchemaInput(
				policy.AuthnFactAccountCount,
				decision.FactCategorySubject,
				decision.ValueKindInteger,
				decision.FactSourceBackend,
			),
			builtinAuthnFactSchemaInput(
				policy.AuthnFactAccountProviderCompleted,
				decision.FactCategorySubject,
				decision.ValueKindBoolean,
				decision.FactSourceBackend,
			),
		)
	default:
		return nil, fmt.Errorf("unsupported builtin authn action %q", action)
	}

	facts := make([]FactSchema, 0, len(inputs))
	for _, input := range inputs {
		fact, err := NewFactSchema(input)
		if err != nil {
			return nil, err
		}

		facts = append(facts, fact)
	}

	return facts, nil
}

// builtinAuthnCommonFactSchemaInputs declares shared request, host, and transport facts.
func builtinAuthnCommonFactSchemaInputs() []FactSchemaInput {
	return []FactSchemaInput{
		builtinAuthnFactSchemaInput(policy.AuthnFactOperation, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceNauthilus),
		builtinAuthnFactSchemaInput(policy.AuthnFactService, decision.FactCategoryResource, decision.ValueKindString, decision.FactSourceNauthilus),
		builtinAuthnFactSchemaInput(policy.AuthnFactCurrentDecision, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceNauthilus),
		builtinAuthnFactSchemaInput(policy.AuthnFactUsername, decision.FactCategorySubject, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactProtocol, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactMethod, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactUserAgent, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactClientIP, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactClientPort, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactClientHostname, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactClientID, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactLocalIP, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactLocalPort, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactIDPClientID, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactSAMLServiceProviderID, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(policy.AuthnFactLoginAttempt, decision.FactCategoryEnvironment, decision.ValueKindInteger, decision.FactSourceCaller),
		builtinAuthnFactSchemaInput(decision.FactCallerPrincipal, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceNauthilus),
		builtinAuthnFactSchemaInput(decision.FactCallerClientID, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceNauthilus),
		builtinAuthnFactSchemaInput(decision.FactCallerAuthenticationKind, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceNauthilus),
		builtinAuthnFactSchemaInput(decision.FactCallerScopes, decision.FactCategoryEnvironment, decision.ValueKindStrings, decision.FactSourceNauthilus),
		builtinAuthnFactSchemaInput(decision.FactTokenSubject, decision.FactCategorySubject, decision.ValueKindString, decision.FactSourceToken),
		builtinAuthnFactSchemaInput(decision.FactTokenIssuer, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceToken),
		builtinAuthnFactSchemaInput(decision.FactTransportKind, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport),
		builtinAuthnFactSchemaInput(decision.FactTransportListener, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport),
		builtinAuthnFactSchemaInput(decision.FactTransportHTTPRoute, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport),
		builtinAuthnFactSchemaInput(decision.FactTransportGRPCMethod, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport),
		builtinAuthnFactSchemaInput(decision.FactTransportSourceIP, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport),
		builtinAuthnFactSchemaInput(decision.FactTransportMTLSIdentity, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport),
	}
}

// builtinAuthnBackendFactSchemaInputs declares shared backend state plus one operation result.
func builtinAuthnBackendFactSchemaInputs(resultID string) []FactSchemaInput {
	return []FactSchemaInput{
		builtinAuthnFactSchemaInput(policy.AuthnFactBackend, decision.FactCategorySubject, decision.ValueKindString, decision.FactSourceBackend),
		builtinAuthnFactSchemaInput(resultID, decision.FactCategorySubject, decision.ValueKindBoolean, decision.FactSourceBackend),
		builtinAuthnFactSchemaInput(policy.AuthnFactAccountField, decision.FactCategorySubject, decision.ValueKindString, decision.FactSourceBackend),
		builtinAuthnFactSchemaInput(policy.AuthnFactGroups, decision.FactCategorySubject, decision.ValueKindStrings, decision.FactSourceBackend),
		builtinAuthnFactSchemaInput(policy.AuthnFactGroupDistinguishedNames, decision.FactCategorySubject, decision.ValueKindStrings, decision.FactSourceBackend),
	}
}

// builtinAuthnFactSchemaInput applies one bounded shape for every strict value kind.
func builtinAuthnFactSchemaInput(
	id string,
	category decision.FactCategory,
	kind decision.ValueKind,
	source decision.FactSource,
) FactSchemaInput {
	input := FactSchemaInput{
		ID:             id,
		AllowedSources: []decision.FactSource{source},
		Category:       category,
		Kind:           kind,
	}

	switch kind {
	case decision.ValueKindString:
		input.MaxLength = builtinAuthnMaximumFactText
	case decision.ValueKindStrings:
		input.MaxLength = builtinAuthnMaximumFactText
		input.MaxItems = builtinAuthnMaximumFactItems
	}

	return input
}

// buildBuiltinAuthnDefinitions constructs target, schema, and checkpoint topology together.
func buildBuiltinAuthnDefinitions(policyAttributes map[string]AttributeDefinition) (
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
		target, schema, targetDefinition, plan, err := buildBuiltinAuthnTarget(action, policyAttributes)
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
	policyAttributes map[string]AttributeDefinition,
) (decision.Target, SchemaDefinition, TargetDefinition, DomainPlanDefinition, error) {
	schemaIdentity, err := NewSchemaIdentity("authn", action, "v1")
	if err != nil {
		return decision.Target{}, SchemaDefinition{}, TargetDefinition{}, DomainPlanDefinition{}, err
	}

	facts, err := builtinAuthnFactSchemas(action, policyAttributes)
	if err != nil {
		return decision.Target{}, SchemaDefinition{}, TargetDefinition{}, DomainPlanDefinition{}, err
	}

	schema, err := NewSchemaDefinition(schemaIdentity, facts)
	if err != nil {
		return decision.Target{}, SchemaDefinition{}, TargetDefinition{}, DomainPlanDefinition{}, err
	}

	schema.builtinAuth = true

	target, err := decision.NewTarget(policy.AuthnNamespace, action)
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

	return NewAuthnDomainPlanDefinition(target, checkpoints)
}

// builtinCheckpointProviders preserves the established auth work order before each checkpoint.
func builtinCheckpointProviders(target decision.Target, checkpoint string) []string {
	return policy.AuthnBuiltinCheckpointProviderIDs(
		policy.Operation(target.Action()),
		policy.Stage(checkpoint),
	)
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
			Targets:              authAndLookup,
			Executions:           []ExecutionClass{ExecutionHostPostAction},
		},
		{ID: builtinEnvironmentProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinTLSProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinRelayProvider, Targets: authenticate, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinRBLProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinAuthBackendProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinSubjectProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinLDAPBackendProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinLuaBackendProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
		{ID: builtinPluginBackendProvider, Targets: authAndLookup, Executions: []ExecutionClass{ExecutionHostSync}},
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
	bruteForceParameters, err := builtinEffectParameters()
	if err != nil {
		return nil, err
	}

	inputs := make([]EffectDefinitionInput, 0, len(builtinAuthEffectBindings))
	for _, binding := range builtinAuthEffectBindings {
		inputs = append(inputs, EffectDefinitionInput{
			ID:         binding.EffectID,
			Kind:       EffectKindObligation,
			Execution:  binding.Execution,
			Targets:    builtinTargetsForEffectID(targets, binding.EffectID),
			Provider:   binding.Provider,
			Parameters: bruteForceParameters,
		})
	}

	result := make([]EffectDefinition, 0, len(inputs))
	for _, input := range inputs {
		effect, err := newEffectDefinition(input, true)
		if err != nil {
			return nil, err
		}

		result = append(result, effect)
	}

	return result, nil
}

// BuiltinAuthEffectIDs returns the canonical effects required by one authn action.
func BuiltinAuthEffectIDs(action string) []string {
	switch action {
	case builtinActionAuthenticate, builtinActionLookupIdentity:
		return []string{builtinBruteForceEffect}
	default:
		return nil
	}
}

// builtinTargetsForEffectID derives exact target allowlists from the shared canonical requirement owner.
func builtinTargetsForEffectID(targets []decision.Target, effectID string) []decision.Target {
	result := make([]decision.Target, 0, len(targets))

	for _, target := range targets {
		if slices.Contains(BuiltinAuthEffectIDs(target.Action()), effectID) {
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
func builtinEffectParameters() ([]ParameterSchema, error) {
	optionalFeature, err := NewParameterSchema(ParameterSchemaInput{
		Name: policy.ObligationArgFeature, Kind: decision.ValueKindString, MaxLength: 128, NonEmpty: true,
	})
	if err != nil {
		return nil, err
	}

	optionalEnvironment, err := NewParameterSchema(ParameterSchemaInput{Name: policy.ObligationArgEnvironment, Kind: decision.ValueKindString, MaxLength: 128})
	if err != nil {
		return nil, err
	}

	return []ParameterSchema{optionalFeature, optionalEnvironment}, nil
}
