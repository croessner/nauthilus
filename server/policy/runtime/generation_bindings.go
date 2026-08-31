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
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

var (
	// ErrInvalidGenerationBinding identifies incomplete prepared runtime bindings.
	ErrInvalidGenerationBinding = errors.New("invalid policy generation binding")

	// ErrProviderContractViolation identifies output that violated host-owned provider authority.
	ErrProviderContractViolation = errors.New("policy provider contract violation")
)

const (
	// AuthnHostProviderKindLuaEnvironment identifies a compiled authn Lua environment source.
	AuthnHostProviderKindLuaEnvironment = "lua_environment"

	// AuthnHostProviderKindLuaSubject identifies a compiled authn Lua subject source.
	AuthnHostProviderKindLuaSubject = "lua_subject"

	// AuthnHostProviderKindNativeEnvironment identifies a captured native authn environment source.
	AuthnHostProviderKindNativeEnvironment = "native_environment"

	// AuthnHostProviderKindNativeSubject identifies a captured native authn subject source.
	AuthnHostProviderKindNativeSubject = "native_subject"
)

// FactProviderInput is the immutable captured input supplied to one fact provider.
type FactProviderInput struct {
	facts      decision.FactSet
	caller     decision.CallerContext
	target     decision.Target
	checkpoint string
}

// NewFactProviderInput constructs one detached captured provider input.
func NewFactProviderInput(
	facts decision.FactSet,
	target decision.Target,
	caller decision.CallerContext,
	checkpoint string,
) (FactProviderInput, error) {
	ownedFacts, err := decision.NewFactSet(facts.Facts())
	if err != nil {
		return FactProviderInput{}, fmt.Errorf("%w: facts: %v", ErrInvalidGenerationBinding, err)
	}

	ownedTarget, err := decision.NewTarget(target.Namespace(), target.Action())
	if err != nil {
		return FactProviderInput{}, fmt.Errorf("%w: target: %v", ErrInvalidGenerationBinding, err)
	}

	if strings.TrimSpace(checkpoint) == "" {
		return FactProviderInput{}, fmt.Errorf("%w: checkpoint is empty", ErrInvalidGenerationBinding)
	}

	ownedCaller, err := cloneBindingCaller(caller)
	if err != nil {
		return FactProviderInput{}, fmt.Errorf("%w: caller: %v", ErrInvalidGenerationBinding, err)
	}

	return FactProviderInput{
		facts: ownedFacts, caller: ownedCaller, target: ownedTarget, checkpoint: checkpoint,
	}, nil
}

// Facts returns the detached facts visible before this provider runs.
func (i FactProviderInput) Facts() decision.FactSet {
	facts, _ := decision.NewFactSet(i.facts.Facts())

	return facts
}

// Caller returns detached redacted caller evidence for this provider call.
func (i FactProviderInput) Caller() decision.CallerContext {
	caller, _ := cloneBindingCaller(i.caller)

	return caller
}

// Target returns the exact captured target.
func (i FactProviderInput) Target() decision.Target {
	return i.target
}

// Checkpoint returns the exact captured checkpoint.
func (i FactProviderInput) Checkpoint() string {
	return i.checkpoint
}

// ProvidedFactInput carries one provider result through its immutable constructor.
type ProvidedFactInput struct {
	Value    decision.Value
	ID       string
	Category decision.FactCategory
}

// ProvidedFact is one prepared provider value before host provenance is attached.
type ProvidedFact struct {
	value    decision.Value
	id       string
	category decision.FactCategory
}

// NewProvidedFact validates one provider result value.
func NewProvidedFact(input ProvidedFactInput) (ProvidedFact, error) {
	if strings.TrimSpace(input.ID) == "" || !input.Category.IsValid() || !input.Value.Kind().IsValid() {
		return ProvidedFact{}, fmt.Errorf("%w: provider fact is incomplete", ErrInvalidGenerationBinding)
	}

	return ProvidedFact{value: input.Value, id: input.ID, category: input.Category}, nil
}

// ID returns the canonical provided fact identity.
func (f ProvidedFact) ID() string {
	return f.id
}

// Value returns the immutable strict provided value.
func (f ProvidedFact) Value() decision.Value {
	return f.value
}

// Category returns the provided fact category.
func (f ProvidedFact) Category() decision.FactCategory {
	return f.category
}

// FactProvider collects facts from one generation-captured provider instance.
type FactProvider interface {
	Collect(context.Context, FactProviderInput) ([]ProvidedFact, error)
}

// AuthnHostProvider is one immutable source that must run in the captured authn host.
type AuthnHostProvider interface {
	ID() string
	Kind() string
}

// FactProviderBinding binds host provenance to one prepared fact provider.
type FactProviderBinding struct {
	Provider  FactProvider
	Source    decision.FactSource
	Authority string
	Component string
}

// EffectExecutionInput carries one selected host effect into its immutable constructor.
type EffectExecutionInput struct {
	Facts      decision.FactSet
	Caller     decision.CallerContext
	Parameters decision.ValueMap
	Target     decision.Target
	EffectID   string
	DecisionID string
	Provider   string
	Generation uint64
	Ordinal    uint32
}

// EffectExecution is one immutable selected host-effect invocation.
type EffectExecution struct {
	facts      decision.FactSet
	caller     decision.CallerContext
	parameters decision.ValueMap
	target     decision.Target
	effectID   string
	decisionID string
	provider   string
	generation uint64
	ordinal    uint32
}

// NewEffectExecution validates and deeply owns one selected effect invocation.
func NewEffectExecution(input EffectExecutionInput) (EffectExecution, error) {
	facts, err := decision.NewFactSet(input.Facts.Facts())
	if err != nil {
		return EffectExecution{}, fmt.Errorf("%w: effect facts: %v", ErrInvalidGenerationBinding, err)
	}

	caller, err := cloneBindingCaller(input.Caller)
	if err != nil {
		return EffectExecution{}, fmt.Errorf("%w: effect caller: %v", ErrInvalidGenerationBinding, err)
	}

	parameters, err := decision.NewValueMap(input.Parameters.Values())
	if err != nil {
		return EffectExecution{}, fmt.Errorf("%w: effect parameters: %v", ErrInvalidGenerationBinding, err)
	}

	target, err := decision.NewTarget(input.Target.Namespace(), input.Target.Action())
	if err != nil {
		return EffectExecution{}, fmt.Errorf("%w: effect target: %v", ErrInvalidGenerationBinding, err)
	}

	if strings.TrimSpace(input.EffectID) == "" || strings.TrimSpace(input.DecisionID) == "" ||
		strings.TrimSpace(input.Provider) == "" || input.Generation == 0 || input.Ordinal == 0 {
		return EffectExecution{}, fmt.Errorf("%w: effect execution is incomplete", ErrInvalidGenerationBinding)
	}

	return EffectExecution{
		facts:      facts,
		caller:     caller,
		parameters: parameters,
		target:     target,
		effectID:   input.EffectID,
		decisionID: input.DecisionID,
		provider:   input.Provider,
		generation: input.Generation,
		ordinal:    input.Ordinal,
	}, nil
}

// Facts returns the detached evaluation facts visible when policy selected the effect.
func (e EffectExecution) Facts() decision.FactSet {
	facts, _ := decision.NewFactSet(e.facts.Facts())

	return facts
}

// Caller returns detached redacted caller evidence for the selected effect.
func (e EffectExecution) Caller() decision.CallerContext {
	caller, _ := cloneBindingCaller(e.caller)

	return caller
}

// Parameters returns a detached strict parameter map.
func (e EffectExecution) Parameters() decision.ValueMap {
	parameters, _ := decision.NewValueMap(e.parameters.Values())

	return parameters
}

// Target returns the exact captured target.
func (e EffectExecution) Target() decision.Target {
	return e.target
}

// EffectID returns the exact selected effect identity.
func (e EffectExecution) EffectID() string {
	return e.effectID
}

// DecisionID returns the internal correlation identity.
func (e EffectExecution) DecisionID() string {
	return e.decisionID
}

// Provider returns the host provider identity.
func (e EffectExecution) Provider() string {
	return e.provider
}

// Generation returns the captured runtime generation identity.
func (e EffectExecution) Generation() uint64 {
	return e.generation
}

// Ordinal returns the stable selected-effect ordinal.
func (e EffectExecution) Ordinal() uint32 {
	return e.ordinal
}

// cloneBindingCaller reconstructs trusted caller evidence without sharing mutable slices.
func cloneBindingCaller(caller decision.CallerContext) (decision.CallerContext, error) {
	return decision.NewCallerContext(decision.TrustedCallerInput{
		Principal:          caller.Principal(),
		ClientID:           caller.ClientID(),
		Subject:            caller.Subject(),
		Issuer:             caller.Issuer(),
		Scopes:             caller.Scopes(),
		AuthenticationKind: caller.AuthenticationKind(),
		SourceIP:           caller.SourceIP(),
		MTLSIdentity:       caller.MTLSIdentity(),
		TransportKind:      caller.TransportKind(),
		Listener:           caller.Listener(),
		HTTPRoute:          caller.HTTPRoute(),
		GRPCMethod:         caller.GRPCMethod(),
		Internal:           caller.Internal(),
	})
}

// SyncEffectProvider executes one generation-captured synchronous host effect.
type SyncEffectProvider interface {
	Execute(context.Context, EffectExecution) effectsupervisor.Result
}

// PostActionProvider prepares immutable work for generation-owned supervision.
type PostActionProvider interface {
	Prepare(context.Context, EffectExecution) (effectsupervisor.Work, error)
}

type generationPostActionProvider struct {
	provider PostActionProvider
	lifetime *generationLifetime
}

type generationFactProvider struct {
	provider FactProvider
	lifetime *generationLifetime
}

type generationFactProviderCall struct {
	provider FactProvider
	lease    *generationLease
}

type generationSyncEffectProvider struct {
	provider SyncEffectProvider
	lifetime *generationLifetime
}

type generationSyncEffectProviderCall struct {
	provider SyncEffectProvider
	lease    *generationLease
}

type generationPostActionProviderCall struct {
	provider PostActionProvider
	lease    *generationLease
}

type generationExecutableWork struct {
	work  effectsupervisor.ExecutableWork
	lease *generationLease
	once  sync.Once
}

// BindingSetInput carries every prepared provider binding into one immutable set.
type BindingSetInput struct {
	FactProviders         map[string]FactProviderBinding
	SyncEffects           map[string]SyncEffectProvider
	PostActions           map[string]PostActionProvider
	AuthnHostProviders    map[string]AuthnHostProvider
	ConditionSets         map[string][]decision.Value
	TimeWindows           map[string]CompiledTimeWindow
	AuthnLuaFacts         []registry.AuthnLuaFactDeclaration
	AuthnPolicyAttributes map[string]registry.AttributeDefinition
	NativeModules         []NativeModuleBindingInput
	PostActionAcceptance  effectsupervisor.Acceptor
}

// BindingSet owns all prepared builtin, Lua, and native evaluation bindings.
type BindingSet struct {
	factProviders         map[string]FactProviderBinding
	syncEffects           map[string]SyncEffectProvider
	postActions           map[string]PostActionProvider
	authnHostProviders    map[string]AuthnHostProvider
	conditionSets         map[string][]decision.Value
	timeWindows           map[string]CompiledTimeWindow
	authnLuaFacts         []registry.AuthnLuaFactDeclaration
	authnPolicyAttributes map[string]registry.AttributeDefinition
	nativeModules         map[string]NativeModuleBinding
	postActionAcceptance  effectsupervisor.Acceptor
}

// NewBindingSet validates and owns one complete prepared binding set.
func NewBindingSet(input BindingSetInput) (*BindingSet, error) {
	if nilInterface(input.PostActionAcceptance) {
		return nil, fmt.Errorf("%w: post-action acceptance is required", ErrInvalidGenerationBinding)
	}

	factProviders, err := cloneFactBindings(input.FactProviders)
	if err != nil {
		return nil, err
	}

	syncEffects, err := cloneProviderMap(input.SyncEffects, "synchronous effect")
	if err != nil {
		return nil, err
	}

	postActions, err := cloneProviderMap(input.PostActions, "post action")
	if err != nil {
		return nil, err
	}

	authnHostProviders, err := cloneAuthnHostProviders(input.AuthnHostProviders)
	if err != nil {
		return nil, err
	}

	nativeModules, err := newNativeModuleBindings(input.NativeModules)
	if err != nil {
		return nil, err
	}

	if err = validateAuthnPolicyAttributes(input.AuthnPolicyAttributes); err != nil {
		return nil, err
	}

	return &BindingSet{
		factProviders:         factProviders,
		syncEffects:           syncEffects,
		postActions:           postActions,
		authnHostProviders:    authnHostProviders,
		conditionSets:         cloneBindingConditionSets(input.ConditionSets),
		timeWindows:           cloneBindingTimeWindows(input.TimeWindows),
		authnLuaFacts:         cloneAuthnLuaFacts(input.AuthnLuaFacts),
		authnPolicyAttributes: cloneAuthnPolicyAttributes(input.AuthnPolicyAttributes),
		nativeModules:         nativeModules,
		postActionAcceptance:  input.PostActionAcceptance,
	}, nil
}

// Clone returns a detached immutable binding index over the same prepared owners.
func (s *BindingSet) Clone() *BindingSet {
	if s == nil {
		return nil
	}

	return &BindingSet{
		factProviders:         cloneMapValues(s.factProviders),
		syncEffects:           cloneMapValues(s.syncEffects),
		postActions:           cloneMapValues(s.postActions),
		authnHostProviders:    cloneMapValues(s.authnHostProviders),
		conditionSets:         cloneBindingConditionSets(s.conditionSets),
		timeWindows:           cloneBindingTimeWindows(s.timeWindows),
		authnLuaFacts:         cloneAuthnLuaFacts(s.authnLuaFacts),
		authnPolicyAttributes: cloneAuthnPolicyAttributes(s.authnPolicyAttributes),
		nativeModules:         cloneNativeModuleBindings(s.nativeModules),
		postActionAcceptance:  s.postActionAcceptance,
	}
}

// withGenerationLifetime binds detached post-action ownership to one candidate lifetime.
func (s *BindingSet) withGenerationLifetime(lifetime *generationLifetime) *BindingSet {
	if s == nil {
		return nil
	}

	result := s.Clone()
	for id, binding := range result.factProviders {
		binding.Provider = &generationFactProvider{provider: binding.Provider, lifetime: lifetime}
		result.factProviders[id] = binding
	}

	for id, provider := range result.syncEffects {
		result.syncEffects[id] = &generationSyncEffectProvider{provider: provider, lifetime: lifetime}
	}

	for id, provider := range result.postActions {
		result.postActions[id] = &generationPostActionProvider{provider: provider, lifetime: lifetime}
	}

	return result
}

// CaptureFactProviderCall retains one generation before asynchronous fact collection starts.
func (p *generationFactProvider) CaptureFactProviderCall() (FactProvider, error) {
	if p == nil || nilInterface(p.provider) || p.lifetime == nil {
		return nil, fmt.Errorf("%w: generation fact-provider owner is incomplete", ErrInvalidGenerationBinding)
	}

	lease := p.lifetime.retain()
	if lease == nil {
		return nil, ErrGenerationUnavailable
	}

	return &generationFactProviderCall{provider: p.provider, lease: lease}, nil
}

// Collect provides safe synchronous fallback ownership for direct provider callers.
func (p *generationFactProvider) Collect(
	ctx context.Context,
	input FactProviderInput,
) ([]ProvidedFact, error) {
	captured, err := p.CaptureFactProviderCall()
	if err != nil {
		return nil, err
	}

	return captured.Collect(ctx, input)
}

// Collect releases one captured provider-call lease after completion or panic unwinding.
func (p *generationFactProviderCall) Collect(
	ctx context.Context,
	input FactProviderInput,
) ([]ProvidedFact, error) {
	defer func() {
		_ = p.lease.release()
	}()

	return p.provider.Collect(ctx, input)
}

// CaptureSyncEffectCall retains one generation before asynchronous effect execution starts.
func (p *generationSyncEffectProvider) CaptureSyncEffectCall() (SyncEffectProvider, error) {
	if p == nil || nilInterface(p.provider) || p.lifetime == nil {
		return nil, fmt.Errorf("%w: generation sync-effect owner is incomplete", ErrInvalidGenerationBinding)
	}

	lease := p.lifetime.retain()
	if lease == nil {
		return nil, ErrGenerationUnavailable
	}

	return &generationSyncEffectProviderCall{provider: p.provider, lease: lease}, nil
}

// Execute provides safe synchronous fallback ownership for direct effect callers.
func (p *generationSyncEffectProvider) Execute(
	ctx context.Context,
	input EffectExecution,
) effectsupervisor.Result {
	captured, err := p.CaptureSyncEffectCall()
	if err != nil {
		return effectsupervisor.Failed("generation_unavailable")
	}

	return captured.Execute(ctx, input)
}

// Execute releases one captured effect-call lease after completion or panic unwinding.
func (p *generationSyncEffectProviderCall) Execute(
	ctx context.Context,
	input EffectExecution,
) effectsupervisor.Result {
	defer func() {
		_ = p.lease.release()
	}()

	return p.provider.Execute(ctx, input)
}

// CapturePostActionCall retains one generation before asynchronous preparation starts.
func (p *generationPostActionProvider) CapturePostActionCall() (PostActionProvider, error) {
	if p == nil || nilInterface(p.provider) || p.lifetime == nil {
		return nil, fmt.Errorf("%w: generation post-action owner is incomplete", ErrInvalidGenerationBinding)
	}

	lease := p.lifetime.retain()
	if lease == nil {
		return nil, ErrGenerationUnavailable
	}

	return &generationPostActionProviderCall{provider: p.provider, lease: lease}, nil
}

// Prepare provides safe synchronous fallback capture for direct post-action callers.
func (p *generationPostActionProvider) Prepare(
	ctx context.Context,
	execution EffectExecution,
) (effectsupervisor.Work, error) {
	captured, err := p.CapturePostActionCall()
	if err != nil {
		return nil, err
	}

	return captured.Prepare(ctx, execution)
}

// Prepare transfers its captured call lease to executable work or releases it on failure.
func (p *generationPostActionProviderCall) Prepare(
	ctx context.Context,
	execution EffectExecution,
) (effectsupervisor.Work, error) {
	transferred := false
	defer func() {
		if !transferred {
			_ = p.lease.release()
		}
	}()

	work, err := p.provider.Prepare(ctx, execution)
	if err != nil {
		if executable, ok := work.(effectsupervisor.ExecutableWork); ok && !nilInterface(executable) {
			cleanupRejectedGenerationWork(executable)
		}

		return nil, err
	}

	executable, ok := work.(effectsupervisor.ExecutableWork)
	if !ok || nilInterface(executable) {
		return nil, fmt.Errorf("%w: post-action work is not executable", ErrInvalidGenerationBinding)
	}

	transferred = true

	return &generationExecutableWork{work: executable, lease: p.lease}, nil
}

// Validate delegates immutable work validation to the captured provider owner.
func (w *generationExecutableWork) Validate() error {
	if w == nil || nilInterface(w.work) {
		return effectsupervisor.ErrInvalidWork
	}

	return w.work.Validate()
}

// Execute delegates detached execution without consulting ambient bindings.
func (w *generationExecutableWork) Execute(ctx context.Context) effectsupervisor.Result {
	if w == nil || nilInterface(w.work) {
		return effectsupervisor.Failed("invalid_generation_work")
	}

	return w.work.Execute(ctx)
}

// Cleanup releases provider work and its retained generation exactly once.
func (w *generationExecutableWork) Cleanup() {
	if w == nil {
		return
	}

	w.once.Do(func() {
		defer func() {
			_ = w.lease.release()
		}()

		w.work.Cleanup()
	})
}

// cleanupRejectedGenerationWork contains cleanup panics when ownership cannot transfer.
func cleanupRejectedGenerationWork(work effectsupervisor.ExecutableWork) {
	defer func() {
		_ = recover()
	}()

	work.Cleanup()
}

// FactProviderIDs returns deterministic prepared fact-provider identities.
func (s *BindingSet) FactProviderIDs() []string {
	if s == nil {
		return nil
	}

	return sortedBindingIDs(s.factProviders)
}

// SyncEffectIDs returns deterministic synchronous effect-provider identities.
func (s *BindingSet) SyncEffectIDs() []string {
	if s == nil {
		return nil
	}

	return sortedBindingIDs(s.syncEffects)
}

// PostActionIDs returns deterministic post-action provider identities.
func (s *BindingSet) PostActionIDs() []string {
	if s == nil {
		return nil
	}

	return sortedBindingIDs(s.postActions)
}

// NativeModuleIDs returns deterministic captured native module identities.
func (s *BindingSet) NativeModuleIDs() []string {
	if s == nil {
		return nil
	}

	return sortedBindingIDs(s.nativeModules)
}

// FactProviders returns a detached binding index over immutable prepared owners.
func (s *BindingSet) FactProviders() map[string]FactProviderBinding {
	if s == nil {
		return nil
	}

	return cloneMapValues(s.factProviders)
}

// SyncEffects returns a detached binding index over immutable prepared owners.
func (s *BindingSet) SyncEffects() map[string]SyncEffectProvider {
	if s == nil {
		return nil
	}

	return cloneMapValues(s.syncEffects)
}

// PostActions returns a detached binding index over immutable prepared owners.
func (s *BindingSet) PostActions() map[string]PostActionProvider {
	if s == nil {
		return nil
	}

	return cloneMapValues(s.postActions)
}

// AuthnHostProvider returns one exact generation-owned host source.
func (s *BindingSet) AuthnHostProvider(id string) (AuthnHostProvider, bool) {
	if s == nil {
		return nil, false
	}

	provider, found := s.authnHostProviders[id]

	return provider, found
}

// AuthnHostProviders returns a detached exact host-source index.
func (s *BindingSet) AuthnHostProviders() map[string]AuthnHostProvider {
	if s == nil {
		return nil
	}

	return cloneMapValues(s.authnHostProviders)
}

// AuthnLuaFacts returns detached registry-script fact declarations.
func (s *BindingSet) AuthnLuaFacts() []registry.AuthnLuaFactDeclaration {
	if s == nil {
		return nil
	}

	return cloneAuthnLuaFacts(s.authnLuaFacts)
}

// AuthnPolicyAttributes returns detached metadata emitted only by scheduled public native auth sources.
func (s *BindingSet) AuthnPolicyAttributes() map[string]registry.AttributeDefinition {
	if s == nil {
		return nil
	}

	return cloneAuthnPolicyAttributes(s.authnPolicyAttributes)
}

// ConditionSets returns detached namespace-scoped strict operand collections.
func (s *BindingSet) ConditionSets() map[string][]decision.Value {
	if s == nil {
		return nil
	}

	return cloneBindingConditionSets(s.conditionSets)
}

// TimeWindows returns detached namespace-scoped recurring schedules.
func (s *BindingSet) TimeWindows() map[string]CompiledTimeWindow {
	if s == nil {
		return nil
	}

	return cloneBindingTimeWindows(s.timeWindows)
}

// NativeModules returns detached native indexes over process-lifetime component owners.
func (s *BindingSet) NativeModules() map[string]NativeModuleBinding {
	if s == nil {
		return nil
	}

	return cloneNativeModuleBindings(s.nativeModules)
}

// PostActionAcceptance returns the captured host ownership-transfer authority.
func (s *BindingSet) PostActionAcceptance() effectsupervisor.Acceptor {
	if s == nil {
		return nil
	}

	return s.postActionAcceptance
}

// ValidateCatalog proves every activated provider and selected host effect has one prepared owner.
func (s *BindingSet) ValidateCatalog(catalog *TargetCatalog) error {
	if s == nil || catalog == nil {
		return fmt.Errorf("%w: bindings and target catalog are required", ErrInvalidGenerationBinding)
	}

	for _, target := range catalog.Targets() {
		if err := s.validateTargetProviders(target); err != nil {
			return err
		}

		if err := s.validateTargetEffects(target); err != nil {
			return err
		}

		if err := s.validateTargetConditionMaterial(target); err != nil {
			return err
		}
	}

	if err := s.validateAuthnHostProviders(catalog); err != nil {
		return err
	}

	return nil
}

// validateTargetConditionMaterial resolves every reachable rule and guard reference in the binding set.
func (s *BindingSet) validateTargetConditionMaterial(target CompiledTarget) error {
	for _, guard := range target.DomainPlan().SchedulerGuards() {
		if err := s.validateConditionExpression(target.Target().Namespace(), guard.Expression()); err != nil {
			return fmt.Errorf(
				"%w: target %s scheduler guard %s: %v",
				ErrInvalidGenerationBinding,
				target.Target().String(),
				guard.Name(),
				err,
			)
		}
	}

	validatedSets := make(map[string]struct{})

	for _, checkpoint := range target.DomainPlan().Checkpoints() {
		for _, setName := range checkpoint.PolicySetIDs() {
			if _, exists := validatedSets[setName]; exists {
				continue
			}

			setID, err := registry.ParsePolicySetID("compiled policy set", setName)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidGenerationBinding, err)
			}

			set, exists := target.LookupPolicySet(setID)
			if !exists {
				return fmt.Errorf("%w: target %s lost policy set %s", ErrInvalidGenerationBinding, target.Target().String(), setName)
			}

			for _, rule := range set.Rules() {
				if err = s.validateConditionExpression(target.Target().Namespace(), rule.Expression()); err != nil {
					return fmt.Errorf(
						"%w: target %s policy rule %s/%s: %v",
						ErrInvalidGenerationBinding,
						target.Target().String(),
						setName,
						rule.Name(),
						err,
					)
				}
			}

			validatedSets[setName] = struct{}{}
		}
	}

	return nil
}

// validateConditionExpression recursively proves referenced condition material is complete and type exact.
func (s *BindingSet) validateConditionExpression(namespace string, expression registry.PolicyExpression) error {
	for _, child := range expression.Children() {
		if err := s.validateConditionExpression(namespace, child); err != nil {
			return err
		}
	}

	reference := expression.Reference()
	if reference == "" {
		return nil
	}

	key := ConditionMaterialKey(namespace, reference)
	if key == "" {
		return fmt.Errorf("condition reference %s has an invalid namespace", reference)
	}

	if strings.HasPrefix(reference, "@time_window.") {
		if _, exists := s.timeWindows[key]; !exists {
			return fmt.Errorf("time-window reference %s is unavailable", reference)
		}

		return nil
	}

	values, exists := s.conditionSets[key]
	if !exists || len(values) == 0 {
		return fmt.Errorf("condition-set reference %s is unavailable", reference)
	}

	for _, value := range values {
		if value.Kind() != expression.FactKind() {
			return fmt.Errorf("condition-set reference %s has value kind %s, want %s", reference, value.Kind(), expression.FactKind())
		}
	}

	return nil
}

// validateTargetProviders resolves every checkpoint-scheduled fact provider.
func (s *BindingSet) validateTargetProviders(target CompiledTarget) error {
	for _, checkpoint := range target.DomainPlan().Checkpoints() {
		for _, providerID := range checkpoint.ProviderIDs() {
			if target.HostPreparesProvider(providerID) {
				descriptor, exists := target.LookupProvider(providerID)
				if !exists {
					return fmt.Errorf(
						"%w: target %s checkpoint %s lost host provider %s",
						ErrInvalidGenerationBinding,
						target.Target().String(),
						checkpoint.Name(),
						providerID,
					)
				}

				if descriptor.IsBuiltin() {
					continue
				}

				if _, exists = s.authnHostProviders[providerID]; !exists {
					return fmt.Errorf(
						"%w: target %s checkpoint %s has no prepared authn host provider %s",
						ErrInvalidGenerationBinding,
						target.Target().String(),
						checkpoint.Name(),
						providerID,
					)
				}

				continue
			}

			if _, exists := s.factProviders[providerID]; !exists {
				return fmt.Errorf(
					"%w: target %s checkpoint %s has no prepared fact provider %s",
					ErrInvalidGenerationBinding,
					target.Target().String(),
					checkpoint.Name(),
					providerID,
				)
			}
		}
	}

	return nil
}

// validateAuthnHostProviders rejects prepared sources absent from every activated exact target.
func (s *BindingSet) validateAuthnHostProviders(catalog *TargetCatalog) error {
	for id := range s.authnHostProviders {
		activated := false

		for _, target := range catalog.Targets() {
			descriptor, exists := target.LookupProvider(id)
			if exists && !descriptor.IsBuiltin() && target.HostPreparesProvider(id) {
				activated = true

				break
			}
		}

		if !activated {
			return fmt.Errorf(
				"%w: prepared authn host provider %s is not activated",
				ErrInvalidGenerationBinding,
				id,
			)
		}
	}

	return nil
}

// validateTargetEffects resolves every host-owned effect through its exact provider class.
func (s *BindingSet) validateTargetEffects(target CompiledTarget) error {
	for _, effectID := range target.EffectIDs() {
		effect, exists := target.LookupEffect(effectID)
		if !exists {
			return fmt.Errorf("%w: target %s lost effect %s", ErrInvalidGenerationBinding, target.Target().String(), effectID)
		}

		switch effect.Execution() {
		case registry.ExecutionReturnOnly:
			continue
		case registry.ExecutionHostSync:
			if _, exists = s.syncEffects[effect.Provider()]; exists {
				continue
			}
		case registry.ExecutionHostPostAction:
			if _, exists = s.postActions[effect.Provider()]; exists {
				continue
			}
		}

		return fmt.Errorf(
			"%w: target %s effect %s has no prepared %s provider %s",
			ErrInvalidGenerationBinding,
			target.Target().String(),
			effectID,
			effect.Execution(),
			effect.Provider(),
		)
	}

	return nil
}

// cloneFactBindings validates immutable fact-provider ownership metadata.
func cloneFactBindings(input map[string]FactProviderBinding) (map[string]FactProviderBinding, error) {
	result := make(map[string]FactProviderBinding, len(input))
	for id, binding := range input {
		if strings.TrimSpace(id) == "" || nilInterface(binding.Provider) || !binding.Source.IsValid() ||
			strings.TrimSpace(binding.Authority) == "" || strings.TrimSpace(binding.Component) == "" {
			return nil, fmt.Errorf("%w: fact provider %q is incomplete", ErrInvalidGenerationBinding, id)
		}

		result[id] = binding
	}

	return result, nil
}

// cloneProviderMap validates and owns one provider identity map.
func cloneProviderMap[T any](input map[string]T, kind string) (map[string]T, error) {
	result := make(map[string]T, len(input))
	for id, provider := range input {
		if strings.TrimSpace(id) == "" || nilInterface(provider) {
			return nil, fmt.Errorf("%w: %s %q is incomplete", ErrInvalidGenerationBinding, kind, id)
		}

		result[id] = provider
	}

	return result, nil
}

// cloneAuthnHostProviders validates the exact provider identity and closed source kind.
func cloneAuthnHostProviders(input map[string]AuthnHostProvider) (map[string]AuthnHostProvider, error) {
	result := make(map[string]AuthnHostProvider, len(input))
	for id, provider := range input {
		if strings.TrimSpace(id) == "" || nilInterface(provider) || provider.ID() != id {
			return nil, fmt.Errorf("%w: authn host provider %q is incomplete", ErrInvalidGenerationBinding, id)
		}

		switch provider.Kind() {
		case AuthnHostProviderKindLuaEnvironment, AuthnHostProviderKindLuaSubject,
			AuthnHostProviderKindNativeEnvironment, AuthnHostProviderKindNativeSubject:
		default:
			return nil, fmt.Errorf("%w: authn host provider %q has an unknown kind", ErrInvalidGenerationBinding, id)
		}

		result[id] = provider
	}

	return result, nil
}

// cloneAuthnLuaFacts deeply detaches registry-script fact declarations.
func cloneAuthnLuaFacts(input []registry.AuthnLuaFactDeclaration) []registry.AuthnLuaFactDeclaration {
	result := make([]registry.AuthnLuaFactDeclaration, len(input))
	for index, declaration := range input {
		result[index] = declaration.Clone()
	}

	return result
}

// cloneAuthnPolicyAttributes deeply owns generated and public native auth policy metadata.
func cloneAuthnPolicyAttributes(
	input map[string]registry.AttributeDefinition,
) map[string]registry.AttributeDefinition {
	result := make(map[string]registry.AttributeDefinition, len(input))
	for id, definition := range input {
		result[id] = registry.CloneDefinition(definition)
	}

	return result
}

// validateAuthnPolicyAttributes rejects map-key drift before schema compilation owns the definitions.
func validateAuthnPolicyAttributes(input map[string]registry.AttributeDefinition) error {
	for id, definition := range input {
		if strings.TrimSpace(id) == "" || definition.ID != id {
			return fmt.Errorf("%w: authn policy attribute %q is incomplete", ErrInvalidGenerationBinding, id)
		}
	}

	return nil
}

// cloneBindingConditionSets deeply owns referenced strict operands.
func cloneBindingConditionSets(input map[string][]decision.Value) map[string][]decision.Value {
	result := make(map[string][]decision.Value, len(input))
	for id, values := range input {
		result[id] = append([]decision.Value(nil), values...)
	}

	return result
}

// cloneBindingTimeWindows deeply owns namespace-scoped recurring schedules.
func cloneBindingTimeWindows(input map[string]CompiledTimeWindow) map[string]CompiledTimeWindow {
	result := make(map[string]CompiledTimeWindow, len(input))
	for id, window := range input {
		result[id] = window.Clone()
	}

	return result
}

// cloneMapValues returns a detached map that retains immutable prepared owners.
func cloneMapValues[T any](input map[string]T) map[string]T {
	result := make(map[string]T, len(input))
	for id, value := range input {
		result[id] = value
	}

	return result
}

// sortedBindingIDs returns stable binding identities for validation and reports.
func sortedBindingIDs[T any](input map[string]T) []string {
	result := make([]string, 0, len(input))
	for id := range input {
		result = append(result, id)
	}

	sort.Strings(result)

	return result
}

// nilInterface rejects both nil and typed-nil prepared dependencies.
func nilInterface(input any) bool {
	if input == nil {
		return true
	}

	value := reflect.ValueOf(input)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
