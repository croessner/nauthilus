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

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

var (
	// ErrInvalidGenerationBinding identifies incomplete prepared runtime bindings.
	ErrInvalidGenerationBinding = errors.New("invalid policy generation binding")
)

// FactProviderInput is the immutable captured input supplied to one fact provider.
type FactProviderInput struct {
	facts      decision.FactSet
	target     decision.Target
	checkpoint string
}

// NewFactProviderInput constructs one detached captured provider input.
func NewFactProviderInput(
	facts decision.FactSet,
	target decision.Target,
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

	return FactProviderInput{facts: ownedFacts, target: ownedTarget, checkpoint: checkpoint}, nil
}

// Facts returns the detached facts visible before this provider runs.
func (i FactProviderInput) Facts() decision.FactSet {
	facts, _ := decision.NewFactSet(i.facts.Facts())

	return facts
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

// FactProviderBinding binds host provenance to one prepared fact provider.
type FactProviderBinding struct {
	Provider  FactProvider
	Source    decision.FactSource
	Authority string
	Component string
}

// EffectExecutionInput carries one selected host effect into its immutable constructor.
type EffectExecutionInput struct {
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
		parameters: parameters,
		target:     target,
		effectID:   input.EffectID,
		decisionID: input.DecisionID,
		provider:   input.Provider,
		generation: input.Generation,
		ordinal:    input.Ordinal,
	}, nil
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

// SyncEffectProvider executes one generation-captured synchronous host effect.
type SyncEffectProvider interface {
	Execute(context.Context, EffectExecution) effectsupervisor.Result
}

// PostActionProvider prepares immutable work for generation-owned supervision.
type PostActionProvider interface {
	Prepare(context.Context, EffectExecution) (effectsupervisor.Work, error)
}

// BindingSetInput carries every prepared provider binding into one immutable set.
type BindingSetInput struct {
	FactProviders        map[string]FactProviderBinding
	SyncEffects          map[string]SyncEffectProvider
	PostActions          map[string]PostActionProvider
	PostActionAcceptance effectsupervisor.Acceptor
}

// BindingSet owns all prepared builtin, Lua, and native evaluation bindings.
type BindingSet struct {
	factProviders        map[string]FactProviderBinding
	syncEffects          map[string]SyncEffectProvider
	postActions          map[string]PostActionProvider
	postActionAcceptance effectsupervisor.Acceptor
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

	return &BindingSet{
		factProviders:        factProviders,
		syncEffects:          syncEffects,
		postActions:          postActions,
		postActionAcceptance: input.PostActionAcceptance,
	}, nil
}

// Clone returns a detached immutable binding index over the same prepared owners.
func (s *BindingSet) Clone() *BindingSet {
	if s == nil {
		return nil
	}

	return &BindingSet{
		factProviders:        cloneMapValues(s.factProviders),
		syncEffects:          cloneMapValues(s.syncEffects),
		postActions:          cloneMapValues(s.postActions),
		postActionAcceptance: s.postActionAcceptance,
	}
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
	}

	return nil
}

// validateTargetProviders resolves every checkpoint-scheduled fact provider.
func (s *BindingSet) validateTargetProviders(target CompiledTarget) error {
	for _, checkpoint := range target.DomainPlan().Checkpoints() {
		for _, providerID := range checkpoint.ProviderIDs() {
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
