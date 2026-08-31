// Copyright (C) 2026 Christian Roessner
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

// Package nativebinding defines the inward-facing candidate preparation seam for native providers.
package nativebinding

import (
	"context"
	"errors"
	"time"

	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

var (
	// ErrInvalidDecisionBinding identifies a configured selection outside frozen native capabilities.
	ErrInvalidDecisionBinding = errors.New("invalid native decision binding")
)

// CallRecord describes one host-invoked native method call without exposing plugin-owned values.
type CallRecord struct {
	Err            error
	Duration       time.Duration
	ModuleName     string
	ComponentName  string
	ExtensionPoint string
	Method         string
	Panicked       bool
}

// Observer receives automatic native method call observations.
type Observer interface {
	ObservePluginCall(CallRecord)
}

// DecisionFactBindingInput selects one exact configured fact component from captured native modules.
type DecisionFactBindingInput struct {
	Definition    policyregistry.ProviderDefinition
	ModuleName    string
	ComponentName string
}

// DecisionEffectBindingInput selects exact configured effects from one captured native component.
type DecisionEffectBindingInput struct {
	Definition    policyregistry.ProviderDefinition
	Effects       []policyregistry.EffectDefinition
	ModuleName    string
	ComponentName string
}

// DecisionBindingInput carries exact operator-activated native selections into candidate preparation.
type DecisionBindingInput struct {
	Observer        Observer
	FactProviders   []DecisionFactBindingInput
	EffectProviders []DecisionEffectBindingInput
}

// DecisionBindings contains immutable runtime adapters for one candidate generation.
type DecisionBindings struct {
	factProviders map[string]policyruntime.FactProviderBinding
	syncEffects   map[string]policyruntime.SyncEffectProvider
	postActions   map[string]policyruntime.PostActionProvider
}

// NewDecisionBindings owns detached maps over generation-bound provider adapters.
func NewDecisionBindings(
	factProviders map[string]policyruntime.FactProviderBinding,
	syncEffects map[string]policyruntime.SyncEffectProvider,
	postActions map[string]policyruntime.PostActionProvider,
) DecisionBindings {
	return DecisionBindings{
		factProviders: cloneBindingMap(factProviders),
		syncEffects:   cloneBindingMap(syncEffects),
		postActions:   cloneBindingMap(postActions),
	}
}

// FactProviders returns a detached map over immutable generation provider owners.
func (b DecisionBindings) FactProviders() map[string]policyruntime.FactProviderBinding {
	return cloneBindingMap(b.factProviders)
}

// SyncEffects returns a detached map over selected synchronous effect owners.
func (b DecisionBindings) SyncEffects() map[string]policyruntime.SyncEffectProvider {
	return cloneBindingMap(b.syncEffects)
}

// PostActions returns a detached map over selected post-action preparation owners.
func (b DecisionBindings) PostActions() map[string]policyruntime.PostActionProvider {
	return cloneBindingMap(b.postActions)
}

// DecisionBindingPreparer validates captured artifacts and resolves exact configured selections.
type DecisionBindingPreparer interface {
	ValidateArtifacts() error
	PrepareDecisionBindings(context.Context, DecisionBindingInput) (DecisionBindings, error)
}

// cloneBindingMap detaches caller-owned binding maps without changing immutable adapter owners.
func cloneBindingMap[T any](input map[string]T) map[string]T {
	result := make(map[string]T, len(input))
	for key, value := range input {
		result[key] = value
	}

	return result
}
