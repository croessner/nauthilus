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

// Package compiler defines the internal policy snapshot compiler boundary.
package compiler

import (
	"context"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

// Input carries already-decoded policy material into the compiler boundary.
type Input struct {
	Config     config.File
	Generation uint64
}

// Compiler builds immutable policy runtime snapshots.
type Compiler interface {
	Compile(context.Context, Input) (*policyruntime.Snapshot, error)
}

// NoopCompiler builds an empty snapshot for wiring and tests.
type NoopCompiler struct{}

// Compile returns an empty snapshot with the requested generation.
func (NoopCompiler) Compile(_ context.Context, input Input) (*policyruntime.Snapshot, error) {
	return &policyruntime.Snapshot{Generation: input.Generation}, nil
}

// SnapshotCompiler builds typed policy snapshots from decoded configuration.
type SnapshotCompiler struct {
	now func() time.Time
}

type compiledSnapshotParts struct {
	policyConfig config.AuthPolicySection
	sets         policyruntime.CompiledSets
	stagePlans   map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan
	guards       map[string]policyruntime.CompiledSchedulerGuard
	attributes   map[string]policyregistry.AttributeDefinition
	checkTypes   map[string]policyruntime.CheckTypeDefinition
	responses    map[string]policyruntime.ResponseDefinition
	obligations  map[string]policyruntime.EffectDefinition
	advice       map[string]policyruntime.EffectDefinition
	fsmEvents    map[string]policyruntime.FSMEventDefinition
	requestAttrs policyruntime.RequestAttributeSettings
}

// NewCompiler returns the default policy snapshot compiler.
func NewCompiler() *SnapshotCompiler {
	return &SnapshotCompiler{
		now: time.Now,
	}
}

// Compile builds a complete immutable policy snapshot.
func (c *SnapshotCompiler) Compile(ctx context.Context, input Input) (*policyruntime.Snapshot, error) {
	if c == nil {
		c = NewCompiler()
	}

	policyConfig := effectivePolicyConfig(input.Config)
	if err := validateHeader(policyConfig); err != nil {
		return nil, err
	}

	parts, err := buildSnapshotParts(ctx, input.Config, policyConfig)
	if err != nil {
		return nil, err
	}

	return c.newSnapshot(input.Generation, parts), nil
}

func buildSnapshotParts(ctx context.Context, file config.File, policyConfig config.AuthPolicySection) (compiledSnapshotParts, error) {
	sets, err := compileSets(policyConfig.Sets)
	if err != nil {
		return compiledSnapshotParts{}, err
	}

	checkTypes := builtinCheckTypeRegistry()
	attributes, checks, requestAttrs, err := compileAttributeRegistry(ctx, file, policyConfig, checkTypes)
	if err != nil {
		return compiledSnapshotParts{}, err
	}

	guards, err := compileSchedulerGuards(policyConfig.SchedulerGuards, attributes, sets)
	if err != nil {
		return compiledSnapshotParts{}, err
	}

	if err := validateCheckSchedulerGuards(checks, guards); err != nil {
		return compiledSnapshotParts{}, err
	}

	fsmEvents := builtinFSMEventRegistry()
	responses := builtinResponseRegistry()
	obligations := builtinObligationRegistry()
	if err := registerNativePluginEffects(obligations); err != nil {
		return compiledSnapshotParts{}, err
	}

	advice := builtinAdviceRegistry()

	policies, err := compilePolicies(compilePolicyInput{
		configs:     policyConfig.Policies,
		checks:      checks,
		attributes:  attributes,
		sets:        sets,
		fsmEvents:   fsmEvents,
		responses:   responses,
		obligations: obligations,
		advice:      advice,
	})
	if err != nil {
		return compiledSnapshotParts{}, err
	}

	stagePlans, err := buildStagePlans(checks, policies)
	if err != nil {
		return compiledSnapshotParts{}, err
	}

	return compiledSnapshotParts{
		policyConfig: policyConfig,
		sets:         sets,
		stagePlans:   stagePlans,
		guards:       guards,
		attributes:   attributes,
		checkTypes:   checkTypes,
		responses:    responses,
		obligations:  obligations,
		advice:       advice,
		fsmEvents:    fsmEvents,
		requestAttrs: requestAttrs,
	}, nil
}

// registerNativePluginEffects exposes registered native effect targets to policy compilation.
func registerNativePluginEffects(obligations map[string]policyruntime.EffectDefinition) error {
	state, ok := pluginloader.DefaultState()
	if !ok {
		return nil
	}

	for _, component := range state.Registry().ObligationTargets() {
		if err := registerNativePluginEffect(obligations, component.QualifiedName, effectKindObligation); err != nil {
			return err
		}
	}

	for _, component := range state.Registry().PostActionTargets() {
		if err := registerNativePluginEffect(obligations, component.QualifiedName, effectKindPostAction); err != nil {
			return err
		}
	}

	return nil
}

// registerNativePluginEffect adds one plugin effect id while preserving registry safety.
func registerNativePluginEffect(obligations map[string]policyruntime.EffectDefinition, id string, kind string) error {
	if id == "" {
		return nil
	}

	if _, exists := obligations[id]; exists {
		return fmt.Errorf("duplicate policy effect id %q", id)
	}

	obligations[id] = policyruntime.EffectDefinition{ID: id, Kind: kind}

	return nil
}

func compileAttributeRegistry(
	ctx context.Context,
	file config.File,
	policyConfig config.AuthPolicySection,
	checkTypes map[string]policyruntime.CheckTypeDefinition,
) (map[string]policyregistry.AttributeDefinition, []policyruntime.CompiledCheck, policyruntime.RequestAttributeSettings, error) {
	attributeRegistry, err := policyregistry.NewBuiltinAttributeRegistry()
	if err != nil {
		return nil, nil, policyruntime.RequestAttributeSettings{}, err
	}

	checks, err := compileChecks(policyConfig.Checks, checkTypes, attributeRegistry)
	if err != nil {
		return nil, nil, policyruntime.RequestAttributeSettings{}, err
	}

	if err := registerGeneratedBruteForceBucketAttributes(file, attributeRegistry); err != nil {
		return nil, nil, policyruntime.RequestAttributeSettings{}, err
	}

	if err := registerGeneratedRBLListAttributes(file, attributeRegistry); err != nil {
		return nil, nil, policyruntime.RequestAttributeSettings{}, err
	}

	if err := registerGeneratedSubjectAttributes(policyConfig.AttributeExports, attributeRegistry); err != nil {
		return nil, nil, policyruntime.RequestAttributeSettings{}, err
	}

	if err := runLuaRegistryScripts(ctx, policyConfig.RegistryScripts, attributeRegistry); err != nil {
		return nil, nil, policyruntime.RequestAttributeSettings{}, err
	}

	if err := registerNativePluginAttributes(attributeRegistry); err != nil {
		return nil, nil, policyruntime.RequestAttributeSettings{}, err
	}

	requestAttrs, err := registerRequestAttributes(policyConfig, attributeRegistry)
	if err != nil {
		return nil, nil, policyruntime.RequestAttributeSettings{}, err
	}

	return attributeRegistry.Snapshot(), checks, requestAttrs, nil
}

// registerNativePluginAttributes copies loader-registered native plugin attributes into the policy registry.
func registerNativePluginAttributes(attributeRegistry *policyregistry.AttributeRegistry) error {
	if attributeRegistry == nil {
		return nil
	}

	state, ok := pluginloader.DefaultState()
	if !ok {
		return nil
	}

	for _, definition := range state.Registry().PolicyAttributes() {
		if err := attributeRegistry.Register(definition); err != nil {
			return err
		}
	}

	return nil
}

func (c *SnapshotCompiler) newSnapshot(generation uint64, parts compiledSnapshotParts) *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		CreatedAt:          c.now(),
		Generation:         generation,
		Mode:               parts.policyConfig.Mode,
		DefaultPolicy:      parts.policyConfig.DefaultPolicy,
		Report:             compileReportSettings(parts.policyConfig.Report),
		AttributeRegistry:  parts.attributes,
		CheckTypeRegistry:  parts.checkTypes,
		ResponseRegistry:   parts.responses,
		ObligationRegistry: parts.obligations,
		AdviceRegistry:     parts.advice,
		FSMEventRegistry:   parts.fsmEvents,
		StagePlans:         parts.stagePlans,
		SchedulerGuards:    parts.guards,
		Sets:               parts.sets,
		RequestAttributes:  parts.requestAttrs,
	}
}

// CompileAndActivate builds a candidate snapshot and publishes it only after success.
func CompileAndActivate(
	ctx context.Context,
	store *policyruntime.SnapshotStore,
	compiler Compiler,
	input Input,
) error {
	if store == nil {
		return fmt.Errorf("policy snapshot store is nil")
	}

	if compiler == nil {
		compiler = NewCompiler()
	}

	snapshot, err := compiler.Compile(ctx, input)
	if err != nil {
		return err
	}

	return store.Activate(snapshot)
}

type policyConfigProvider interface {
	GetAuthPolicy() config.AuthPolicySection
}

func effectivePolicyConfig(file config.File) config.AuthPolicySection {
	if provider, ok := file.(policyConfigProvider); ok {
		return provider.GetAuthPolicy()
	}

	return config.AuthPolicySection{
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		Report: config.PolicyReportConfig{
			IncludeFSM:    true,
			IncludeChecks: true,
		},
	}
}

func validateHeader(policyConfig config.AuthPolicySection) error {
	switch policyConfig.Mode {
	case "enforce", "observe":
	default:
		return configPathError("auth.policy.mode", "must be one of enforce or observe")
	}

	if policyConfig.DefaultPolicy == "" {
		return configPathError("auth.policy.default_policy", "must not be empty")
	}

	if policyConfig.DefaultPolicy != policy.BuiltinDefaultSet {
		return configPathError("auth.policy.default_policy", "references unknown built-in policy set")
	}

	return nil
}

func compileReportSettings(report config.PolicyReportConfig) policyruntime.ReportSettings {
	if !report.IncludeFSM {
		report.IncludeFSM = true
	}

	if !report.IncludeChecks {
		report.IncludeChecks = true
	}

	return policyruntime.ReportSettings{
		Enabled:           report.Enabled,
		IncludeFSM:        report.IncludeFSM,
		IncludeChecks:     report.IncludeChecks,
		IncludeAttributes: report.IncludeAttributes,
	}
}
