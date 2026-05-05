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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
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
	attributes   map[string]policyregistry.AttributeDefinition
	checkTypes   map[string]policyruntime.CheckTypeDefinition
	responses    map[string]policyruntime.ResponseDefinition
	obligations  map[string]policyruntime.EffectDefinition
	advice       map[string]policyruntime.EffectDefinition
	fsmEvents    map[string]policyruntime.FSMEventDefinition
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

	parts, err := buildSnapshotParts(ctx, policyConfig)
	if err != nil {
		return nil, err
	}

	return c.newSnapshot(input.Generation, parts), nil
}

func buildSnapshotParts(ctx context.Context, policyConfig config.AuthPolicySection) (compiledSnapshotParts, error) {
	attributeRegistry, err := policyregistry.NewBuiltinAttributeRegistry()
	if err != nil {
		return compiledSnapshotParts{}, err
	}

	sets, err := compileSets(policyConfig.Sets)
	if err != nil {
		return compiledSnapshotParts{}, err
	}

	checkTypes := builtinCheckTypeRegistry()
	checks, err := compileChecks(policyConfig.Checks, checkTypes, attributeRegistry)
	if err != nil {
		return compiledSnapshotParts{}, err
	}

	if err := runLuaRegistryScripts(ctx, policyConfig.RegistryScripts, attributeRegistry); err != nil {
		return compiledSnapshotParts{}, err
	}

	attributes := attributeRegistry.Snapshot()
	fsmEvents := builtinFSMEventRegistry()
	responses := builtinResponseRegistry()
	obligations := builtinObligationRegistry()
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
		attributes:   attributes,
		checkTypes:   checkTypes,
		responses:    responses,
		obligations:  obligations,
		advice:       advice,
		fsmEvents:    fsmEvents,
	}, nil
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
		Sets:               parts.sets,
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
