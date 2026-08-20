// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package compiler_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

type policyReportFieldState uint8

const (
	policyReportFieldOmitted policyReportFieldState = iota
	policyReportFieldFalse
	policyReportFieldTrue
)

type policyReportMigrationCase struct {
	name              string
	includeFSM        policyReportFieldState
	includeChecks     policyReportFieldState
	reportEnabled     bool
	includeAttributes bool
}

type policyReportCompiledMeaning struct {
	Enabled           bool
	IncludeFSM        bool
	IncludeChecks     bool
	IncludeAttributes bool
}

type policyReportMigrationAcceptance struct{}

// Accept supplies the capability required to compile immutable builtin effects.
func (policyReportMigrationAcceptance) Accept(
	context.Context,
	effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

func TestPolicyMigrationCompiledPlanReportParity(t *testing.T) {
	cases := []policyReportMigrationCase{
		{name: "disabled_omitted", includeFSM: policyReportFieldOmitted, includeChecks: policyReportFieldOmitted},
		{name: "enabled_omitted", includeFSM: policyReportFieldOmitted, includeChecks: policyReportFieldOmitted, reportEnabled: true},
		{name: "disabled_false", includeFSM: policyReportFieldFalse, includeChecks: policyReportFieldFalse},
		{name: "enabled_false", includeFSM: policyReportFieldFalse, includeChecks: policyReportFieldFalse, reportEnabled: true},
		{name: "disabled_true", includeFSM: policyReportFieldTrue, includeChecks: policyReportFieldTrue},
		{name: "enabled_true", includeFSM: policyReportFieldTrue, includeChecks: policyReportFieldTrue, reportEnabled: true},
		{
			name: "enabled_false_true_with_attributes", includeFSM: policyReportFieldFalse,
			includeChecks: policyReportFieldTrue, reportEnabled: true, includeAttributes: true,
		},
		{
			name: "enabled_true_false_with_attributes", includeFSM: policyReportFieldTrue,
			includeChecks: policyReportFieldFalse, reportEnabled: true, includeAttributes: true,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			legacy := compileLegacyPolicyReport(t, test)
			unified := compileUnifiedPolicyReport(t, test)
			want := policyReportCompiledMeaning{
				Enabled:           test.reportEnabled,
				IncludeFSM:        true,
				IncludeChecks:     true,
				IncludeAttributes: test.includeAttributes,
			}

			if !reflect.DeepEqual(legacy, want) {
				t.Fatalf("legacy compiled report = %#v, want %#v", legacy, want)
			}

			if !reflect.DeepEqual(unified, legacy) {
				t.Fatalf("standalone compiled report = %#v, want legacy %#v", unified, legacy)
			}
		})
	}
}

// compileLegacyPolicyReport obtains report meaning from the actual pre-cutover snapshot compiler.
func compileLegacyPolicyReport(t *testing.T, test policyReportMigrationCase) policyReportCompiledMeaning {
	t.Helper()

	report := config.PolicyReportConfig{
		Enabled:           test.reportEnabled,
		IncludeAttributes: test.includeAttributes,
	}
	test.includeFSM.apply(&report.IncludeFSM)
	test.includeChecks.apply(&report.IncludeChecks)

	configured := &config.FileSettings{Auth: &config.AuthSection{Policy: config.AuthPolicySection{Report: report}}}

	snapshot, err := compiler.NewCompiler().Compile(
		context.Background(),
		compiler.Input{Config: configured, Generation: 1},
	)
	if err != nil {
		t.Fatalf("compile legacy policy report: %v", err)
	}

	return compiledSnapshotReportMeaning(snapshot.Report)
}

// compileUnifiedPolicyReport obtains report meaning after standalone normalization and catalog compilation.
func compileUnifiedPolicyReport(t *testing.T, test policyReportMigrationCase) policyReportCompiledMeaning {
	t.Helper()

	report := policyconfig.ReportConfig{
		Enabled:           test.reportEnabled,
		IncludeAttributes: test.includeAttributes,
	}
	test.includeFSM.apply(&report.IncludeFSM)
	test.includeChecks.apply(&report.IncludeChecks)

	document := policyconfig.Document{Policy: policyconfig.PolicyConfig{Targets: []policyconfig.TargetConfig{{
		Namespace: policy.AuthnNamespace,
		Action:    string(policy.OperationAuthenticate),
		Schema:    "authn/authenticate/v1",
		Report:    report,
	}}}}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("normalize standalone policy report: %v", err)
	}

	catalog, err := input.Compile(context.Background(), policyReportMigrationAcceptance{})
	if err != nil {
		t.Fatalf("compile standalone policy report: %v", err)
	}

	for _, target := range catalog.Targets() {
		if target.Target().String() == "authn/authenticate" {
			report := target.Report()

			return policyReportCompiledMeaning{
				Enabled:           report.Enabled(),
				IncludeFSM:        report.IncludeFSM(),
				IncludeChecks:     report.IncludeChecks(),
				IncludeAttributes: report.IncludeAttributes(),
			}
		}
	}

	t.Fatal("compiled standalone authn/authenticate target is missing")

	return policyReportCompiledMeaning{}
}

// apply preserves the test distinction between omitted, explicit false, and explicit true fields.
func (s policyReportFieldState) apply(target *bool) {
	if s == policyReportFieldOmitted {
		return
	}

	*target = s == policyReportFieldTrue
}

// compiledSnapshotReportMeaning projects the immutable legacy snapshot carrier.
func compiledSnapshotReportMeaning(report policyruntime.ReportSettings) policyReportCompiledMeaning {
	return policyReportCompiledMeaning{
		Enabled:           report.Enabled,
		IncludeFSM:        report.IncludeFSM,
		IncludeChecks:     report.IncludeChecks,
		IncludeAttributes: report.IncludeAttributes,
	}
}
