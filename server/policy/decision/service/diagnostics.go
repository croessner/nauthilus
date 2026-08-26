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

package service

import (
	"sort"
	"strconv"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	maximumDiagnosticEntries = 64
	maximumDiagnosticBytes   = 8 * 1024
)

// sanitizeDiagnostics builds the fixed bounded public projection without serializing the internal report.
func sanitizeDiagnostics(
	request decision.DecisionRequest,
	target policyruntime.CompiledTarget,
	checkpoint string,
	generation uint64,
	code decision.StatusCode,
	report runtimeReport,
) *decision.Diagnostics {
	if !request.Options().IncludeDiagnostics {
		return nil
	}

	entries := make(map[string]decision.Value)
	addDiagnosticString(entries, "target.namespace", target.Target().Namespace())
	addDiagnosticString(entries, "target.action", target.Target().Action())
	addDiagnosticString(entries, "schema.version", target.Schema().Identity().Version().String())
	addDiagnosticString(entries, "checkpoint", checkpoint)
	addDiagnosticString(entries, "outcome", string(code))
	addDiagnosticInteger(entries, "runtime.generation", int64(generation))
	addDiagnosticInteger(entries, "facts.accepted", int64(report.facts.Len()))
	addDiagnosticInteger(entries, "providers.executed", int64(executedProviderCount(report.providers)))

	addPolicyDiagnostic(entries, target, report.policySet)
	addProviderDiagnostics(entries, target, report.providers)
	addEffectDiagnostics(entries, target, report.effects)

	bounded := boundDiagnosticEntries(entries)

	diagnostics, err := decision.NewDiagnostics(bounded)
	if err != nil {
		return nil
	}

	return &diagnostics
}

// addPolicyDiagnostic projects only one catalog-approved selected-set alias.
func addPolicyDiagnostic(
	entries map[string]decision.Value,
	target policyruntime.CompiledTarget,
	policySet string,
) {
	setID, err := registry.ParsePolicySetID("diagnostics", policySet)
	if err != nil {
		return
	}

	set, ok := target.LookupPolicySet(setID)
	if ok && set.DiagnosticID() != "" {
		addDiagnosticString(entries, "policy."+set.DiagnosticID(), "selected")
	}
}

// addProviderDiagnostics projects stable states only for catalog-approved aliases.
func addProviderDiagnostics(
	entries map[string]decision.Value,
	target policyruntime.CompiledTarget,
	providers []providerRecord,
) {
	for _, provider := range providers {
		descriptor, ok := target.LookupProvider(provider.use)
		if ok && descriptor.DiagnosticID() != "" {
			addDiagnosticString(entries, "provider."+descriptor.DiagnosticID(), providerAliasStatus(provider.state))
		}
	}
}

// addEffectDiagnostics projects non-actionable states only for catalog-approved aliases.
func addEffectDiagnostics(
	entries map[string]decision.Value,
	target policyruntime.CompiledTarget,
	effects []effectRecord,
) {
	for _, effect := range effects {
		descriptor, ok := target.LookupEffect(effect.id)
		if ok && descriptor.DiagnosticID() != "" {
			addDiagnosticString(entries, "effect."+descriptor.DiagnosticID(), diagnosticEffectState(effect.state))
		}
	}
}

// executedProviderCount counts providers that reached an invocation outcome.
func executedProviderCount(records []providerRecord) int {
	count := 0

	for _, record := range records {
		if record.state != providerStateSkipped && record.state != providerStateUnavailable {
			count++
		}
	}

	return count
}

// diagnosticEffectState maps internal ownership states to fixed non-actionable vocabulary.
func diagnosticEffectState(state effectsupervisor.State) string {
	switch state {
	case effectsupervisor.StateSucceeded:
		return "succeeded"
	case effectsupervisor.StateAccepted:
		return "enqueued"
	default:
		return string(providerStateFailed)
	}
}

// addDiagnosticString inserts one constructor-validated bounded string value.
func addDiagnosticString(entries map[string]decision.Value, key string, text string) {
	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err == nil {
		entries[key] = value
	}
}

// addDiagnosticInteger inserts one constructor-validated bounded integer value.
func addDiagnosticInteger(entries map[string]decision.Value, key string, number int64) {
	value, err := decision.NewValue(decision.ValueInput{Integer: &number})
	if err == nil {
		entries[key] = value
	}
}

// boundDiagnosticEntries applies deterministic entry and exact scalar JSON-size limits.
func boundDiagnosticEntries(entries map[string]decision.Value) map[string]decision.Value {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	result := make(map[string]decision.Value)

	for _, key := range keys {
		if len(result) == maximumDiagnosticEntries {
			break
		}

		result[key] = entries[key]
		if diagnosticProjectionSize(result) > maximumDiagnosticBytes {
			delete(result, key)

			continue
		}
	}

	return result
}

// diagnosticProjectionSize returns the exact JSON size of the scalar diagnostics map.
func diagnosticProjectionSize(values map[string]decision.Value) int {
	size := 2
	first := true

	for key, value := range values {
		if !first {
			size++
		}

		first = false
		size += len(strconv.Quote(key)) + 1 + diagnosticJSONValueSize(value)
	}

	return size
}

// diagnosticJSONValueSize returns one scalar value's exact JSON encoding size.
func diagnosticJSONValueSize(value decision.Value) int {
	if text, ok := value.StringValue(); ok {
		return len(strconv.Quote(text))
	}

	if number, ok := value.Integer(); ok {
		return len(strconv.FormatInt(number, 10))
	}

	return len("null")
}
