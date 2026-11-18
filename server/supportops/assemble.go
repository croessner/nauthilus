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

package supportops

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// assemble merges the source results into one answer. Findings of different sources are never merged: a current
// gauge and a log count are different evidence, and an instance identity across sources is not proven. Hypotheses
// relate them instead.
func (s *Service) assemble(plan requestPlan, query Query, results []SourceResult) *DiagnosticsResult {
	result := &DiagnosticsResult{SchemaVersion: SchemaVersion,
		Scope:   ResultScope{Window: plan.window, QueriedAt: query.Now.UTC(), Deployment: s.deployment, Instance: s.instance},
		Sources: make([]SourceReport, 0, len(results)), Findings: []Finding{}}

	for _, sourceResult := range results {
		result.Sources = append(result.Sources, sourceResult.Report)

		for _, finding := range sourceResult.Findings {
			if query.Wants(finding.Component) {
				result.Findings = append(result.Findings, normalizedFinding(finding))
			}
		}
	}

	sortFindings(result.Findings)

	for index := range result.Findings {
		result.Findings[index].ID = fmt.Sprintf("F%d", index+1)
	}

	result.Hypotheses = deriveHypotheses(result.Findings)
	result.Notes = resultNotes(plan, query, result)

	return result
}

// normalizedFinding cleans labels and keeps list fields non-nil.
func normalizedFinding(finding Finding) Finding {
	finding.Labels = SanitizeLabels(finding.Labels)

	if finding.Symptoms == nil {
		finding.Symptoms = []Symptom{}
	}

	return finding
}

// sortFindings orders findings by component vocabulary, source, scope, and labels so answers are deterministic.
func sortFindings(findings []Finding) {
	slices.SortStableFunc(findings, func(left, right Finding) int {
		return cmp.Or(
			cmp.Compare(slices.Index(Components, left.Component), slices.Index(Components, right.Component)),
			cmp.Compare(slices.Index(SourceNames, left.Source), slices.Index(SourceNames, right.Source)),
			cmp.Compare(left.Scope.Instance, right.Scope.Instance),
			cmp.Compare(labelKey(left.Labels), labelKey(right.Labels)),
		)
	})
}

// labelKey renders labels in a stable order for sorting.
func labelKey(labels map[string]string) string {
	var builder strings.Builder

	for _, name := range slices.Sorted(maps.Keys(labels)) {
		builder.WriteString(name)
		builder.WriteByte('=')
		builder.WriteString(labels[name])
		builder.WriteByte(';')
	}

	return builder.String()
}

// resultNotes explains how to read the answer.
func resultNotes(plan requestPlan, query Query, result *DiagnosticsResult) []string {
	notes := []string{NoteValuesAreUntrusted}

	for _, report := range result.Sources {
		notes = append(notes, sourceNotes(report, plan, query)...)
	}

	if len(result.Hypotheses) > 0 {
		notes = append(notes, NoteHypothesesAreNotFindings)
	}

	return notes
}

// sourceNotes returns the notes one source report implies.
func sourceNotes(report SourceReport, plan requestPlan, query Query) []string {
	switch report.Name {
	case SourceRuntime:
		if report.Status == SourceStatusNotRequested || report.Status == SourceStatusNotConfigured {
			return nil
		}

		notes := []string{NoteLocalViewNotCluster, NoteRuntimeCountersAreLifetime}
		if plan.window.Until.Before(query.Now.Add(-futureSkew)) {
			notes = append(notes, NoteRuntimeIsCurrentStateOnly)
		}

		return notes
	case SourceLoki:
		switch {
		case report.Status == SourceStatusNotRequested || report.Status == SourceStatusNotConfigured:
			return []string{NoteNoHistoricalSource}
		case report.Status != SourceStatusOK || report.Truncated:
			return []string{NoteHistoricalSourceIncomplete}
		}
	}

	return nil
}
