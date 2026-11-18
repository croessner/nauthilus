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
	"context"
	"slices"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

const (
	// maxLabelRunes bounds one label value that leaves the host.
	maxLabelRunes = 160
)

// Source is one read-only observation source. Collect must not change any state, must honor ctx, and reports its own
// completeness; it never returns an error, so one failing source cannot hide the others.
type Source interface {
	Name() string
	Kind() SourceKind
	Collect(ctx context.Context, query Query) SourceResult
}

// Query is what the service asks every source. Components is never empty.
type Query struct {
	Window     Window
	Now        time.Time
	Components []string
	Instance   string
}

// Wants reports whether the query asks for component.
func (q Query) Wants(component string) bool {
	return slices.Contains(q.Components, component)
}

// SourceResult is one source's contribution: its completeness report and its findings without ids.
type SourceResult struct {
	Findings []Finding
	Report   SourceReport
}

// UnknownFinding returns the finding that states missing data for a component in a scope.
func UnknownFinding(source string, component string, scope FindingScope, freshness Freshness, observed Observation) Finding {
	return Finding{Component: component, Source: source, Scope: scope, Status: StatusUnknown, Freshness: freshness,
		Observed: observed, Symptoms: []Symptom{}}
}

// SanitizeLabels bounds and cleans label values observed in infrastructure data before they leave the host.
func SanitizeLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}

	cleaned := make(map[string]string, len(labels))

	for name, value := range labels {
		cleaned[supportaccess.SanitizeText(name, maxLabelRunes)] = supportaccess.SanitizeText(value, maxLabelRunes)
	}

	return cleaned
}

// TimePointer returns a pointer to a copy of t in UTC.
func TimePointer(t time.Time) *time.Time {
	utc := t.UTC()

	return &utc
}
