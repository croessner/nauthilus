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
	"slices"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// requestPlan is a validated request: a bounded window and the effective component and source sets.
type requestPlan struct {
	window     Window
	components []string
	sources    []string
}

// wantsSource reports whether the plan asks for a source.
func (p requestPlan) wantsSource(name string) bool {
	return slices.Contains(p.sources, name)
}

// newPlan validates a request against the fixed vocabularies and bounds. An absent window is the last 15 minutes;
// an absent component or source list means all of them.
func newPlan(request DiagnosticsRequest, now time.Time) (requestPlan, *Error) {
	window, err := planHeader(request.SchemaVersion, request.AuditReference, request.Window, now)
	if err != nil {
		return requestPlan{}, err
	}

	components, ok := planSelection(request.Components, Components)
	if !ok {
		return requestPlan{}, newError(CodeInvalidRequest, nil)
	}

	sources, ok := planSelection(request.Sources, SourceNames)
	if !ok {
		return requestPlan{}, newError(CodeInvalidRequest, nil)
	}

	return requestPlan{window: window, components: components, sources: sources}, nil
}

// planHeader validates the fields every operations request shares and returns its window.
func planHeader(schemaVersion string, auditReference string, requested *Window, now time.Time) (Window, *Error) {
	if schemaVersion != SchemaVersion || !supportaccess.ValidAuditReference(auditReference) {
		return Window{}, newError(CodeInvalidRequest, nil)
	}

	return planWindow(requested, now)
}

// logOverviewPlan is a validated log overview request.
type logOverviewPlan struct {
	window Window
	levels []string
	page   pagePlan
}

// planLogOverview validates a log overview request: its window, its levels in vocabulary order (warnings and errors
// when absent), and its page bound to the window and levels.
func planLogOverview(request LogOverviewRequest, now time.Time) (logOverviewPlan, *Error) {
	window, err := planHeader(request.SchemaVersion, request.AuditReference, pageWindow(request.Window, request.Page), now)
	if err != nil {
		return logOverviewPlan{}, err
	}

	levels, ok := planLevels(request.Levels)
	if !ok {
		return logOverviewPlan{}, newError(CodeInvalidRequest, nil)
	}

	page, err := planPage(request.Page, DefaultLogGroupPageLimit, MaxLogGroupPageLimit, window,
		append([]string{operationLogOverview}, levels...)...)
	if err != nil {
		return logOverviewPlan{}, err
	}

	return logOverviewPlan{window: window, levels: levels, page: page}, nil
}

// pageWindow returns the requested window, or for a request without one the window its cursor continues.
func pageWindow(requested *Window, page *LogPage) *Window {
	if requested != nil {
		return requested
	}

	return cursorWindow(page)
}

// planLevels returns the requested levels in vocabulary order, or warnings and errors for an empty request.
func planLevels(requested []string) ([]string, bool) {
	if len(requested) == 0 {
		return slices.Clone(DefaultLogLevels), true
	}

	return planSelection(requested, LogLevels)
}

// windowKey renders a window for a query digest.
func windowKey(window Window) string {
	return window.From.UTC().Format(time.RFC3339Nano) + "/" + window.Until.UTC().Format(time.RFC3339Nano)
}

// windowPrecision is the precision of every planned window: the smallest unit of a range selector, so a historical
// source can count exactly the planned window and the log events read the same one.
const windowPrecision = time.Millisecond

// planWindow bounds the requested window: From before Until, Until not in the future beyond a small skew, and at
// most MaxWindow long. Both bounds keep whole milliseconds; finer digits are dropped.
func planWindow(requested *Window, now time.Time) (Window, *Error) {
	if requested == nil {
		now = now.UTC().Truncate(windowPrecision)

		return Window{From: now.Add(-DefaultWindow), Until: now}, nil
	}

	window := Window{From: requested.From.UTC().Truncate(windowPrecision), Until: requested.Until.UTC().Truncate(windowPrecision)}

	switch {
	case window.From.IsZero() || window.Until.IsZero() || !window.From.Before(window.Until):
		return Window{}, newError(CodeInvalidRequest, nil)
	case window.Until.After(now.Add(futureSkew)):
		return Window{}, newError(CodeInvalidRequest, nil)
	case window.Until.Sub(window.From) > MaxWindow:
		return Window{}, newError(CodeWindowTooLarge, nil)
	default:
		return window, nil
	}
}

// planSelection returns the requested members of vocabulary in vocabulary order, or all of them for an empty
// request. An unknown or repeated value is invalid.
func planSelection(requested []string, vocabulary []string) ([]string, bool) {
	if len(requested) == 0 {
		return slices.Clone(vocabulary), true
	}

	if len(requested) > len(vocabulary) {
		return nil, false
	}

	seen := make(map[string]struct{}, len(requested))

	for _, value := range requested {
		if _, duplicate := seen[value]; duplicate || !slices.Contains(vocabulary, value) {
			return nil, false
		}

		seen[value] = struct{}{}
	}

	selected := make([]string, 0, len(requested))

	for _, value := range vocabulary {
		if _, ok := seen[value]; ok {
			selected = append(selected, value)
		}
	}

	return selected, true
}
