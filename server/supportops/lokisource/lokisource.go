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

// Package lokisource is the optional historical source of the operational diagnostics. It runs only compiled metric
// LogQL queries below a selector and tenant fixed in the configuration: the nauthilus_diagnostics profile counts lines
// with fixed message literals per instance, and the log overview counts warning and error lines per instance, level,
// and message. No caller value reaches a query, no log line leaves Loki (only aggregated counts and message label
// values), redirects are never followed, and every answer is bounded in bytes and series. The query mechanics are shared with
// the other historical sources through package windowsource.
package lokisource

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
)

const (
	queryPath = "/loki/api/v1/query"

	// codePrefix starts every failure code of the source, such as LOKI_TIMEOUT.
	codePrefix = "LOKI"

	// messageField is the slog message key of every Nauthilus log line (definitions.LogKeyMsg).
	messageField = "msg"

	// minCoverageLines is the smallest line count that proves an instance logged inside the window.
	minCoverageLines = 1
)

// Config is the fixed connection and query boundary of one Loki source.
type Config = windowsource.Connection

// Source is the Loki diagnostics source: the shared window engine with the compiled log profile and the fixed
// stream boundary of the log overview.
type Source struct {
	*windowsource.Engine

	selector      string
	instanceLabel string
}

// New validates the boundary and builds the source. The HTTP client never follows redirects.
func New(cfg Config) (*Source, error) {
	count := func(literal string) func(int64) string {
		return func(rangeSeconds int64) string {
			return countQuery(cfg.InstanceLabel, streamSelector(cfg.Selector), literal, rangeSeconds)
		}
	}

	engine, err := windowsource.New(cfg, windowsource.Profile{Name: supportops.SourceLoki, CodePrefix: codePrefix,
		QueryPath: queryPath, RangePath: rangePath, TimeParam: lokiTime, Basis: supportops.BasisLogWindow, View: supportops.CoverageLogLabels,
		MinCoverage: minCoverageLines, Coverage: count(""), Entries: profileQueries(count)})
	if err != nil {
		return nil, err
	}

	return &Source{Engine: engine, selector: streamSelector(cfg.Selector), instanceLabel: cfg.InstanceLabel}, nil
}

// lokiTime renders the evaluation time as the Unix nanoseconds Loki expects.
func lokiTime(at time.Time) string {
	return strconv.FormatInt(at.UnixNano(), 10)
}

// streamSelector renders the fixed selector with quoted values in label order.
func streamSelector(selector map[string]string) string {
	names := make([]string, 0, len(selector))
	for name := range selector {
		names = append(names, name)
	}

	slices.Sort(names)

	matchers := make([]string, 0, len(names))
	for _, name := range names {
		matchers = append(matchers, name+"="+strconv.Quote(selector[name]))
	}

	return "{" + strings.Join(matchers, ",") + "}"
}

// countQuery returns the metric query counting matching lines per instance over rangeSeconds. A profile literal
// is matched only as the value of the log message field, never anywhere in the line.
func countQuery(instanceLabel string, selector string, literal string, rangeSeconds int64) string {
	return fmt.Sprintf("sum by (%s) (count_over_time(%s%s [%ds]))", instanceLabel, selector, lineFilter(literal), rangeSeconds)
}

// lineFilter returns the line filter stages of a profile literal, and none for the coverage query. Loki applies the
// stages in order: the substring stage drops every line without the literal before the unanchored message pattern
// runs, which keeps a query cheap on windows that hold many lines. The pattern quotes the literal verbatim, so the
// substring stage never drops a line the pattern would count.
func lineFilter(literal string) string {
	if literal == "" {
		return ""
	}

	return " |= " + strconv.Quote(literal) + " |~ " + strconv.Quote(messagePattern(literal))
}

// messagePattern returns the RE2 line filter that matches literal as the complete msg field of a slog JSON line
// ("msg":"...") or a slog text line (msg="..."). Both encoders escape quotes inside values, so a client-supplied
// value such as a typed username can never form the anchored field, and a substring elsewhere in the line does not
// match.
func messagePattern(literal string) string {
	quoted := regexp.QuoteMeta(literal)

	return `"` + messageField + `":"` + quoted + `"|(^|\s)` + messageField + `="` + quoted + `"`
}
