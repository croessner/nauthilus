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

package lokisource

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
)

const (
	rangePath = "/loki/api/v1/query_range"

	// overviewBuckets is the number of time buckets of one overview.
	overviewBuckets = 12

	// overviewLevelLabel and overviewMessageLabel receive the parsed fields; dedicated names never collide with a
	// stream label such as level.
	overviewLevelLabel   = "nauthilus_level"
	overviewMessageLabel = "nauthilus_msg"

	// levelField is the slog level key of every Nauthilus log line.
	levelField = "level"
)

// slogLevels maps the overview level vocabulary to the slog level names of a log line.
var slogLevels = map[string]string{supportops.LogLevelError: "ERROR", supportops.LogLevelWarn: "WARN"}

// logFormat is one slog encoder: the line filter stages that keep only lines of the wanted levels, and the parser.
type logFormat struct {
	prefilter func(alternation string) string
	parser    string
}

// logFormats covers the slog JSON and text encoders, so the overview needs no knowledge of the configured format.
// A text line fails the JSON parser and is dropped by the __error__ stage. The non-strict logfmt parser does not fail
// on a JSON line and would read a level=ERROR typed into a JSON value, so the text query excludes JSON lines first.
var logFormats = []logFormat{
	{parser: "json", prefilter: func(alternation string) string {
		return ` |~ ` + strconv.Quote(`"`+levelField+`":"(`+alternation+`)"`)
	}},
	{parser: "logfmt", prefilter: func(alternation string) string {
		return ` !~ ` + strconv.Quote(`^\s*\{`) + ` |~ ` + strconv.Quote(`(^|\s)`+levelField+`=(`+alternation+`)(\s|$)`)
	}},
}

// LogOverview counts the warning and error lines of every message per instance and bucket inside the window. Only
// level names of the fixed vocabulary reach a query; messages leave Loki as aggregated label values that the service
// normalizes before they leave the host.
func (s *Source) LogOverview(ctx context.Context, query supportops.LogOverviewQuery) supportops.LogOverviewSourceResult {
	alternation := levelAlternation(query.Levels)
	builds := make([]func(int64) string, 0, len(logFormats))

	for _, format := range logFormats {
		builds = append(builds, func(stepSeconds int64) string {
			return overviewRangeQuery(s.instanceLabel, s.selector, format, alternation, stepSeconds)
		})
	}

	ranged := s.CollectRange(ctx, supportops.Query{Window: query.Window, Now: query.Now}, overviewBuckets, builds)
	result := supportops.LogOverviewSourceResult{Buckets: ranged.Buckets, Report: ranged.Report, Series: []supportops.LogSeries{}}

	misaligned := false

	for _, series := range ranged.Series {
		for _, entry := range series {
			converted, ok, dropped := s.logSeries(entry, ranged.Buckets)
			misaligned = misaligned || dropped

			if ok {
				result.Series = append(result.Series, converted)
			}
		}
	}

	if misaligned && result.Report.Status == supportops.SourceStatusOK {
		result.Report.Status, result.Report.Code = supportops.SourceStatusPartial, codePrefix+"_BUCKETS_MISALIGNED"
	}

	return result
}

// logSeries converts one range series into a log series; a level outside the vocabulary is dropped. The last result
// reports points that fell off the bucket grid.
func (s *Source) logSeries(series windowsource.Series, grid []supportops.Window) (supportops.LogSeries, bool, bool) {
	level, ok := overviewLevel(series.Labels[overviewLevelLabel])
	if !ok {
		return supportops.LogSeries{}, false, false
	}

	counts, misaligned := windowsource.BucketCounts(series, grid)
	message := series.Labels[overviewMessageLabel]
	converted := supportops.LogSeries{Instance: windowsource.InstanceName(series.Labels[s.instanceLabel]), Level: level,
		Message: message, Counts: counts}

	if entry, profiled := profileEntryOf(message); profiled {
		converted.Component, converted.Symptom = entry.component, entry.symptom
	}

	return converted, true, misaligned
}

// overviewLevel maps a slog level name back to the overview vocabulary.
func overviewLevel(name string) (string, bool) {
	for level, slogName := range slogLevels {
		if slogName == name {
			return level, true
		}
	}

	return "", false
}

// levelAlternation renders the slog names of the requested levels as an RE2 alternation in vocabulary order.
func levelAlternation(levels []string) string {
	names := make([]string, 0, len(levels))

	for _, level := range supportops.LogLevels {
		for _, requested := range levels {
			if requested == level {
				names = append(names, slogLevels[level])
			}
		}
	}

	return strings.Join(names, "|")
}

// overviewRangeQuery returns the range query that counts warning and error lines of one log format per instance, level,
// and message over stepSeconds. The prefilter drops every other line before the parser runs, and the level matcher
// after the parser keeps a level word inside another field from counting.
func overviewRangeQuery(instanceLabel string, selector string, format logFormat, alternation string, stepSeconds int64) string {
	return fmt.Sprintf(`sum by (%s, %s, %s) (count_over_time(%s%s | %s %s=%q, %s=%q | __error__="" | %s=~%q [%ds]))`,
		instanceLabel, overviewLevelLabel, overviewMessageLabel, selector, format.prefilter(alternation),
		format.parser, overviewLevelLabel, levelField, overviewMessageLabel, messageField, overviewLevelLabel, alternation,
		stepSeconds)
}
