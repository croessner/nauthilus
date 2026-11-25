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
	rangePath  = "/loki/api/v1/query_range"
	seriesPath = "/loki/api/v1/series"

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
var slogLevels = map[string]string{supportops.LogLevelError: "ERROR", supportops.LogLevelWarn: "WARN",
	supportops.LogLevelNotice: "NOTICE", supportops.LogLevelInfo: "INFO", supportops.LogLevelDebug: "DEBUG"}

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

// LogOverview counts the lines of every message at the requested levels per instance and bucket inside the window.
// Every bucket is counted by instant queries at its exact end, so the counts cover exactly [from, until) of every
// bucket, whatever the window and however Loki aligns range evaluations. Only level names of the fixed vocabulary
// reach the query; messages leave Loki as aggregated label values.
func (s *Source) LogOverview(ctx context.Context, query supportops.LogOverviewQuery) supportops.LogOverviewSourceResult {
	alternation := levelAlternation(query.Levels)
	builds := make([]func(int64) string, 0, len(logFormats))

	for _, format := range logFormats {
		builds = append(builds, func(rangeMillis int64) string {
			return overviewCountQuery(s.instanceLabel, s.selector, format, alternation, rangeMillis)
		})
	}

	counted := s.CollectBuckets(ctx, supportops.Query{Window: query.Window, Now: query.Now}, overviewBuckets, builds)
	result := supportops.LogOverviewSourceResult{Buckets: counted.Buckets, Report: counted.Report, Series: []supportops.LogSeries{}}

	for _, series := range counted.Series {
		for _, entry := range series {
			if converted, ok := s.logSeries(entry); ok {
				result.Series = append(result.Series, converted)
			}
		}
	}

	return result
}

// logSeries converts one counted series into a log series; a level outside the vocabulary is dropped.
func (s *Source) logSeries(series windowsource.BucketSeries) (supportops.LogSeries, bool) {
	level, ok := overviewLevel(series.Labels[overviewLevelLabel])
	if !ok {
		return supportops.LogSeries{}, false
	}

	message := series.Labels[overviewMessageLabel]
	converted := supportops.LogSeries{Instance: windowsource.InstanceName(series.Labels[s.instanceLabel]), Level: level,
		Message: message, Counts: series.Counts}

	if entry, profiled := profileEntryOf(message); profiled {
		converted.Component, converted.Symptom = entry.component, entry.symptom
	}

	return converted, true
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

// overviewCountQuery returns the instant query that counts the lines of one log format per instance, level, and
// message over rangeMillis milliseconds.
func overviewCountQuery(instanceLabel string, selector string, format logFormat, alternation string, rangeMillis int64) string {
	return fmt.Sprintf(`sum by (%s, %s, %s) (count_over_time(%s%s [%dms]))`, instanceLabel, overviewLevelLabel,
		overviewMessageLabel, selector, parserStages(format, alternation), rangeMillis)
}

// parserStages returns the pipeline of one log format shared by the overview and the events: the prefilter drops
// every other line before the parser runs, the parser extracts level and message into dedicated labels, and the
// level matcher after the parser keeps a level word inside another field from counting.
func parserStages(format logFormat, alternation string) string {
	return fmt.Sprintf(` %s| %s %s=%q, %s=%q | __error__="" | %s=~%q`, strings.TrimPrefix(format.prefilter(alternation), " ")+" ",
		format.parser, overviewLevelLabel, levelField, overviewMessageLabel, messageField, overviewLevelLabel, alternation)
}
