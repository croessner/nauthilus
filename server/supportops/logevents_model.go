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
	"time"
)

// Bounds of the log event filters a caller sends.
const (
	// maxInstanceFilterRunes bounds the instance filter.
	maxInstanceFilterRunes = 256

	// maxMessageFilterRunes bounds the exact message filter.
	maxMessageFilterRunes = 4096
)

// Log line formats of a log event.
const (
	LogFormatJSON   = "json"
	LogFormatLogfmt = "logfmt"
)

// Note codes of the log events.
const (
	// NoteLogPageReducedBySourceLimit means the source byte bound forced a smaller page than requested; the cursor
	// continues without a gap.
	NoteLogPageReducedBySourceLimit = "LOG_PAGE_REDUCED_BY_SOURCE_LIMIT"
)

// LogEventsRequest asks for the stored log events of the deployment inside a window, newest first, optionally only of
// one instance and one exact message (as an overview group names them).
type LogEventsRequest struct {
	Window         *Window  `json:"window,omitempty"`
	Page           *LogPage `json:"page,omitempty"`
	Levels         []string `json:"levels,omitempty"`
	Instance       string   `json:"instance,omitempty"`
	Message        *string  `json:"message,omitempty"`
	SchemaVersion  string   `json:"schema_version"`
	AuditReference string   `json:"audit_reference,omitempty"`
}

// LogEventsResult is one page of stored log events. An event is an observation, never an incident.
type LogEventsResult struct {
	Events        []LogEvent      `json:"events"`
	Gaps          []LogGap        `json:"gaps"`
	Notes         []string        `json:"notes"`
	Source        SourceReport    `json:"source"`
	Scope         ResultScope     `json:"scope"`
	Page          LogEventsPage   `json:"page"`
	Filter        LogEventsFilter `json:"filter"`
	SchemaVersion string          `json:"schema_version"`
}

// LogEventsFilter echoes the effective filter of the answer.
type LogEventsFilter struct {
	Message  *string  `json:"message,omitempty"`
	Levels   []string `json:"levels"`
	Instance string   `json:"instance,omitempty"`
}

// LogEventsPage states the page of a log events answer. LimitApplied is below Limit when the source byte bound
// forced a smaller page. NextCursor is null on the last page.
type LogEventsPage struct {
	NextCursor   *string `json:"next_cursor"`
	Limit        int     `json:"limit"`
	LimitApplied int     `json:"limit_applied"`
}

// LogEvent is one stored log line: its time, instance, stream labels, and every field of the line. Values are
// complete; only authentication secrets are replaced and named in RedactedFields or SecretsRedacted.
type LogEvent struct {
	At             time.Time         `json:"at"`
	Labels         map[string]string `json:"labels"`
	Fields         map[string]any    `json:"fields"`
	RedactedFields []string          `json:"redacted_fields,omitempty"`

	// RepeatedFields names fields whose name the line repeated; their value is the list of every value in order.
	RepeatedFields []string `json:"repeated_fields,omitempty"`

	// Line is the complete stored line with authentication secrets replaced.
	Line            string `json:"line"`
	Instance        string `json:"instance"`
	Level           string `json:"level"`
	Message         string `json:"message"`
	Format          string `json:"format"`
	SecretsRedacted bool   `json:"secrets_redacted,omitempty"`
}

// LogEventsSource is a historical source that can return stored log lines of a window, newest first.
type LogEventsSource interface {
	LogEvents(ctx context.Context, query LogEventsQuery) LogEventsSourceResult
}

// LogEventsQuery is what the service asks the log events source. Levels is never empty; Position continues a page.
type LogEventsQuery struct {
	Window   Window
	Now      time.Time
	Message  *string
	Position LogPosition
	Levels   []string
	Instance string
	Limit    int
}

// LogEventsSourceResult is the source's raw contribution: up to Limit lines newest first, whether more follow, the
// position of the next page, the effective page size after the source byte bound, and every gap the source bounds
// left inside the page's span.
type LogEventsSourceResult struct {
	Next         *LogPosition
	Lines        []LogLine
	Gaps         []LogGap
	Report       SourceReport
	LimitApplied int
	More         bool
}

// LogPosition is where the next page of log events starts, in the stable order newest first, then by stream key,
// then by line. Lines after Before are done. Without a stream, the first Skip lines at exactly Before are done; with
// StreamDigest, the streams before StreamIndex (in stream key order) and the first Skip lines of that stream at Before
// are done. Exclusive means every line at Before is done.
type LogPosition struct {
	Before       time.Time
	StreamDigest string
	StreamIndex  int
	Skip         int
	Exclusive    bool
}

// LogGap is a part of the stored lines the source bounds could not return: the time, the stream labels, and why.
type LogGap struct {
	At     time.Time         `json:"at"`
	Labels map[string]string `json:"labels"`
	Reason string            `json:"reason"`
}

// LogLine is one stored log line as the source returned it; Stream is the canonical key of its stream labels.
type LogLine struct {
	At       time.Time
	Labels   map[string]string
	Instance string
	Stream   string
	Line     string
}
