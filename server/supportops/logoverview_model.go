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

// Log level vocabulary of the log answers. Requests may only name these levels.
const (
	LogLevelError  = "error"
	LogLevelWarn   = "warn"
	LogLevelNotice = "notice"
	LogLevelInfo   = "info"
	LogLevelDebug  = "debug"
)

// LogLevels lists every level in response order, most severe first.
var LogLevels = []string{LogLevelError, LogLevelWarn, LogLevelNotice, LogLevelInfo, LogLevelDebug}

// DefaultLogLevels are the levels of a request that names none: warnings and errors.
var DefaultLogLevels = []string{LogLevelError, LogLevelWarn}

// Note codes of the log answers.
const (
	NoteLogMessagesAreNotIncidents = "LOG_MESSAGES_ARE_NOT_INCIDENTS"

	// NoteLogNoCoverage means no instance logged any line in the window: an empty message list proves nothing.
	NoteLogNoCoverage = "LOG_NO_COVERAGE"

	// NoteLogSecretsRedacted means authentication secrets were replaced by <redacted>; nothing else was changed.
	NoteLogSecretsRedacted = "LOG_SECRETS_REDACTED"

	// NoteLogMorePages means the answer is one page; next_cursor continues it.
	NoteLogMorePages = "LOG_MORE_PAGES"

	// NoteLogPagesRequery means every page runs the source query again, so a window that still receives lines can
	// shift between pages; a window in the past is stable.
	NoteLogPagesRequery = "LOG_PAGES_REQUERY_THE_SOURCE"
)

// LogPage is the page part of a paginated log request: the cursor of the previous answer and the page size.
type LogPage struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// LogPageResult states the page of a paginated log answer. NextCursor is null on the last page.
type LogPageResult struct {
	NextCursor *string `json:"next_cursor"`
	Limit      int     `json:"limit"`
	Offset     int     `json:"offset"`
	Total      int     `json:"total"`
}

// LogOverviewRequest asks for the messages the deployment logged inside a window at the requested levels.
type LogOverviewRequest struct {
	Window         *Window  `json:"window,omitempty"`
	Page           *LogPage `json:"page,omitempty"`
	Levels         []string `json:"levels,omitempty"`
	SchemaVersion  string   `json:"schema_version"`
	AuditReference string   `json:"audit_reference,omitempty"`
}

// LogOverviewResult is the answer of one log overview call. A message group is an observation, never an incident.
type LogOverviewResult struct {
	Messages      []LogMessageGroup `json:"messages"`
	Notes         []string          `json:"notes"`
	Buckets       []Window          `json:"buckets"`
	Source        SourceReport      `json:"source"`
	Scope         ResultScope       `json:"scope"`
	Page          LogPageResult     `json:"page"`
	SchemaVersion string            `json:"schema_version"`
	BucketSeconds int64             `json:"bucket_seconds"`
}

// LogMessageGroup is one exact message at one level with its counts in the covered window. Different messages are
// never merged; only lines with the identical message text count into one group.
type LogMessageGroup struct {
	Instances []LogInstanceCount `json:"instances"`

	// Counts holds one count per entry of LogOverviewResult.Buckets.
	Counts      []int64    `json:"counts"`
	FirstBucket *time.Time `json:"first_bucket_from,omitempty"`
	LastBucket  *time.Time `json:"last_bucket_until,omitempty"`
	ID          string     `json:"id"`
	Level       string     `json:"level"`
	Message     string     `json:"message"`
	Status      Status     `json:"status"`

	// SecretsRedacted tells that authentication secrets inside the message were replaced.
	SecretsRedacted bool `json:"secrets_redacted,omitempty"`

	// MessageExact tells that Message is the stored text unchanged, so it works as the message filter of the log
	// events; a replaced secret or a visible format character makes it false.
	MessageExact bool `json:"message_exact"`

	// Component and Symptom name the diagnostics category of a profiled message.
	Component string `json:"component,omitempty"`
	Symptom   string `json:"symptom,omitempty"`
	Count     int64  `json:"count"`
}

// LogInstanceCount is the count of one message group on one instance.
type LogInstanceCount struct {
	Instance string `json:"instance"`
	Count    int64  `json:"count"`
}

// LogOverviewSource is a historical source that can count log messages per level, instance, and bucket.
type LogOverviewSource interface {
	LogOverview(ctx context.Context, query LogOverviewQuery) LogOverviewSourceResult
}

// LogOverviewQuery is what the service asks the log overview source. Levels is never empty.
type LogOverviewQuery struct {
	Window Window
	Now    time.Time
	Levels []string
}

// LogOverviewSourceResult is the source's raw contribution: its completeness report, the bucket grid, and one series
// per instance, level, and message as logged. The service groups identical messages and pages the groups.
type LogOverviewSourceResult struct {
	Series  []LogSeries
	Buckets []Window
	Report  SourceReport
}

// LogSeries is the count of one message at one level on one instance, one count per bucket.
type LogSeries struct {
	Counts    []int64
	Instance  string
	Level     string
	Message   string
	Component string
	Symptom   string
}
