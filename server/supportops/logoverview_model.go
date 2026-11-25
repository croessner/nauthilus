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

// Log level vocabulary of the log overview. Requests may only name these levels.
const (
	LogLevelError = "error"
	LogLevelWarn  = "warn"
)

// LogLevels lists every overview level in response order.
var LogLevels = []string{LogLevelError, LogLevelWarn}

// Message forms tell how much of an observed log message left the host.
const (
	// MessageFormLiteral is the message exactly as logged; it held nothing that looked variable.
	MessageFormLiteral = "literal"

	// MessageFormNormalized is the message with every variable-looking part replaced by a placeholder.
	MessageFormNormalized = "normalized"
)

// Note codes of the log overview.
const (
	NoteLogMessagesAreNotIncidents = "LOG_MESSAGES_ARE_NOT_INCIDENTS"
	NoteLogMessagesNormalized      = "LOG_MESSAGES_NORMALIZED"
	NoteLogGroupsOmitted           = "LOG_GROUPS_OMITTED"
	NoteLogBucketsExceedWindow     = "LOG_BUCKETS_EXCEED_WINDOW"

	// NoteLogNoCoverage means no instance logged any line in the window: an empty message list proves nothing.
	NoteLogNoCoverage = "LOG_NO_COVERAGE"
)

// LogOverviewRequest asks for the warning and error messages the deployment logged inside a window.
type LogOverviewRequest struct {
	Window         *Window  `json:"window,omitempty"`
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
	Omitted       LogOmission       `json:"omitted"`
	SchemaVersion string            `json:"schema_version"`
	BucketSeconds int64             `json:"bucket_seconds"`
}

// LogOmission states what the result left out after the source answered: groups beyond the response bound and the
// lines they counted.
type LogOmission struct {
	Groups int   `json:"groups"`
	Lines  int64 `json:"lines"`
}

// LogMessageGroup is one message at one level with its counts in the covered window.
type LogMessageGroup struct {
	Instances []LogInstanceCount `json:"instances"`

	// Counts holds one count per entry of LogOverviewResult.Buckets.
	Counts      []int64    `json:"counts"`
	FirstBucket *time.Time `json:"first_bucket_from,omitempty"`
	LastBucket  *time.Time `json:"last_bucket_until,omitempty"`
	ID          string     `json:"id"`
	Level       string     `json:"level"`
	Message     string     `json:"message"`
	MessageForm string     `json:"message_form"`
	Status      Status     `json:"status"`

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

// LogOverviewSource is a historical source that can count warning and error messages per instance and bucket.
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
// per instance, level, and message as logged. The service normalizes and groups it before it leaves the host.
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
