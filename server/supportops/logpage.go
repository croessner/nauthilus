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
	"time"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// Page sizes of the paginated log answers.
const (
	// DefaultLogGroupPageLimit is the message groups of one overview page when the caller sends none.
	DefaultLogGroupPageLimit = 50

	// MaxLogGroupPageLimit bounds the message groups of one overview page.
	MaxLogGroupPageLimit = 200

	// DefaultLogEventPageLimit is the log events of one page when the caller sends none.
	DefaultLogEventPageLimit = 100

	// MaxLogEventPageLimit bounds the log events of one page; it stays below the usual Loki entry limit of 5000.
	MaxLogEventPageLimit = 500

	// MaxLogEventRead bounds the lines one log read asks the source for, the usual Loki entry limit. A run of lines
	// with one timestamp longer than this cannot be paged through.
	MaxLogEventRead = 5000

	// maxCursorSkip bounds the lines a cursor names as done at one timestamp; the source checks it against the run.
	maxCursorSkip = 1 << 24
)

// pageCursor is the opaque page state of a log answer: an offset for the overview, or the time and the number of
// already returned events at that time for the events. It carries the window of the first page, so a follow-up
// request without a window continues the same window, and Digest binds it to one query.
type pageCursor struct {
	Digest       string `json:"d"`
	StreamDigest string `json:"t,omitempty"`
	Before       int64  `json:"b,omitempty"`
	From         int64  `json:"f"`
	Until        int64  `json:"u"`
	Offset       int    `json:"o,omitempty"`
	Skip         int    `json:"s,omitempty"`
	StreamIndex  int    `json:"i,omitempty"`
	Exclusive    bool   `json:"x,omitempty"`
}

// pagePlan is a validated page request.
type pagePlan struct {
	window      Window
	digest      string
	cursor      pageCursor
	offset      int
	limit       int
	cursorGiven bool
}

// position returns the source position of a log events cursor.
func (p pagePlan) position() LogPosition {
	position := LogPosition{StreamDigest: p.cursor.StreamDigest, StreamIndex: p.cursor.StreamIndex, Skip: p.cursor.Skip,
		Exclusive: p.cursor.Exclusive}

	if p.cursor.Before > 0 {
		position.Before = time.Unix(0, p.cursor.Before).UTC()
	}

	return position
}

// positionCursor renders a source position as the position fields of a cursor.
func positionCursor(position LogPosition) pageCursor {
	return pageCursor{Before: position.Before.UnixNano(), Skip: position.Skip, StreamDigest: position.StreamDigest,
		StreamIndex: position.StreamIndex, Exclusive: position.Exclusive}
}

// encode renders the cursor of a next page of the same query.
func (p pagePlan) encode(position pageCursor) string {
	position.Digest, position.From, position.Until = p.digest, p.window.From.UnixNano(), p.window.Until.UnixNano()

	return supportaccess.EncodeCursor(position)
}

// cursorWindow returns the window a cursor continues, or nil for no or an unreadable cursor; the cursor itself is
// validated by planPage.
func cursorWindow(page *LogPage) *Window {
	var cursor pageCursor

	if page == nil || !supportaccess.DecodeCursor(page.Cursor, &cursor) || cursor.From <= 0 || cursor.Until <= cursor.From {
		return nil
	}

	return &Window{From: time.Unix(0, cursor.From).UTC(), Until: time.Unix(0, cursor.Until).UTC()}
}

// valid reports whether a decoded cursor belongs to the query digest and holds a position the services can use.
func (c pageCursor) valid(digest string) bool {
	switch {
	case c.Digest != digest || c.Offset < 0 || c.Before < 0:
		return false
	case c.Skip < 0 || c.Skip > maxCursorSkip || c.StreamIndex < 0:
		return false
	default:
		positioned := c.Skip > 0 || c.StreamDigest != "" || c.StreamIndex > 0 || c.Exclusive

		return !positioned || c.Before > 0
	}
}

// planPage validates the page size and the cursor of a log request against the digest of its query parts and window.
func planPage(page *LogPage, fallback int, maximum int, window Window, parts ...string) (pagePlan, *Error) {
	plan := pagePlan{window: window, digest: supportaccess.QueryDigest(append(parts, windowKey(window))...), limit: fallback}
	digest := plan.digest

	if page == nil {
		return plan, nil
	}

	switch {
	case page.Limit < 0 || page.Limit > maximum:
		return pagePlan{}, newError(CodeInvalidRequest, nil)
	case page.Limit > 0:
		plan.limit = page.Limit
	}

	if page.Cursor == "" {
		return plan, nil
	}

	var cursor pageCursor
	if !supportaccess.DecodeCursor(page.Cursor, &cursor) || !cursor.valid(digest) {
		return pagePlan{}, newError(CodeInvalidCursor, nil)
	}

	plan.offset, plan.cursor, plan.cursorGiven = cursor.Offset, cursor, true

	return plan, nil
}
