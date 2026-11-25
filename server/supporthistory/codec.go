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

package supporthistory

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

const (
	flowAttemptPrefix    = "fl1."
	requestAttemptPrefix = "rq1."
	cursorVersion        = 1
	maxCursorLength      = 512
	maxCursorKeyLength   = 128
	maxCursorMarks       = 4
	cursorDigestDomain   = "nauthilus.support_history.cursor.v1\x00"
)

var (
	flowRefPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// attemptID renders the stable, non-authorizing diagnostic id of an attempt key.
func attemptID(key AttemptKey) string {
	if key.Kind == AttemptFlow {
		return flowAttemptPrefix + key.Value
	}

	return requestAttemptPrefix + key.Value
}

// parseAttemptID validates a diagnostic attempt id; a malformed id is a client error, an unknown one is not.
func parseAttemptID(value string) (AttemptKey, *Error) {
	switch {
	case strings.HasPrefix(value, flowAttemptPrefix) && flowRefPattern.MatchString(value[len(flowAttemptPrefix):]):
		return AttemptKey{Kind: AttemptFlow, Value: value[len(flowAttemptPrefix):]}, nil
	case strings.HasPrefix(value, requestAttemptPrefix) && requestIDPattern.MatchString(value[len(requestAttemptPrefix):]):
		return AttemptKey{Kind: AttemptRequest, Value: value[len(requestAttemptPrefix):]}, nil
	default:
		return AttemptKey{}, invalid(CodeInvalidAttemptID)
	}
}

// cursorState is the opaque paging state. It carries a position and the digest of the query it belongs to, never
// any authority: every page is authorized and filtered again.
type cursorState struct {
	Digest    string `json:"fp"`
	Key       string `json:"key"`
	AtMillis  int64  `json:"at"`
	QueriedAt int64  `json:"q"`
	Version   int    `json:"v"`
}

// queryDigest binds a cursor to the operation, the projection, and the normalized query.
func queryDigest(operation string, parts ...string) string {
	hash := sha256.New()
	hash.Write([]byte(cursorDigestDomain + operation + "\x00" + string(ProjectionDetail)))

	for _, part := range parts {
		hash.Write([]byte{0})
		hash.Write([]byte(part))
	}

	return hex.EncodeToString(hash.Sum(nil))[:32]
}

// listCursorState is the opaque paging state of an inner list: the events of one attempt, or the contributions or
// hit claimants of one ban. Like cursorState it carries a position, the frozen query time, and the digest of the list
// and query it belongs to, never any authority. Marks hold the list-specific integer parts of the position.
type listCursorState struct {
	Digest    string  `json:"fp"`
	Key       string  `json:"key,omitempty"`
	Marks     []int64 `json:"m,omitempty"`
	AtMillis  int64   `json:"at,omitempty"`
	QueriedAt int64   `json:"q"`
	Version   int     `json:"v"`
}

// encodeState renders a cursor state as opaque URL-safe text.
func encodeState(state any) string {
	raw, _ := json.Marshal(state)

	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeState parses opaque cursor text into a state; false means the text is no cursor of this service.
func decodeState(value string, state any) bool {
	if len(value) > maxCursorLength {
		return false
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)

	return err == nil && json.Unmarshal(raw, state) == nil
}

// encodeCursor renders a cursor for the next page.
func encodeCursor(position AnchorPosition, queriedAt time.Time, digest string) string {
	return encodeState(cursorState{Version: cursorVersion, AtMillis: position.At.UnixMilli(), Key: position.Key,
		QueriedAt: queriedAt.UnixMilli(), Digest: digest})
}

// decodeCursor parses a cursor and checks that it belongs to the same query.
func decodeCursor(value, digest string) (*cursorState, *Error) {
	if value == "" {
		return nil, nil
	}

	var state cursorState
	if !decodeState(value, &state) || state.Version != cursorVersion || state.Digest != digest ||
		state.AtMillis <= 0 || state.QueriedAt <= 0 || len(state.Key) > maxCursorKeyLength {
		return nil, invalid(CodeInvalidCursor)
	}

	return &state, nil
}

// encodeListCursor renders the cursor of the next inner-list page.
func encodeListCursor(state listCursorState) string {
	state.Version = cursorVersion

	return encodeState(state)
}

// decodeListCursor parses an inner-list cursor and checks that it belongs to the same list and query and carries
// exactly the expected number of marks; list-specific value checks stay with the list.
func decodeListCursor(value, digest string, marks int) (*listCursorState, *Error) {
	if value == "" {
		return nil, nil
	}

	var state listCursorState
	if !decodeState(value, &state) || state.Version != cursorVersion || state.Digest != digest ||
		state.AtMillis < 0 || state.QueriedAt <= 0 || len(state.Key) > maxCursorKeyLength ||
		len(state.Marks) != marks || marks > maxCursorMarks {
		return nil, invalid(CodeInvalidCursor)
	}

	return &state, nil
}

// at returns the position instant of an inner-list cursor.
func (c *listCursorState) at() time.Time {
	return time.UnixMilli(c.AtMillis).UTC()
}

// queriedAt returns the frozen upper read bound of the paged list.
func (c *listCursorState) queriedAt() time.Time {
	return time.UnixMilli(c.QueriedAt).UTC()
}

// position returns the exclusive paging position of a cursor.
func (c *cursorState) position() AnchorPosition {
	return AnchorPosition{At: time.UnixMilli(c.AtMillis).UTC(), Key: c.Key}
}

// queriedAt returns the frozen upper read bound of the paged query.
func (c *cursorState) queriedAt() time.Time {
	return time.UnixMilli(c.QueriedAt).UTC()
}
