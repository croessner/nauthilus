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

// queryDigest binds a cursor to the operation, the caller projection, and the normalized query.
func queryDigest(operation string, projection Projection, parts ...string) string {
	hash := sha256.New()
	hash.Write([]byte(cursorDigestDomain + operation + "\x00" + string(projection)))

	for _, part := range parts {
		hash.Write([]byte{0})
		hash.Write([]byte(part))
	}

	return hex.EncodeToString(hash.Sum(nil))[:32]
}

// encodeCursor renders a cursor for the next page.
func encodeCursor(position AnchorPosition, queriedAt time.Time, digest string) string {
	state := cursorState{Version: cursorVersion, AtMillis: position.At.UnixMilli(), Key: position.Key,
		QueriedAt: queriedAt.UnixMilli(), Digest: digest}

	raw, _ := json.Marshal(state)

	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeCursor parses a cursor and checks that it belongs to the same query.
func decodeCursor(value, digest string) (*cursorState, *Error) {
	if value == "" {
		return nil, nil
	}

	if len(value) > maxCursorLength {
		return nil, invalid(CodeInvalidCursor)
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, invalid(CodeInvalidCursor)
	}

	var state cursorState
	if err = json.Unmarshal(raw, &state); err != nil || state.Version != cursorVersion || state.Digest != digest ||
		state.AtMillis <= 0 || state.QueriedAt <= 0 || len(state.Key) > 128 {
		return nil, invalid(CodeInvalidCursor)
	}

	return &state, nil
}

// position returns the exclusive paging position of a cursor.
func (c *cursorState) position() AnchorPosition {
	return AnchorPosition{At: time.UnixMilli(c.AtMillis).UTC(), Key: c.Key}
}

// queriedAt returns the frozen upper read bound of the paged query.
func (c *cursorState) queriedAt() time.Time {
	return time.UnixMilli(c.QueriedAt).UTC()
}
