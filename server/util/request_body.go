// Copyright (C) 2026 Christian Roessner
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

package util

import (
	"errors"
	"fmt"
	"io"
)

const (
	// DefaultHTTPRequestBodyLimit is the shared fallback limit for hook request bodies.
	DefaultHTTPRequestBodyLimit int64 = 1 << 20
)

var (
	// ErrRequestBodyTooLarge reports that a request body exceeded its configured limit.
	ErrRequestBodyTooLarge = errors.New("request body too large")
)

// ReadBoundedRequestBody reads at most limit plus one byte to detect oversized bodies.
func ReadBoundedRequestBody(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("request body limit must not be negative")
	}

	if reader == nil {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(body)) > limit {
		return nil, ErrRequestBodyTooLarge
	}

	return body, nil
}
