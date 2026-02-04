// Copyright (C) 2024 Christian Rößner
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
	"fmt"

	"github.com/gin-contrib/sessions"
)

// GetSessionValue retrieves a value from the session and asserts its type.
func GetSessionValue[T any](session sessions.Session, key string) (T, error) {
	val := session.Get(key)
	if val == nil {
		var zero T
		return zero, fmt.Errorf("missing session value: %s", key)
	}

	tVal, ok := val.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("invalid type for session value: %s (expected %T, got %T)", key, zero, val)
	}

	return tVal, nil
}
