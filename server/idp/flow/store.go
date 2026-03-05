// Copyright (C) 2025 Christian Rößner
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

package flow

import (
	"context"
	"time"
)

// Store defines persistence capabilities for flow states.
type Store interface {
	Load(ctx context.Context, flowID string) (*State, error)
	Save(ctx context.Context, state *State) error
	Delete(ctx context.Context, flowID string) error
	TouchTTL(ctx context.Context, flowID string, ttl time.Duration) error
}
