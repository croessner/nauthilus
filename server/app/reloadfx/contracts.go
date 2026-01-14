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

package reloadfx

import (
	"context"

	"github.com/croessner/nauthilus/server/app/configfx"
)

// Reloadable is a component that can apply a new configuration snapshot without a full restart.
//
// Order must be stable and independent from Fx group ordering.
// Lower values are applied first.
type Reloadable interface {
	Name() string
	Order() int
	ApplyConfig(ctx context.Context, snap configfx.Snapshot) error
}
