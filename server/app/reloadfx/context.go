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

type previousSnapshotKey struct{}

// WithPreviousSnapshot stores the previous snapshot on the context.
//
// This is primarily used by reloadables that need to compare the old and new config
// (e.g., to decide whether a live apply is possible).
func WithPreviousSnapshot(ctx context.Context, snap configfx.Snapshot) context.Context {
	return context.WithValue(ctx, previousSnapshotKey{}, snap)
}

func PreviousSnapshotFromContext(ctx context.Context) (configfx.Snapshot, bool) {
	v := ctx.Value(previousSnapshotKey{})
	if v == nil {
		return configfx.Snapshot{}, false
	}

	snap, ok := v.(configfx.Snapshot)

	return snap, ok
}
