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

package runtime

import "context"

type policySnapshotContextKey struct{}

// ContextWithPolicySnapshot attaches one detached generation-owned policy view.
func ContextWithPolicySnapshot(ctx context.Context, snapshot *Snapshot) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	if snapshot == nil {
		return ctx
	}

	return context.WithValue(ctx, policySnapshotContextKey{}, snapshot.Clone())
}

// PolicySnapshotFromContext returns a detached generation-owned policy view.
func PolicySnapshotFromContext(ctx context.Context) *Snapshot {
	if ctx == nil {
		return nil
	}

	snapshot, _ := ctx.Value(policySnapshotContextKey{}).(*Snapshot)

	return snapshot.Clone()
}
