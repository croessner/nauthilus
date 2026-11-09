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

package pluginruntime

import (
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v4/server/core"
)

// TestRequestSnapshotExposesMatchedRBLLists pins that plugins see every RBL list that listed the client IP, in
// configuration order. The host never mutates the list after RBL evaluation, so the snapshot shares it read-only.
func TestRequestSnapshotExposesMatchedRBLLists(t *testing.T) {
	tests := []struct {
		name    string
		matched []string
		want    []string
	}{
		{name: "no RBL match", matched: nil, want: nil},
		{name: "matched lists", matched: []string{"zen.example.test", "bl.example.test"},
			want: []string{"zen.example.test", "bl.example.test"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &core.AuthState{}
			auth.Runtime.RBLPolicy = core.RBLPolicyFact{MatchedLists: test.matched, MatchedCount: len(test.matched)}

			snapshot := NewRequestSnapshotFromAuthState(auth)
			if !slices.Equal(snapshot.Diagnostics.RBLMatchedLists, test.want) {
				t.Fatalf("RBL matched lists = %#v, want %#v", snapshot.Diagnostics.RBLMatchedLists, test.want)
			}
		})
	}
}
