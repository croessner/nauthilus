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

package lualib

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func pString(v string) *string {
	return &v
}

func TestSetStatusMessage(t *testing.T) {
	testCases := []struct {
		name          string
		initialStatus *string
		newStatus     string
	}{
		{
			name:          "NilInitialStatus",
			initialStatus: nil,
			newStatus:     "Testing status message",
		},
		{
			name:          "NonNilInitialStatus",
			initialStatus: pString("Initial status message"),
			newStatus:     "New status message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			L.Push(lua.LString(tc.newStatus))

			lFunc := SetStatusMessage(&tc.initialStatus)
			lFunc(L)

			if tc.initialStatus == nil || *tc.initialStatus != tc.newStatus {
				t.Errorf("expected status to be %s, got %s", tc.newStatus, *tc.initialStatus)
			}
		})
	}
}
