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

package backendmonitoring

import "testing"

func TestHealthGateKeepsServerAliveUntilFailureThreshold(t *testing.T) {
	t.Parallel()

	gate := newHealthGate(2, 1, true)

	if healthy := gate.Record(false); !healthy {
		t.Fatal("first failure should not trip a gate with threshold 2")
	}

	if healthy := gate.Record(false); healthy {
		t.Fatal("second consecutive failure should trip the gate")
	}
}

func TestHealthGateRequiresRecoveryThreshold(t *testing.T) {
	t.Parallel()

	gate := newHealthGate(1, 2, true)

	if healthy := gate.Record(false); healthy {
		t.Fatal("first failure should trip a gate with threshold 1")
	}

	if healthy := gate.Record(true); healthy {
		t.Fatal("first recovery success should not recover a gate with threshold 2")
	}

	if healthy := gate.Record(true); !healthy {
		t.Fatal("second consecutive recovery success should recover the gate")
	}
}

func TestServerProbeStateDeepSuccessCountsAsConnectSuccess(t *testing.T) {
	t.Parallel()

	state := newServerProbeState(nil)
	state.connect = newHealthGate(1, 1, true)
	state.deep = newHealthGate(1, 1, true)

	if healthy := state.record("connect", false); healthy {
		t.Fatal("connect failure should make connect gate unhealthy")
	}

	if healthy := state.record("deep", true); !healthy {
		t.Fatal("deep success should recover the connect gate")
	}

	if !state.healthy(nil) {
		t.Fatal("server should be healthy after deep success recovered connect gate")
	}
}
