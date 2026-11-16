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

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// loginContractVersion identifies rows written under the diagnostic data contract (DIAGNOSTIC_CONTRACT.md).
const loginContractVersion uint16 = 1

// applyContractInfo copies the versioned row identity and the host-sealed terminal outcome.
func applyContractInfo(row *clickHouseRow, request pluginapi.PostActionRequest) error {
	eventID, err := newEventID()
	if err != nil {
		return err
	}

	row.ContractVersion = loginContractVersion
	row.EventID = eventID

	applyTerminalOutcome(row, request.Outcome)

	if request.Snapshot.Diagnostics.BruteForceName != "" {
		tolerated := request.Snapshot.Diagnostics.BruteForceTolerated
		row.BruteForceTolerated = &tolerated
	}

	return nil
}

// applyTerminalOutcome maps the terminal outcome; an unsealed outcome is written as unknown, never as a failure.
func applyTerminalOutcome(row *clickHouseRow, outcome pluginapi.AuthOutcome) {
	if !outcome.Known {
		row.Outcome = string(pluginapi.AuthOutcomeUnknown)
		row.Transport = string(outcome.Transport)

		return
	}

	row.Operation = outcome.Operation
	row.Outcome = string(outcome.Decision)
	row.OutcomeStage = outcome.Stage
	row.OutcomeMarker = outcome.OutcomeMarker
	row.ResponseMarker = outcome.ResponseMarker
	row.PolicyRule = outcome.PolicyRule
	row.TempFailReason = outcome.TempFailReason
	row.TempFailCheckpoint = outcome.TempFailCheckpoint
	row.PolicyStatus = outcome.PolicyStatus
	row.FSMState = outcome.FSMState
	row.Transport = string(outcome.Transport)

	if outcome.Transport == pluginapi.AuthTransportHTTP && outcome.TransportStatus > 0 {
		row.TransportStatus = uintPointer(uint64(outcome.TransportStatus))
	}
}

// newEventID returns a random 128-bit hex identifier that stays stable across requeues of the encoded row.
func newEventID() (string, error) {
	var buffer [16]byte

	if _, err := rand.Read(buffer[:]); err != nil {
		return "", fmt.Errorf("generate clickhouse event id: %w", err)
	}

	return hex.EncodeToString(buffer[:]), nil
}
