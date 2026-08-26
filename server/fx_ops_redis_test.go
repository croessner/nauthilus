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

package main

import (
	"io"
	"log/slog"
	"testing"
)

func TestRestartRedisRequiresInjectedRebuilder(t *testing.T) {
	orchestrator := &restartOrchestrator{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	step := ""

	err := orchestrator.rebuildRedisForRestart(t.Context(), nil, logger, &step)
	if err == nil {
		t.Fatal("rebuildRedisForRestart() error = nil, want missing dependency error")
	}

	if step != "rebuild_redis" {
		t.Fatalf("rebuildRedisForRestart() step = %q, want %q", step, "rebuild_redis")
	}
}
