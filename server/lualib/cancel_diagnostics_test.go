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

package lualib

import (
	"context"
	"testing"
	"time"
)

func TestRuntimeCancellationDiagnosticsPrefersRequestCancellation(t *testing.T) {
	t.Parallel()

	requestCtx, requestCancel := context.WithCancel(context.Background())
	groupCtx, groupCancel := context.WithCancel(requestCtx)
	runtimeCtx, runtimeCancel := context.WithCancel(groupCtx)

	requestCancel()
	groupCancel()
	runtimeCancel()

	diagnostics := NewRuntimeCancellationDiagnostics(runtimeCtx, groupCtx, requestCtx)
	if diagnostics.Source != RuntimeCancellationSourceRequest {
		t.Fatalf("expected request cancellation source, got %q", diagnostics.Source)
	}
}

func TestRuntimeCancellationDiagnosticsDetectsLuaTimeout(t *testing.T) {
	t.Parallel()

	runtimeCtx, runtimeCancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer runtimeCancel()

	<-runtimeCtx.Done()

	diagnostics := NewRuntimeCancellationDiagnostics(runtimeCtx, context.Background(), context.Background())
	if diagnostics.Source != RuntimeCancellationSourceLuaTimeout {
		t.Fatalf("expected Lua timeout source, got %q", diagnostics.Source)
	}
}
