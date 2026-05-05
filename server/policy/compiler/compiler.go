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

// Package compiler defines the internal policy snapshot compiler boundary.
package compiler

import (
	"context"

	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

// Input carries already-decoded policy material into the compiler boundary.
type Input struct {
	Generation uint64
}

// Compiler builds immutable policy runtime snapshots.
type Compiler interface {
	Compile(context.Context, Input) (*policyruntime.Snapshot, error)
}

// NoopCompiler builds an empty snapshot for wiring and tests.
type NoopCompiler struct{}

// Compile returns an empty snapshot with the requested generation.
func (NoopCompiler) Compile(_ context.Context, input Input) (*policyruntime.Snapshot, error) {
	return &policyruntime.Snapshot{Generation: input.Generation}, nil
}
