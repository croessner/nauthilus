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

// Package policyfx wires policy snapshot reloads into the runtime container.
package policyfx

import (
	"context"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/reloadfx"
	"github.com/croessner/nauthilus/server/policy/compiler"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"

	"go.uber.org/fx"
)

// Module registers policy snapshot reload support.
func Module() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				NewReloader,
				fx.As(new(reloadfx.Reloadable)),
				fx.ResultTags(`group:"reloadables"`),
			),
		),
	)
}

// Reloader compiles and publishes a complete policy snapshot after config reload.
type Reloader struct {
	store    *policyruntime.SnapshotStore
	compiler compiler.Compiler
}

// NewReloader returns the default policy reload component.
func NewReloader() *Reloader {
	return &Reloader{
		store:    policyruntime.DefaultStore(),
		compiler: compiler.NewCompiler(),
	}
}

// Name returns the reload component name.
func (r *Reloader) Name() string {
	return "policy_snapshot"
}

// Order runs policy validation before components that apply runtime side effects.
func (r *Reloader) Order() int {
	return 20
}

// ApplyConfig compiles and publishes the policy snapshot for the new config.
func (r *Reloader) ApplyConfig(ctx context.Context, snap configfx.Snapshot) error {
	return compiler.CompileAndActivate(ctx, r.store, r.compiler, compiler.Input{
		Config:     snap.File,
		Generation: snap.Version,
	})
}

var _ reloadfx.Reloadable = (*Reloader)(nil)
