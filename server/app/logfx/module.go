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

package logfx

import (
	"context"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/reloadfx"
	"github.com/croessner/nauthilus/server/log/level"

	"go.uber.org/fx"
)

// Module defines the logfx module for UberFX.
var Module = fx.Module("logfx",
	fx.Provide(
		NewLogger,
		// Register the reloader as a Reloadable component
		fx.Annotate(
			NewLevelReloader,
			fx.As(new(reloadfx.Reloadable)),
			fx.ResultTags(`group:"reloaders"`),
		),
	),
	fx.Invoke(BridgeStdLog),
)

// LevelReloader handles atomic updates of the level package configuration.
type LevelReloader struct{}

// NewLevelReloader creates a new LevelReloader instance.
func NewLevelReloader() *LevelReloader {
	return &LevelReloader{}
}

// Name returns the name of the reloader for the reload manager.
func (l *LevelReloader) Name() string {
	return "log_level_source"
}

// Order defines the execution order during a reload.
func (l *LevelReloader) Order() int {
	return 10
}

// ApplyConfig syncs the new configuration to the level package.
func (l *LevelReloader) ApplyConfig(ctx context.Context, snap configfx.Snapshot) error {
	if snap.File != nil && snap.File.GetServer() != nil {
		level.ApplyGlobalConfig(snap.File.GetServer().GetLog().IsAddSourceEnabled())
	}

	return nil
}

var _ reloadfx.Reloadable = (*LevelReloader)(nil)
