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

package reloadfx

import (
	"context"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/pluginruntime"
)

const pluginReloadOrder = 30

// PluginRuntime reconfigures native plugins from a new config snapshot.
type PluginRuntime interface {
	Reconfigure(context.Context, config.File) error
}

// PluginReloadable adapts the native plugin runtime into reloadfx ordering.
type PluginReloadable struct {
	runtime PluginRuntime
}

// NewPluginReloadable returns the default native plugin reload adapter.
func NewPluginReloadable() *PluginReloadable {
	return &PluginReloadable{runtime: defaultPluginRuntime{}}
}

// NewPluginReloadableWithRuntime returns a native plugin reload adapter for tests.
func NewPluginReloadableWithRuntime(runtime PluginRuntime) *PluginReloadable {
	return &PluginReloadable{runtime: runtime}
}

// Name returns the reloadable component name.
func (r *PluginReloadable) Name() string {
	return "native_plugins"
}

// Order returns the native plugin reload order.
func (r *PluginReloadable) Order() int {
	return pluginReloadOrder
}

// ApplyConfig applies config-only changes to reloadable native plugins.
func (r *PluginReloadable) ApplyConfig(ctx context.Context, snap configfx.Snapshot) error {
	if r == nil || r.runtime == nil {
		return nil
	}

	return r.runtime.Reconfigure(ctx, snap.File)
}

type defaultPluginRuntime struct{}

// Reconfigure forwards to the process default plugin runtime when it exists.
func (defaultPluginRuntime) Reconfigure(ctx context.Context, file config.File) error {
	runner, ok := pluginruntime.DefaultRunner()
	if !ok {
		return nil
	}

	return runner.Reconfigure(ctx, file)
}
