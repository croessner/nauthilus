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

package configfx

import (
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
)

// Snapshot represents an immutable configuration view.
//
// Version is monotonically increasing and changes whenever a new snapshot is swapped in.
type Snapshot struct {
	File    config.File
	Version uint64
}

// Provider provides the current config snapshot.
//
// Newly migrated components should prefer this over global `config.GetFile()`.
type Provider interface {
	Current() Snapshot
}

// Reloader extends Provider with a reload capability.
type Reloader interface {
	Provider

	Reload() (Snapshot, error)
}

type provider struct {
	snapshot atomic.Value // stores Snapshot
}

var _ Reloader = (*provider)(nil)

// NewProvider constructs a Provider from an already loaded global config.
//
// It does not load configuration itself; the legacy startup path still calls `config.NewFile()`.
func NewProvider() (Reloader, error) {
	if !config.IsFileLoaded() {
		return nil, config.ErrConfigNotLoaded{}
	}

	p := &provider{}
	p.snapshot.Store(Snapshot{File: config.GetFile(), Version: 1})

	return p, nil
}

func (p *provider) Current() Snapshot {
	v := p.snapshot.Load()
	if v == nil {
		return Snapshot{}
	}

	return v.(Snapshot)
}

func (p *provider) Reload() (Snapshot, error) {
	if err := config.ReloadConfigFile(); err != nil {
		return p.Current(), err
	}

	cur := p.Current()
	next := Snapshot{File: config.GetFile(), Version: cur.Version + 1}
	p.snapshot.Store(next)

	return next, nil
}
