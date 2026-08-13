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

	"github.com/croessner/nauthilus/v3/server/config"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
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

// Reloader extends Provider with candidate-only configuration preparation.
type Reloader interface {
	Provider

	Prepare() (Snapshot, error)
}

type provider struct {
	generations *policyruntime.GenerationStore
	snapshot    atomic.Value // stores Snapshot only before generation ownership is available
}

var _ Reloader = (*provider)(nil)

// NewProviderWithSnapshot constructs a Provider from a specific config.File instance.
func NewProviderWithSnapshot(file config.File) Provider {
	p := &provider{}
	p.snapshot.Store(Snapshot{File: file, Version: 1})

	return p
}

// NewProvider constructs a Provider from an already loaded global config.
//
// It does not load configuration itself; the legacy startup path still calls `config.NewFile()`.
func NewProvider() (Reloader, error) {
	generations := policyruntime.DefaultGenerationStore()
	if generations.Active() == nil && !config.IsFileLoaded() {
		return nil, config.ErrConfigNotLoaded{}
	}

	p := &provider{generations: generations}
	if generations.Active() == nil {
		p.snapshot.Store(Snapshot{File: config.GetFile(), Version: 1})
	}

	return p, nil
}

// Current captures config and version through one generation load when available.
func (p *provider) Current() Snapshot {
	if p != nil && p.generations != nil {
		if generation := p.generations.Active(); generation != nil {
			return Snapshot{File: generation.Config(), Version: generation.ID()}
		}
	}

	v := p.snapshot.Load()
	if v == nil {
		return Snapshot{}
	}

	return v.(Snapshot)
}

// Prepare decodes and validates the next config without publishing any state.
func (p *provider) Prepare() (Snapshot, error) {
	cur := p.Current()

	candidate, err := config.PrepareFile()
	if err != nil {
		return cur, err
	}

	next := Snapshot{File: candidate, Version: cur.Version + 1}

	return next, nil
}
