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

package pluginruntime

import (
	"context"
	"sync"

	"github.com/croessner/nauthilus/v4/server/config"
)

// Reconfigurer hands configuration reloads to the process plugin runner.
//
// The policy coordinator is constructed before the runtime starts the runner, so the runner is
// attached later. Before the first attachment there is no running plugin state to reconfigure.
// After the runner was detached for shutdown, reloads are refused with ErrNotReady so that no
// plugin config change is accepted without reaching the plugins.
type Reconfigurer struct {
	runner   *Runner
	mu       sync.RWMutex
	detached bool
}

// NewReconfigurer returns a reconfigurer without an attached runner.
func NewReconfigurer() *Reconfigurer {
	return &Reconfigurer{}
}

// Attach makes runner the target of later reloads.
func (r *Reconfigurer) Attach(runner *Runner) {
	if r == nil {
		return
	}

	r.mu.Lock()
	r.runner = runner
	r.detached = false
	r.mu.Unlock()
}

// Detach removes runner as reload target when it is still attached.
func (r *Reconfigurer) Detach(runner *Runner) {
	if r == nil {
		return
	}

	r.mu.Lock()
	if r.runner == runner {
		r.runner = nil
		r.detached = true
	}
	r.mu.Unlock()
}

// PrepareReconfigure validates a candidate against the attached runner.
func (r *Reconfigurer) PrepareReconfigure(ctx context.Context, file config.File) (*ReconfigurePlan, error) {
	if r == nil {
		return nil, nil
	}

	r.mu.RLock()
	runner, detached := r.runner, r.detached
	r.mu.RUnlock()

	if detached {
		return nil, ErrNotReady
	}

	return runner.PrepareReconfigure(ctx, file)
}
