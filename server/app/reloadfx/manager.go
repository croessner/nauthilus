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

package reloadfx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/opsfx"

	"go.uber.org/fx"
)

// Manager coordinates a configuration reload.
//
// A reload is serialized via opsfx.Gate, swaps the config snapshot via configfx.Reloader,
// and then calls all registered Reloadable components in a deterministic order.
type Manager struct {
	gate        *opsfx.Gate
	reloader    configfx.Reloader
	logger      *slog.Logger
	reloadables []Reloadable
}

type managerIn struct {
	fx.In

	Gate     *opsfx.Gate
	Reloader configfx.Reloader
	Logger   *slog.Logger

	Reloadables []Reloadable `group:"reloadables"`
}

// NewManager constructs a reload Manager.
func NewManager(in managerIn) *Manager {
	rls := append([]Reloadable(nil), in.Reloadables...)
	sort.SliceStable(rls, func(i, j int) bool {
		if rls[i].Order() == rls[j].Order() {
			return rls[i].Name() < rls[j].Name()
		}

		return rls[i].Order() < rls[j].Order()
	})

	return &Manager{
		gate:        in.Gate,
		reloader:    in.Reloader,
		logger:      in.Logger,
		reloadables: rls,
	}
}

// Reload performs one reload operation.
//
// Behavior:
//   - serialized (no overlap with other ops sharing the same gate)
//   - best-effort: continues applying config even if a component fails
//   - returns an aggregated error (via errors.Join) if one or more components fail
func (m *Manager) Reload(ctx context.Context) error {
	return m.gate.WithLock(func() error {
		prev := m.reloader.Current()

		snap, err := m.reloader.Reload()
		if err != nil {
			m.logger.Error("configuration reload failed", slog.Any("error", err))
			return err
		}

		ctx = WithPreviousSnapshot(ctx, prev)

		var errs []error
		for _, r := range m.reloadables {
			if r == nil {
				continue
			}

			if err := r.ApplyConfig(ctx, snap); err != nil {
				wrapped := fmt.Errorf("reloadable %s apply config failed: %w", r.Name(), err)
				errs = append(errs, wrapped)
				m.logger.Error("apply config failed", slog.String("component", r.Name()), slog.Any("error", err))
			}
		}

		return errors.Join(errs...)
	})
}
