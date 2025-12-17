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

package restartfx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/croessner/nauthilus/server/app/opsfx"

	"go.uber.org/fx"
)

// Manager coordinates an in-process restart operation.
//
// A restart is serialized via opsfx.Gate and then invokes all registered Restartable
// components in a deterministic order.
type Manager struct {
	gate         *opsfx.Gate
	logger       *slog.Logger
	restartables []Restartable
}

type managerIn struct {
	fx.In

	Gate   *opsfx.Gate
	Logger *slog.Logger

	Restartables []Restartable `group:"restartables"`
}

// NewManager constructs a restart Manager.
func NewManager(in managerIn) *Manager {
	rss := append([]Restartable(nil), in.Restartables...)
	sort.SliceStable(rss, func(i, j int) bool {
		if rss[i].Order() == rss[j].Order() {
			return rss[i].Name() < rss[j].Name()
		}

		return rss[i].Order() < rss[j].Order()
	})

	return &Manager{
		gate:         in.Gate,
		logger:       in.Logger,
		restartables: rss,
	}
}

// Restart performs one restart operation.
//
// Behavior:
//   - serialized (no overlap with other ops sharing the same gate)
//   - best-effort: continues restarting other components even if one fails
//   - returns an aggregated error (via errors.Join) if one or more components fail
func (m *Manager) Restart(ctx context.Context) error {
	return m.gate.WithLock(func() error {
		if m.logger != nil {
			m.logger.Info("in-process restart requested", slog.Int("restartables", len(m.restartables)))
		}

		var errs []error
		for _, r := range m.restartables {
			if r == nil {
				continue
			}

			if m.logger != nil {
				m.logger.Debug("restarting component", slog.String("component", r.Name()), slog.Int("order", r.Order()))
			}

			if err := r.Restart(ctx); err != nil {
				wrapped := fmt.Errorf("restartable %s restart failed: %w", r.Name(), err)
				errs = append(errs, wrapped)
				m.logger.Error("restart failed", slog.String("component", r.Name()), slog.Any("error", err))

				continue
			}

			if m.logger != nil {
				m.logger.Debug("restart succeeded", slog.String("component", r.Name()))
			}
		}

		return errors.Join(errs...)
	})
}
