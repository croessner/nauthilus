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

	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/app/opsfx"

	"go.uber.org/fx"
)

// Manager coordinates a configuration reload.
//
// A reload is serialized via opsfx.Gate, prepares config off-side, commits the complete
// policy generation, and then calls non-policy Reloadable components in deterministic order.
type Manager struct {
	gate        *opsfx.Gate
	reloader    configfx.Reloader
	coordinator GenerationCoordinator
	logger      *slog.Logger
	reloadables []Reloadable
}

type managerIn struct {
	fx.In

	Gate        *opsfx.Gate
	Reloader    configfx.Reloader
	Coordinator GenerationCoordinator
	Logger      *slog.Logger

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
		coordinator: in.Coordinator,
		logger:      in.Logger,
		reloadables: rls,
	}
}

// Reload performs one reload operation.
//
// Behavior:
//   - serialized (no overlap with other ops sharing the same gate)
//   - fail-closed before the atomic policy generation commit
//   - best-effort for non-policy components after the commit
//   - returns an aggregated error (via errors.Join) if one or more components fail
func (m *Manager) Reload(ctx context.Context) error {
	return m.gate.WithLock(func() error {
		prev := m.reloader.Current()
		errs := make([]error, 0)

		snap, err := m.reloader.Prepare()
		if err != nil {
			m.logger.Error("configuration candidate preparation failed", slog.Any("error", err))
			return err
		}

		ctx = WithPreviousSnapshot(ctx, prev)
		if err = m.applyGeneration(ctx, snap); err != nil && !generationCommitted(err) {
			return err
		} else if err != nil {
			errs = append(errs, err)
		}

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

// applyGeneration publishes one complete candidate and records whether failure occurred before or after commit.
func (m *Manager) applyGeneration(ctx context.Context, snap configfx.Snapshot) error {
	err := m.coordinator.Apply(ctx, snap)
	if err == nil {
		return nil
	}

	message := "policy runtime generation commit failed"
	if generationCommitted(err) {
		message = "policy runtime generation committed with retirement failure"
	}

	m.logger.Error(
		message,
		slog.Uint64("runtime_generation", snap.Version),
		slog.Any("error", err),
	)

	return err
}

// generationCommitted distinguishes post-publication failures from rejected candidates.
func generationCommitted(err error) bool {
	var committed interface {
		GenerationCommitted() bool
	}

	return errors.As(err, &committed) && committed.GenerationCommitted()
}
