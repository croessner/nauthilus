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

package loopsfx

import (
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/app/redifx"
	"github.com/croessner/nauthilus/v4/server/bruteforce"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// AffectedAccountsMaintenanceService runs the bounded affected-account maintenance on a fixed interval.
// It reuses the generic ticker loop of StatsService without CPU measurement.
type AffectedAccountsMaintenanceService struct {
	loop *StatsService
}

// NewAffectedAccountsMaintenanceService wires the maintainer to the current configuration snapshot.
func NewAffectedAccountsMaintenanceService(cfgProvider configfx.Provider, logger *slog.Logger, redisClient redifx.Client) *AffectedAccountsMaintenanceService {
	maintainer := bruteforce.NewAffectedAccountsMaintainer(redisClient, logger)

	return &AffectedAccountsMaintenanceService{
		loop: NewStatsService(bruteforce.AffectedAccountsMaintenanceInterval, nil, func(ctx context.Context) {
			runAffectedAccountsMaintenance(ctx, cfgProvider, maintainer)
		}),
	}
}

// runAffectedAccountsMaintenance executes one tick when brute-force protection is enabled in the snapshot.
// The tick is bounded by the interval so a stalled Redis call never overlaps the next tick.
func runAffectedAccountsMaintenance(ctx context.Context, cfgProvider configfx.Provider, maintainer *bruteforce.AffectedAccountsMaintainer) {
	snap := cfgProvider.Current()
	if snap.File == nil || !snap.File.HasRuntimeModule(definitions.ControlBruteForce) {
		return
	}

	tickCtx, cancel := context.WithTimeout(ctx, bruteforce.AffectedAccountsMaintenanceInterval)
	defer cancel()

	// Errors are logged and counted by the maintainer; the next tick retries.
	_ = maintainer.RunOnce(tickCtx, snap.File)
}

// Start begins the maintenance loop.
func (s *AffectedAccountsMaintenanceService) Start(parent context.Context) error {
	return s.loop.Start(parent)
}

// Stop terminates the maintenance loop within the stop deadline.
func (s *AffectedAccountsMaintenanceService) Stop(stopCtx context.Context) error {
	return s.loop.Stop(stopCtx)
}
