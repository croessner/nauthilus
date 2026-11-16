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

package bruteforce

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// affectedAccountsMaintenanceActions counts lifecycle changes by action: armed, rearmed, adopted,
	// backfilled, extended, removed, index_restored, index_orphan_removed.
	affectedAccountsMaintenanceActions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bruteforce_affected_accounts_maintenance_total",
		Help: "Affected-account lifecycle changes made by the background maintenance, by action",
	}, []string{"action"})

	// affectedAccountsMaintenanceErrors counts failed or refused maintenance steps by step name.
	affectedAccountsMaintenanceErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bruteforce_affected_accounts_maintenance_errors_total",
		Help: "Failed or refused affected-account maintenance steps, by step",
	}, []string{"step"})

	// affectedAccountsMembers publishes the cardinality of the affected-account set, retention ZSET and index.
	affectedAccountsMembers = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bruteforce_affected_accounts_members",
		Help: "Members of the affected-account set, retention ZSET and index, refreshed by every instance per tick",
	}, []string{"key"})
)
