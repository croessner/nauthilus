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
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
)

// Affected-account lifecycle keys. The set S is the membership, the index I keeps first-seen scores for paged
// listings, the retention ZSET L keeps one retain-until deadline per account, and the state hash M keeps the
// maintenance heartbeat and cursors. L and M are slot siblings of S, so scripts can update S and L atomically
// in Redis Cluster. I lives in its own slot and is only ever updated best-effort and repaired.
const (
	affectedAccountsStateSuffix = "maintenance"
	affectedAccountsLeaseSuffix = "maintenance:lease"
)

// AffectedAccountKeys holds the Redis keys of the affected-account lifecycle for one prefix.
type AffectedAccountKeys struct {
	Set       string
	Index     string
	Retention string
	State     string
	Lease     string
}

// NewAffectedAccountKeys builds the lifecycle keys. It fails with rediscli.ErrNoSlotSibling when the prefix
// makes a same-slot retention key impossible; callers must then skip retention writes and maintenance.
func NewAffectedAccountKeys(prefix string) (AffectedAccountKeys, error) {
	keys := AffectedAccountKeys{
		Set:   rediscli.GetAffectedAccountsKey(prefix),
		Index: rediscli.GetAffectedAccountsIndexKey(prefix),
	}

	var err error

	if keys.Retention, err = rediscli.GetAffectedAccountsRetentionKey(prefix); err != nil {
		return keys, err
	}

	if keys.State, err = rediscli.SlotSiblingKey(prefix, keys.Set, affectedAccountsStateSuffix); err != nil {
		return keys, err
	}

	keys.Lease, err = rediscli.SlotSiblingKey(prefix, keys.Set, affectedAccountsLeaseSuffix)

	return keys, err
}

// AffectedAccountRetention returns R, the minimum time an affected account stays listed after the last
// activity that refreshed its deadline.
//
// R is a visibility policy: the configured retention (default 24h), raised to the longest lifetime of the
// brute-force state that one failed or blocked request can write (password history, RWP window, ban time plus
// two bucket periods, and toleration TTLs). Bans, counters, and toleration are IP or network keyed and cannot
// be mapped back to an account, so they are never checked per account; the cleanup never touches them.
func AffectedAccountRetention(cfg config.File) time.Duration {
	bfCfg := cfg.GetBruteForce()
	retention := max(
		bfCfg.GetAffectedAccountsRetention(),
		cfg.GetServer().GetRedis().GetNegCacheTTL(),
		bfCfg.GetRWPWindow(),
		bfCfg.GetTolerateTTL(),
	)

	var maxBanTime, maxPeriod time.Duration

	for _, rule := range cfg.GetBruteForceRules() {
		maxBanTime = max(maxBanTime, rule.GetBanTime())
		maxPeriod = max(maxPeriod, rule.GetPeriod())
	}

	retention = max(retention, maxBanTime+2*maxPeriod)

	for _, toleration := range bfCfg.GetCustomTolerations() {
		retention = max(retention, toleration.GetTolerateTTL())
	}

	return retention
}

// affectedAccountDeadline returns the retain-until score for activity observed at now.
func affectedAccountDeadline(now time.Time, retention time.Duration) float64 {
	return float64(now.Add(retention).Unix())
}
