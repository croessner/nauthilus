// Copyright (C) 2026 Christian Rößner
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

package main

import (
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/clickhousestore"
)

// historyConfigProvider is the narrow config surface of the support history wiring.
type historyConfigProvider interface {
	GetHistory() *config.HistorySection
}

// accountMappingResolver adapts the side-effect-free stored login mapping reader to the history service.
type accountMappingResolver struct {
	reader backend.AccountMappingReader
}

// ResolveLogins reads current stored mappings; it never authenticates, evaluates Policy, or writes.
func (r accountMappingResolver) ResolveLogins(ctx context.Context, logins []string) []supporthistory.IdentityMapping {
	lookups := r.reader.ReadMany(ctx, logins)
	mappings := make([]supporthistory.IdentityMapping, 0, len(lookups))

	for _, lookup := range lookups {
		mappings = append(mappings, supporthistory.IdentityMapping{Login: lookup.Username, Accounts: lookup.Accounts,
			Err: lookup.Err})
	}

	return mappings
}

// configuredBanPrefixes returns the IP families and prefix lengths of the configured brute-force rules.
func configuredBanPrefixes(cfg config.File) supporthistory.PrefixSource {
	return func() []supporthistory.Prefix {
		var prefixes []supporthistory.Prefix

		for _, rule := range cfg.GetBruteForce().GetBuckets() {
			if rule.IPv4 && rule.GetCIDR() <= 32 {
				prefixes = append(prefixes, supporthistory.Prefix{Family: 4, Bits: int(rule.GetCIDR())})
			}

			if rule.IPv6 {
				prefixes = append(prefixes, supporthistory.Prefix{Family: 6, Bits: int(rule.GetCIDR())})
			}
		}

		return prefixes
	}
}

// newSupportHistoryService builds the process-owned history service. It returns nil when no ClickHouse history
// source is configured or the reader cannot be built; the routes then answer HISTORY_NOT_CONFIGURED and
// authentication is unaffected.
func newSupportHistoryService(cfg config.File, redisClient rediscli.Client, logger *slog.Logger) *supporthistory.Service {
	provider, ok := cfg.(historyConfigProvider)
	if !ok {
		return nil
	}

	section := provider.GetHistory().GetClickHouse()
	if !section.IsEnabled() {
		return nil
	}

	store, err := clickhousestore.New(clickhousestore.Config{URL: section.GetURL(), Database: section.GetDatabase(),
		Username: section.GetUsername(), Password: section.GetPassword(), Deployment: section.GetDeployment(),
		Mode: clickhousestore.BudgetMode(section.GetBudgetMode()), Budget: clickhousestore.Budget{
			MaxExecutionTime: section.GetMaxExecutionTime(), MaxRowsToRead: section.GetMaxRowsToRead(),
			MaxBytesToRead: section.GetMaxBytesToRead(), MaxResponseBytes: section.GetMaxResponseBytes()}})
	if err != nil {
		_ = level.Error(logger).Log(definitions.LogKeyMsg, "Support history reader disabled", definitions.LogKeyError, err)

		return nil
	}

	options := supporthistory.Options{Attempts: store, Bans: store, Timeout: section.GetTimeout(),
		Audit: supporthistory.LogAuditRecorder{Logger: logger}, Prefixes: configuredBanPrefixes(cfg)}
	if redisClient != nil {
		options.Identity = accountMappingResolver{reader: backend.AccountMappingReader{Cfg: cfg, Redis: redisClient}}
	}

	service, err := supporthistory.NewService(options)
	if err != nil {
		_ = level.Error(logger).Log(definitions.LogKeyMsg, "Support history service disabled", definitions.LogKeyError, err)

		return nil
	}

	return service
}
