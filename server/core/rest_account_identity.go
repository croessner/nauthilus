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

package core

import (
	"context"
	stderrors "errors"
	"fmt"
	"slices"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	bf "github.com/croessner/nauthilus/v4/server/model/bruteforce"
	"github.com/croessner/nauthilus/v4/server/util"
)

const (
	// bruteForceAccountResolutionMaxNames bounds the login names one mapping-resolved listing may resolve.
	bruteForceAccountResolutionMaxNames = 100
	bruteForceAccountResolutionField    = "account_resolution"
)

// errAccountMappingLookup marks a cache flush that could not read the stored account mappings.
var errAccountMappingLookup = stderrors.New("account mapping lookup failed")

// accountMappingReader is the read-only identity resolution shared by the brute-force list and the
// cache flush. Implementations must not write state, count requests, or run hooks.
type accountMappingReader interface {
	ReadMany(ctx context.Context, usernames []string) []backend.AccountMappingLookup
}

// effectiveAccountMappingReader returns the injected reader or the Redis-backed production reader.
func (deps restAdminDeps) effectiveAccountMappingReader() accountMappingReader {
	if deps.AccountMappings != nil {
		return deps.AccountMappings
	}

	return backend.AccountMappingReader{Cfg: deps.effectiveCfg(), Redis: deps.effectiveRedis()}
}

// readAccountMappings resolves stored account mappings for names within one Redis read deadline.
func readAccountMappings(ctx context.Context, deps restAdminDeps, names []string) []backend.AccountMappingLookup {
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, deps.effectiveCfg())
	defer cancel()

	return deps.effectiveAccountMappingReader().ReadMany(dCtx, names)
}

// validateBruteForceAccountResolution checks the requested account resolution mode and its cost bound.
func validateBruteForceAccountResolution(filterCmd *bf.FilterCmd) error {
	if filterCmd == nil {
		return nil
	}

	switch filterCmd.AccountResolution {
	case "", bf.AccountResolutionNone:
		return nil
	case bf.AccountResolutionAccountMapping:
	default:
		return fmt.Errorf("unsupported value %q; use %q or %q",
			filterCmd.AccountResolution, bf.AccountResolutionNone, bf.AccountResolutionAccountMapping)
	}

	names := uniqueStrings(filterCmd.Accounts)
	if len(names) == 0 {
		return fmt.Errorf("%q requires at least one account", bf.AccountResolutionAccountMapping)
	}

	if len(names) > bruteForceAccountResolutionMaxNames {
		return fmt.Errorf("%q accepts at most %d distinct accounts", bf.AccountResolutionAccountMapping, bruteForceAccountResolutionMaxNames)
	}

	return nil
}

// mappedAccountListing is the outcome of one mapping-resolved account filter.
type mappedAccountListing struct {
	err         error
	accounts    []string
	resolutions []bf.AccountResolution
	hasMore     bool
}

// listMappedBlockedAccountNames resolves each requested login name through the stored account mappings,
// checks the literal name and every mapped account, and pages the matched union.
//
// The literal name is always checked, so state stored under a canonical name, a removed user, or an
// older key layout stays visible even when no mapping exists.
func listMappedBlockedAccountNames(
	ctx context.Context,
	deps restAdminDeps,
	wantedAccounts []string,
	key string,
	pageQuery bruteForceListPageQuery,
) mappedAccountListing {
	names := uniqueStrings(wantedAccounts)
	resolutions := newAccountResolutions(readAccountMappings(ctx, deps, names))

	members, err := readAffectedAccountMembers(ctx, deps, key, checkedAccountNames(resolutions))
	if err != nil {
		return mappedAccountListing{err: err, resolutions: resolutions}
	}

	matched := applyAffectedAccountMembers(resolutions, members)
	listing := mappedAccountListing{err: resolutionError(resolutions), resolutions: resolutions}

	listing.accounts, listing.hasMore, _ = pageStringSlice(matched, pageQuery)

	return listing
}

// newAccountResolutions turns mapping lookups into per-name resolutions with their checked names.
func newAccountResolutions(lookups []backend.AccountMappingLookup) []bf.AccountResolution {
	resolutions := make([]bf.AccountResolution, len(lookups))

	for index, lookup := range lookups {
		resolution := bf.AccountResolution{
			Input:    lookup.Username,
			Source:   bf.AccountResolutionAccountMapping,
			Accounts: lookup.Accounts,
			Checked:  uniqueStrings(append([]string{lookup.Username}, lookup.Accounts...)),
			Matched:  []string{},
			Status:   accountResolutionStatus(lookup),
		}

		if lookup.Err != nil {
			errMsg := lookup.Err.Error()
			resolution.Error = &errMsg
		}

		resolutions[index] = resolution
	}

	return resolutions
}

// accountResolutionStatus classifies one mapping lookup without claiming backend-verified identity.
func accountResolutionStatus(lookup backend.AccountMappingLookup) string {
	switch {
	case lookup.Err != nil:
		return bf.AccountResolutionStatusError
	case len(lookup.Accounts) == 0:
		return bf.AccountResolutionStatusUnmapped
	case len(lookup.Accounts) == 1:
		return bf.AccountResolutionStatusMapped
	default:
		return bf.AccountResolutionStatusAmbiguous
	}
}

// checkedAccountNames returns the deduplicated union of all checked names in first-seen order.
func checkedAccountNames(resolutions []bf.AccountResolution) []string {
	names := make([]string, 0, len(resolutions))
	for _, resolution := range resolutions {
		names = append(names, resolution.Checked...)
	}

	return uniqueStrings(names)
}

// applyAffectedAccountMembers fills per-name matches and returns the matched union in first-seen order.
func applyAffectedAccountMembers(resolutions []bf.AccountResolution, members []string) []string {
	matched := make([]string, 0, len(members))

	for index := range resolutions {
		resolution := &resolutions[index]

		for _, name := range resolution.Checked {
			if !slices.Contains(members, name) {
				continue
			}

			resolution.Matched = append(resolution.Matched, name)
			matched = append(matched, name)
		}

		resolution.LiteralMatch = slices.Contains(resolution.Matched, resolution.Input)
	}

	return uniqueStrings(matched)
}

// resolutionError joins the technical failures of all undecided names.
func resolutionError(resolutions []bf.AccountResolution) error {
	var errs []error

	for _, resolution := range resolutions {
		if resolution.Error != nil {
			errs = append(errs, fmt.Errorf("%w for %q: %s", errAccountMappingLookup, resolution.Input, *resolution.Error))
		}
	}

	return stderrors.Join(errs...)
}

// userFlushFailureMessage maps a synchronous cache-flush failure to its operator-facing message.
func userFlushFailureMessage(err error) string {
	if stderrors.Is(err, errAccountMappingLookup) {
		return "Account mapping lookup failed"
	}

	return "Identity cache invalidation failed"
}

// collectUserAccountMappings returns the accounts and owned hash fields stored for one login name.
//
// It uses the same read-only resolver as the brute-force list. A read failure is returned instead of
// being swallowed, so a flush cannot report success while the canonical account was never resolved.
func collectUserAccountMappings(ctx context.Context, deps restAdminDeps, username string) (config.StringSet, config.StringSet, error) {
	accountNames := config.NewStringSet()
	fields := config.NewStringSet()
	lookup := readAccountMappings(ctx, deps, []string{username})[0]

	if lookup.Err != nil {
		return accountNames, fields, fmt.Errorf("%w for %q: %w", errAccountMappingLookup, username, lookup.Err)
	}

	for _, field := range lookup.Fields {
		fields.Set(field)
	}

	for _, accountName := range lookup.Accounts {
		accountNames.Set(accountName)
	}

	return accountNames, fields, nil
}
