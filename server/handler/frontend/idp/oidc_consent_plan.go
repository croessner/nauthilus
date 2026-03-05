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

package idp

import (
	"fmt"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
)

type consentScopePlan struct {
	Mode      string
	Requested []string
	Required  []string
	Optional  []string
}

func buildConsentScopePlan(client *config.OIDCClient, globalMode string, requested []string) consentScopePlan {
	mode := strings.ToLower(strings.TrimSpace(globalMode))
	if mode != config.OIDCConsentModeGranularOptional {
		mode = config.OIDCConsentModeAllOrNothing
	}

	if client != nil {
		mode = client.GetConsentMode(globalMode)
	}

	normalizedRequested := uniqueScopes(requested)
	plan := consentScopePlan{
		Mode:      mode,
		Requested: normalizedRequested,
	}

	if mode != config.OIDCConsentModeGranularOptional {
		plan.Required = normalizedRequested

		return plan
	}

	var requiredScopes []string
	var optionalScopes []string
	if client != nil {
		requiredScopes = uniqueScopes(client.RequiredScopes)
		optionalScopes = uniqueScopes(client.OptionalScopes)
	}

	if !slices.Contains(requiredScopes, definitions.ScopeOpenId) {
		requiredScopes = append(requiredScopes, definitions.ScopeOpenId)
	}

	requiredMap := scopeToSet(requiredScopes)
	optionalMap := scopeToSet(optionalScopes)
	hasOptionalWhitelist := len(optionalMap) > 0

	for _, scope := range normalizedRequested {
		switch {
		case scope == definitions.ScopeOpenId:
			plan.Required = append(plan.Required, scope)
		case requiredMap[scope]:
			plan.Required = append(plan.Required, scope)
		case hasOptionalWhitelist && !optionalMap[scope]:
			// Explicitly configured optional scopes act as whitelist.
			// Everything else remains required for compatibility.
			plan.Required = append(plan.Required, scope)
		default:
			plan.Optional = append(plan.Optional, scope)
		}
	}

	return plan
}

func (p consentScopePlan) ResolveGranted(selectedOptional []string) ([]string, error) {
	if p.Mode != config.OIDCConsentModeGranularOptional {
		return p.Requested, nil
	}

	requiredMap := scopeToSet(p.Required)
	optionalMap := scopeToSet(p.Optional)
	selectedMap := scopeToSet(uniqueScopes(selectedOptional))

	for selected := range selectedMap {
		if !optionalMap[selected] {
			return nil, fmt.Errorf("invalid optional scope selection: %s", selected)
		}
	}

	granted := make([]string, 0, len(p.Requested))

	for _, scope := range p.Requested {
		if requiredMap[scope] || selectedMap[scope] {
			granted = append(granted, scope)
		}
	}

	return granted, nil
}

func uniqueScopes(scopes []string) []string {
	unique := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))

	for _, scope := range scopes {
		normalized := strings.TrimSpace(scope)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}

		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}

	return unique
}

func scopeToSet(scopes []string) map[string]bool {
	set := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		set[scope] = true
	}

	return set
}
