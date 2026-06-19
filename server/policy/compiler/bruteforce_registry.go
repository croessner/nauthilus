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

package compiler

import (
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

const bruteForceBucketConfigPath = "auth.controls.brute_force.buckets"

func registerGeneratedBruteForceBucketAttributes(
	file config.File,
	registry *policyregistry.AttributeRegistry,
) error {
	if file == nil || registry == nil {
		return nil
	}

	bruteForce := file.GetBruteForce()
	if bruteForce == nil {
		return nil
	}

	seen := make(map[string]string)

	for index, rule := range bruteForce.GetBuckets() {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			return configPathError(fmt.Sprintf("%s[%d].name", bruteForceBucketConfigPath, index), "must not be empty")
		}

		identifier := policy.IdentifierSegment(name)
		if previous, exists := seen[identifier]; exists {
			return configPathError(
				fmt.Sprintf("%s[%d].name", bruteForceBucketConfigPath, index),
				fmt.Sprintf("normalizes to policy identifier %q already used by bucket %q", identifier, previous),
			)
		}

		seen[identifier] = name

		if err := registerGeneratedAttributes(registry, generatedBruteForceBucketAttributes(identifier, name)); err != nil {
			return err
		}
	}

	return nil
}

func generatedBruteForceBucketAttributes(identifier string, name string) []policyregistry.AttributeDefinition {
	return []policyregistry.AttributeDefinition{
		generatedBruteForceBucketAttribute(identifier, name, "matched", policyregistry.AttributeTypeBool),
		generatedBruteForceBucketAttribute(identifier, name, "count", policyregistry.AttributeTypeNumber),
		generatedBruteForceBucketAttribute(identifier, name, "limit", policyregistry.AttributeTypeNumber),
		generatedBruteForceBucketAttribute(identifier, name, "effective_limit", policyregistry.AttributeTypeNumber),
		generatedBruteForceBucketAttribute(identifier, name, "remaining", policyregistry.AttributeTypeNumber),
		generatedBruteForceBucketAttribute(identifier, name, "ratio", policyregistry.AttributeTypeNumber),
		generatedBruteForceBucketAttribute(identifier, name, "over_limit", policyregistry.AttributeTypeBool),
		generatedBruteForceBucketAttribute(identifier, name, "already_banned", policyregistry.AttributeTypeBool),
		generatedBruteForceBucketAttribute(identifier, name, "repeating", policyregistry.AttributeTypeBool),
	}
}

func generatedBruteForceBucketAttribute(
	identifier string,
	name string,
	suffix string,
	valueType policyregistry.AttributeType,
) policyregistry.AttributeDefinition {
	return policyregistry.AttributeDefinition{
		ID:            policy.BruteForceBucketAttributeID(identifier, suffix),
		Description:   fmt.Sprintf("Brute-force bucket %q %s fact.", name, suffix),
		Stage:         policy.StagePreAuth,
		Operations:    []policy.Operation{policy.OperationAuthenticate},
		ProducerTypes: []string{policy.CheckTypeBruteForce},
		Category:      policyregistry.AttributeCategoryEnvironment,
		Type:          valueType,
		Source:        policyregistry.SourceBuiltin,
		Details:       generatedBruteForceBucketDetails(),
	}
}

func generatedBruteForceBucketDetails() map[string]policyregistry.DetailDefinition {
	return map[string]policyregistry.DetailDefinition{
		"rule":             {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"bucket_id":        {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"client_net":       {Type: policyregistry.AttributeTypeCIDR, Sensitivity: policyregistry.DetailSensitivityInternal},
		"matched":          {Type: policyregistry.AttributeTypeBool, Sensitivity: policyregistry.DetailSensitivityInternal},
		"over_limit":       {Type: policyregistry.AttributeTypeBool, Sensitivity: policyregistry.DetailSensitivityInternal},
		"already_banned":   {Type: policyregistry.AttributeTypeBool, Sensitivity: policyregistry.DetailSensitivityInternal},
		"repeating":        {Type: policyregistry.AttributeTypeBool, Sensitivity: policyregistry.DetailSensitivityInternal},
		"limit":            {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
		"effective_limit":  {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
		"remaining":        {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
		"ratio":            {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
		"period_seconds":   {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
		"ban_time_seconds": {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
		"cidr":             {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
	}
}
