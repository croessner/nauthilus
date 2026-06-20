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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

const rblListConfigPath = "auth.controls.rbl.lists"

func registerGeneratedRBLListAttributes(
	file config.File,
	registry *policyregistry.AttributeRegistry,
) error {
	if file == nil || registry == nil {
		return nil
	}

	rblSection := file.GetRBLs()
	if rblSection == nil {
		return nil
	}

	return registerGeneratedNamedAttributes(
		registry,
		rblSection.GetLists(),
		rblListConfigPath,
		"RBL list",
		func(rbl config.RBL) string { return rbl.Name },
		generatedRBLListAttributes,
	)
}

func generatedRBLListAttributes(identifier string, name string) []policyregistry.AttributeDefinition {
	return []policyregistry.AttributeDefinition{
		generatedRBLListAttribute(identifier, name, "listed", policyregistry.AttributeTypeBool),
		generatedRBLListAttribute(identifier, name, "weight", policyregistry.AttributeTypeNumber),
		generatedRBLListAttribute(identifier, name, "error", policyregistry.AttributeTypeBool),
		generatedRBLListAttribute(identifier, name, "allow_failure", policyregistry.AttributeTypeBool),
	}
}

func generatedRBLListAttribute(
	identifier string,
	name string,
	suffix string,
	valueType policyregistry.AttributeType,
) policyregistry.AttributeDefinition {
	return policyregistry.AttributeDefinition{
		ID:            policy.RBLListAttributeID(identifier, suffix),
		Description:   fmt.Sprintf("RBL list %q %s fact.", name, suffix),
		Stage:         policy.StagePreAuth,
		Operations:    []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
		ProducerTypes: []string{policy.CheckTypeRBL},
		Category:      policyregistry.AttributeCategoryEnvironment,
		Type:          valueType,
		Source:        policyregistry.SourceBuiltin,
		Details:       generatedRBLListDetails(),
	}
}

func generatedRBLListDetails() map[string]policyregistry.DetailDefinition {
	return map[string]policyregistry.DetailDefinition{
		"list":           {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"list_id":        {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"host":           {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"query":          {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"return_code":    {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		detailReasonCode: {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"ip_family":      {Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityInternal},
		"listed":         {Type: policyregistry.AttributeTypeBool, Sensitivity: policyregistry.DetailSensitivityInternal},
		"error":          {Type: policyregistry.AttributeTypeBool, Sensitivity: policyregistry.DetailSensitivityInternal},
		"allow_failure":  {Type: policyregistry.AttributeTypeBool, Sensitivity: policyregistry.DetailSensitivityInternal},
		"weight":         {Type: policyregistry.AttributeTypeNumber, Sensitivity: policyregistry.DetailSensitivityInternal},
	}
}
