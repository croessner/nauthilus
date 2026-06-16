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

package pluginapi

import "context"

// PolicyStage identifies a policy evaluation checkpoint.
type PolicyStage string

const (
	// PolicyStagePreAuth covers checks that run before backend authentication.
	PolicyStagePreAuth PolicyStage = "pre_auth"

	// PolicyStageAuthBackend covers backend and password evaluation facts.
	PolicyStageAuthBackend PolicyStage = "auth_backend"

	// PolicyStageSubjectAnalysis covers subject analysis after backend evaluation.
	PolicyStageSubjectAnalysis PolicyStage = "subject_analysis"

	// PolicyStageAccountProvider covers account-list provider facts.
	PolicyStageAccountProvider PolicyStage = "account_provider"

	// PolicyStageAuthDecision covers final auth result selection.
	PolicyStageAuthDecision PolicyStage = "auth_decision"
)

// PolicyOperation identifies the request operation evaluated by policy code.
type PolicyOperation string

const (
	// PolicyOperationAuthenticate is normal password authentication.
	PolicyOperationAuthenticate PolicyOperation = "authenticate"

	// PolicyOperationLookupIdentity is trusted identity lookup without password verification.
	PolicyOperationLookupIdentity PolicyOperation = "lookup_identity"

	// PolicyOperationListAccounts is account-list provider evaluation.
	PolicyOperationListAccounts PolicyOperation = "list_accounts"
)

// PolicyDecision is a transport-independent policy effect.
type PolicyDecision string

const (
	// PolicyDecisionNeutral allows the current stage to continue.
	PolicyDecisionNeutral PolicyDecision = "neutral"

	// PolicyDecisionDeny rejects the current operation.
	PolicyDecisionDeny PolicyDecision = "deny"

	// PolicyDecisionPermit permits the current operation where the stage allows it.
	PolicyDecisionPermit PolicyDecision = "permit"

	// PolicyDecisionTempFail reports a temporary failure for the current operation.
	PolicyDecisionTempFail PolicyDecision = "tempfail"
)

// AttributeType describes the declared value type of a policy attribute or detail.
type AttributeType string

const (
	// AttributeTypeBool identifies boolean attribute values.
	AttributeTypeBool AttributeType = "bool"

	// AttributeTypeString identifies string attribute values.
	AttributeTypeString AttributeType = "string"

	// AttributeTypeStringList identifies string-list attribute values.
	AttributeTypeStringList AttributeType = "string_list"

	// AttributeTypeNumber identifies numeric attribute values.
	AttributeTypeNumber AttributeType = "number"

	// AttributeTypeIP identifies IP address attribute values.
	AttributeTypeIP AttributeType = "ip"

	// AttributeTypeCIDR identifies CIDR attribute values.
	AttributeTypeCIDR AttributeType = "cidr"

	// AttributeTypeDateTime identifies datetime attribute values.
	AttributeTypeDateTime AttributeType = "datetime"
)

// AttributeCategory identifies the XACML-style attribute category.
type AttributeCategory string

const (
	// AttributeCategoryEnvironment identifies environment attributes.
	AttributeCategoryEnvironment AttributeCategory = "environment"

	// AttributeCategorySubject identifies subject attributes.
	AttributeCategorySubject AttributeCategory = "subject"

	// AttributeCategoryResource identifies resource attributes.
	AttributeCategoryResource AttributeCategory = "resource"
)

// DetailSensitivity describes how policy detail values may be exposed.
type DetailSensitivity string

const (
	// DetailSensitivityPublic marks detail values safe for selected public output.
	DetailSensitivityPublic DetailSensitivity = "public"

	// DetailSensitivityInternal marks detail values for internal diagnostics.
	DetailSensitivityInternal DetailSensitivity = "internal"

	// DetailSensitivitySecret marks detail values that must never be exposed.
	DetailSensitivitySecret DetailSensitivity = "secret"
)

// DetailDefinition describes a typed policy attribute detail.
type DetailDefinition struct {
	Type        AttributeType
	Sensitivity DetailSensitivity
	Purpose     string
	MaxLength   int
}

// AttributeDefinition describes one policy attribute registered by a plugin.
type AttributeDefinition struct {
	Details       map[string]DetailDefinition
	ID            string
	Description   string
	Stage         PolicyStage
	Operations    []PolicyOperation
	ProducerTypes []string
	ProducerCheck string
	Category      AttributeCategory
	Type          AttributeType
}

// Policy exposes policy attribute registration and fact emission.
type Policy interface {
	RegisterAttribute(AttributeDefinition) error
	Emit(context.Context, PolicyFact) error
}
