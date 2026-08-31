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

package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/presentation"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/croessner/nauthilus/v4/server/policy/report"
)

// StandardAuthFacts projects request-local host observations into the captured catalog vocabulary.
func (e *authnCandidateExecution) StandardAuthFacts(
	_ context.Context,
	target decision.Target,
	checkpoint string,
) (decision.FactSet, error) {
	if e == nil || e.auth == nil || target.Action() != string(e.operation) ||
		(checkpoint != string(policy.StagePreAuth) && checkpoint != string(policy.StageAuthDecision)) {
		return decision.NewFactSet(nil)
	}

	policyCtx := existingPolicyContext(e.ginCtx)
	if policyCtx == nil {
		return decision.NewFactSet(nil)
	}

	policyReport := policyCtx.Report()

	attributeIDs := make([]string, 0, len(policyReport.Attributes))
	for attributeID := range policyReport.Attributes {
		attributeIDs = append(attributeIDs, attributeID)
	}

	sort.Strings(attributeIDs)

	facts := make([]decision.Fact, 0, len(attributeIDs))
	for _, attributeID := range attributeIDs {
		attribute := policyReport.Attributes[attributeID]
		definition, exists := policyCtx.AttributeDefinition(attributeID)

		if !exists || !authnAttributeApplies(attribute, definition, e.operation, checkpoint) {
			continue
		}

		projected, err := authnPolicyAttributeFacts(attribute, definition)
		if err != nil {
			return decision.FactSet{}, fmt.Errorf("project authn attribute %s: %w", attributeID, err)
		}

		facts = append(facts, projected...)
	}

	return decision.NewFactSet(facts)
}

// authnAttributeApplies restricts projection to the active operation and reached semantic stages.
func authnAttributeApplies(
	attribute report.AttributeValue,
	definition policyregistry.AttributeDefinition,
	operation policy.Operation,
	checkpoint string,
) bool {
	if attribute.Operation != "" && attribute.Operation != operation {
		return false
	}

	if len(definition.Operations) > 0 && !slices.Contains(definition.Operations, operation) {
		return false
	}

	return checkpoint != string(policy.StagePreAuth) || attribute.Stage == policy.StagePreAuth
}

// authnPolicyAttributeFacts projects one admitted attribute and its selected public response detail.
func authnPolicyAttributeFacts(
	attribute report.AttributeValue,
	definition policyregistry.AttributeDefinition,
) ([]decision.Fact, error) {
	factID, authority, exists := policy.AuthnCanonicalFactIdentity(attribute.ID, string(definition.Source))
	if !exists {
		return nil, nil
	}

	category, err := authnPolicyFactCategory(definition.Category)
	if err != nil {
		return nil, err
	}

	value, err := authnPolicyFactValue(definition.Type, attribute.Value)
	if err != nil {
		return nil, err
	}

	provenance, err := authnPolicyFactProvenance(definition, authority)
	if err != nil {
		return nil, err
	}

	fact, err := decision.NewFact(factID, category, value, provenance)
	if err != nil {
		return nil, err
	}

	detailFacts, err := authnPolicyResponseDetailFacts(attribute, definition, factID, category, provenance)
	if err != nil {
		return nil, err
	}

	return append([]decision.Fact{fact}, detailFacts...), nil
}

// authnPolicyResponseDetailFacts projects public details in deterministic registry order.
func authnPolicyResponseDetailFacts(
	attribute report.AttributeValue,
	definition policyregistry.AttributeDefinition,
	factID string,
	category decision.FactCategory,
	provenance decision.Provenance,
) ([]decision.Fact, error) {
	detailNames := make([]string, 0, len(definition.Details))
	for detailName := range definition.Details {
		detailNames = append(detailNames, detailName)
	}

	sort.Strings(detailNames)

	result := make([]decision.Fact, 0, len(detailNames)*3)
	for _, detailName := range detailNames {
		detailDefinition := definition.Details[detailName]
		detail, present := attribute.Details[detailName]

		if !present || !authnPublicResponseDetail(detailDefinition, detail) {
			continue
		}

		facts, err := authnPolicyResponseDetailFactSet(
			factID,
			detailName,
			detailDefinition,
			detail,
			category,
			provenance,
		)
		if err != nil {
			return nil, err
		}

		result = append(result, facts...)
	}

	return result, nil
}

// authnPolicyResponseDetailFactSet constructs text, truncation, and raw-selection facts.
func authnPolicyResponseDetailFactSet(
	factID string,
	detailName string,
	definition policyregistry.DetailDefinition,
	detail report.DetailValue,
	category decision.FactCategory,
	provenance decision.Provenance,
) ([]decision.Fact, error) {
	text, ok := detail.Value.(string)
	if !ok {
		return nil, fmt.Errorf("public response detail %s is not a string", detailName)
	}

	selected := strings.TrimSpace(text) != ""
	maxLength := definition.MaxLength

	if maxLength <= 0 {
		maxLength = 256
	}

	text, truncated := presentation.SanitizeResponseMessageWithState(text, maxLength)

	detailValue, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		return nil, err
	}

	truncatedValue, err := decision.NewValue(decision.ValueInput{Boolean: &truncated})
	if err != nil {
		return nil, err
	}

	selectedValue, err := decision.NewValue(decision.ValueInput{Boolean: &selected})
	if err != nil {
		return nil, err
	}

	return authnPolicyResponseDetailMetadataFacts(
		factID,
		detailName,
		category,
		provenance,
		detailValue,
		truncatedValue,
		selectedValue,
	)
}

// authnPolicyResponseDetailMetadataFacts binds the three strict detail values to canonical IDs.
func authnPolicyResponseDetailMetadataFacts(
	factID string,
	detailName string,
	category decision.FactCategory,
	provenance decision.Provenance,
	detailValue decision.Value,
	truncatedValue decision.Value,
	selectedValue decision.Value,
) ([]decision.Fact, error) {
	inputs := []struct {
		id    string
		value decision.Value
	}{
		{id: policy.AuthnResponseDetailFactID(factID, detailName), value: detailValue},
		{id: policy.AuthnResponseDetailTruncatedFactID(factID, detailName), value: truncatedValue},
		{id: policy.AuthnResponseDetailSelectedFactID(factID, detailName), value: selectedValue},
	}

	result := make([]decision.Fact, 0, len(inputs))
	for _, input := range inputs {
		fact, err := decision.NewFact(input.id, category, input.value, provenance)
		if err != nil {
			return nil, err
		}

		result = append(result, fact)
	}

	return result, nil
}

// authnPublicResponseDetail requires both compiled and emitted metadata to authorize disclosure.
func authnPublicResponseDetail(
	definition policyregistry.DetailDefinition,
	detail report.DetailValue,
) bool {
	return definition.Type == policyregistry.AttributeTypeString &&
		definition.Sensitivity == policyregistry.DetailSensitivityPublic &&
		definition.Purpose == policyregistry.DetailPurposeResponseMessage &&
		detail.Sensitivity == report.SensitivityPublic &&
		detail.Purpose == report.PurposeResponseMessage
}

// authnPolicyFactCategory maps the captured registry category into the closed Decision Service category.
func authnPolicyFactCategory(category policyregistry.AttributeCategory) (decision.FactCategory, error) {
	switch category {
	case policyregistry.AttributeCategoryEnvironment:
		return decision.FactCategoryEnvironment, nil
	case policyregistry.AttributeCategorySubject:
		return decision.FactCategorySubject, nil
	case policyregistry.AttributeCategoryResource:
		return decision.FactCategoryResource, nil
	default:
		return "", fmt.Errorf("unsupported category %q", category)
	}
}

// authnPolicyFactProvenance preserves the captured source and host-assigned provider authority.
func authnPolicyFactProvenance(
	definition policyregistry.AttributeDefinition,
	authority string,
) (decision.Provenance, error) {
	var source decision.FactSource

	switch definition.Source {
	case policyregistry.SourceBuiltin:
		source = decision.FactSourceNauthilus
	case policyregistry.SourceLua:
		source = decision.FactSourceLua
	case policyregistry.SourcePlugin:
		source = decision.FactSourcePlugin
	default:
		return decision.Provenance{}, fmt.Errorf("unsupported source %q", definition.Source)
	}

	component := definition.ProducerCheck
	if component == "" && len(definition.ProducerTypes) > 0 {
		component = definition.ProducerTypes[0]
	}

	if component == "" {
		component = "auth-policy"
	}

	return decision.NewProvenance(source, authority, component)
}

// authnPolicyFactValue converts one registry-declared runtime value without coercing its type.
func authnPolicyFactValue(valueType policyregistry.AttributeType, raw any) (decision.Value, error) {
	switch valueType {
	case policyregistry.AttributeTypeBool:
		value, ok := raw.(bool)
		if !ok {
			return decision.Value{}, fmt.Errorf("expected bool, got %T", raw)
		}

		return decision.NewValue(decision.ValueInput{Boolean: &value})
	case policyregistry.AttributeTypeString:
		return authnStringFactValue(raw)
	case policyregistry.AttributeTypeStringList:
		value, ok := raw.([]string)
		if !ok {
			return decision.Value{}, fmt.Errorf("expected string list, got %T", raw)
		}

		return decision.NewValue(decision.ValueInput{Strings: value})
	case policyregistry.AttributeTypeNumber:
		return authnNumberFactValue(raw)
	case policyregistry.AttributeTypeIP, policyregistry.AttributeTypeCIDR:
		return authnAddressFactValue(raw)
	case policyregistry.AttributeTypeDateTime:
		value, ok := raw.(time.Time)
		if !ok {
			return decision.Value{}, fmt.Errorf("expected time, got %T", raw)
		}

		return decision.NewValue(decision.ValueInput{Timestamp: &value})
	default:
		return decision.Value{}, fmt.Errorf("unsupported type %q", valueType)
	}
}

// authnStringFactValue creates one exact string value.
func authnStringFactValue(raw any) (decision.Value, error) {
	value, ok := raw.(string)
	if !ok {
		return decision.Value{}, fmt.Errorf("expected string, got %T", raw)
	}

	return decision.NewValue(decision.ValueInput{String: &value})
}

// authnNumberFactValue accepts the concrete numeric forms emitted by Go and extension adapters.
func authnNumberFactValue(raw any) (decision.Value, error) {
	var value float64

	switch typed := raw.(type) {
	case float64:
		value = typed
	case float32:
		value = float64(typed)
	case int:
		value = float64(typed)
	case int32:
		value = float64(typed)
	case int64:
		value = float64(typed)
	case uint:
		value = float64(typed)
	case uint32:
		value = float64(typed)
	case uint64:
		value = float64(typed)
	default:
		return decision.Value{}, fmt.Errorf("expected number, got %T", raw)
	}

	return decision.NewValue(decision.ValueInput{Double: &value})
}

// authnAddressFactValue normalizes admitted IP and CIDR values to the generic string vocabulary.
func authnAddressFactValue(raw any) (decision.Value, error) {
	var value string

	switch typed := raw.(type) {
	case string:
		value = typed
	case net.IP:
		value = typed.String()
	case *net.IPNet:
		value = typed.String()
	case netip.Addr:
		value = typed.String()
	case netip.Prefix:
		value = typed.String()
	default:
		return decision.Value{}, fmt.Errorf("expected IP or CIDR, got %T", raw)
	}

	return decision.NewValue(decision.ValueInput{String: &value})
}
