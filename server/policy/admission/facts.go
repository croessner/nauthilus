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

package admission

import (
	"sort"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

type submittedFactInput struct {
	values         decision.ValueMap
	allowed        map[string]struct{}
	prefix         string
	category       decision.FactCategory
	schemaCategory bool
}

type trustedFactInput struct {
	value  decision.Value
	id     string
	source decision.FactSource
	set    bool
}

// buildAdmittedFacts constructs all assertions and schema-declared trusted evidence once.
func buildAdmittedFacts(
	caller decision.CallerContext,
	request decision.DecisionRequest,
	fields compiledFieldLists,
	schema policyruntime.CompiledSchema,
) (decision.FactSet, error) {
	definitions := schemaDefinitions(schema)

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, caller.Principal(), "request")
	if err != nil {
		return decision.FactSet{}, admissionError(ErrInvalidRequest, "caller assertion provenance is invalid")
	}

	facts := make([]decision.Fact, 0, submittedFactCount(request)+len(definitions))
	inputs := []submittedFactInput{
		{values: request.Subject().Attributes(), allowed: fields.subject, prefix: subjectFactPrefix, category: decision.FactCategorySubject},
		{values: request.Resource().Attributes(), allowed: fields.resource, prefix: resourceFactPrefix, category: decision.FactCategoryResource},
		{values: request.Environment().Attributes(), allowed: fields.environment, prefix: environmentFactPrefix, category: decision.FactCategoryEnvironment},
		{values: request.Attributes(), allowed: fields.input, prefix: inputFactPrefix, schemaCategory: true},
	}

	for _, input := range inputs {
		if err := appendSubmittedFacts(&facts, input, definitions, provenance); err != nil {
			return decision.FactSet{}, err
		}
	}

	if err := appendTrustedFacts(&facts, caller, definitions); err != nil {
		return decision.FactSet{}, err
	}

	result, err := decision.NewFactSet(facts)
	if err != nil {
		return decision.FactSet{}, admissionError(ErrInvalidRequest, "admitted facts contain a duplicate or collision")
	}

	if err := schema.ValidatePresentFacts(result); err != nil {
		return decision.FactSet{}, admissionError(ErrInvalidRequest, "admitted facts violate the selected exact schema")
	}

	return result, nil
}

// schemaDefinitions indexes one detached compiled schema by canonical fact identity.
func schemaDefinitions(schema policyruntime.CompiledSchema) map[string]registry.FactSchema {
	definitions := make(map[string]registry.FactSchema)
	for _, definition := range schema.Facts() {
		definitions[definition.ID()] = definition
	}

	return definitions
}

// appendSubmittedFacts validates one request category against both profile and exact schema authority.
func appendSubmittedFacts(
	facts *[]decision.Fact,
	input submittedFactInput,
	definitions map[string]registry.FactSchema,
	provenance decision.Provenance,
) error {
	values := input.values.Values()
	keys := sortedValueKeys(input.values)

	for _, key := range keys {
		if reservedSubmittedKey(key) {
			return admissionError(ErrInvalidRequest, "submitted field is shaped like a trusted fact family")
		}

		if !containsKey(input.allowed, key) {
			return admissionError(ErrPermissionDenied, "submitted field is outside the profile allowlist")
		}

		id := input.prefix + "." + key

		definition, exists := definitions[id]
		if !exists || (!input.schemaCategory && definition.Category() != input.category) ||
			!sourceAllowed(definition, decision.FactSourceCaller) {
			return admissionError(ErrInvalidRequest, "submitted field is not caller-owned by the selected exact schema")
		}

		category := input.category
		if input.schemaCategory {
			category = definition.Category()
		}

		fact, err := decision.NewFact(id, category, values[key], provenance)
		if err != nil {
			return admissionError(ErrInvalidRequest, "submitted field cannot be constructed as a caller fact")
		}

		*facts = append(*facts, fact)
	}

	return nil
}

// appendTrustedFacts adds only declared trusted caller, token, and transport evidence.
func appendTrustedFacts(
	facts *[]decision.Fact,
	caller decision.CallerContext,
	definitions map[string]registry.FactSchema,
) error {
	inputs, err := trustedFactInputs(caller)
	if err != nil {
		return err
	}

	provenance := make(map[decision.FactSource]decision.Provenance, 3)

	for _, input := range inputs {
		if !input.set {
			continue
		}

		definition, declared := definitions[input.id]
		if !declared {
			continue
		}

		owner, exists := provenance[input.source]
		if !exists {
			owner, err = decision.NewProvenance(input.source, caller.Principal(), "authenticator")
			if err != nil {
				return admissionError(ErrInvalidRequest, "trusted fact provenance is invalid")
			}

			provenance[input.source] = owner
		}

		fact, err := decision.NewFact(input.id, definition.Category(), input.value, owner)
		if err != nil {
			return admissionError(ErrInvalidRequest, "trusted evidence cannot be constructed as a schema fact")
		}

		*facts = append(*facts, fact)
	}

	return nil
}

// trustedFactInputs converts constructor-validated caller evidence into deterministic strict values.
func trustedFactInputs(caller decision.CallerContext) ([]trustedFactInput, error) {
	inputs := make([]trustedFactInput, 0, 12)

	for _, input := range []struct {
		value  string
		id     string
		source decision.FactSource
	}{
		{value: caller.Principal(), id: decision.FactCallerPrincipal, source: decision.FactSourceNauthilus},
		{value: caller.ClientID(), id: decision.FactCallerClientID, source: decision.FactSourceNauthilus},
		{value: caller.AuthenticationKind(), id: decision.FactCallerAuthenticationKind, source: decision.FactSourceNauthilus},
		{value: caller.Subject(), id: decision.FactTokenSubject, source: decision.FactSourceToken},
		{value: caller.Issuer(), id: decision.FactTokenIssuer, source: decision.FactSourceToken},
		{value: caller.TransportKind(), id: decision.FactTransportKind, source: decision.FactSourceTransport},
		{value: caller.Listener(), id: decision.FactTransportListener, source: decision.FactSourceTransport},
		{value: caller.HTTPRoute(), id: decision.FactTransportHTTPRoute, source: decision.FactSourceTransport},
		{value: caller.GRPCMethod(), id: decision.FactTransportGRPCMethod, source: decision.FactSourceTransport},
		{value: caller.MTLSIdentity(), id: decision.FactTransportMTLSIdentity, source: decision.FactSourceTransport},
	} {
		value, err := trustedStringValue(input.value)
		if err != nil {
			return nil, err
		}

		inputs = append(inputs, trustedFactInput{
			value: value, id: input.id, source: input.source, set: input.value != "",
		})
	}

	scopes, err := trustedStringsValue(caller.Scopes())
	if err != nil {
		return nil, err
	}

	inputs = append(inputs, trustedFactInput{
		value: scopes, id: decision.FactCallerScopes,
		source: decision.FactSourceNauthilus, set: len(caller.Scopes()) > 0,
	})

	sourceIP := ""
	if caller.SourceIP().IsValid() {
		sourceIP = caller.SourceIP().String()
	}

	value, err := trustedStringValue(sourceIP)
	if err != nil {
		return nil, err
	}

	inputs = append(inputs, trustedFactInput{
		value: value, id: decision.FactTransportSourceIP,
		source: decision.FactSourceTransport, set: sourceIP != "",
	})

	sort.Slice(inputs, func(first int, second int) bool {
		return inputs[first].id < inputs[second].id
	})

	return inputs, nil
}

// trustedStringValue constructs one optional trusted scalar without exposing it through errors.
func trustedStringValue(input string) (decision.Value, error) {
	if input == "" {
		return decision.Value{}, nil
	}

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		return decision.Value{}, admissionError(ErrInvalidRequest, "trusted text evidence is invalid")
	}

	return value, nil
}

// trustedStringsValue constructs one sorted non-empty trusted string list.
func trustedStringsValue(input []string) (decision.Value, error) {
	if len(input) == 0 {
		return decision.Value{}, nil
	}

	owned := append([]string(nil), input...)
	sort.Strings(owned)

	value, err := decision.NewValue(decision.ValueInput{Strings: owned})
	if err != nil {
		return decision.Value{}, admissionError(ErrInvalidRequest, "trusted scope evidence is invalid")
	}

	return value, nil
}

// sortedValueKeys returns deterministic immutable map traversal order.
func sortedValueKeys(values decision.ValueMap) []string {
	owned := values.Values()
	keys := make([]string, 0, len(owned))

	for key := range owned {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

// sourceAllowed reports exact schema ownership by one fact source.
func sourceAllowed(definition registry.FactSchema, source decision.FactSource) bool {
	for _, allowed := range definition.AllowedSources() {
		if allowed == source {
			return true
		}
	}

	return false
}
