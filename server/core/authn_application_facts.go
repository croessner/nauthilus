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
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

const (
	authnFactAuthorityHost           = "nauthilus"
	authnFactAuthorityAccountBackend = "account-provider"
	authnFactComponentAdapter        = "application-adapter"
	maximumAuthnFactInteger          = uint64(1<<63 - 1)
)

type authnFactBuilder struct {
	hostProvenance decision.Provenance
}

type authnFactCollector struct {
	facts []decision.Fact
}

type authnRequestAttributes struct {
	environment map[string]decision.Value
	input       map[string]decision.Value
}

// newAuthnFactBuilder constructs the fixed host provenance owner.
func newAuthnFactBuilder() (authnFactBuilder, error) {
	hostProvenance, err := decision.NewProvenance(
		decision.FactSourceNauthilus,
		authnFactAuthorityHost,
		authnFactComponentAdapter,
	)
	if err != nil {
		return authnFactBuilder{}, err
	}

	return authnFactBuilder{hostProvenance: hostProvenance}, nil
}

// Build converts request and current backend state exactly once into immutable facts.
func (b authnFactBuilder) Build(
	input AuthInput,
	operation policy.Operation,
	result authnApplicationResult,
	existing decision.FactSet,
) (decision.FactSet, error) {
	if !result.validFor(operation) {
		return decision.FactSet{}, ErrAuthOutcomeMissing
	}

	collector := authnFactCollector{facts: existing.Facts()}
	if err := b.addHostRequestFacts(&collector, input, operation); err != nil {
		return decision.FactSet{}, err
	}

	if err := b.addResultFacts(&collector, operation, result); err != nil {
		return decision.FactSet{}, err
	}

	facts, err := decision.NewFactSet(collector.facts)
	if err != nil {
		return decision.FactSet{}, fmt.Errorf("finalize authn fact set: %w", err)
	}

	return facts, nil
}

// RequestAttributes maps caller assertions for provenance assignment by the Decision Service.
func (authnFactBuilder) RequestAttributes(input AuthInput) (authnRequestAttributes, error) {
	attributes := authnRequestAttributes{
		environment: make(map[string]decision.Value),
		input:       make(map[string]decision.Value),
	}

	requestFacts := []struct {
		id    string
		value string
	}{
		{id: policy.AuthnFactUsername, value: input.Credentials.Username},
		{id: policy.AuthnFactMethod, value: input.Context.Method},
		{id: policy.AuthnFactUserAgent, value: input.Context.UserAgent},
		{id: policy.AuthnFactClientIP, value: input.Context.ClientIP},
		{id: policy.AuthnFactClientPort, value: input.Context.ClientPort},
		{id: policy.AuthnFactClientHostname, value: input.Context.ClientHostname},
		{id: policy.AuthnFactClientID, value: input.Context.ClientID},
		{id: policy.AuthnFactLocalIP, value: input.Context.LocalIP},
		{id: policy.AuthnFactLocalPort, value: input.Context.LocalPort},
		{id: policy.AuthnFactIDPClientID, value: input.Context.OIDCCID},
		{id: policy.AuthnFactSAMLServiceProviderID, value: input.Context.SAMLEntityID},
	}

	for _, fact := range requestFacts {
		if err := addAuthnRequestString(attributes.input, fact.id, "input.", fact.value); err != nil {
			return authnRequestAttributes{}, err
		}
	}

	if err := addAuthnRequestString(
		attributes.environment,
		policy.AuthnFactProtocol,
		"environment.",
		input.Context.Protocol,
	); err != nil {
		return authnRequestAttributes{}, err
	}

	if input.AuthLoginAttempt == 0 {
		return attributes, nil
	}

	if uint64(input.AuthLoginAttempt) > maximumAuthnFactInteger {
		return authnRequestAttributes{}, fmt.Errorf("authn login attempt exceeds signed fact range")
	}

	key, err := authnRequestAttributeKey(policy.AuthnFactLoginAttempt, "input.")
	if err != nil {
		return authnRequestAttributes{}, err
	}

	value := int64(input.AuthLoginAttempt)

	loginAttempt, err := decision.NewValue(decision.ValueInput{Integer: &value})
	if err != nil {
		return authnRequestAttributes{}, err
	}

	attributes.input[key] = loginAttempt

	return attributes, nil
}

// addAuthnRequestString stores one optional strict assertion under its category-local key.
func addAuthnRequestString(
	target map[string]decision.Value,
	id string,
	prefix string,
	input string,
) error {
	if input == "" {
		return nil
	}

	key, err := authnRequestAttributeKey(id, prefix)
	if err != nil {
		return err
	}

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		return err
	}

	target[key] = value

	return nil
}

// authnRequestAttributeKey removes only the exact category prefix from a canonical fact ID.
func authnRequestAttributeKey(id string, prefix string) (string, error) {
	if !strings.HasPrefix(id, prefix) || len(id) == len(prefix) {
		return "", fmt.Errorf("authn fact %q is outside request category %q", id, prefix)
	}

	return strings.TrimPrefix(id, prefix), nil
}

// addHostRequestFacts records only host-selected operation data before backend projection.
func (b authnFactBuilder) addHostRequestFacts(
	collector *authnFactCollector,
	input AuthInput,
	operation policy.Operation,
) error {
	if err := collector.addString(
		policy.AuthnFactOperation,
		decision.FactCategoryEnvironment,
		string(operation),
		b.hostProvenance,
	); err != nil {
		return err
	}

	if err := collector.addString(
		policy.AuthnFactService,
		decision.FactCategoryResource,
		input.Service,
		b.hostProvenance,
	); err != nil {
		return err
	}

	return nil
}

// addResultFacts records the existing outcome and its exact backend-owned projection.
func (b authnFactBuilder) addResultFacts(
	collector *authnFactCollector,
	operation policy.Operation,
	result authnApplicationResult,
) error {
	decisionValue := result.currentDecision()
	if err := collector.addString(
		policy.AuthnFactCurrentDecision,
		decision.FactCategoryEnvironment,
		string(decisionValue),
		b.hostProvenance,
	); err != nil {
		return err
	}

	if operation == policy.OperationListAccounts {
		return b.addAccountResultFacts(collector, result.accounts)
	}

	return b.addAuthResultFacts(collector, operation, result.auth)
}

// addAuthResultFacts records backend identity and authentication result state.
func (b authnFactBuilder) addAuthResultFacts(
	collector *authnFactCollector,
	operation policy.Operation,
	outcome *AuthOutcome,
) error {
	provenance, err := decision.NewProvenance(
		decision.FactSourceBackend,
		outcome.Backend.String(),
		string(operation),
	)
	if err != nil {
		return err
	}

	if err := collector.addString(
		policy.AuthnFactBackend,
		decision.FactCategorySubject,
		outcome.Backend.String(),
		provenance,
	); err != nil {
		return err
	}

	resultFact := policy.AuthnFactAuthenticated
	if operation == policy.OperationLookupIdentity {
		resultFact = policy.AuthnFactIdentityFound
	}

	if err := collector.addBoolean(
		resultFact,
		decision.FactCategorySubject,
		outcome.Decision == AuthDecisionOK,
		provenance,
	); err != nil {
		return err
	}

	if err := collector.addOptionalString(
		policy.AuthnFactAccountField,
		decision.FactCategorySubject,
		outcome.AccountField,
		provenance,
	); err != nil {
		return err
	}

	if err := collector.addOptionalStrings(
		policy.AuthnFactGroups,
		decision.FactCategorySubject,
		outcome.Groups,
		provenance,
	); err != nil {
		return err
	}

	return collector.addOptionalStrings(
		policy.AuthnFactGroupDistinguishedNames,
		decision.FactCategorySubject,
		outcome.GroupDistinguishedNames,
		provenance,
	)
}

// addAccountResultFacts records bounded account-provider completion without exporting accounts.
func (b authnFactBuilder) addAccountResultFacts(
	collector *authnFactCollector,
	outcome *ListAccountsOutcome,
) error {
	provenance, err := decision.NewProvenance(
		decision.FactSourceBackend,
		authnFactAuthorityAccountBackend,
		string(policy.OperationListAccounts),
	)
	if err != nil {
		return err
	}

	if err := collector.addInteger(
		policy.AuthnFactAccountCount,
		decision.FactCategorySubject,
		int64(len(outcome.Accounts)),
		provenance,
	); err != nil {
		return err
	}

	return collector.addBoolean(
		policy.AuthnFactAccountProviderCompleted,
		decision.FactCategorySubject,
		outcome.Decision != AuthDecisionTempFail,
		provenance,
	)
}

// currentDecision returns the established result category without exposing result payloads.
func (r authnApplicationResult) currentDecision() AuthDecision {
	if r.auth != nil {
		return r.auth.Decision
	}

	if r.accounts != nil {
		return r.accounts.Decision
	}

	return AuthDecisionUnset
}

// addOptionalString omits absent optional text while preserving strict values for present text.
func (c *authnFactCollector) addOptionalString(
	id string,
	category decision.FactCategory,
	input string,
	provenance decision.Provenance,
) error {
	if input == "" {
		return nil
	}

	return c.addString(id, category, input, provenance)
}

// addString appends one strict string fact under the supplied provenance owner.
func (c *authnFactCollector) addString(
	id string,
	category decision.FactCategory,
	input string,
	provenance decision.Provenance,
) error {
	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		return err
	}

	return c.addFact(id, category, value, provenance)
}

// addBoolean appends one strict boolean fact under the supplied provenance owner.
func (c *authnFactCollector) addBoolean(
	id string,
	category decision.FactCategory,
	input bool,
	provenance decision.Provenance,
) error {
	value, err := decision.NewValue(decision.ValueInput{Boolean: &input})
	if err != nil {
		return err
	}

	return c.addFact(id, category, value, provenance)
}

// addInteger appends one strict signed integer fact under the supplied provenance owner.
func (c *authnFactCollector) addInteger(
	id string,
	category decision.FactCategory,
	input int64,
	provenance decision.Provenance,
) error {
	value, err := decision.NewValue(decision.ValueInput{Integer: &input})
	if err != nil {
		return err
	}

	return c.addFact(id, category, value, provenance)
}

// addOptionalStrings omits empty lists and appends a detached strict list otherwise.
func (c *authnFactCollector) addOptionalStrings(
	id string,
	category decision.FactCategory,
	input []string,
	provenance decision.Provenance,
) error {
	if len(input) == 0 {
		return nil
	}

	value, err := decision.NewValue(decision.ValueInput{Strings: input})
	if err != nil {
		return err
	}

	return c.addFact(id, category, value, provenance)
}

// addFact constructs one canonical fact before the final collision check.
func (c *authnFactCollector) addFact(
	id string,
	category decision.FactCategory,
	value decision.Value,
	provenance decision.Provenance,
) error {
	fact, err := decision.NewFact(id, category, value, provenance)
	if err != nil {
		return err
	}

	c.facts = append(c.facts, fact)

	return nil
}
