// Package main composes admitted verifier and preexisting provider evidence for Policy.
package main

import (
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"math"
	"strings"
)

const (
	maximumChainRecords = 128
	maximumChainBytes   = 262144
	maximumPeerBytes    = 8192
)

type fieldSpec struct {
	view.Field
	Values       []string
	MaxItems     int
	MaxBytes     int
	MinInteger   int64
	MaxInteger   int64
	ProviderOnly bool
}

// chainFields owns the exact bounded semantic view without signature or Recipe payloads.
func chainFields() []fieldSpec {
	fields := []fieldSpec{
		integerField(valueSequence, 1, 128, true), integerField(valueMessageInstance, 1, math.MaxInt64, true),
		{Field: view.Field{Name: valueHopBinding, Kind: pluginapi.DecisionValueKindBytes, Required: true}, MaxBytes: 32, ProviderOnly: true},
		booleanField(valueIsTarget), textField(valueSignerDomain, 253, true),
		enumField(valueSignatureState, 16, "pass"),
		enumField(valueCustodyTransition, 32, "origin", "ordinary", "next_domain", "terminal_next_domain"),
		booleanField(valueDoNotModify), booleanField(valueDoNotExplode), booleanField(valueFeedback), booleanField(valueFeedHere), booleanField(valueExploded),
		enumField(valueRecipeMode, 16, "unchanged", "applied"), enumField(valueRecipeBodyMode, 16, "absent", "steps", valueUnavailable),
		listField(valueChangeClasses, 2, 64, "body.rewrite", "header.rewrite"), listField(valueAffectedHeaders, 128, 64),
		integerField(valueChangeCount, 0, 128, true), integerField(valueAffectedHeaderCount, 0, 128, true),
		enumField(valueHistoryHeaderState, 16, valueMatched, valueMismatch, valueUnavailable, valueUnsupported),
		enumField(valueHistoryBodyState, 16, valueMatched, valueMismatch, valueUnavailable, valueUnsupported),
		enumField(valueBodyAvailability, 16, "known", valueUnavailable),
	}
	fields = append(fields, tupleFields(valueSigner)...)

	return append(fields,
		enumField(valueIdentityContractState, 16, valueMatched, valueDomainOnly, valueMissing, valueMismatch, valueUnavailable),
		enumField(valueIdentityContractStrength, 16, valueCidr, valueAsn, valueDomainOnly, valueNone),
		listField(valueViolationClasses, 14, 64, violationCatalog()...),
	)
}

// peerFields preserves independent IP, network, ASN and geographic availability.
func peerFields() []fieldSpec {
	fields := []fieldSpec{textField(valueReputationProfile, 32, true)}
	for _, kind := range []string{valueIP, valueNetwork, valueAsn} {
		fields = append(fields, tupleFields(kind)...)
	}

	org := textField(valueAsnOrg, 128, false)
	org.ProviderOnly = true

	return append(fields,
		enumField(valueGeoipState, 16, valueFresh, valueStale, valueNotFound, valueUnavailable),
		integerField(valueGeoipAgeSeconds, 0, 31536000, false), textField(valueCountryIso, 2, false),
		integerField(valueAsn, 1, 4294967295, false), org, textField(valueAsnPrefix, 43, false),
		enumField(valueTargetContractState, 16, valueMatched, valueMissing, valueMismatch, valueUnavailable),
		enumField(valueTargetContractStrength, 16, valueCidr, valueAsn, valueNone),
	)
}

// tupleFields projects the common tuple once using the normative role-specific field names.
func tupleFields(role string) []fieldSpec {
	fields := make([]fieldSpec, 0, 10)

	for _, base := range view.Fields() {
		if role != valueSigner && base.Name == valueProfile {
			continue
		}

		base.Name = tupleFieldName(role, base.Name)
		fields = append(fields, fieldSpec{Field: base})
	}

	return fields
}

// tupleFieldName preserves the chain's reputation qualifiers and the peer's compact names.
func tupleFieldName(role, suffix string) string {
	if role == valueSigner {
		switch suffix {
		case valueState, valueProfile, "band", "age_seconds":
			return "signer_reputation_" + suffix
		}
	}

	return role + "_" + suffix
}

// violationCatalog fixes the privacy-minimized explanation vocabulary independently of Policy decisions.
func violationCatalog() []string {
	return strings.Fields("authentication_not_pass body_change_forbidden body_unavailable contract_missing contract_mismatch do_not_explode_violated do_not_modify_violated header_change_forbidden history_not_matched identity_unavailable reputation_blocked reputation_unavailable recipe_not_authorized upstream_nonpermittable")
}

// textField declares one bounded scalar string.
func textField(name string, limit int, required bool) fieldSpec {
	return fieldSpec{Field: view.Field{Name: name, Kind: pluginapi.DecisionValueKindString, MaxLength: limit, Required: required}}
}

// enumField declares one required closed string vocabulary.
func enumField(name string, limit int, values ...string) fieldSpec {
	field := textField(name, limit, true)
	field.Values = values

	return field
}

// booleanField declares one required semantic flag.
func booleanField(name string) fieldSpec {
	return fieldSpec{Field: view.Field{Name: name, Kind: pluginapi.DecisionValueKindBoolean, Required: true}}
}

// integerField declares the exact numeric range and requiredness.
func integerField(name string, minimum, maximum int64, required bool) fieldSpec {
	return fieldSpec{Field: view.Field{Name: name, Kind: pluginapi.DecisionValueKindInteger, Required: required}, MinInteger: minimum, MaxInteger: maximum}
}

// listField declares a required bounded canonical string set.
func listField(name string, items, length int, values ...string) fieldSpec {
	return fieldSpec{Field: view.Field{Name: name, Kind: pluginapi.DecisionValueKindStrings, Required: true, MaxLength: length}, MaxItems: items, Values: values}
}
