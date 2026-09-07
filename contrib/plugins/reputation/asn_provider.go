package main

import (
	"context"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

type providerASNResolver struct {
	source  *sourcePolicy
	records []pluginapi.DecisionRecord
}

// lookupASN resolves only source-owned, exactly correlated provider evidence.
func (r providerASNResolver) lookupASN(ctx context.Context, provider, ip string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if r.source == nil || provider != r.source.config.ASNProvider || len(r.records) > maximumSubjects {
		return "", errASNUnavailable
	}

	var selected map[string]pluginapi.DecisionRecordFieldValue

	for _, record := range r.records {
		fields, matches, err := matchingASNRecord(record, ip)
		if err != nil {
			return "", err
		}

		if !matches {
			continue
		}

		if selected != nil {
			return "", errASNUnavailable
		}

		selected = fields
	}

	if selected == nil {
		return "", errASNUnavailable
	}

	return r.recordASN(selected)
}

// recordASN distinguishes a bounded-age database miss from unavailable or contradictory attribution.
func (r providerASNResolver) recordASN(fields map[string]pluginapi.DecisionRecordFieldValue) (string, error) {
	state, validState := fields["lookup_state"].Value().StringValue()
	age, validAge := fields["data_age_seconds"].Value().Integer()

	asnField, hasASN := fields["asn"]
	asn, validASN := asnField.Value().Integer()

	if !validState || !validAge || age < 0 || age > int64(r.source.asnMaxAge/time.Second) {
		return "", errASNUnavailable
	}

	if state == assessmentMissing && (!hasASN || (validASN && asn == 0)) {
		return "", errASNNotFound
	}

	if (state != assessmentFresh && state != assessmentStale) || !validASN || asn <= 0 || asn > 4294967295 {
		return "", errASNUnavailable
	}

	return strconv.FormatInt(asn, 10), nil
}

// splitASNProviderFacts separates only the configured protected provider output from the closed producer vocabulary.
func (c *configuration) splitASNProviderFacts(source *sourcePolicy, facts []pluginapi.DecisionFactView) ([]pluginapi.DecisionFactView, asnResolver, error) {
	declared := c.asnFacts
	if len(declared) == 0 {
		return facts, nil, nil
	}

	filtered := make([]pluginapi.DecisionFactView, 0, len(facts))
	resolver := providerASNResolver{source: source}
	seen := make(map[string]bool)

	for _, fact := range facts {
		if declared[fact.ID()] == "" {
			filtered = append(filtered, fact)
			continue
		}

		records, valid := fact.Value().Records()
		if seen[fact.ID()] || !valid || fact.Category() != pluginapi.DecisionFactCategoryEnvironment || len(records.Records()) > maximumSubjects {
			return nil, nil, errASNUnavailable
		}

		if source != nil && fact.ID() == source.config.ASNFact {
			resolver.records = records.Records()
		}

		seen[fact.ID()] = true
	}

	return filtered, resolver, nil
}

// asnProviderFactPrefix binds the admitted geographic fact to the exact provider module identity.
func asnProviderFactPrefix(provider string) string {
	_, qualified, ok := strings.Cut(provider, "/plugin.")
	if !ok {
		return ""
	}

	module, _, ok := strings.Cut(qualified, ".")
	if !ok {
		return ""
	}

	return "plugin." + module + "."
}

// asnProviderInputs freezes exact upstream ownership, scheduling, and visible record-field requirements.
func asnProviderInputs(config *configuration) []pluginapi.DecisionFactInputDescriptor {
	if config == nil {
		return nil
	}

	inputs := make([]pluginapi.DecisionFactInputDescriptor, 0)
	for _, fact := range slices.Sorted(maps.Keys(config.asnFacts)) {
		inputs = append(inputs, pluginapi.DecisionFactInputDescriptor{ID: fact, Provider: config.asnFacts[fact],
			Category: pluginapi.DecisionFactCategoryEnvironment, Kind: pluginapi.DecisionValueKindRecords,
			Fields: []pluginapi.DecisionFactInputFieldDescriptor{
				{Name: "ip", Kind: pluginapi.DecisionValueKindString}, {Name: "lookup_state", Kind: pluginapi.DecisionValueKindString},
				{Name: "data_age_seconds", Kind: pluginapi.DecisionValueKindInteger}, {Name: "asn", Kind: pluginapi.DecisionValueKindInteger},
			},
		})
	}

	return inputs
}

// matchingASNRecord rejects malformed provider addresses before selecting an exact canonical IP.
func matchingASNRecord(record pluginapi.DecisionRecord, ip string) (map[string]pluginapi.DecisionRecordFieldValue, bool, error) {
	fields := recordFieldValues(record)
	address, ok := fields["ip"].Value().StringValue()

	canonical, err := canonicalIP(address)
	if !ok || err != nil || address != canonical {
		return nil, false, errASNUnavailable
	}

	return fields, address == ip, nil
}
