package main

import (
	"context"
	projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"strings"
	"time"
)

type decisionProvider struct {
	plugin *Plugin
	config *configuration
}

// Descriptor binds exact upstream owners and every private record field consumed by the composer.
func (p decisionProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	descriptor := pluginapi.DecisionFactProviderDescriptor{Name: "assessment", Namespace: valueDkim2, Timeout: time.Second,
		Targets: []pluginapi.DecisionTargetSelector{{Namespace: valueDkim2, Action: "accept-message-instance"}},
		Outputs: []pluginapi.DecisionFactOutputDescriptor{
			{Name: valueAssessedChain, Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords},
			{Name: valueSMTPPeer, Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords},
			{Name: valueAssessmentComplete, Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindBoolean},
		},
	}
	if p.config != nil {
		descriptor.Inputs = p.config.providerInputs()
	}

	return descriptor
}

// providerInputs exposes configuration-compiled exact dependency and visibility requirements.
func (c *configuration) providerInputs() []pluginapi.DecisionFactInputDescriptor {
	fields := []pluginapi.DecisionFactInputFieldDescriptor{
		{Name: valueRole, Kind: pluginapi.DecisionValueKindString}, {Name: valueKind, Kind: pluginapi.DecisionValueKindString},
		{Name: valueSequence, Kind: pluginapi.DecisionValueKindInteger}, {Name: valueMessageInstance, Kind: pluginapi.DecisionValueKindInteger},
		{Name: valueHopBinding, Kind: pluginapi.DecisionValueKindBytes}, {Name: valueSignerDomain, Kind: pluginapi.DecisionValueKindString},
	}
	for _, field := range view.Fields() {
		fields = append(fields, pluginapi.DecisionFactInputFieldDescriptor{Name: field.Name, Kind: field.Kind})
	}

	inputs := []pluginapi.DecisionFactInputDescriptor{
		{ID: "resource.dkim2.chain", Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords, Fields: projection.HopInputFields()},
		{ID: c.raw.ReputationFact, Provider: c.raw.ReputationProvider, Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords, Fields: fields},
	}
	for _, field := range geographicInputs() {
		inputs = append(inputs, pluginapi.DecisionFactInputDescriptor{ID: providerFactPrefix(c.raw.GeoIPProvider) + field.Name, Provider: c.raw.GeoIPProvider,
			Category: pluginapi.DecisionFactCategoryEnvironment, Kind: field.Kind})
	}

	return inputs
}

// geographicInputs declares only the geographic fields the composer consumes.
func geographicInputs() []pluginapi.DecisionFactInputFieldDescriptor {
	return []pluginapi.DecisionFactInputFieldDescriptor{
		{Name: valueIP, Kind: pluginapi.DecisionValueKindString}, {Name: valueLookupState, Kind: pluginapi.DecisionValueKindString},
		{Name: valueDataAgeSeconds, Kind: pluginapi.DecisionValueKindInteger}, {Name: valueAsn, Kind: pluginapi.DecisionValueKindInteger},
		{Name: valueCountryIso, Kind: pluginapi.DecisionValueKindString}, {Name: valueAsnOrg, Kind: pluginapi.DecisionValueKindString}, {Name: valueAsnPrefix, Kind: pluginapi.DecisionValueKindString},
	}
}

// providerFactPrefix derives the exact module-owned fact prefix from a validated native provider reference.
func providerFactPrefix(provider string) string {
	_, qualified, _ := strings.Cut(provider, "/plugin.")
	module, _, _ := strings.Cut(qualified, ".")

	return valuePlugin + module + "."
}

// Collect validates the verifier projection, exact signer correlation and peer evidence before publishing any fact.
func (p decisionProvider) Collect(ctx context.Context, request pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, error) {
	metric := valueUnavailable
	defer func() { p.plugin.recordComposition(ctx, metric) }()

	if err := ctx.Err(); err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	if p.plugin == nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable}, nil
	}

	cfg := p.plugin.snapshot()
	if cfg == nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable}, nil
	}

	result, outcome, err := cfg.collect(request)
	metric = outcome

	return result, err
}

// collect runs every validation stage in order and returns the result with its bounded composition metric.
func (c *configuration) collect(request pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, string, error) {
	source, err := projection.Decode(request)
	if err != nil {
		return invalidComposition(), metricProjectionInvalid, nil
	}

	facts := make(map[string]pluginapi.DecisionValue)
	for _, fact := range request.Facts() {
		facts[fact.ID()] = fact.Value()
	}

	subjects, err := decodeSubjects(facts[c.raw.ReputationFact])
	if err != nil {
		return invalidComposition(), metricReputationInvalid, nil
	}

	correlated, err := correlateSubjects(source, subjects, c.raw.DecisionProfile)
	if err != nil {
		return invalidComposition(), metricCorrelationInvalid, nil
	}

	geo, err := decodeGeographic(geographicFacts(facts, c.raw.GeoIPProvider), source.ClientIP)
	if err != nil {
		return invalidComposition(), metricGeoIPInvalid, nil
	}

	composed, err := c.compose(source, correlated, geo)
	if err != nil {
		return invalidComposition(), metricCompositionInvalid, nil
	}

	result, err := composed.facts()
	if err != nil {
		return result, metricCompositionInvalid, err
	}

	return result, metricCompleted, nil
}

// geographicFacts selects the GeoIP provider outputs the composition consumes.
func geographicFacts(facts map[string]pluginapi.DecisionValue, provider string) map[string]pluginapi.DecisionValue {
	geographic := make(map[string]pluginapi.DecisionValue)

	for _, field := range geographicInputs() {
		if value, found := facts[providerFactPrefix(provider)+field.Name]; found {
			geographic[field.Name] = value
		}
	}

	return geographic
}

// invalidComposition returns an explicit atomic failure with no partial chain or peer view.
func invalidComposition() pluginapi.DecisionFactResult {
	return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}
}

// facts freezes both validated collections and reports structural completion independently of evidence availability.
func (c composition) facts() (pluginapi.DecisionFactResult, error) {
	result := pluginapi.DecisionFactResult{}

	for _, output := range []struct {
		name    string
		records []pluginapi.DecisionRecord
	}{{valueAssessedChain, c.chain}, {valueSMTPPeer, []pluginapi.DecisionRecord{c.peer}}} {
		list, err := pluginapi.NewDecisionRecordList(output.records)
		if err != nil {
			return pluginapi.DecisionFactResult{}, err
		}

		value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &list})
		if err != nil {
			return pluginapi.DecisionFactResult{}, err
		}

		result.Facts = append(result.Facts, pluginapi.DecisionFactOutput{Name: output.name, Value: value})
	}

	complete := true

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Boolean: &complete})
	if err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	result.Facts = append(result.Facts, pluginapi.DecisionFactOutput{Name: valueAssessmentComplete, Value: value})

	return result, nil
}
