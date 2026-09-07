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

	source, err := projection.Decode(request)
	if err != nil {
		return invalidComposition(), nil
	}

	facts := make(map[string]pluginapi.DecisionValue)
	for _, fact := range request.Facts() {
		facts[fact.ID()] = fact.Value()
	}

	subjects, err := decodeSubjects(facts[cfg.raw.ReputationFact])
	if err != nil {
		return invalidComposition(), nil
	}

	correlated, err := correlateSubjects(source, subjects, cfg.raw.DecisionProfile)
	if err != nil {
		return invalidComposition(), nil
	}

	geographic := make(map[string]pluginapi.DecisionValue)

	for _, field := range geographicInputs() {
		if value, found := facts[providerFactPrefix(cfg.raw.GeoIPProvider)+field.Name]; found {
			geographic[field.Name] = value
		}
	}

	geo, err := decodeGeographic(geographic, source.ClientIP)
	if err != nil {
		return invalidComposition(), nil
	}

	composed, err := cfg.compose(source, correlated, geo)
	if err != nil {
		return invalidComposition(), nil
	}

	return composed.facts()
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
