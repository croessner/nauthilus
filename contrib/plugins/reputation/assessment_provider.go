package main

import (
	"context"
	"sort"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type assessmentProvider struct {
	plugin     *Plugin
	config     *configuration
	descriptor pluginapi.DecisionFactProviderDescriptor
}

// Descriptor returns the configuration-compiled generic target and record-output contract.
func (p assessmentProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return p.descriptor
}

// Collect publishes correlated primary assessments without granting permit/deny authority to the provider.
func (p assessmentProvider) Collect(ctx context.Context, request pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, error) {
	subjects, err := p.config.extractSubjects(request.Target(), request.Facts())
	if err != nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
	}

	binding := p.config.bindings[request.Target()]
	state, metrics := p.plugin.observedState()

	collections := make(map[string][]pluginapi.DecisionRecord, 4)
	for _, output := range assessmentOutputNames(binding.OutputFact) {
		collections[output] = make([]pluginapi.DecisionRecord, 0, len(subjects))
	}

	for _, subject := range subjects {
		profiles := emptyProfiles(assessmentUnavailable)
		if state != nil && !subject.unavailable {
			profiles = state.assessProfiles(ctx, subject.subjectInput)
		}

		if metrics != nil {
			selected := profiles[binding.DecisionProfile]
			metrics.assessment.Add(ctx, request.Target().Namespace+"/"+request.Target().Action, subject.kind, selected.State, selected.Band, selected.Override)
		}

		for output, profile := range assessmentOutputProfiles(binding) {
			record, err := assessmentRecord(subject, profiles[profile])
			if err != nil {
				return pluginapi.DecisionFactResult{}, err
			}

			collections[output] = append(collections[output], record)
		}
	}

	inputs := make([]outputInput, 0, 4)

	for _, name := range assessmentOutputNames(binding.OutputFact) {
		list, err := pluginapi.NewDecisionRecordList(collections[name])
		if err != nil {
			return pluginapi.DecisionFactResult{}, err
		}

		inputs = append(inputs, outputInput{name: name, input: pluginapi.DecisionValueInput{Records: &list}})
	}

	return factOutputs(inputs)
}

// registerAssessments groups exact targets under explicitly named, namespace-bound generic components.
func (p *Plugin) registerAssessments(registrar pluginapi.DecisionRegistrar, cfg *configuration) error {
	components := make(map[string]*assessmentProvider)

	extractors := make(map[string][]extractorConfig)
	for target, binding := range cfg.bindings {
		extractors[binding.Component] = append(extractors[binding.Component], binding.Subjects...)
		provider := components[binding.Component]
		if provider == nil {
			provider = &assessmentProvider{plugin: p, config: cfg, descriptor: pluginapi.DecisionFactProviderDescriptor{
				Namespace: target.Namespace, Name: binding.Component, Timeout: 2 * time.Second}}
			components[binding.Component] = provider
		}

		provider.descriptor.Targets = append(provider.descriptor.Targets, target)
		for _, name := range assessmentOutputNames(binding.OutputFact) {
			provider.descriptor.Outputs = append(provider.descriptor.Outputs, pluginapi.DecisionFactOutputDescriptor{
				Name: name, Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords})
		}
	}

	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		provider := components[name]

		inputs, err := assessmentInputs(extractors[name])
		if err != nil {
			return err
		}

		provider.descriptor.Inputs = inputs
		sort.Slice(provider.descriptor.Targets, func(i, j int) bool {
			return provider.descriptor.Targets[i].Action < provider.descriptor.Targets[j].Action
		})
		sort.Slice(provider.descriptor.Outputs, func(i, j int) bool { return provider.descriptor.Outputs[i].Name < provider.descriptor.Outputs[j].Name })

		if err := registrar.RegisterDecisionFactProvider(provider); err != nil {
			return err
		}
	}

	return nil
}

// assessmentOutputNames keeps the selected tuple and all profile views individually bounded.
func assessmentOutputNames(base string) []string {
	result := []string{base}
	for _, profile := range assessmentProfileNames() {
		result = append(result, base+"_"+profile)
	}

	return result
}

// assessmentOutputProfiles binds all views of one subject to the same atomic snapshots.
func assessmentOutputProfiles(binding targetBindingConfig) map[string]string {
	result := map[string]string{binding.OutputFact: binding.DecisionProfile}
	for _, profile := range assessmentProfileNames() {
		result[binding.OutputFact+"_"+profile] = profile
	}

	return result
}
