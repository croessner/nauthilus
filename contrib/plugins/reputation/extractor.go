package main

import (
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type targetBindingConfig struct {
	Component       string            `mapstructure:"component"`
	DecisionProfile string            `mapstructure:"decision_profile"`
	Subjects        []extractorConfig `mapstructure:"subjects"`
	Target          string            `mapstructure:"target"`
	OutputFact      string            `mapstructure:"output_fact"`
}

type extractorConfig struct {
	CorrelationFields []string `mapstructure:"correlation_fields"`
	Attribute         string   `mapstructure:"attribute"`
	Field             string   `mapstructure:"field"`
	Role              string   `mapstructure:"role"`
	Kind              string   `mapstructure:"kind"`
}

type extractedSubject struct {
	correlation map[string]pluginapi.DecisionRecordFieldValue
	subjectInput
}

// compileExtractors fixes exact target selectors, typed roles and bounded correlation fields before activation.
func (c *configuration) compileExtractors() error {
	if len(c.raw.TargetBindings) > 32 {
		return errConfiguration
	}

	c.bindings = make(map[pluginapi.DecisionTargetSelector]targetBindingConfig, len(c.raw.TargetBindings))
	outputs := make(map[string]struct{})
	components := make(map[string]string)

	for _, binding := range c.raw.TargetBindings {
		if binding.Component == "" {
			binding.Component = "assessment"
		}

		if !identifierPattern.MatchString(binding.Component) || binding.Component == componentObservation {
			return errConfiguration
		}

		if binding.DecisionProfile == "" {
			binding.DecisionProfile = profileOperational
		}

		if !profileName(binding.DecisionProfile) {
			return errConfiguration
		}
		target, err := exactSelector(binding.Target)
		if err != nil || !identifierPattern.MatchString(binding.OutputFact) || len(binding.Subjects) < 1 || len(binding.Subjects) > maximumSubjects {
			return errConfiguration
		}

		if namespace, exists := components[binding.Component]; exists && namespace != target.Namespace {
			return errConfiguration
		}

		components[binding.Component] = target.Namespace

		if _, exists := c.bindings[target]; exists {
			return errConfiguration
		}

		for _, name := range assessmentOutputNames(binding.OutputFact) {
			if !identifierPattern.MatchString(name) {
				return errConfiguration
			}

			if _, exists := outputs[name]; exists {
				return errConfiguration
			}

			outputs[name] = struct{}{}
		}

		for _, extractor := range binding.Subjects {
			if err := validateExtractor(extractor); err != nil {
				return err
			}
		}

		c.bindings[target] = binding
	}

	return nil
}

// validateExtractor rejects dynamic selectors, nested traversal and undeclared subject spaces.
func validateExtractor(extractor extractorConfig) error {
	if !validExtractorAttribute(extractor.Attribute) || !identifierPattern.MatchString(extractor.Role) || !subjectKind(extractor.Kind) {
		return errConfiguration
	}

	if extractor.Field != "" && !identifierPattern.MatchString(extractor.Field) {
		return errConfiguration
	}

	if !uniqueIdentifiers(extractor.CorrelationFields, 8, true) || (extractor.Field == "" && len(extractor.CorrelationFields) > 0) {
		return errConfiguration
	}

	for _, name := range extractor.CorrelationFields {
		if assessmentField(name) {
			return errConfiguration
		}
	}

	return nil
}

// exactSelector parses one public generic target without wildcards or namespace inference.
func exactSelector(value string) (pluginapi.DecisionTargetSelector, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return pluginapi.DecisionTargetSelector{}, errConfiguration
	}

	target := pluginapi.DecisionTargetSelector{Namespace: parts[0], Action: parts[1]}
	if pluginapi.ValidateDecisionTargetSelector(target) != nil {
		return pluginapi.DecisionTargetSelector{}, errConfiguration
	}

	return target, nil
}

// extractSubjects applies only the compiled target's scalar and record field extractors.
func (c *configuration) extractSubjects(target pluginapi.DecisionTargetSelector, facts []pluginapi.DecisionFactView) ([]extractedSubject, error) {
	binding, exists := c.bindings[target]
	if !exists {
		return nil, errObservationInput
	}

	indexed := make(map[string]pluginapi.DecisionValue, len(facts))
	for _, fact := range facts {
		if _, exists := indexed[fact.ID()]; exists {
			return nil, errObservationInput
		}

		indexed[fact.ID()] = fact.Value()
	}

	result := make([]extractedSubject, 0, len(binding.Subjects))
	for _, extractor := range binding.Subjects {
		value, exists := indexed[extractor.Attribute]
		if !exists {
			return nil, errObservationInput
		}

		subjects, err := c.extractValues(extractor, value)
		if err != nil {
			return nil, err
		}

		result = append(result, subjects...)
		if len(result) > maximumExpandedSubjects {
			return nil, errObservationInput
		}
	}

	return result, nil
}

// extractValues preserves record-local identity instead of mixing fields from unrelated records.
func (c *configuration) extractValues(extractor extractorConfig, value pluginapi.DecisionValue) ([]extractedSubject, error) {
	if extractor.Field == "" {
		subject, err := c.extractedValue(extractor, value, nil)
		if err != nil {
			return nil, err
		}

		return []extractedSubject{subject}, nil
	}

	records, ok := value.Records()
	if !ok || len(records.Records()) > maximumExpandedSubjects {
		return nil, errObservationInput
	}

	result := make([]extractedSubject, 0, len(records.Records()))
	for _, record := range records.Records() {
		fields := make(map[string]pluginapi.DecisionRecordFieldValue)
		for _, field := range record.Fields() {
			fields[field.Name()] = field.Value()
		}

		subject, err := c.extractedValue(extractor, fields[extractor.Field].Value(), fields)
		if err != nil {
			return nil, err
		}

		result = append(result, subject)
	}

	return result, nil
}

// extractedValue canonicalizes a typed value and retains only explicitly configured correlation fields.
func (c *configuration) extractedValue(extractor extractorConfig, value pluginapi.DecisionValue, fields map[string]pluginapi.DecisionRecordFieldValue) (extractedSubject, error) {
	text, ok := value.StringValue()
	if !ok {
		return extractedSubject{}, errObservationInput
	}

	canonical, err := c.canonicalSubject(extractor.Kind, text)
	if err != nil {
		return extractedSubject{}, err
	}

	correlation := make(map[string]pluginapi.DecisionRecordFieldValue, len(extractor.CorrelationFields))
	for _, name := range extractor.CorrelationFields {
		field, exists := fields[name]
		if !exists {
			return extractedSubject{}, errObservationInput
		}

		correlation[name] = field
	}

	return extractedSubject{subjectInput: subjectInput{role: extractor.Role, kind: extractor.Kind, value: canonical}, correlation: correlation}, nil
}

// validExtractorAttribute reuses the public canonical fact contract without hard-coding target-specific namespaces.
func validExtractorAttribute(attribute string) bool {
	scalar := false

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Boolean: &scalar})
	if err != nil {
		return false
	}

	_, err = pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: attribute, Category: pluginapi.DecisionFactCategoryResource, Value: value})

	return err == nil
}
