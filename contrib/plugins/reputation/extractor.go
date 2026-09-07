package main

import (
	"strconv"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// maximumAssessmentSubjects bounds read-only correlation independently of event write fanout.
const maximumAssessmentSubjects = 160
const deriveNetworkFromIP = "network_from_ip"

type targetBindingConfig struct {
	Component       string            `mapstructure:"component"`
	DecisionProfile string            `mapstructure:"decision_profile"`
	Subjects        []extractorConfig `mapstructure:"subjects"`
	Target          string            `mapstructure:"target"`
	OutputFact      string            `mapstructure:"output_fact"`
}

type extractorConfig struct {
	Provider          string                                 `mapstructure:"provider"`
	Category          pluginapi.DecisionFactCategory         `mapstructure:"category"`
	CorrelationTypes  map[string]pluginapi.DecisionValueKind `mapstructure:"correlation_types"`
	Optional          bool                                   `mapstructure:"optional"`
	Derive            string                                 `mapstructure:"derive"`
	InputKind         pluginapi.DecisionValueKind            `mapstructure:"input_kind"`
	CorrelationFields []string                               `mapstructure:"correlation_fields"`
	Attribute         string                                 `mapstructure:"attribute"`
	Field             string                                 `mapstructure:"field"`
	Role              string                                 `mapstructure:"role"`
	Kind              string                                 `mapstructure:"kind"`
}

type extractedSubject struct {
	unavailable bool
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

		if _, err := assessmentInputs(binding.Subjects); err != nil {
			return err
		}
		c.bindings[target] = binding
	}

	return nil
}

// validateExtractor rejects dynamic selectors, nested traversal and undeclared subject spaces.
func validateExtractor(extractor extractorConfig) error {
	if extractor.Optional && extractor.Field != "" {
		return errConfiguration
	}

	if extractor.Derive != "" && (extractor.Derive != deriveNetworkFromIP || extractor.Kind != kindNetwork || extractor.InputKind == pluginapi.DecisionValueKindInteger) {
		return errConfiguration
	}

	if extractor.InputKind != "" && extractor.InputKind != pluginapi.DecisionValueKindString && (extractor.InputKind != pluginapi.DecisionValueKindInteger || extractor.Kind != kindASN) {
		return errConfiguration
	}

	if !validExtractorAttribute(extractor.Attribute) || !identifierPattern.MatchString(extractor.Role) || !subjectKind(extractor.Kind) {
		return errConfiguration
	}

	if extractor.Field != "" && !identifierPattern.MatchString(extractor.Field) {
		return errConfiguration
	}

	if !uniqueIdentifiers(extractor.CorrelationFields, 8, true) || (extractor.Field == "" && len(extractor.CorrelationFields) > 0) {
		return errConfiguration
	}

	if len(extractor.CorrelationTypes) != len(extractor.CorrelationFields) {
		return errConfiguration
	}
	for _, name := range extractor.CorrelationFields {
		kind := extractor.CorrelationTypes[name]
		if assessmentField(name) || !kind.IsValid() || kind == pluginapi.DecisionValueKindRecords {
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
			if !extractor.Optional {
				return nil, errObservationInput
			}

			result = append(result, extractedSubject{subjectInput: subjectInput{role: extractor.Role, kind: extractor.Kind}, unavailable: true})

			continue
		}

		subjects, err := c.extractValues(extractor, value)
		if err != nil {
			return nil, err
		}

		result = append(result, subjects...)
		if len(result) > maximumAssessmentSubjects {
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
	if !ok || len(records.Records()) > maximumAssessmentSubjects {
		return nil, errObservationInput
	}

	result := make([]extractedSubject, 0, len(records.Records()))
	for _, record := range records.Records() {
		fields := recordFieldValues(record)

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
	text, err := extractorText(extractor, value)
	if err != nil {
		return extractedSubject{}, err
	}

	canonical, err := c.extractionSubject(extractor, text)
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

// extractorText accepts only the configured wire kind and canonicalizes a bounded integer ASN.
func extractorText(extractor extractorConfig, value pluginapi.DecisionValue) (string, error) {
	if extractor.InputKind == pluginapi.DecisionValueKindInteger {
		number, valid := value.Integer()
		if !valid || extractor.Kind != kindASN || number < 1 || number > 4294967295 {
			return "", errObservationInput
		}

		return strconv.FormatInt(number, 10), nil
	}

	text, valid := value.StringValue()
	if !valid {
		return "", errObservationInput
	}

	return text, nil
}

// extractionSubject derives configured network identities from the same canonical IP used by learning.
func (c *configuration) extractionSubject(extractor extractorConfig, value string) (string, error) {
	if extractor.Derive == deriveNetworkFromIP {
		canonical, err := canonicalIP(value)
		if err != nil {
			return "", err
		}

		return c.networkSubject(canonical), nil
	}

	return c.canonicalSubject(extractor.Kind, value)
}
