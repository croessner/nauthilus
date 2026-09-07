package reputationview

import pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"

// Field defines one required or conditionally measured common tuple member.
type Field struct {
	Name      string
	Kind      pluginapi.DecisionValueKind
	MaxLength int
	Required  bool
}

// Fields returns the closed tuple vocabulary with detached schema metadata.
func Fields() []Field {
	return []Field{
		{Name: fieldState, Kind: pluginapi.DecisionValueKindString, MaxLength: 16, Required: true},
		{Name: fieldProfile, Kind: pluginapi.DecisionValueKindString, MaxLength: 32, Required: true},
		{Name: fieldBand, Kind: pluginapi.DecisionValueKindString, MaxLength: 16, Required: true},
		{Name: fieldOverride, Kind: pluginapi.DecisionValueKindString, MaxLength: 16, Required: true},
		{Name: fieldRiskScore, Kind: pluginapi.DecisionValueKindDouble},
		{Name: fieldTrustScore, Kind: pluginapi.DecisionValueKindDouble},
		{Name: fieldConfidence, Kind: pluginapi.DecisionValueKindDouble},
		{Name: fieldSamples, Kind: pluginapi.DecisionValueKindDouble},
		{Name: fieldSourceDiversity, Kind: pluginapi.DecisionValueKindInteger},
		{Name: fieldAgeSeconds, Kind: pluginapi.DecisionValueKindInteger},
	}
}

// Decode validates a complete closed tuple before a composer may consume it.
func Decode(fields map[string]pluginapi.DecisionRecordFieldValue) (Tuple, error) {
	if err := validateFields(fields); err != nil {
		return Tuple{}, err
	}

	state, _ := fields[fieldState].Value().StringValue()
	profile, _ := fields[fieldProfile].Value().StringValue()
	band, _ := fields[fieldBand].Value().StringValue()
	override, _ := fields[fieldOverride].Value().StringValue()
	tuple := Tuple{State: state, Profile: profile, Band: band, Override: override}

	if len(fields) == 10 {
		risk, _ := fields[fieldRiskScore].Value().Double()
		trust, _ := fields[fieldTrustScore].Value().Double()
		confidence, _ := fields[fieldConfidence].Value().Double()
		samples, _ := fields[fieldSamples].Value().Double()
		diversity, _ := fields[fieldSourceDiversity].Value().Integer()
		age, _ := fields[fieldAgeSeconds].Value().Integer()
		tuple.Details = &Details{Risk: risk, Trust: trust, Confidence: confidence, Samples: samples, Diversity: int(diversity), AgeSeconds: age}
	}

	return tuple, tuple.Validate()
}

// validateFields rejects unknown vocabulary, wrong kinds and partial detail sets.
func validateFields(fields map[string]pluginapi.DecisionRecordFieldValue) error {
	if len(fields) != 4 && len(fields) != 10 {
		return ErrAssessment
	}

	known := 0

	for _, spec := range Fields() {
		value, present := fields[spec.Name]
		if !present {
			if spec.Required || len(fields) == 10 {
				return ErrAssessment
			}

			continue
		}

		if value.Value().Kind() != spec.Kind {
			return ErrAssessment
		}

		known++
	}

	if known != len(fields) {
		return ErrAssessment
	}

	return nil
}

// Encode emits exactly the validated state-dependent tuple vocabulary.
func Encode(tuple Tuple) (map[string]pluginapi.DecisionRecordFieldValue, error) {
	if err := tuple.Validate(); err != nil {
		return nil, err
	}

	values := map[string]pluginapi.DecisionValueInput{
		fieldState: {String: &tuple.State}, fieldProfile: {String: &tuple.Profile},
		fieldBand: {String: &tuple.Band}, fieldOverride: {String: &tuple.Override},
	}
	if details := tuple.Details; details != nil {
		diversity := int64(details.Diversity)
		values[fieldRiskScore] = pluginapi.DecisionValueInput{Double: &details.Risk}
		values[fieldTrustScore] = pluginapi.DecisionValueInput{Double: &details.Trust}
		values[fieldConfidence] = pluginapi.DecisionValueInput{Double: &details.Confidence}
		values[fieldSamples] = pluginapi.DecisionValueInput{Double: &details.Samples}
		values[fieldSourceDiversity] = pluginapi.DecisionValueInput{Integer: &diversity}
		values[fieldAgeSeconds] = pluginapi.DecisionValueInput{Integer: &details.AgeSeconds}
	}

	result := make(map[string]pluginapi.DecisionRecordFieldValue, len(values))
	for name, input := range values {
		value, err := pluginapi.NewDecisionValue(input)
		if err != nil {
			return nil, err
		}

		field, err := pluginapi.NewDecisionRecordFieldValue(value)
		if err != nil {
			return nil, err
		}

		result[name] = field
	}

	return result, nil
}
