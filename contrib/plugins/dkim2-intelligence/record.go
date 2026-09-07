package main

import (
	"fmt"
	projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"slices"
	"sort"
)

type recordBuilder struct {
	fields map[string]pluginapi.DecisionRecordFieldValue
	err    error
}

// newRecordBuilder owns one complete record until all schema and conditional checks pass.
func newRecordBuilder() *recordBuilder {
	return &recordBuilder{fields: make(map[string]pluginapi.DecisionRecordFieldValue)}
}

// add constructs immutable typed leaves and retains the first failure without publishing partial output.
func (b *recordBuilder) add(name string, input pluginapi.DecisionValueInput) {
	if b.err != nil {
		return
	}

	value, err := pluginapi.NewDecisionValue(input)
	if err != nil {
		b.err = err
		return
	}

	field, err := pluginapi.NewDecisionRecordFieldValue(value)
	if err != nil {
		b.err = err
		return
	}

	b.fields[name] = field
}

// text adds an owned string leaf.
func (b *recordBuilder) text(name, value string) {
	b.add(name, pluginapi.DecisionValueInput{String: &value})
}

// integer adds an owned integer leaf.
func (b *recordBuilder) integer(name string, value int64) {
	b.add(name, pluginapi.DecisionValueInput{Integer: &value})
}

// boolean adds an owned semantic flag.
func (b *recordBuilder) boolean(name string, value bool) {
	b.add(name, pluginapi.DecisionValueInput{Boolean: &value})
}

// strings adds a canonical list, preserving an explicitly empty list.
func (b *recordBuilder) strings(name string, values []string) {
	b.add(name, pluginapi.DecisionValueInput{Strings: append([]string{}, values...)})
}

// tuple projects only validated common assessment members and shares the peer profile explicitly.
func (b *recordBuilder) tuple(role string, tuple view.Tuple) {
	fields, err := view.Encode(tuple)
	if err != nil {
		b.err = err
		return
	}

	for name, value := range fields {
		if role != valueSigner && name == valueProfile {
			continue
		}

		b.fields[tupleFieldName(role, name)] = value
	}
}

// record validates the complete closed view before freezing deterministic fields.
func (b *recordBuilder) record(specs []fieldSpec, maximumBytes int) (pluginapi.DecisionRecord, error) {
	if b.err != nil {
		return pluginapi.DecisionRecord{}, b.err
	}

	if err := validateRecordFields(b.fields, specs, maximumBytes); err != nil {
		return pluginapi.DecisionRecord{}, err
	}

	if err := validateRecordSemantics(b.fields); err != nil {
		return pluginapi.DecisionRecord{}, err
	}

	names := make([]string, 0, len(b.fields))
	for name := range b.fields {
		names = append(names, name)
	}

	sort.Strings(names)

	fields := make([]pluginapi.DecisionRecordField, 0, len(names))
	for _, name := range names {
		field, err := pluginapi.NewDecisionRecordField(name, b.fields[name])
		if err != nil {
			return pluginapi.DecisionRecord{}, err
		}

		fields = append(fields, field)
	}

	return pluginapi.NewDecisionRecord(fields)
}

// validateRecordFields applies exact kinds, bounds, closed vocabularies and conservative aggregate accounting.
func validateRecordFields(fields map[string]pluginapi.DecisionRecordFieldValue, specs []fieldSpec, maximumBytes int) error {
	size, known := 0, 0

	for _, spec := range specs {
		field, present := fields[spec.Name]
		if !present {
			if spec.Required {
				return errCorrelation
			}

			continue
		}

		count, err := validateField(field.Value(), spec)
		if err != nil {
			return fmt.Errorf("invalid composed field %s: %w", spec.Name, err)
		}

		size += len(spec.Name) + count + 16
		known++
	}

	if known != len(fields) || size > maximumBytes {
		return errCorrelation
	}

	return nil
}

// validateField validates closed scalar or canonical list semantics without truncation.
func validateField(value pluginapi.DecisionValue, spec fieldSpec) (int, error) {
	if value.Kind() != spec.Kind {
		return 0, errCorrelation
	}

	switch spec.Kind {
	case pluginapi.DecisionValueKindString:
		text, _ := value.StringValue()
		if !validFieldText(text, spec) {
			return 0, errCorrelation
		}

		return composedValueBytes(value), nil
	case pluginapi.DecisionValueKindInteger:
		number, _ := value.Integer()
		if spec.MaxInteger > 0 && (number < spec.MinInteger || number > spec.MaxInteger) {
			return 0, errCorrelation
		}
	case pluginapi.DecisionValueKindBytes:
		data, _ := value.Bytes()
		if len(data) != spec.MaxBytes {
			return 0, errCorrelation
		}

		return composedValueBytes(value), nil
	case pluginapi.DecisionValueKindStrings:
		if err := validateStringList(value, spec); err != nil {
			return 0, err
		}

	}

	return composedValueBytes(value), nil
}

// validateRecordSemantics cross-checks the common tuples and the independent contract state/strength pair.
func validateRecordSemantics(fields map[string]pluginapi.DecisionRecordFieldValue) error {
	if _, chain := fields[valueSequence]; chain {
		if err := validateMappedTuple(fields, valueSigner, ""); err != nil {
			return err
		}

		domain, _ := fields[valueSignerDomain].Value().StringValue()
		if !projection.CanonicalDomain(domain) {
			return errCorrelation
		}

		return validateChainContract(fields)
	}

	profile, _ := fields[valueReputationProfile].Value().StringValue()
	for _, role := range []string{valueIP, valueNetwork, valueAsn} {
		if err := validateMappedTuple(fields, role, profile); err != nil {
			return err
		}
	}

	if err := validatePeerGeographicFields(fields); err != nil {
		return err
	}

	return validateContractPair(fields, "target_contract_", false)
}

// validateChainContract prevents current-peer evidence from being assigned to historical records.
func validateChainContract(fields map[string]pluginapi.DecisionRecordFieldValue) error {
	target, ok := fields[valueIsTarget].Value().Boolean()
	if !ok {
		return errCorrelation
	}

	state, _ := fields[valueIdentityContractState].Value().StringValue()
	if !target && state == valueMatched {
		return errCorrelation
	}

	return validateContractPair(fields, "identity_contract_", !target)
}

// validateMappedTuple reverses only the exact schema-owned field mapping into the common decoder.
func validateMappedTuple(fields map[string]pluginapi.DecisionRecordFieldValue, role, profile string) error {
	tuple := make(map[string]pluginapi.DecisionRecordFieldValue)

	for _, spec := range view.Fields() {
		if role != valueSigner && spec.Name == valueProfile {
			value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &profile})
			if err != nil {
				return err
			}

			field, err := pluginapi.NewDecisionRecordFieldValue(value)
			if err != nil {
				return err
			}

			tuple[spec.Name] = field
		} else if field, present := fields[tupleFieldName(role, spec.Name)]; present {
			tuple[spec.Name] = field
		}
	}

	_, err := view.Decode(tuple)

	return err
}

// validateContractPair rejects stronger evidence than the recorded identity state supports.
func validateContractPair(fields map[string]pluginapi.DecisionRecordFieldValue, prefix string, historical bool) error {
	state, _ := fields[prefix+valueState].Value().StringValue()
	strength, _ := fields[prefix+"strength"].Value().StringValue()

	switch state {
	case valueMatched:
		if strength == valueCidr || strength == valueAsn {
			return nil
		}
	case valueDomainOnly:
		if historical && strength == valueDomainOnly {
			return nil
		}
	case valueMissing, valueMismatch, valueUnavailable:
		if strength == valueNone {
			return nil
		}
	}

	return errCorrelation
}

// validatePeerGeographicFields keeps absent and unavailable geographic states free of conditional details.
func validatePeerGeographicFields(fields map[string]pluginapi.DecisionRecordFieldValue) error {
	state, _ := fields[valueGeoipState].Value().StringValue()
	_, hasAge := fields[valueGeoipAgeSeconds]

	matched := state == valueFresh || state == valueStale
	if matched != hasAge {
		return errCorrelation
	}

	for _, name := range []string{valueCountryIso, valueAsn, valueAsnOrg, valueAsnPrefix} {
		if _, present := fields[name]; present && !matched {
			return errCorrelation
		}
	}

	if country, present := fields[valueCountryIso]; present {
		text, _ := country.Value().StringValue()
		if !validCountry(text) {
			return errCorrelation
		}
	}

	return nil
}

// validateStringList enforces a bounded sorted unique set of exact closed values where declared.
func validateStringList(value pluginapi.DecisionValue, spec fieldSpec) error {
	values, _ := value.Strings()
	if len(values) > spec.MaxItems || !projection.SortedUniqueStrings(values) {
		return errCorrelation
	}

	for _, text := range values {
		if !validFieldText(text, spec) {
			return errCorrelation
		}
	}

	return nil
}

// validFieldText enforces the schema-owned string bound and optional closed vocabulary.
func validFieldText(value string, spec fieldSpec) bool {
	return len(value) <= spec.MaxLength && (len(spec.Values) == 0 || slices.Contains(spec.Values, value))
}
