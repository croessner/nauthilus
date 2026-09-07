package main

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"
)

type managementInput struct {
	TTLSeconds                                                        *int64
	Kind, Subject, Band, Reason, AuditID, Origin, PreviousAudit, Slot string
}

// decodeManagementInput rejects unknown, duplicate, null and trailing data before canonical subject lookup.
func decodeManagementInput(body []byte, operation string, cfg *configuration) (managementInput, error) {
	var input managementInput
	if len(body) == 0 || len(body) > 4096 || cfg == nil || !utf8.Valid(body) {
		return input, errAssessment
	}

	fields := input.fields(operation)
	if err := decodeManagementFields(body, fields); err != nil {
		return input, err
	}

	canonical, err := cfg.canonicalSubject(input.Kind, input.Subject)
	if err != nil {
		return input, err
	}

	input.Subject = canonical
	if operation == managementLookup {
		return input, nil
	}

	return input, input.validateMutation(operation)
}

// decodeManagementFields decodes one flat object against exact operation-owned typed destinations.
func decodeManagementFields(body []byte, fields map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))

	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errAssessment
	}

	seen := map[string]bool{}
	for decoder.More() {
		if err := decodeManagementField(decoder, fields, seen); err != nil {
			return err
		}
	}

	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return errAssessment
	}

	if _, err = decoder.Token(); err != io.EOF {
		return errAssessment
	}

	return nil
}

// fields defines exact operation-specific decoding destinations.
func (input *managementInput) fields(operation string) map[string]any {
	fields := map[string]any{fieldKind: &input.Kind, "subject": &input.Subject}
	if operation != managementLookup {
		fields["slot"] = &input.Slot

		fields[managementReason], fields["audit_id"], fields["origin"], fields["previous_audit"] = &input.Reason, &input.AuditID, &input.Origin, &input.PreviousAudit
		if operation == managementPut {
			fields["band"], fields["ttl_seconds"] = &input.Band, &input.TTLSeconds
		}
	}

	return fields
}

// validateMutation bounds operator audit fields, slot selection and explicit override lifetime.
func (input managementInput) validateMutation(operation string) error {
	if input.Slot == "" {
		input.Slot = storageActive
	}

	if input.Slot != storageActive && input.Slot != managementPrevious {
		return errAssessment
	}

	if !input.validAuditFields() {
		return errAssessment
	}

	if operation == managementDelete {
		if input.PreviousAudit == "" {
			return errAssessment
		}

		return nil
	}

	if operation != managementPut || !input.validOverride() {
		return errAssessment
	}

	return nil
}

// validAuditFields rejects malformed audit metadata independently of mutation type.
func (input managementInput) validAuditFields() bool {
	return identifierPattern.MatchString(input.Reason) && identifierPattern.MatchString(input.Origin) && safeAuditText(input.AuditID) && (input.PreviousAudit == "" || safeAuditText(input.PreviousAudit))
}

// decodeManagementField rejects duplicate, unknown or null fields before assigning a typed value.
func decodeManagementField(decoder *json.Decoder, fields map[string]any, seen map[string]bool) error {
	token, err := decoder.Token()

	name, ok := token.(string)
	if err != nil || !ok || seen[name] || fields[name] == nil {
		return errAssessment
	}

	seen[name] = true

	var raw json.RawMessage
	if decoder.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, fields[name]) != nil {
		return errAssessment
	}

	return nil
}

// validOverride validates the requested band and explicit bounded lifetime.
func (input managementInput) validOverride() bool {
	return overrideBand(input.Band) && input.Band != overrideNone && input.TTLSeconds != nil &&
		*input.TTLSeconds >= 0 && *input.TTLSeconds <= int64(maximumRetention/time.Second)
}
