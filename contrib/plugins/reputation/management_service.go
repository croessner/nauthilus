package main

import (
	"context"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// manage returns success only after the selected override and its audit receipt agree in a fresh primary read.
func (s *stateOwner) manage(ctx context.Context, operation string, input managementInput, actor string) (managementView, error) {
	if !s.ready.Load() {
		return managementView{}, errStateUnavailable
	}

	if operation != managementLookup {
		if err := s.mutateManagedOverride(ctx, operation, input, actor); err != nil {
			return managementView{}, err
		}
	}

	view, snapshots, err := s.managementLookup(ctx, subjectInput{kind: input.Kind, value: input.Subject})
	if err != nil || operation == managementLookup {
		return view, err
	}

	index := managementSlotIndex(input.Slot)
	if index < 0 || index >= len(snapshots) {
		return managementView{}, errStateUnavailable
	}

	snapshot := snapshots[index]
	if err := verifyManagementChange(snapshot, operation, input, actor); err != nil {
		return managementView{}, err
	}

	receipt := snapshot.Audit.managementAudit
	view.Audit = &receipt

	return view, nil
}

// mutateManagedOverride selects one host-derived rotation slot and atomically records its bounded operator receipt.
func (s *stateOwner) mutateManagedOverride(ctx context.Context, operation string, input managementInput, actor string) error {
	if !safeAuditText(actor) || !safeAuditText(input.AuditID) || input.AuditID == input.PreviousAudit {
		return errAssessment
	}

	tag, err := s.managementSubjectTag(ctx, input)
	if err != nil {
		return err
	}

	request := overrideRequest{Audit: true, Tag: tag, Kind: input.Kind, Band: input.Band, Reason: input.Reason,
		Creator: actor, AuditID: input.AuditID, Origin: input.Origin, PreviousAudit: input.PreviousAudit}
	wanted := storageOverrideDeleted

	if operation == managementPut {
		if input.TTLSeconds == nil {
			return errAssessment
		}

		request.Operation, request.TTL, wanted = overrideOperationPut, float64(*input.TTLSeconds), storageOverrideWritten
	} else if operation == managementDelete && safeAuditText(input.PreviousAudit) {
		request.Operation = overrideOperationDelete
	} else {
		return errAssessment
	}

	keys := s.keys.subject(request.Tag, s.models[0].id)

	response, err := s.run(ctx, scriptOverride, []string{keys.Override, s.keys.audit(request.Tag)}, request)
	if err != nil {
		return err
	}

	if len(response) < 1 || response[0] != wanted {
		return errStateUnavailable
	}

	return nil
}

// managementSlotIndex accepts only the named active or previous host key generation.
func managementSlotIndex(slot string) int {
	switch slot {
	case "", storageActive:
		return 0
	case managementPrevious:
		return 1
	default:
		return -1
	}
}

// managementLookup shares scoring and rotation rules, exposing only metadata from the exact reads used for the result.
func (s *stateOwner) managementLookup(ctx context.Context, subject subjectInput) (managementView, []assessmentSnapshot, error) {
	profiles, snapshots, err := s.readAssessment(ctx, subject, true)
	if err != nil {
		return managementView{}, nil, err
	}

	revision, err := s.config.configurationRevision()
	if err != nil {
		return managementView{}, nil, err
	}

	view := managementView{Schema: managementSchema, Kind: subject.kind, ModelID: s.models[0].id,
		ModelRevision: s.models[0].fingerprint, ConfigRevision: revision, Evidence: managementEvidenceSlots(subject.kind, snapshots)}
	if subject.kind == kindIP && profiles[profileOperational].Override == overrideNone {
		canonical, _ := s.config.canonicalSubject(subject.kind, subject.value)

		band, err := s.config.networkOverride(ctx, canonical, func(ctx context.Context, network subjectInput) (string, error) {
			current, history, err := s.readAssessment(ctx, network, true)
			if err != nil {
				return "", err
			}

			band := current[profileOperational].Override
			if band != overrideNone {
				view.Evidence = append(view.Evidence, managementEvidenceSlots(kindNetwork, history)...)
			}

			return band, nil
		})
		if err != nil {
			return managementView{}, nil, err
		}

		profiles = overlayOverrideBand(profiles, band)
	}

	view.Profiles = operatorProfiles(profiles)

	return view, snapshots, nil
}

// managementEvidenceSlots identifies ring positions without disclosing key versions or subject tags.
func managementEvidenceSlots(kind string, snapshots []assessmentSnapshot) []managementEvidence {
	result := make([]managementEvidence, 0, len(snapshots))
	for index, snapshot := range snapshots {
		slot := storageActive
		if index == 1 {
			slot = managementPrevious
		}

		result = append(result, operatorEvidence(kind, slot, snapshot))
	}

	return result
}

// verifyManagementChange compares the complete requested change against the independent primary read.
func verifyManagementChange(snapshot assessmentSnapshot, operation string, input managementInput, actor string) error {
	if snapshot.Audit == nil {
		return errStateUnavailable
	}

	expectedAudit := managementAudit{Schema: managementAuditSchema, Kind: input.Kind, Operation: operation, Reason: input.Reason,
		Creator: actor, AuditID: input.AuditID, PreviousAudit: input.PreviousAudit, Origin: input.Origin, CreatedAt: snapshot.Audit.CreatedAt}
	if snapshot.Audit.managementAudit != expectedAudit {
		return errStateUnavailable
	}

	if operation == managementDelete {
		if snapshot.OperatorOverride != nil {
			return errStateUnavailable
		}

		return nil
	}

	return verifyManagedOverride(snapshot, input, actor)
}

// verifyManagedOverride confirms lifetime and every persisted override field alongside its matching audit clock.
func verifyManagedOverride(snapshot assessmentSnapshot, input managementInput, actor string) error {
	record := snapshot.OperatorOverride
	if record == nil || input.TTLSeconds == nil {
		return errStateUnavailable
	}

	expected := overrideRecord{Schema: overrideSchema, Tag: record.Tag, Kind: input.Kind, Band: input.Band,
		Reason: input.Reason, Creator: actor, AuditID: input.AuditID, Origin: input.Origin, CreatedAt: snapshot.Audit.CreatedAt}
	if *input.TTLSeconds > 0 {
		expected.ExpiresAt = expected.CreatedAt + float64(*input.TTLSeconds)
	}

	if *record != expected {
		return errStateUnavailable
	}

	return nil
}

// managementSubjectTag resolves one named slot exclusively through the host HMAC ring.
func (s *stateOwner) managementSubjectTag(ctx context.Context, input managementInput) (string, error) {
	canonical, err := s.config.canonicalSubject(input.Kind, input.Subject)
	if err != nil {
		return "", err
	}

	tags, err := s.planner.tagger.Candidates(ctx, pluginapi.OpaqueIdentifierInput{Scope: s.config.raw.SubjectScope, Kind: input.Kind, Value: canonical})

	index := managementSlotIndex(input.Slot)
	if err != nil || len(tags) < 1 || len(tags) > 2 || index < 0 || index >= len(tags) {
		return "", errStateUnavailable
	}

	return tags[index].String(), nil
}
