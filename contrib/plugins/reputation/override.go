package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const overrideSchema = "reputation-override.v1"
const overrideOperationPut = "put"
const overrideOperationDelete = "delete"

var errOverrideConflict = errors.New("reputation override changed")

type overrideInput struct {
	Band          string
	Reason        string
	Creator       string
	AuditID       string
	Origin        string
	PreviousAudit string
	TTL           time.Duration
}

type overrideRecord struct {
	Schema    string  `json:"schema"`
	Tag       string  `json:"tag"`
	Kind      string  `json:"kind"`
	Band      string  `json:"band"`
	Reason    string  `json:"reason"`
	Creator   string  `json:"creator"`
	AuditID   string  `json:"audit_id"`
	Origin    string  `json:"origin"`
	CreatedAt float64 `json:"created_at"`
	ExpiresAt float64 `json:"expires_at"`
}

type overrideRequest struct {
	Audit         bool    `json:"audit"`
	Operation     string  `json:"operation"`
	Tag           string  `json:"tag"`
	Kind          string  `json:"kind"`
	Band          string  `json:"band"`
	Reason        string  `json:"reason"`
	Creator       string  `json:"creator"`
	AuditID       string  `json:"audit_id"`
	Origin        string  `json:"origin"`
	PreviousAudit string  `json:"previous_audit"`
	TTL           float64 `json:"ttl"`
}

// putOverride writes only the active subject slot; authenticated management owns authorization and explicit rotation copies.
func (s *stateOwner) putOverride(ctx context.Context, subject subjectInput, input overrideInput) (overrideRecord, error) {
	if !s.ready.Load() || input.validate() != nil {
		return overrideRecord{}, errAssessment
	}

	tag, err := s.activeSubjectTag(ctx, subject)
	if err != nil {
		return overrideRecord{}, err
	}

	request := overrideRequest{Operation: overrideOperationPut, Tag: tag, Kind: subject.kind, Band: input.Band, Reason: input.Reason,
		Creator: input.Creator, AuditID: input.AuditID, Origin: input.Origin, PreviousAudit: input.PreviousAudit, TTL: input.TTL.Seconds()}

	response, err := s.run(ctx, scriptOverride, []string{s.keys.subject(tag, s.models[0].id).Override}, request)
	if err != nil {
		return overrideRecord{}, err
	}

	if len(response) != 2 || response[0] != storageOverrideWritten {
		return overrideRecord{}, errStateUnavailable
	}

	record, err := decodeOverrideRecord(response[1], tag, subject.kind)
	if err != nil || record.Band != input.Band || record.AuditID != input.AuditID {
		return overrideRecord{}, errStateUnavailable
	}

	return record, nil
}

// decodeOverrideRecord validates bounded audit readback from the host's primary script response.
func decodeOverrideRecord(raw any, tag, kind string) (overrideRecord, error) {
	encoded, ok := raw.(string)
	if !ok || len(encoded) > 4096 {
		return overrideRecord{}, errStateUnavailable
	}

	var record overrideRecord

	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&record) != nil || record.Schema != overrideSchema || record.Tag != tag || record.Kind != kind ||
		!positiveBound(record.CreatedAt, 1e11) || !nonnegativeBound(record.ExpiresAt, 1e11) ||
		(record.ExpiresAt != 0 && record.ExpiresAt <= record.CreatedAt) {
		return overrideRecord{}, errStateUnavailable
	}

	input := overrideInput{Band: record.Band, Reason: record.Reason, Creator: record.Creator, AuditID: record.AuditID, Origin: record.Origin}
	if input.validate() != nil {
		return overrideRecord{}, errStateUnavailable
	}

	return record, nil
}

// getOverride reads active-slot operator metadata without refreshing authority or consulting replica state.
func (s *stateOwner) getOverride(ctx context.Context, subject subjectInput) (*overrideRecord, error) {
	if !s.ready.Load() {
		return nil, errStateUnavailable
	}

	tag, err := s.activeSubjectTag(ctx, subject)
	if err != nil {
		return nil, err
	}

	response, err := s.run(ctx, scriptOverride, []string{s.keys.subject(tag, s.models[0].id).Override}, overrideRequest{Operation: "get", Tag: tag, Kind: subject.kind})
	if err != nil {
		return nil, err
	}

	if len(response) == 1 && response[0] == storageOverrideMissing {
		return nil, nil
	}

	if len(response) != 2 || response[0] != storageOverrideRead {
		return nil, errStateUnavailable
	}

	record, err := decodeOverrideRecord(response[1], tag, subject.kind)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// deleteOverride removes only the operator revision explicitly selected by authenticated management.
func (s *stateOwner) deleteOverride(ctx context.Context, subject subjectInput, previousAudit string) error {
	if !s.ready.Load() || !safeAuditText(previousAudit) {
		return errAssessment
	}

	tag, err := s.activeSubjectTag(ctx, subject)
	if err != nil {
		return err
	}

	response, err := s.run(ctx, scriptOverride, []string{s.keys.subject(tag, s.models[0].id).Override}, overrideRequest{
		Operation: overrideOperationDelete, Tag: tag, Kind: subject.kind, PreviousAudit: previousAudit})
	if err != nil {
		return err
	}

	if len(response) != 1 || response[0] != storageOverrideDeleted {
		return errStateUnavailable
	}

	return nil
}

// activeSubjectTag canonicalizes management input before deriving the one active host-owned identifier.
func (s *stateOwner) activeSubjectTag(ctx context.Context, subject subjectInput) (string, error) {
	canonical, err := s.config.canonicalSubject(subject.kind, subject.value)
	if err != nil {
		return "", err
	}

	tag, err := s.planner.tagger.Tag(ctx, pluginapi.OpaqueIdentifierInput{Scope: s.config.raw.SubjectScope, Kind: subject.kind, Value: canonical})
	if err != nil {
		return "", err
	}

	return tag.String(), nil
}

// validate bounds all operator metadata and accepts no implicit override or unbounded lifetime.
func (i overrideInput) validate() error {
	if !overrideBand(i.Band) || i.Band == overrideNone || !identifierPattern.MatchString(i.Reason) ||
		!identifierPattern.MatchString(i.Origin) || !safeAuditText(i.Creator) || !safeAuditText(i.AuditID) ||
		(i.PreviousAudit != "" && !safeAuditText(i.PreviousAudit)) || i.TTL < 0 || i.TTL > maximumRetention {
		return errAssessment
	}

	return nil
}

// safeAuditText excludes control characters and surrounding whitespace from bounded operator identities.
func safeAuditText(value string) bool {
	if !utf8.ValidString(value) || len(value) < 1 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}

	for _, character := range value {
		if character < 32 || character == 127 {
			return false
		}
	}

	return true
}
