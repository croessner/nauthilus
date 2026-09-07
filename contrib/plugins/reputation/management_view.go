package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

const managementAuditSchema = "reputation-operator-audit.v1"

type managementAudit struct {
	Schema        string  `json:"schema"`
	Kind          string  `json:"kind"`
	Operation     string  `json:"operation"`
	Reason        string  `json:"reason"`
	Creator       string  `json:"creator"`
	AuditID       string  `json:"audit_id"`
	PreviousAudit string  `json:"previous_audit"`
	Origin        string  `json:"origin"`
	CreatedAt     float64 `json:"created_at"`
}

type managementAuditRecord struct {
	managementAudit
	Tag string `json:"tag"`
}

type managementOverride struct {
	Band      string  `json:"band"`
	Reason    string  `json:"reason"`
	Creator   string  `json:"creator"`
	AuditID   string  `json:"audit_id"`
	Origin    string  `json:"origin"`
	CreatedAt float64 `json:"created_at"`
	ExpiresAt float64 `json:"expires_at"`
}

type managementScores struct {
	Risk       float64 `json:"risk_score"`
	Trust      float64 `json:"trust_score"`
	Confidence float64 `json:"confidence"`
	Samples    float64 `json:"samples"`
	Diversity  int     `json:"source_diversity"`
	AgeSeconds int64   `json:"age_seconds"`
}

type managementProfile struct {
	Details  *managementScores `json:"details,omitempty"`
	State    string            `json:"state"`
	Band     string            `json:"band"`
	Override string            `json:"override"`
}

type managementEvidence struct {
	SourceClasses   map[string][]string `json:"source_classes"`
	Override        *managementOverride `json:"override,omitempty"`
	Audit           *managementAudit    `json:"last_change,omitempty"`
	Kind            string              `json:"kind"`
	Slot            string              `json:"slot"`
	State           string              `json:"state"`
	ObservedAt      float64             `json:"observed_at"`
	UpdatedAt       float64             `json:"updated_at"`
	RiskAt          float64             `json:"risk_at"`
	TrustAt         float64             `json:"trust_at"`
	AuthoritativeAt float64             `json:"authoritative_at"`
}

type managementView struct {
	Profiles       map[string]managementProfile `json:"profiles"`
	Evidence       []managementEvidence         `json:"evidence"`
	Audit          *managementAudit             `json:"verified_change,omitempty"`
	Schema         string                       `json:"schema"`
	Kind           string                       `json:"kind"`
	ModelID        string                       `json:"model_id"`
	ModelRevision  string                       `json:"model_revision"`
	ConfigRevision string                       `json:"config_revision"`
}

// validateManagement rejects malformed protected metadata before any operator response is constructed.
func (s assessmentSnapshot) validateManagement(cfg *configuration, tag, kind string) error {
	if err := s.validateOperatorOverride(tag, kind); err != nil {
		return err
	}

	if s.Audit != nil && s.Audit.validate(tag, kind, s.Now) != nil {
		return errAssessment
	}

	return s.validateManagementSources(cfg)
}

// validateManagementSources bounds profile membership to configured evidence classes.
func (s assessmentSnapshot) validateManagementSources(cfg *configuration) error {
	if s.State == assessmentMissing && len(s.Sources) == 0 {
		return nil
	}

	if len(s.Sources) != 3 {
		return errAssessment
	}

	for profile, classes := range s.Sources {
		if !profileName(profile) || len(classes) > 8 {
			return errAssessment
		}

		for class, present := range classes {
			if _, ok := cfg.raw.SourceClassCaps[class]; !ok || !present {
				return errAssessment
			}
		}
	}

	return nil
}

// validate binds audit metadata to the exact host-derived key without exporting that key identity.
func (a managementAuditRecord) validate(tag, kind string, now float64) error {
	input := managementInput{Reason: a.Reason, Origin: a.Origin, AuditID: a.AuditID, PreviousAudit: a.PreviousAudit}
	if a.Schema != managementAuditSchema || a.Tag != tag || a.Kind != kind ||
		(a.Operation != managementPut && a.Operation != managementDelete) || !safeAuditText(a.Creator) ||
		!positiveBound(a.CreatedAt, now) || !input.validAuditFields() {
		return errAssessment
	}

	return nil
}

// operatorEvidence copies only sanctioned metadata and excludes raw subjects and opaque tags.
func operatorEvidence(kind, slot string, snapshot assessmentSnapshot) managementEvidence {
	result := managementEvidence{Kind: kind, Slot: slot, State: snapshot.State, ObservedAt: snapshot.Now, UpdatedAt: snapshot.UpdatedAt,
		RiskAt: snapshot.RiskAt, TrustAt: snapshot.TrustAt, AuthoritativeAt: snapshot.AuthoritativeAt, SourceClasses: map[string][]string{}}
	for profile, classes := range snapshot.Sources {
		names := make([]string, 0, len(classes))
		for class := range classes {
			names = append(names, class)
		}

		slices.Sort(names)
		result.SourceClasses[profile] = names
	}

	if value := snapshot.OperatorOverride; value != nil {
		result.Override = &managementOverride{Band: value.Band, Reason: value.Reason, Creator: value.Creator, AuditID: value.AuditID,
			Origin: value.Origin, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt}
	}

	if snapshot.Audit != nil {
		receipt := snapshot.Audit.managementAudit
		result.Audit = &receipt
	}

	return result
}

// operatorProfiles preserves conditional measurements instead of inventing numeric zero evidence.
func operatorProfiles(profiles map[string]assessmentTuple) map[string]managementProfile {
	result := make(map[string]managementProfile, len(profiles))
	for name, tuple := range profiles {
		profile := managementProfile{State: tuple.State, Band: tuple.Band, Override: tuple.Override}
		if d := tuple.Details; d != nil {
			profile.Details = &managementScores{Risk: d.Risk, Trust: d.Trust, Confidence: d.Confidence, Samples: d.Samples, Diversity: d.Diversity, AgeSeconds: d.AgeSeconds}
		}

		result[name] = profile
	}

	return result
}

// configurationRevision includes read-time calibration without changing the immutable ingestion model.
func (c *configuration) configurationRevision() (string, error) {
	encoded, err := json.Marshal(c.raw)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(encoded)

	return hex.EncodeToString(digest[:]), nil
}

// validateOperatorOverride binds detailed override metadata to the same primary snapshot and clock.
func (s assessmentSnapshot) validateOperatorOverride(tag, kind string) error {
	if s.OperatorOverride != nil {
		raw, err := json.Marshal(s.OperatorOverride)
		if err != nil {
			return errAssessment
		}

		record, err := decodeOverrideRecord(string(raw), tag, kind)
		if err != nil || record.Band != s.Override || record.CreatedAt > s.Now || (record.ExpiresAt > 0 && record.ExpiresAt <= s.Now) {
			return errAssessment
		}
	} else if s.Override != overrideNone {
		return errAssessment
	}

	return nil
}
