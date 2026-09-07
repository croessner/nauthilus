package main

import (
	"context"
	"encoding/json"
	"math"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type assessmentRequest struct {
	Details        bool                `json:"details"`
	Profiles       []profileDefinition `json:"profiles"`
	Classes        []classDefinition   `json:"classes"`
	Fingerprint    string              `json:"fingerprint"`
	Kind           string              `json:"kind"`
	Tag            string              `json:"tag"`
	Retention      float64             `json:"retention"`
	DiversityFloor float64             `json:"diversity_floor"`
}

type assessmentSnapshot struct {
	Sources          map[string]map[string]bool `json:"sources,omitempty"`
	OperatorOverride *overrideRecord            `json:"operator_override,omitempty"`
	Audit            *managementAuditRecord     `json:"audit,omitempty"`
	UpdatedAt        float64                    `json:"updated_at"`
	Profiles         []profileMass              `json:"profiles"`
	State            string                     `json:"state"`
	Override         string                     `json:"override"`
	Now              float64                    `json:"now"`
	RiskAt           float64                    `json:"risk_at"`
	TrustAt          float64                    `json:"trust_at"`
	AuthoritativeAt  float64                    `json:"authoritative_at"`
}

// assess selects one profile from the complete, independently validated multi-profile snapshot.
func (s *stateOwner) assess(ctx context.Context, subject subjectInput, profile string) assessmentTuple {
	if !profileName(profile) {
		return emptyAssessment(assessmentUnavailable, profile)
	}

	return s.assessProfiles(ctx, subject)[profile]
}

// assessProfiles requires every configured tag version and never exposes a partial rotation snapshot.
func (s *stateOwner) assessProfiles(ctx context.Context, subject subjectInput) map[string]assessmentTuple {
	result, _, err := s.readAssessment(ctx, subject, false)
	if err != nil {
		return emptyProfiles(assessmentUnavailable)
	}

	if subject.kind == kindIP {
		canonical, _ := s.config.canonicalSubject(subject.kind, subject.value)
		return s.applyNetworkOverride(ctx, canonical, result)
	}

	return result
}

// readAssessment shares primary reads and conservative rotation merging with the exact operator view.
func (s *stateOwner) readAssessment(ctx context.Context, subject subjectInput, details bool) (map[string]assessmentTuple, []assessmentSnapshot, error) {
	unavailable := emptyProfiles(assessmentUnavailable)
	if !s.ready.Load() {
		return unavailable, nil, errStateUnavailable
	}

	canonical, err := s.config.canonicalSubject(subject.kind, subject.value)
	if err != nil {
		return unavailable, nil, err
	}

	tags, err := s.planner.tagger.Candidates(ctx, pluginapi.OpaqueIdentifierInput{Scope: s.config.raw.SubjectScope, Kind: subject.kind, Value: canonical})
	if err != nil || len(tags) < 1 || len(tags) > 2 {
		return unavailable, nil, errStateUnavailable
	}

	result := emptyProfiles(assessmentMissing)
	snapshots := make([]assessmentSnapshot, 0, len(tags))

	for _, tag := range tags {
		snapshot, err := s.snapshotTagDetails(ctx, tag.String(), subject.kind, details)
		if err != nil {
			return unavailable, nil, err
		}

		for _, profile := range assessmentProfileNames() {
			current, err := snapshot.assessment(profile, s.config.raw.Score, s.config.raw.Bands)
			if err != nil {
				return unavailable, nil, err
			}

			merged := mergeAssessments(result[profile], current)
			if merged.validate() != nil {
				return unavailable, nil, errAssessment
			}

			result[profile] = merged
		}

		snapshots = append(snapshots, snapshot)
	}

	return result, snapshots, nil
}

// emptyProfiles creates all closed profile tuples together so failures cannot leave partially trusted output.
func emptyProfiles(state string) map[string]assessmentTuple {
	result := make(map[string]assessmentTuple, 3)
	for _, profile := range assessmentProfileNames() {
		result[profile] = emptyAssessment(state, profile)
	}

	return result
}

// assessmentProfileNames fixes deterministic output order independently of configuration map iteration.
func assessmentProfileNames() []string {
	return []string{profileFast, profileOperational, profileBaseline}
}

// snapshotTag obtains one atomic primary snapshot for the active model and its model-independent override.
func (s *stateOwner) snapshotTag(ctx context.Context, tag, kind string) (assessmentSnapshot, error) {
	return s.snapshotTagDetails(ctx, tag, kind, false)
}

// snapshotTagDetails adds protected operator metadata only when explicitly requested by management.
func (s *stateOwner) snapshotTagDetails(ctx context.Context, tag, kind string, details bool) (assessmentSnapshot, error) {
	model := s.models[0]
	keys := s.keys.subject(tag, model.id)
	request := assessmentRequest{Details: details, Profiles: model.profiles, Classes: model.classes, Fingerprint: model.fingerprint, Kind: kind, Tag: tag,
		Retention: s.config.retention.Seconds(), DiversityFloor: s.config.raw.Bands.DiversityMassFloor}

	scriptKeys := []string{keys.State, keys.Seen, keys.Override}
	if details {
		scriptKeys = append(scriptKeys, s.keys.audit(tag))
	}

	response, err := s.run(ctx, scriptAssessment, scriptKeys, request)
	if err != nil || len(response) != 2 || response[0] != storageSnapshot {
		return assessmentSnapshot{}, errStateUnavailable
	}

	encoded, ok := response[1].(string)
	if !ok || len(encoded) > 16384 {
		return assessmentSnapshot{}, errStateUnavailable
	}

	var snapshot assessmentSnapshot

	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&snapshot) != nil {
		return assessmentSnapshot{}, errStateUnavailable
	}

	if details && snapshot.validateManagement(s.config, tag, kind) != nil {
		return assessmentSnapshot{}, errStateUnavailable
	}

	return snapshot, nil
}

// assessment validates the entire detached snapshot before applying pure scoring and band configuration.
func (s assessmentSnapshot) assessment(profile string, score scoreConfig, bands bandConfig) (assessmentTuple, error) {
	if !positiveBound(s.Now, 1e11) || !overrideBand(s.Override) {
		return assessmentTuple{}, errAssessment
	}

	result := emptyAssessment(s.State, profile)

	result.Override = s.Override
	if s.State == assessmentMissing {
		if !s.emptyEvidence() {
			return assessmentTuple{}, errAssessment
		}
	} else {
		if s.State != assessmentFresh {
			return assessmentTuple{}, errAssessment
		}

		scores, err := s.scores(score)
		if err != nil {
			return assessmentTuple{}, err
		}

		selected := scores[profile]
		recentAuthority := riskEvidenceRecent(s.Now, s.AuthoritativeAt, bands.AuthoritativeRiskMaxAge)
		severe := scores[profileFast].Risk >= bands.SevereRiskScore && riskEvidenceRecent(s.Now, s.RiskAt, bands.SevereRiskMaxAge)
		result.Band = learnedAssessmentBand(scores[profileFast], scores[profileOperational], recentAuthority, severe, bands)
		age := math.Floor(s.Now - s.UpdatedAt)
		result.Details = &assessmentDetails{Risk: selected.Risk, Trust: selected.Trust, Confidence: selected.Confidence,
			Samples: selected.Samples, Diversity: selected.Diversity, AgeSeconds: int64(age)}
	}

	if result.Override != overrideNone {
		result.Band = result.Override
	}

	return result, result.validate()
}

// scores validates every configured dimension and evidence clock before deriving any output.
func (s assessmentSnapshot) scores(cfg scoreConfig) (map[string]profileScore, error) {
	if len(s.Profiles) != 3 || !positiveBound(s.UpdatedAt, s.Now) || !nonnegativeBound(s.RiskAt, s.Now) || !nonnegativeBound(s.TrustAt, s.Now) ||
		!nonnegativeBound(s.AuthoritativeAt, s.RiskAt) {
		return nil, errAssessment
	}

	result := make(map[string]profileScore, 3)

	for _, mass := range s.Profiles {
		if mass.validate() != nil {
			return nil, errAssessment
		}

		if _, exists := result[mass.Name]; exists {
			return nil, errAssessment
		}

		result[mass.Name] = scoreMass(mass, cfg)
	}

	return result, nil
}

// emptyAssessment creates only the closed no-evidence tuples, never numeric zero evidence.
func emptyAssessment(state, profile string) assessmentTuple {
	band := bandUnknown
	if state == assessmentUnavailable {
		band = assessmentUnavailable
	}

	return assessmentTuple{State: state, Profile: profile, Band: band, Override: overrideNone}
}

// emptyEvidence excludes invented measurements from a missing-state response.
func (s assessmentSnapshot) emptyEvidence() bool {
	return len(s.Profiles) == 0 && s.RiskAt == 0 && s.TrustAt == 0 && s.AuthoritativeAt == 0 && s.UpdatedAt == 0
}

// validate checks finite bounded per-profile totals before applying the scoring transform.
func (m profileMass) validate() error {
	if !profileName(m.Name) || !nonnegativeBound(m.Risk, 8e6) || !nonnegativeBound(m.Trust, 8e6) ||
		!nonnegativeBound(m.Samples, 8e6) || m.Diversity < 0 || m.Diversity > 8 || m.RiskDiversity < 0 || m.RiskDiversity > m.Diversity {
		return errAssessment
	}

	return nil
}
