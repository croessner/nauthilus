package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	manifestSchema         = "reputation-manifest.v1"
	manifestShardCount     = 16
	maximumManifestPayload = 60 * 1024
)

var errManifestPlan = errors.New("invalid reputation manifest plan")

type manifestSubject struct {
	Role   string  `json:"role"`
	Kind   string  `json:"kind"`
	Tag    string  `json:"tag"`
	Weight float64 `json:"weight"`
}

type manifestModel struct {
	Subjects         []manifestSubject   `json:"subjects"`
	Profiles         []profileDefinition `json:"profiles"`
	Classes          []classDefinition   `json:"classes"`
	EligibleProfiles []string            `json:"eligible_profiles"`
	ID               string              `json:"id"`
	Fingerprint      string              `json:"fingerprint"`
	Direction        string              `json:"direction"`
	Authoritative    bool                `json:"authoritative"`
}

type manifestPayload struct {
	ObservedTime string          `json:"observed_time"`
	Models       []manifestModel `json:"models"`
	Magnitude    *float64        `json:"magnitude"`
	Schema       string          `json:"schema"`
	SeenTag      string          `json:"seen_tag"`
	TagVersion   string          `json:"tag_version"`
	Signal       string          `json:"signal"`
	SourceClass  string          `json:"source_class"`
	Origin       string          `json:"origin"`
	ObservedAt   float64         `json:"observed_at"`
}

type manifestCandidate struct {
	Payload     string `json:"payload"`
	Fingerprint string `json:"fingerprint"`
}

type manifestRequest struct {
	Candidates         []manifestCandidate `json:"candidates"`
	AllocationTag      string              `json:"allocation_tag"`
	SourceTag          string              `json:"source_tag"`
	AllocationIdentity string              `json:"allocation_identity"`
	ObservedAt         float64             `json:"observed_at"`
	Lateness           float64             `json:"lateness"`
	FutureSkew         float64             `json:"future_skew"`
	Retention          float64             `json:"retention"`
	MaximumNewSubjects int                 `json:"maximum_new_subjects"`
	MaximumEvents      int                 `json:"maximum_events"`
}

type manifestPlanner struct {
	config *configuration
	tagger pluginapi.OpaqueIdentifierTagger
	models []*modelDefinition
}

// newManifestPlanner binds one active and optional shadow model to a stable allocation service.
func newManifestPlanner(cfg *configuration, tagger pluginapi.OpaqueIdentifierTagger, models []*modelDefinition) (*manifestPlanner, error) {
	if cfg == nil || tagger == nil || len(models) < 1 || len(models) > 2 {
		return nil, errManifestPlan
	}

	seen := make(map[string]bool, len(models))
	for _, model := range models {
		if model == nil || seen[model.id] {
			return nil, errManifestPlan
		}

		seen[model.id] = true
	}

	owned := append([]*modelDefinition(nil), models...)
	sort.Slice(owned, func(i, j int) bool { return owned[i].id < owned[j].id })

	return &manifestPlanner{config: cfg, tagger: tagger, models: owned}, nil
}

// plan freezes every active/previous candidate before allocating an event or mutating a subject.
func (p *manifestPlanner) plan(ctx context.Context, admitted admittedObservation) (manifestRequest, error) {
	if admitted.source == nil || admitted.signal == nil || len(admitted.subjects) < 1 || len(admitted.subjects) > maximumExpandedSubjects {
		return manifestRequest{}, errManifestPlan
	}

	request, err := p.allocationRequest(ctx, admitted)
	if err != nil {
		return manifestRequest{}, err
	}

	versions, err := p.tagger.Candidates(ctx, pluginapi.OpaqueIdentifierInput{Scope: p.config.raw.SubjectScope, Kind: taggerProbe, Value: "manifest"})
	if err != nil || len(versions) < 1 || len(versions) > 2 {
		return manifestRequest{}, errManifestPlan
	}

	for _, version := range versions {
		candidate, err := p.candidate(ctx, admitted, version.Version())
		if err != nil {
			return manifestRequest{}, err
		}

		request.Candidates = append(request.Candidates, candidate)
	}

	return request, nil
}

// allocationRequest uses a non-rotating dedicated scope so all writer generations address the same event key.
func (p *manifestPlanner) allocationRequest(ctx context.Context, admitted admittedObservation) (manifestRequest, error) {
	identity, err := p.allocationIdentity(ctx)
	if err != nil {
		return manifestRequest{}, err
	}

	allocation, err := p.tagPair(ctx, p.config.raw.ManifestScope, "event_allocation", admitted.source.config.SourcePolicyID, admitted.input.eventID, "")
	if err != nil {
		return manifestRequest{}, err
	}

	source, err := p.tagger.Tag(ctx, pluginapi.OpaqueIdentifierInput{Scope: p.config.raw.ManifestScope, Kind: "source", Value: admitted.source.config.SourcePolicyID})
	if err != nil {
		return manifestRequest{}, err
	}

	return manifestRequest{AllocationTag: allocation, SourceTag: source.String(), AllocationIdentity: identity,
		ObservedAt: float64(admitted.input.observedAt.UnixNano()) / 1e9, Lateness: min(admitted.source.lateness, admitted.signal.maxAge).Seconds(),
		FutureSkew: admitted.source.futureSkew.Seconds(), Retention: p.config.manifestTTL.Seconds(), MaximumNewSubjects: p.config.raw.MaximumNewSubjectsPerSourceHour,
		MaximumEvents: p.config.raw.MaximumEventManifestsPerSource}, nil
}

// candidate produces one key-version-specific canonical contribution without retaining any raw identifiers.
func (p *manifestPlanner) candidate(ctx context.Context, admitted admittedObservation, version string) (manifestCandidate, error) {
	seen, err := p.tagPair(ctx, p.config.raw.SubjectScope, "seen_event", admitted.source.config.SourcePolicyID, admitted.input.eventID, version)
	if err != nil {
		return manifestCandidate{}, err
	}

	payload := manifestPayload{ObservedTime: admitted.input.observedAt.UTC().Format(time.RFC3339Nano), Schema: manifestSchema, SeenTag: seen, TagVersion: version, Signal: admitted.signal.name, SourceClass: admitted.source.config.SourceClass,
		Origin: admitted.signal.config.EvidenceOrigin, ObservedAt: float64(admitted.input.observedAt.UnixNano()) / 1e9, Magnitude: admitted.input.magnitude}
	for _, model := range p.models {
		contribution, err := p.modelContribution(ctx, model, admitted, version)
		if err != nil {
			return manifestCandidate{}, err
		}

		payload.Models = append(payload.Models, contribution)
	}

	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > maximumManifestPayload {
		return manifestCandidate{}, errManifestPlan
	}

	fingerprint, err := p.tagger.Tag(ctx, pluginapi.OpaqueIdentifierInput{Scope: p.config.raw.ManifestScope, Kind: "payload", Value: string(encoded)})
	if err != nil {
		return manifestCandidate{}, err
	}

	return manifestCandidate{Payload: string(encoded), Fingerprint: fingerprint.String()}, nil
}

// modelContribution records each model's complete effective weights and immutable accumulator definitions.
func (p *manifestPlanner) modelContribution(ctx context.Context, model *modelDefinition, admitted admittedObservation, version string) (manifestModel, error) {
	signal := model.config.signals[admitted.signal.name]
	if signal == nil {
		return manifestModel{}, errManifestPlan
	}

	result := manifestModel{ID: model.id, Fingerprint: model.fingerprint, Profiles: model.profiles, Classes: model.classes, EligibleProfiles: sortedStrings(signal.config.Profiles),
		Direction: signal.config.Direction, Authoritative: signal.config.Authoritative}
	for _, subject := range admitted.subjects {
		multiplier, exists := signal.config.SubjectRoles[subject.role][subject.kind]
		if !exists {
			return manifestModel{}, errManifestPlan
		}

		tag, err := p.tagger.TagVersion(ctx, pluginapi.OpaqueIdentifierInput{Scope: p.config.raw.SubjectScope, Kind: subject.kind, Value: subject.value}, version)
		if err != nil {
			return manifestModel{}, err
		}

		weight := signal.config.Weight * multiplier
		if admitted.input.magnitude != nil {
			weight *= *admitted.input.magnitude
		}

		if !nonnegativeBound(weight, 1000) {
			return manifestModel{}, errManifestPlan
		}

		result.Subjects = append(result.Subjects, manifestSubject{Role: subject.role, Kind: subject.kind, Tag: tag.String(), Weight: weight})
	}

	sort.Slice(result.Subjects, func(i, j int) bool {
		return result.Subjects[i].Kind+result.Subjects[i].Tag < result.Subjects[j].Kind+result.Subjects[j].Tag
	})

	return result, nil
}

// tagPair frames a source-policy and producer-local event ID through a typed host HMAC operation.
func (p *manifestPlanner) tagPair(ctx context.Context, scope, kind, source, event, version string) (string, error) {
	encoded, err := json.Marshal([2]string{source, event})
	if err != nil {
		return "", errManifestPlan
	}

	input := pluginapi.OpaqueIdentifierInput{Scope: scope, Kind: kind, Value: string(encoded)}

	var tag pluginapi.OpaqueIdentifierTag
	if version == "" {
		tag, err = p.tagger.Tag(ctx, input)
	} else {
		tag, err = p.tagger.TagVersion(ctx, input, version)
	}

	if err != nil {
		return "", err
	}

	return tag.String(), nil
}

// allocationIdentity rejects a rotating allocation key ring before any manifest allocation can occur.
func (p *manifestPlanner) allocationIdentity(ctx context.Context) (string, error) {
	tags, err := p.tagger.Candidates(ctx, pluginapi.OpaqueIdentifierInput{Scope: p.config.raw.ManifestScope, Kind: "allocation_identity", Value: manifestSchema})
	if err != nil || len(tags) != 1 {
		return "", errManifestPlan
	}

	return tags[0].String(), nil
}
