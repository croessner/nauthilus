package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"unicode/utf8"
)

const (
	managementAllocation      = "allocation"
	allocationStatusOperation = "status"
	allocationDrainOperation  = "drain"
	storageDraining           = "draining"
	managementReason          = "reason"
	managementAction          = "action"
)

type allocationAudit struct {
	Reason  string `json:"reason"`
	Origin  string `json:"origin"`
	AuditID string `json:"audit_id"`
	Creator string `json:"creator"`
}

type allocationView struct {
	Audit          *allocationAudit `json:"audit,omitempty"`
	Mode           string           `json:"mode"`
	Generation     int              `json:"generation"`
	NextGeneration int              `json:"next_generation"`
	FencedShards   int              `json:"fenced_shards"`
	DrainedAt      float64          `json:"drained_at"`
	Retention      float64          `json:"retention"`
	ObservedAt     float64          `json:"observed_at"`
}

// auditedMetadataRequest attaches only host-attributed audit metadata to the existing allocation protocol.
func (s *stateOwner) auditedMetadataRequest(operation string, audit *allocationAudit) metadataRequest {
	request := s.metadataRequest(operation)
	request.Audit = audit

	return request
}

// allocationStatus verifies current-generation metadata and every shard through the primary without exposing identities.
func (s *stateOwner) allocationStatus(ctx context.Context) (allocationView, error) {
	first, err := s.allocationMetadata(ctx)
	if err != nil {
		return allocationView{}, err
	}

	fenced := 0

	for shard := range manifestShardCount {
		result, err := s.run(ctx, scriptControl, []string{s.keys.control(shard)}, controlRequest{Operation: allocationStatusOperation, Schema: manifestSchema, Identity: s.identity})
		if err != nil || len(result) != 1 {
			return allocationView{}, errStateUnavailable
		}

		if result[0] == storageDraining {
			fenced++
		}
	}

	last, err := s.allocationMetadata(ctx)
	if err != nil || first.Mode != last.Mode || first.Generation != last.Generation || first.DrainedAt != last.DrainedAt {
		return allocationView{}, errStateUnavailable
	}

	last.FencedShards = fenced
	if last.DrainedAt > 0 && fenced != manifestShardCount {
		return allocationView{}, errStateUnavailable
	}

	return last, nil
}

// allocationMetadata validates the bounded primary snapshot for the configured key and generation.
func (s *stateOwner) allocationMetadata(ctx context.Context) (allocationView, error) {
	var view allocationView

	result, err := s.run(ctx, scriptMetadata, s.keys.metadata(), s.metadataRequest(allocationStatusOperation))
	if err != nil || len(result) != 2 {
		return view, errStateUnavailable
	}

	encoded, ok := result[1].(string)
	if !ok || len(encoded) > 4096 {
		return view, errStateUnavailable
	}

	decoder := json.NewDecoder(bytes.NewBufferString(encoded))
	decoder.DisallowUnknownFields()

	if decoder.Decode(&view) != nil || !view.valid(s.config.raw.AllocationDrainGeneration) {
		return allocationView{}, errStateUnavailable
	}

	return view, nil
}

// valid rejects malformed clocks, generations and audit fields before returning administrative status.
func (v allocationView) valid(generation int) bool {
	if v.Mode != storageActive && v.Mode != storageDraining {
		return false
	}

	if v.Generation != generation || v.NextGeneration != generation+1 || !positiveBound(v.ObservedAt, 100000000000) ||
		!positiveBound(v.Retention, maximumRetention.Seconds()) || v.DrainedAt < 0 || v.DrainedAt > v.ObservedAt {
		return false
	}

	return v.Audit == nil || v.Audit.valid()
}

// valid bounds every allocation audit field, including the host-authenticated actor.
func (a allocationAudit) valid() bool {
	return identifierPattern.MatchString(a.Reason) && identifierPattern.MatchString(a.Origin) && safeAuditText(a.AuditID) && safeAuditText(a.Creator)
}

// decodeAllocationInput accepts only the operation-specific closed body and host-owned actor.
func decodeAllocationInput(body []byte, actor string) (string, allocationAudit, error) {
	var action string

	audit := allocationAudit{Creator: actor}

	fields := map[string]any{managementAction: &action, managementReason: &audit.Reason, "origin": &audit.Origin, "audit_id": &audit.AuditID}
	if len(body) == 0 || len(body) > 4096 || !utf8.Valid(body) || decodeManagementFields(body, fields) != nil {
		return "", audit, errAssessment
	}

	switch action {
	case allocationStatusOperation:
		if decodeManagementFields(body, map[string]any{managementAction: &action}) != nil {
			return "", audit, errAssessment
		}
	case allocationDrainOperation:
		if !audit.valid() {
			return "", audit, errAssessment
		}
	default:
		return "", audit, errAssessment
	}

	return action, audit, nil
}

// manageAllocation provides recovery independently of writer readiness while preserving exact audit identity on retries.
func (s *stateOwner) manageAllocation(ctx context.Context, body []byte, actor string) (allocationView, error) {
	action, audit, err := decodeAllocationInput(body, actor)
	if err != nil {
		return allocationView{}, err
	}

	if action == allocationDrainOperation {
		if err := s.quiesceAudited(ctx, &audit); err != nil {
			return allocationView{}, err
		}
	}

	view, err := s.allocationStatus(ctx)
	if err != nil {
		return allocationView{}, err
	}

	if action == allocationDrainOperation && !view.verifiesDrain(audit) {
		return allocationView{}, errStateUnavailable
	}

	return view, nil
}

// verifiesDrain requires the requested receipt, complete fencing and the durable retention clock.
func (v allocationView) verifiesDrain(audit allocationAudit) bool {
	return v.Audit != nil && *v.Audit == audit && v.FencedShards == manifestShardCount && v.DrainedAt > 0
}

// serveAllocation retains authenticated maintenance access after writers are fenced.
func (h managementHook) serveAllocation(ctx context.Context, body []byte, actor string) (response any, status int) {
	state, _ := h.plugin.observedState()
	if state == nil {
		return nil, http.StatusServiceUnavailable
	}

	view, err := state.manageAllocation(ctx, body, actor)
	switch err {
	case nil:
		return view, http.StatusOK
	case errAssessment:
		return nil, http.StatusBadRequest
	case errOverrideConflict:
		return nil, http.StatusConflict
	default:
		return nil, http.StatusServiceUnavailable
	}
}
