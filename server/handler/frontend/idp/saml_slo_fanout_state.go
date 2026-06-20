// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package idp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	"github.com/redis/go-redis/v9"
)

var (
	errSLOFanoutStateUnavailable   = errors.New("slo fanout transaction state is not available")
	errSLOFanoutResponseUnmatched  = errors.New("logout response does not correlate with an open fanout request")
	errSLOFanoutResponseRelayState = errors.New("logout response relay state does not match fanout transaction")
)

type sloFanoutParticipantOutcome struct {
	EntityID   string    `json:"entity_id"`
	RequestID  string    `json:"request_id"`
	Successful bool      `json:"successful"`
	StatusCode string    `json:"status_code"`
	Detail     string    `json:"detail,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
}

type sloFanoutTransactionState struct {
	Transaction     slodomain.Transaction                  `json:"transaction"`
	Pending         map[string]slodomain.Participant       `json:"pending"`
	Outcomes        map[string]sloFanoutParticipantOutcome `json:"outcomes,omitempty"`
	PreSuccessCount int                                    `json:"pre_success_count"`
	PreFailureCount int                                    `json:"pre_failure_count"`
	UpdatedAt       time.Time                              `json:"updated_at"`
}

type sloFanoutAggregationResult struct {
	TransactionID     string
	InResponseTo      string
	ParticipantEntity string
	SuccessCount      int
	FailureCount      int
	PendingCount      int
	Status            slodomain.Status
	Final             bool
}

func (h *SAMLHandler) storeSLOFanoutTransactionState(
	ctx context.Context,
	transaction *slodomain.Transaction,
	result *sloFanoutResult,
) error {
	state, err := newSLOFanoutTransactionState(transaction, result, time.Now().UTC())
	if err != nil {
		return err
	}

	if state == nil {
		return nil
	}

	handle := h.sloFanoutStorageHandle()
	if handle == nil {
		return errSLOFanoutStateUnavailable
	}

	rawState, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("cannot encode slo fanout transaction state: %w", err)
	}

	ttl := h.sloReplayTTL()
	transactionKey := h.sloFanoutStateKey(state.Transaction.TransactionID)

	pipe := handle.Pipeline()
	pipe.Set(ctx, transactionKey, rawState, ttl)

	for requestID := range state.Pending {
		pipe.Set(ctx, h.sloFanoutRequestKey(requestID), state.Transaction.TransactionID, ttl)
	}

	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("cannot persist slo fanout transaction state: %w", err)
	}

	return nil
}

func newSLOFanoutTransactionState(
	transaction *slodomain.Transaction,
	result *sloFanoutResult,
	now time.Time,
) (*sloFanoutTransactionState, error) {
	if transaction == nil {
		return nil, fmt.Errorf("slo fanout transaction is missing")
	}

	if result == nil || len(result.Dispatches) == 0 {
		return nil, nil
	}

	if transaction.Status != slodomain.SLOStatusFanoutRunning {
		return nil, fmt.Errorf("slo fanout transaction must be in status fanout_running, got %q", transaction.Status)
	}

	state := &sloFanoutTransactionState{
		Transaction: *transaction,
		Pending:     make(map[string]slodomain.Participant, len(result.Dispatches)),
		Outcomes:    make(map[string]sloFanoutParticipantOutcome),
		UpdatedAt:   now.UTC(),
	}

	for _, dispatch := range result.Dispatches {
		requestID := strings.TrimSpace(dispatch.Participant.RequestID)
		if requestID == "" {
			return nil, fmt.Errorf("slo fanout participant request id is missing")
		}

		if _, exists := state.Pending[requestID]; exists {
			return nil, fmt.Errorf("duplicate slo fanout request id %q", requestID)
		}

		state.Pending[requestID] = dispatch.Participant
	}

	preSuccessCount := max(len(transaction.Participants)-len(result.Dispatches), 0)

	state.PreSuccessCount = preSuccessCount
	state.PreFailureCount = len(result.Failures)

	return state, nil
}

func (h *SAMLHandler) applySLOFanoutLogoutResponse(
	ctx context.Context,
	logoutResponse *saml.LogoutResponse,
	relayState string,
) (*sloFanoutAggregationResult, error) {
	requestID, err := sloLogoutResponseRequestID(logoutResponse)
	if err != nil {
		return nil, err
	}

	handle := h.sloFanoutStorageHandle()
	if handle == nil {
		return nil, errSLOFanoutStateUnavailable
	}

	transactionID, state, err := h.loadSLOFanoutTransactionState(ctx, requestID)
	if err != nil {
		return nil, err
	}

	if err = validateSLOFanoutRelayState(relayState, transactionID); err != nil {
		return nil, err
	}

	participant, isPending := state.Pending[requestID]
	if !isPending {
		if aggregation, done := state.completedFanoutAggregation(transactionID, requestID); done {
			return aggregation, nil
		}

		return nil, fmt.Errorf("%w: %q", errSLOFanoutResponseUnmatched, requestID)
	}

	if err = validateSLOFanoutResponseIssuer(logoutResponse, participant); err != nil {
		return nil, err
	}

	state.recordSLOFanoutOutcome(requestID, participant, logoutResponse)
	successCount, failureCount := state.outcomeCounts()
	state.UpdatedAt = time.Now().UTC()

	final := len(state.Pending) == 0

	if final {
		if err = h.applyFinalSLOFanoutStatus(ctx, transactionID, requestID, participant.EntityID, state, successCount, failureCount); err != nil {
			return nil, err
		}
	}

	if err = state.Transaction.Validate(); err != nil {
		return nil, err
	}

	if err = h.persistUpdatedSLOFanoutTransactionState(ctx, handle, transactionID, requestID, state, final); err != nil {
		return nil, err
	}

	return newSLOFanoutAggregationResult(transactionID, requestID, participant.EntityID, state, successCount, failureCount, final), nil
}

// newSLOFanoutAggregationResult builds the public aggregation response.
func newSLOFanoutAggregationResult(
	transactionID string,
	requestID string,
	participantEntityID string,
	state *sloFanoutTransactionState,
	successCount int,
	failureCount int,
	final bool,
) *sloFanoutAggregationResult {
	return &sloFanoutAggregationResult{
		TransactionID:     transactionID,
		InResponseTo:      requestID,
		ParticipantEntity: participantEntityID,
		SuccessCount:      successCount,
		FailureCount:      failureCount,
		PendingCount:      len(state.Pending),
		Status:            state.Transaction.Status,
		Final:             final,
	}
}

// sloLogoutResponseRequestID returns the required InResponseTo identifier.
func sloLogoutResponseRequestID(logoutResponse *saml.LogoutResponse) (string, error) {
	if logoutResponse == nil {
		return "", fmt.Errorf("logout response payload is missing")
	}

	requestID := strings.TrimSpace(logoutResponse.InResponseTo)
	if requestID == "" {
		return "", fmt.Errorf("logout response InResponseTo is missing")
	}

	return requestID, nil
}

// validateSLOFanoutRelayState ensures RelayState still addresses the transaction.
func validateSLOFanoutRelayState(relayState string, transactionID string) error {
	relayState = strings.TrimSpace(relayState)
	if relayState == "" || relayState == transactionID {
		return nil
	}

	return fmt.Errorf("%w: expected %q, got %q", errSLOFanoutResponseRelayState, transactionID, relayState)
}

// completedFanoutAggregation returns the idempotent aggregation for an already processed request.
func (s *sloFanoutTransactionState) completedFanoutAggregation(
	transactionID string,
	requestID string,
) (*sloFanoutAggregationResult, bool) {
	if _, done := s.Outcomes[requestID]; !done {
		return nil, false
	}

	successCount, failureCount := s.outcomeCounts()

	return &sloFanoutAggregationResult{
		TransactionID: transactionID,
		InResponseTo:  requestID,
		SuccessCount:  successCount,
		FailureCount:  failureCount,
		PendingCount:  len(s.Pending),
		Status:        s.Transaction.Status,
		Final:         s.Transaction.Status.IsTerminal(),
	}, true
}

// validateSLOFanoutResponseIssuer checks that the response issuer matches the pending participant.
func validateSLOFanoutResponseIssuer(logoutResponse *saml.LogoutResponse, participant slodomain.Participant) error {
	issuer := samlIssuerValue(logoutResponse.Issuer)

	participantEntityID := strings.TrimSpace(participant.EntityID)
	if issuer == "" || participantEntityID == "" || issuer == participantEntityID {
		return nil
	}

	return fmt.Errorf("logout response issuer %q does not match pending participant %q", issuer, participant.EntityID)
}

// newSLOFanoutParticipantOutcome builds the stored outcome for one LogoutResponse.
func newSLOFanoutParticipantOutcome(
	requestID string,
	participant slodomain.Participant,
	logoutResponse *saml.LogoutResponse,
) sloFanoutParticipantOutcome {
	outcome := sloFanoutParticipantOutcome{
		EntityID:   participant.EntityID,
		RequestID:  requestID,
		Successful: samlLogoutResponseIsSuccess(logoutResponse),
		StatusCode: samlLogoutResponseStatusCode(logoutResponse),
		ReceivedAt: time.Now().UTC(),
	}

	if logoutResponse.Status.StatusMessage != nil {
		outcome.Detail = strings.TrimSpace(logoutResponse.Status.StatusMessage.Value)
	}

	return outcome
}

// recordSLOFanoutOutcome stores a participant outcome and removes the pending request.
func (s *sloFanoutTransactionState) recordSLOFanoutOutcome(
	requestID string,
	participant slodomain.Participant,
	logoutResponse *saml.LogoutResponse,
) {
	if s.Outcomes == nil {
		s.Outcomes = make(map[string]sloFanoutParticipantOutcome)
	}

	s.Outcomes[requestID] = newSLOFanoutParticipantOutcome(requestID, participant, logoutResponse)
	delete(s.Pending, requestID)
}

// applyFinalSLOFanoutStatus records terminal aggregation status.
func (h *SAMLHandler) applyFinalSLOFanoutStatus(
	ctx context.Context,
	transactionID string,
	requestID string,
	participantEntityID string,
	state *sloFanoutTransactionState,
	successCount int,
	failureCount int,
) error {
	finalStatus := aggregateSLOFanoutTerminalStatus(successCount, failureCount)
	if err := state.Transaction.TransitionTo(finalStatus, time.Now().UTC()); err != nil {
		return err
	}

	recordSLOTerminalStatus(slodomain.SLODirectionIDPInitiated, finalStatus)
	h.auditSLOEvent(
		ctx,
		"fanout_response_aggregated",
		transactionID,
		requestID,
		participantEntityID,
		samlMetricLabelStatus, finalStatus,
		"success_count", successCount,
		"failure_count", failureCount,
		"pending", len(state.Pending),
	)

	return nil
}

// persistUpdatedSLOFanoutTransactionState stores the updated transaction and request index changes.
func (h *SAMLHandler) persistUpdatedSLOFanoutTransactionState(
	ctx context.Context,
	handle redis.UniversalClient,
	transactionID string,
	requestID string,
	state *sloFanoutTransactionState,
	final bool,
) error {
	rawState, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("cannot encode updated slo fanout transaction state: %w", err)
	}

	pipe := handle.Pipeline()
	pipe.Set(ctx, h.sloFanoutStateKey(transactionID), rawState, h.sloReplayTTL())
	pipe.Del(ctx, h.sloFanoutRequestKey(requestID))

	if final {
		for pendingRequestID := range state.Pending {
			pipe.Del(ctx, h.sloFanoutRequestKey(pendingRequestID))
		}
	}

	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("cannot persist updated slo fanout transaction state: %w", err)
	}

	return nil
}

func (h *SAMLHandler) loadSLOFanoutTransactionState(
	ctx context.Context,
	requestID string,
) (string, *sloFanoutTransactionState, error) {
	handle := h.sloFanoutStorageHandle()
	if handle == nil {
		return "", nil, errSLOFanoutStateUnavailable
	}

	requestKey := h.sloFanoutRequestKey(requestID)

	transactionID, err := handle.Get(ctx, requestKey).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil, fmt.Errorf("%w: %q", errSLOFanoutResponseUnmatched, requestID)
	}

	if err != nil {
		return "", nil, fmt.Errorf("cannot load slo fanout request index: %w", err)
	}

	transactionID = strings.TrimSpace(transactionID)
	if transactionID == "" {
		return "", nil, fmt.Errorf("slo fanout request index is missing transaction id")
	}

	transactionKey := h.sloFanoutStateKey(transactionID)

	rawState, err := handle.Get(ctx, transactionKey).Bytes()
	if errors.Is(err, redis.Nil) {
		return "", nil, fmt.Errorf("%w: transaction %q", errSLOFanoutResponseUnmatched, transactionID)
	}

	if err != nil {
		return "", nil, fmt.Errorf("cannot load slo fanout transaction state: %w", err)
	}

	var state sloFanoutTransactionState
	if err = json.Unmarshal(rawState, &state); err != nil {
		return "", nil, fmt.Errorf("cannot decode slo fanout transaction state: %w", err)
	}

	if strings.TrimSpace(state.Transaction.TransactionID) == "" {
		return "", nil, fmt.Errorf("slo fanout transaction state is invalid")
	}

	return transactionID, &state, nil
}

func (h *SAMLHandler) sloFanoutStorageHandle() redis.UniversalClient {
	if h == nil || h.deps == nil || h.deps.Redis == nil {
		return nil
	}

	return h.deps.Redis.GetWriteHandle()
}

func (h *SAMLHandler) sloFanoutStateKey(transactionID string) string {
	return h.sloFanoutPrefix() + ":fanout:tx:" + url.QueryEscape(strings.TrimSpace(transactionID))
}

func (h *SAMLHandler) sloFanoutRequestKey(requestID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(requestID)))

	return h.sloFanoutPrefix() + ":fanout:req:" + hex.EncodeToString(sum[:])
}

func (h *SAMLHandler) sloFanoutPrefix() string {
	return h.redisPrefix() + "idp:saml:slo"
}

func (s *sloFanoutTransactionState) outcomeCounts() (successCount, failureCount int) {
	if s == nil {
		return 0, 0
	}

	successCount = s.PreSuccessCount
	failureCount = s.PreFailureCount

	for _, outcome := range s.Outcomes {
		if outcome.Successful {
			successCount++
		} else {
			failureCount++
		}
	}

	return successCount, failureCount
}

func aggregateSLOFanoutTerminalStatus(successCount, failureCount int) slodomain.Status {
	switch {
	case failureCount == 0:
		return slodomain.SLOStatusDone
	case successCount == 0:
		return slodomain.SLOStatusFailed
	default:
		return slodomain.SLOStatusPartial
	}
}

func samlLogoutResponseIsSuccess(logoutResponse *saml.LogoutResponse) bool {
	if logoutResponse == nil {
		return false
	}

	return strings.TrimSpace(logoutResponse.Status.StatusCode.Value) == saml.StatusSuccess
}

func samlLogoutResponseStatusCode(logoutResponse *saml.LogoutResponse) string {
	if logoutResponse == nil {
		return ""
	}

	topLevel := strings.TrimSpace(logoutResponse.Status.StatusCode.Value)
	if logoutResponse.Status.StatusCode.StatusCode == nil {
		return topLevel
	}

	secondary := strings.TrimSpace(logoutResponse.Status.StatusCode.StatusCode.Value)
	if secondary == "" {
		return topLevel
	}

	if topLevel == "" {
		return secondary
	}

	return topLevel + "/" + secondary
}
