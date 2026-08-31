// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/sessionstate"
)

// StepUpCompletion identifies the parent protocol flow released by one committed proof.
type StepUpCompletion struct {
	Handle               sessionstate.Handle
	Flow                 sessionstate.Handle
	SelfServiceOperation string
	Method               string
	Scope                string
	Level                int
	ProvenAt             time.Time
	FreshUntil           time.Time
}

// ConsumeFailLatchedStepUp terminalizes one delayed-response proof without authenticating the browser session.
//
//nolint:gocyclo // Fail-latched consume validates the full non-authenticating terminal state before deletion.
func (s *CanonicalSession) ConsumeFailLatchedStepUp(
	ctx context.Context,
	handle sessionstate.Handle,
	method string,
) (StepUpCompletion, error) {
	method = strings.TrimSpace(method)
	if s == nil || s.Stores == nil || s.clock == nil || s.Handle == "" || handle == "" || method == "" ||
		s.Anchor.Value.Authenticated || s.Anchor.Value.IdentityReference != "" || s.Anchor.Value.Assurance.Level != 0 ||
		!slices.Contains(s.Anchor.Value.StepUps, handle) {
		return StepUpCompletion{}, sessionstate.ErrBindingMismatch
	}

	loaded, err := s.Stores.StepUp.Load(ctx, sessionstate.Reference{Session: s.Handle, Record: handle})
	if err != nil {
		return StepUpCompletion{}, err
	}

	stepUp := loaded.Value
	if stepUp.Completed || stepUp.AuthOutcome != "fail_latched" || stepUp.Flow == "" ||
		strings.TrimSpace(stepUp.SelfServiceOperation) != "" || stepUp.PendingIdentityReference == "" ||
		stepUp.PendingIdentity.Subject != stepUp.PendingIdentityReference ||
		!slices.Contains(stepUp.SupportedMethods, method) {
		return StepUpCompletion{}, sessionstate.ErrBindingMismatch
	}

	consumed, err := s.Stores.ConsumeStepUp(ctx, sessionstate.DeleteRequest{
		Reference:        sessionstate.Reference{Session: s.Handle, Record: handle},
		ExpectedRevision: loaded.Revision,
	})
	if err != nil {
		return StepUpCompletion{}, err
	}

	anchor, err := s.Stores.Session.Load(ctx, sessionstate.Reference{Session: s.Handle, Record: s.Handle})
	if err != nil {
		return StepUpCompletion{}, err
	}

	s.Anchor = anchor

	return StepUpCompletion{
		Handle: consumed.Value.Handle, Flow: consumed.Value.Flow, Method: method,
		Scope: consumed.Value.Scope, Level: consumed.Value.RequestedLevel,
	}, nil
}

// CompleteStepUp atomically marks one typed challenge complete and publishes its session assurance.
func (s *CanonicalSession) CompleteStepUp(
	ctx context.Context,
	handle sessionstate.Handle,
	method string,
	freshness time.Duration,
) (StepUpCompletion, error) {
	if err := validateAssuranceSession(s); err != nil {
		return StepUpCompletion{}, err
	}

	method = strings.TrimSpace(method)
	if handle == "" || method == "" || freshness <= 0 {
		return StepUpCompletion{}, sessionstate.ErrBindingMismatch
	}

	loaded, err := s.Stores.StepUp.Load(ctx, sessionstate.Reference{Session: s.Handle, Record: handle})
	if err != nil {
		return StepUpCompletion{}, err
	}

	update, err := s.prepareStepUpCompletion(loaded.Value, method, freshness)
	if err != nil {
		return StepUpCompletion{}, err
	}

	receipt, err := s.Stores.Commit(ctx, sessionstate.TransactionRequest{
		Session: &sessionstate.CommitRequest[sessionstate.SessionAnchor]{
			Reference:        sessionstate.Reference{Session: s.Handle, Record: s.Handle},
			ExpectedRevision: s.Anchor.Revision, Value: update.anchor, TTL: update.anchorTTL,
		},
		StepUp: []sessionstate.CommitRequest[sessionstate.StepUpRecord]{
			{
				Reference:        sessionstate.Reference{Session: s.Handle, Record: handle},
				ExpectedRevision: loaded.Revision, Value: update.stepUp, TTL: update.stepUpTTL,
			},
		},
	})
	if err != nil {
		return StepUpCompletion{}, fmt.Errorf("canonical step-up completion: %w", err)
	}

	update.anchor.Revision = receipt.Revision
	s.Anchor = sessionstate.Versioned[sessionstate.SessionAnchor]{Value: update.anchor, Revision: receipt.Revision}

	return update.completion, nil
}

type stepUpCompletionUpdate struct {
	anchor     sessionstate.SessionAnchor
	stepUp     sessionstate.StepUpRecord
	completion StepUpCompletion
	anchorTTL  time.Duration
	stepUpTTL  time.Duration
}

func (s *CanonicalSession) prepareStepUpCompletion(
	stepUp sessionstate.StepUpRecord,
	method string,
	freshness time.Duration,
) (stepUpCompletionUpdate, error) {
	selfServiceOperation := strings.TrimSpace(stepUp.SelfServiceOperation)
	if stepUp.Completed || (stepUp.Flow == "") == (selfServiceOperation == "") ||
		stepUp.RequestedLevel <= 0 || strings.TrimSpace(stepUp.Scope) == "" ||
		len(stepUp.SupportedMethods) > 0 && !slices.Contains(stepUp.SupportedMethods, method) {
		return stepUpCompletionUpdate{}, sessionstate.ErrBindingMismatch
	}

	now := s.clock.Now().UTC()

	freshUntil := now.Add(freshness)
	if freshUntil.After(s.Anchor.Value.AbsoluteExpiresAt) {
		freshUntil = s.Anchor.Value.AbsoluteExpiresAt
	}

	anchorTTL := s.Anchor.Value.ExpiresAt.Sub(now)

	stepUpTTL := stepUp.ExpiresAt.Sub(now)
	if !freshUntil.After(now) || anchorTTL <= 0 || stepUpTTL <= 0 {
		return stepUpCompletionUpdate{}, sessionstate.ErrExpired
	}

	anchor := s.Anchor.Value
	anchor.Assurance = sessionstate.AssuranceSummary{
		Level: stepUp.RequestedLevel, Method: method, Scope: stepUp.Scope,
		ProvenAt: now, ExpiresAt: freshUntil,
	}
	stepUp.ProofMethod = method
	stepUp.CompletedAt = now
	stepUp.FreshUntil = freshUntil
	stepUp.Completed = true

	return stepUpCompletionUpdate{
		anchor: anchor, stepUp: stepUp, anchorTTL: anchorTTL, stepUpTTL: stepUpTTL,
		completion: StepUpCompletion{
			Handle: stepUp.Handle, Flow: stepUp.Flow, SelfServiceOperation: selfServiceOperation,
			Method: method, Scope: stepUp.Scope, Level: stepUp.RequestedLevel,
			ProvenAt: now, FreshUntil: freshUntil,
		},
	}, nil
}
