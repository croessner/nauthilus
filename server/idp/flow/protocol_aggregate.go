// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package flow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/v3/server/sessionstate"
)

// ProtocolAggregate is the sole request composition boundary for OIDC and SAML flow records.
type ProtocolAggregate struct {
	oidc *TypedStore
	saml *TypedStore
}

// NewProtocolAggregate binds both protocol repositories to one canonical browser session.
func NewProtocolAggregate(
	stores *sessionstate.RedisStores,
	session sessionstate.Handle,
	ttl time.Duration,
) *ProtocolAggregate {
	return &ProtocolAggregate{
		oidc: NewTypedStore(stores, session, FlowProtocolOIDC, ttl),
		saml: NewTypedStore(stores, session, FlowProtocolSAML, ttl),
	}
}

// Load resolves a ticket to exactly one typed protocol record.
func (a *ProtocolAggregate) Load(ctx context.Context, flowID string) (*State, error) {
	if a == nil || a.oidc == nil || a.saml == nil {
		return nil, fmt.Errorf("protocol aggregate: unavailable")
	}

	oidcState, oidcErr := a.oidc.Load(ctx, flowID)
	if oidcErr != nil && !errors.Is(oidcErr, sessionstate.ErrNotFound) {
		return nil, fmt.Errorf("protocol aggregate: load OIDC: %w", oidcErr)
	}

	samlState, samlErr := a.saml.Load(ctx, flowID)
	if samlErr != nil && !errors.Is(samlErr, sessionstate.ErrNotFound) {
		return nil, fmt.Errorf("protocol aggregate: load SAML: %w", samlErr)
	}

	switch {
	case oidcErr == nil && samlErr == nil:
		return nil, ErrAmbiguousProtocolFlow
	case oidcErr == nil:
		return oidcState, nil
	case samlErr == nil:
		return samlState, nil
	default:
		return nil, ErrFlowNotFound
	}
}

// Resume resolves one unambiguous typed protocol flow into its current redirect decision.
func (a *ProtocolAggregate) Resume(ctx context.Context, flowID string) (Decision, error) {
	state, err := a.Load(ctx, flowID)
	if err != nil {
		return Decision{}, err
	}

	policy, err := PolicyForFlowType(state.Type)
	if err != nil {
		return Decision{}, err
	}

	if !policy.AllowsStep(state.CurrentStep) {
		return Decision{}, fmt.Errorf("protocol aggregate: %w (%s)", ErrInvalidStep, state.CurrentStep)
	}

	return Decision{
		Type: DecisionTypeRedirect, RedirectURI: NewURIBuilder().Resolve(state, FlowActionResume),
		Reason: string(FlowActionResume),
	}, nil
}
