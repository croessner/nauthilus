// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package flow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/v4/server/sessionstate"
)

// LoginAggregate resolves external protocol and internal self-service login records.
type LoginAggregate struct {
	protocol    *ProtocolAggregate
	selfService *TypedStore
}

// NewLoginAggregate binds all browser-login repositories to one canonical session.
func NewLoginAggregate(
	stores *sessionstate.RedisStores,
	session sessionstate.Handle,
	ttl time.Duration,
) *LoginAggregate {
	return &LoginAggregate{
		protocol: NewProtocolAggregate(stores, session, ttl),
		selfService: NewTypedStore(
			stores,
			session,
			FlowProtocolInternal,
			ttl,
		),
	}
}

// Load resolves one opaque ticket to exactly one external or internal login record.
func (a *LoginAggregate) Load(ctx context.Context, flowID string) (*State, error) {
	if a == nil || a.protocol == nil || a.selfService == nil {
		return nil, fmt.Errorf("login aggregate: unavailable")
	}

	protocolState, protocolErr := a.protocol.Load(ctx, flowID)
	if protocolErr != nil && !errors.Is(protocolErr, ErrFlowNotFound) {
		return nil, fmt.Errorf("login aggregate: load protocol: %w", protocolErr)
	}

	selfServiceState, selfServiceErr := a.selfService.Load(ctx, flowID)
	if selfServiceErr != nil && !errors.Is(selfServiceErr, sessionstate.ErrNotFound) {
		return nil, fmt.Errorf("login aggregate: load self-service: %w", selfServiceErr)
	}

	switch {
	case protocolErr == nil && selfServiceErr == nil:
		return nil, ErrAmbiguousLoginFlow
	case protocolErr == nil:
		return protocolState, nil
	case selfServiceErr == nil:
		return selfServiceState, nil
	default:
		return nil, ErrFlowNotFound
	}
}
