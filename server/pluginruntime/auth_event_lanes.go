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

package pluginruntime

import (
	"context"
	"errors"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	// DefaultAuthEventCompletionQueueCapacity bounds OIDC completion events waiting for delivery per process.
	DefaultAuthEventCompletionQueueCapacity = 1024

	authEventLaneCompletion = "oidc_completion"
)

// authEventLanes separates second-factor events from OIDC completion events into independent bounded queues. Silent
// SSO renewals and forced authorize navigations can issue many codes; they must never evict second-factor evidence,
// which the MFA attempt budget bounds.
type authEventLanes struct {
	mfa        *AuthEventDispatcher
	completion *AuthEventDispatcher
}

// newAuthEventLanes builds both lanes for the registered step-event sinks, or returns nil without sinks.
func newAuthEventLanes(runner *Runner) *authEventLanes {
	mfa := NewAuthEventDispatcher(runner, DefaultAuthEventQueueCapacity)
	if mfa == nil {
		return nil
	}

	return &authEventLanes{mfa: mfa, completion: newLaneDispatcher(sinkNames(runner.registry.AuthEventSinks()),
		DefaultAuthEventCompletionQueueCapacity, runner.deliverAuthEvent, laneCounter(authEventLaneCompletion))}
}

// start launches the delivery goroutine of every lane.
func (l *authEventLanes) start() {
	if l == nil {
		return
	}

	l.mfa.Start()
	l.completion.Start()
}

// route returns the lane of one event type; every type outside the completion evidence keeps the second-factor lane.
func (l *authEventLanes) route(eventType pluginapi.AuthEventType) *AuthEventDispatcher {
	if l == nil {
		return nil
	}

	if eventType.Completion() {
		return l.completion
	}

	return l.mfa
}

// stop drains every lane within ctx.
func (l *authEventLanes) stop(ctx context.Context) error {
	if l == nil {
		return nil
	}

	return errors.Join(l.mfa.Stop(ctx), l.completion.Stop(ctx))
}
