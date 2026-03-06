// Copyright (C) 2025 Christian Rößner
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

package flow

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	reasonInvalidTransitionRecovered = "invalid_transition_recovered"
	reasonStaleFlowRecovered         = "stale_flow_recovered"
)

// Controller orchestrates flow actions based on policies and persistence.
type Controller struct {
	store      Store
	uriBuilder *URIBuilder
}

// NewController creates a flow controller using the given state store.
func NewController(store Store) *Controller {
	return &Controller{store: store, uriBuilder: NewURIBuilder()}
}

// PreviewStart validates and normalizes a flow state and returns the start
// redirect decision without persisting the state.
func (c *Controller) PreviewStart(state *State, now time.Time) (Decision, error) {
	if state == nil {
		return Decision{}, fmt.Errorf("flow controller: %w", ErrEmptyFlowID)
	}

	state.Normalize(now)
	if err := state.Validate(); err != nil {
		return Decision{}, err
	}

	policy, err := PolicyForFlowType(state.FlowType)
	if err != nil {
		return Decision{}, err
	}

	if !policy.AllowsAction(state.CurrentStep, FlowActionStart) {
		return Decision{}, TransitionError{FlowType: state.FlowType, From: state.CurrentStep, To: state.CurrentStep, Action: FlowActionStart}
	}

	return Decision{Type: DecisionTypeRedirect, RedirectURI: c.uriBuilder.Resolve(state, FlowActionStart), Reason: string(FlowActionStart)}, nil
}

// Start persists a validated flow state and returns the initial redirect decision.
func (c *Controller) Start(ctx context.Context, state *State, now time.Time) (Decision, error) {
	decision, err := c.PreviewStart(state, now)
	if err != nil {
		return Decision{}, err
	}

	if c == nil || c.store == nil {
		return Decision{}, fmt.Errorf("flow controller: missing store")
	}

	if err := c.store.Save(ctx, state); err != nil {
		return Decision{}, err
	}

	return decision, nil
}

// Advance transitions the flow to the requested next step.
func (c *Controller) Advance(ctx context.Context, flowID string, to FlowStep, now time.Time) (Decision, error) {
	return c.transition(ctx, flowID, to, FlowActionAdvance, now)
}

// Back transitions the flow to a valid previous step.
func (c *Controller) Back(ctx context.Context, flowID string, to FlowStep, now time.Time) (Decision, error) {
	return c.transition(ctx, flowID, to, FlowActionBack, now)
}

// Cancel terminates the flow through a policy-allowed cancel action.
func (c *Controller) Cancel(ctx context.Context, flowID string) (Decision, error) {
	state, err := c.store.Load(ctx, flowID)
	if err != nil {
		return Decision{}, err
	}

	if state == nil {
		return Decision{}, fmt.Errorf("flow controller: %w", ErrFlowNotFound)
	}

	policy, err := PolicyForFlowType(state.FlowType)
	if err != nil {
		return Decision{}, err
	}

	if !policy.AllowsAction(state.CurrentStep, FlowActionCancel) {
		return Decision{}, TransitionError{FlowType: state.FlowType, From: state.CurrentStep, To: state.CurrentStep, Action: FlowActionCancel}
	}

	if err := c.store.Delete(ctx, flowID); err != nil {
		return Decision{}, err
	}

	return Decision{Type: DecisionTypeRedirect, RedirectURI: c.uriBuilder.Resolve(state, FlowActionCancel), Reason: string(FlowActionCancel)}, nil
}

// Complete finalizes the flow and removes its persisted state.
func (c *Controller) Complete(ctx context.Context, flowID string) (Decision, error) {
	state, err := c.store.Load(ctx, flowID)
	if err != nil {
		return Decision{}, err
	}

	if state == nil {
		return Decision{}, fmt.Errorf("flow controller: %w", ErrFlowNotFound)
	}

	policy, err := PolicyForFlowType(state.FlowType)
	if err != nil {
		return Decision{}, err
	}

	if !policy.AllowsAction(state.CurrentStep, FlowActionComplete) {
		return Decision{}, TransitionError{FlowType: state.FlowType, From: state.CurrentStep, To: state.CurrentStep, Action: FlowActionComplete}
	}

	if state.AuthOutcome == AuthOutcomeFailLatched {
		return Decision{}, TransitionError{FlowType: state.FlowType, From: state.CurrentStep, To: state.CurrentStep, Action: FlowActionComplete}
	}

	if err := c.store.Delete(ctx, flowID); err != nil {
		return Decision{}, err
	}

	return Decision{Type: DecisionTypeRedirect, RedirectURI: c.uriBuilder.Resolve(state, FlowActionComplete), Reason: string(FlowActionComplete)}, nil
}

// Resume returns the redirect decision for the currently persisted flow step.
func (c *Controller) Resume(ctx context.Context, flowID string) (Decision, error) {
	state, err := c.store.Load(ctx, flowID)
	if err != nil {
		return Decision{}, err
	}

	if state == nil {
		return Decision{}, fmt.Errorf("flow controller: %w", ErrFlowNotFound)
	}

	policy, err := PolicyForFlowType(state.FlowType)
	if err != nil {
		return Decision{}, err
	}

	if !policy.AllowsStep(state.CurrentStep) {
		return Decision{}, fmt.Errorf("flow controller: %w (%s)", ErrInvalidStep, state.CurrentStep)
	}

	return Decision{Type: DecisionTypeRedirect, RedirectURI: c.uriBuilder.Resolve(state, FlowActionResume), Reason: string(FlowActionResume)}, nil
}

// Abort forcefully deletes persisted flow state and returns an error decision.
func (c *Controller) Abort(ctx context.Context, flowID string) (Decision, error) {
	if err := c.store.Delete(ctx, flowID); err != nil {
		return Decision{}, err
	}

	return Decision{Type: DecisionTypeError, Reason: string(FlowActionAbort)}, nil
}

// State returns the currently persisted flow state.
func (c *Controller) State(ctx context.Context, flowID string) (*State, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("flow controller: missing store")
	}

	state, err := c.store.Load(ctx, flowID)
	if err != nil {
		return nil, err
	}

	if state == nil {
		return nil, fmt.Errorf("flow controller: %w", ErrFlowNotFound)
	}

	return state, nil
}

// SetAuthOutcome updates the persisted first-factor outcome for a flow.
func (c *Controller) SetAuthOutcome(ctx context.Context, flowID string, outcome AuthOutcome, now time.Time) error {
	state, err := c.State(ctx, flowID)
	if err != nil {
		return err
	}

	if err = state.UpdateAuthOutcome(outcome); err != nil {
		return err
	}

	state.Normalize(now)

	if err = c.store.Save(ctx, state); err != nil {
		return err
	}

	return nil
}

// Recover handles recovery for transition violations and stale flow IDs.
func (c *Controller) Recover(ctx context.Context, flowID string, cause error) (Decision, error) {
	if c == nil || c.store == nil {
		return Decision{}, fmt.Errorf("flow controller: missing store")
	}

	if flowID == "" {
		return Decision{}, fmt.Errorf("flow controller: %w", ErrEmptyFlowID)
	}

	if cause == nil {
		return Decision{}, fmt.Errorf("flow controller: %w", ErrInvalidAction)
	}

	if transitionErr, ok := errors.AsType[TransitionError](cause); ok {
		if err := c.store.Delete(ctx, flowID); err != nil {
			return Decision{}, err
		}

		reportTransitionViolation(transitionErr)

		return Decision{Type: DecisionTypeRedirect, RedirectURI: defaultStartURI, Reason: reasonInvalidTransitionRecovered}, nil
	}

	if errors.Is(cause, ErrFlowNotFound) || errors.Is(cause, ErrEmptyFlowID) {
		reportStaleFlow(flowID)

		return Decision{Type: DecisionTypeRedirect, RedirectURI: defaultStartURI, Reason: reasonStaleFlowRecovered}, nil
	}

	return Decision{}, cause
}

func (c *Controller) transition(ctx context.Context, flowID string, to FlowStep, action FlowAction, now time.Time) (Decision, error) {
	state, err := c.store.Load(ctx, flowID)
	if err != nil {
		return Decision{}, err
	}

	if state == nil {
		return Decision{}, fmt.Errorf("flow controller: %w", ErrFlowNotFound)
	}

	policy, err := PolicyForFlowType(state.FlowType)
	if err != nil {
		return Decision{}, err
	}

	if !policy.AllowsAction(state.CurrentStep, action) || !policy.CanTransition(state.CurrentStep, to) {
		return Decision{}, TransitionError{FlowType: state.FlowType, From: state.CurrentStep, To: to, Action: action}
	}

	if state.AuthOutcome == AuthOutcomeFailLatched && to != FlowStepLogin {
		return Decision{}, TransitionError{FlowType: state.FlowType, From: state.CurrentStep, To: to, Action: action}
	}

	state.CurrentStep = to
	state.Normalize(now)

	if err := c.store.Save(ctx, state); err != nil {
		return Decision{}, err
	}

	return Decision{Type: DecisionTypeRedirect, RedirectURI: c.uriBuilder.Resolve(state, action), Reason: string(action)}, nil
}
