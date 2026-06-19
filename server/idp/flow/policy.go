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

import "fmt"

// Policy defines flow-specific rules for actions and transitions.
type Policy interface {
	Type() Type
	AllowsStep(step Step) bool
	AllowsAction(step Step, action Action) bool
	CanTransition(from Step, to Step) bool
}

type staticPolicy struct {
	flowType        Type
	allowedActions  map[Step]map[Action]struct{}
	allowedSteps    map[Step]struct{}
	allowedNextStep map[Step]map[Step]struct{}
}

// Type returns the flow type this static policy applies to.
func (p staticPolicy) Type() Type {
	return p.flowType
}

// AllowsStep reports whether a step is valid for this flow type.
func (p staticPolicy) AllowsStep(step Step) bool {
	_, ok := p.allowedSteps[step]

	return ok
}

// AllowsAction reports whether an action is allowed at the given step.
func (p staticPolicy) AllowsAction(step Step, action Action) bool {
	actions, ok := p.allowedActions[step]
	if !ok {
		return false
	}

	_, ok = actions[action]

	return ok
}

// CanTransition reports whether a transition from one step to another is allowed.
func (p staticPolicy) CanTransition(from Step, to Step) bool {
	steps, ok := p.allowedNextStep[from]
	if !ok {
		return false
	}

	_, ok = steps[to]

	return ok
}

// DefaultPolicies provides baseline rules for the initial supported flow types.
func DefaultPolicies() map[Type]Policy {
	return map[Type]Policy{
		FlowTypeOIDCAuthorization: oidcAuthorizationPolicy(),
		FlowTypeOIDCDeviceCode:    oidcDevicePolicy(),
		FlowTypeSAML:              samlPolicy(),
		FlowTypeRequireMFA:        requireMFAPolicy(),
	}
}

// PolicyForFlowType returns a baseline policy for a known flow type.
func PolicyForFlowType(flowType Type) (Policy, error) {
	policies := DefaultPolicies()

	policy, ok := policies[flowType]
	if !ok {
		return nil, fmt.Errorf("flow policy: %w (%s)", ErrInvalidFlowType, flowType)
	}

	return policy, nil
}

func oidcAuthorizationPolicy() Policy {
	return staticPolicy{
		flowType: FlowTypeOIDCAuthorization,
		allowedActions: map[Step]map[Action]struct{}{
			FlowStepStart: {
				FlowActionStart:   {},
				FlowActionAdvance: {},
			},
			FlowStepLogin: {
				FlowActionAdvance: {},
				FlowActionCancel:  {},
			},
			FlowStepMFA: {
				FlowActionAdvance: {},
				FlowActionBack:    {},
				FlowActionCancel:  {},
			},
			FlowStepConsent: {
				FlowActionAdvance: {},
				FlowActionBack:    {},
				FlowActionCancel:  {},
			},
			FlowStepCallback: {
				FlowActionComplete: {},
				FlowActionAbort:    {},
			},
		},
		allowedSteps: stepsToSet(FlowStepStart, FlowStepLogin, FlowStepMFA, FlowStepConsent, FlowStepCallback, FlowStepDone),
		allowedNextStep: map[Step]map[Step]struct{}{
			FlowStepStart:    stepsToSet(FlowStepLogin),
			FlowStepLogin:    stepsToSet(FlowStepMFA, FlowStepConsent, FlowStepCallback),
			FlowStepMFA:      stepsToSet(FlowStepConsent, FlowStepCallback, FlowStepLogin),
			FlowStepConsent:  stepsToSet(FlowStepCallback, FlowStepMFA),
			FlowStepCallback: stepsToSet(FlowStepDone),
		},
	}
}

func oidcDevicePolicy() Policy {
	return staticPolicy{
		flowType: FlowTypeOIDCDeviceCode,
		allowedActions: map[Step]map[Action]struct{}{
			FlowStepStart: {
				FlowActionStart:   {},
				FlowActionAdvance: {},
			},
			FlowStepDeviceVerification: {
				FlowActionAdvance: {},
				FlowActionCancel:  {},
			},
			FlowStepLogin: {
				FlowActionAdvance: {},
				FlowActionCancel:  {},
			},
			FlowStepMFA: {
				FlowActionAdvance: {},
				FlowActionBack:    {},
				FlowActionCancel:  {},
			},
			FlowStepConsent: {
				FlowActionAdvance: {},
				FlowActionBack:    {},
				FlowActionCancel:  {},
			},
			FlowStepCallback: {
				FlowActionComplete: {},
				FlowActionAbort:    {},
			},
		},
		allowedSteps: stepsToSet(FlowStepStart, FlowStepDeviceVerification, FlowStepLogin, FlowStepMFA, FlowStepConsent, FlowStepCallback, FlowStepDone),
		allowedNextStep: map[Step]map[Step]struct{}{
			FlowStepStart:              stepsToSet(FlowStepDeviceVerification),
			FlowStepDeviceVerification: stepsToSet(FlowStepLogin),
			FlowStepLogin:              stepsToSet(FlowStepMFA, FlowStepConsent, FlowStepCallback),
			FlowStepMFA:                stepsToSet(FlowStepConsent, FlowStepCallback, FlowStepLogin),
			FlowStepConsent:            stepsToSet(FlowStepCallback, FlowStepMFA),
			FlowStepCallback:           stepsToSet(FlowStepDone),
		},
	}
}

func samlPolicy() Policy {
	return staticPolicy{
		flowType: FlowTypeSAML,
		allowedActions: map[Step]map[Action]struct{}{
			FlowStepStart: {
				FlowActionStart:   {},
				FlowActionAdvance: {},
			},
			FlowStepLogin: {
				FlowActionAdvance: {},
				FlowActionCancel:  {},
			},
			FlowStepMFA: {
				FlowActionAdvance: {},
				FlowActionBack:    {},
				FlowActionCancel:  {},
			},
			FlowStepCallback: {
				FlowActionComplete: {},
				FlowActionAbort:    {},
			},
		},
		allowedSteps: stepsToSet(FlowStepStart, FlowStepLogin, FlowStepMFA, FlowStepCallback, FlowStepDone),
		allowedNextStep: map[Step]map[Step]struct{}{
			FlowStepStart:    stepsToSet(FlowStepLogin),
			FlowStepLogin:    stepsToSet(FlowStepMFA, FlowStepCallback),
			FlowStepMFA:      stepsToSet(FlowStepCallback, FlowStepLogin),
			FlowStepCallback: stepsToSet(FlowStepDone),
		},
	}
}

func requireMFAPolicy() Policy {
	return staticPolicy{
		flowType: FlowTypeRequireMFA,
		allowedActions: map[Step]map[Action]struct{}{
			FlowStepStart: {
				FlowActionStart:   {},
				FlowActionAdvance: {},
			},
			FlowStepRequireMFAChallenge: {
				FlowActionAdvance: {},
				FlowActionCancel:  {},
			},
			FlowStepCallback: {
				FlowActionComplete: {},
				FlowActionAbort:    {},
			},
		},
		allowedSteps: stepsToSet(FlowStepStart, FlowStepRequireMFAChallenge, FlowStepCallback, FlowStepDone),
		allowedNextStep: map[Step]map[Step]struct{}{
			FlowStepStart:               stepsToSet(FlowStepRequireMFAChallenge),
			FlowStepRequireMFAChallenge: stepsToSet(FlowStepCallback),
			FlowStepCallback:            stepsToSet(FlowStepDone),
		},
	}
}

func stepsToSet[T comparable](values ...T) map[T]struct{} {
	result := make(map[T]struct{}, len(values))

	for _, value := range values {
		result[value] = struct{}{}
	}

	return result
}
