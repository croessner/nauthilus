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

const (
	defaultStartURI  = "/login"
	defaultCancelURI = "/"
	defaultErrorURI  = "/login"
)

// URIBuilder resolves navigation targets for flow decisions.
type URIBuilder struct {
	transitions map[Type]map[Step]map[Action]string
}

// NewURIBuilder returns a default URI builder with flow-specific navigation rules.
func NewURIBuilder() *URIBuilder {
	return &URIBuilder{
		transitions: map[Type]map[Step]map[Action]string{
			FlowTypeOIDCAuthorization: {
				FlowStepLogin: {
					FlowActionCancel: defaultCancelURI,
				},
			},
			FlowTypeOIDCDeviceCode: {
				FlowStepLogin: {
					FlowActionCancel: defaultCancelURI,
				},
			},
			FlowTypeSAML: {
				FlowStepLogin: {
					FlowActionCancel: defaultCancelURI,
				},
			},
			FlowTypeRequireMFA: {
				FlowStepRequireMFAChallenge: {
					FlowActionCancel: defaultCancelURI,
				},
			},
		},
	}
}

// Resolve computes the redirect target for the given action and state.
func (b *URIBuilder) Resolve(state *State, action Action) string {
	if state == nil {
		return defaultErrorURI
	}

	if uri, ok := explicitFlowTarget(state, action); ok {
		return uri
	}

	if uri, ok := b.transitionTarget(state, action); ok {
		return uri
	}

	return defaultFlowTarget(action)
}

// explicitFlowTarget returns the target carried by the current flow state.
func explicitFlowTarget(state *State, action Action) (string, bool) {
	switch action {
	case FlowActionResume:
		if state.Metadata != nil {
			if target, ok := state.Metadata[FlowMetadataResumeTarget]; ok && target != "" {
				return target, true
			}
		}

		if state.ReturnTarget != "" {
			return state.ReturnTarget, true
		}
	case FlowActionStart, FlowActionAdvance, FlowActionBack, FlowActionComplete:
		if state.ReturnTarget != "" {
			return state.ReturnTarget, true
		}
	case FlowActionCancel:
		if state.CancelTarget != "" {
			return state.CancelTarget, true
		}
	}

	return "", false
}

// transitionTarget returns a configured target for the current flow step.
func (b *URIBuilder) transitionTarget(state *State, action Action) (string, bool) {
	if b == nil {
		return "", false
	}

	steps, ok := b.transitions[state.Type]
	if !ok {
		return "", false
	}

	actions, ok := steps[state.CurrentStep]
	if !ok {
		return "", false
	}

	uri, ok := actions[action]

	return uri, ok
}

// defaultFlowTarget returns the fallback redirect target for an action.
func defaultFlowTarget(action Action) string {
	switch action {
	case FlowActionCancel:
		return defaultCancelURI
	case FlowActionStart:
		return defaultStartURI
	default:
		return defaultErrorURI
	}
}
