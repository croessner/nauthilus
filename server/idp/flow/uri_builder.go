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
	transitions map[FlowType]map[FlowStep]map[FlowAction]string
}

// NewURIBuilder returns a default URI builder with flow-specific navigation rules.
func NewURIBuilder() *URIBuilder {
	return &URIBuilder{
		transitions: map[FlowType]map[FlowStep]map[FlowAction]string{
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
func (b *URIBuilder) Resolve(state *State, action FlowAction) string {
	if state == nil {
		return defaultErrorURI
	}

	switch action {
	case FlowActionResume:
		if state.Metadata != nil {
			if target, ok := state.Metadata[FlowMetadataResumeTarget]; ok && target != "" {
				return target
			}
		}

		if state.ReturnTarget != "" {
			return state.ReturnTarget
		}
	case FlowActionStart, FlowActionAdvance, FlowActionBack, FlowActionComplete:
		if state.ReturnTarget != "" {
			return state.ReturnTarget
		}
	case FlowActionCancel:
		if state.CancelTarget != "" {
			return state.CancelTarget
		}
	}

	if b != nil {
		if steps, ok := b.transitions[state.FlowType]; ok {
			if actions, ok := steps[state.CurrentStep]; ok {
				if uri, ok := actions[action]; ok {
					return uri
				}
			}
		}
	}

	switch action {
	case FlowActionCancel:
		return defaultCancelURI
	case FlowActionStart:
		return defaultStartURI
	default:
		return defaultErrorURI
	}
}
