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

package pluginapi

// AuthOutcomeDecision is the transport-independent terminal result of one authn request.
type AuthOutcomeDecision string

const (
	// AuthOutcomeOK marks a request answered with success.
	AuthOutcomeOK AuthOutcomeDecision = "ok"

	// AuthOutcomeFail marks a request answered with a definite rejection.
	AuthOutcomeFail AuthOutcomeDecision = "fail"

	// AuthOutcomeTempFail marks a request answered with a temporary failure.
	AuthOutcomeTempFail AuthOutcomeDecision = "tempfail"

	// AuthOutcomeUnknown marks a request whose terminal result was not sealed when detached work ran.
	AuthOutcomeUnknown AuthOutcomeDecision = "unknown"
)

// AuthTransport names the boundary that delivered the terminal result to the client.
type AuthTransport string

const (
	// AuthTransportHTTP marks results committed through an HTTP response.
	AuthTransportHTTP AuthTransport = "http"

	// AuthTransportGRPC marks results returned through a gRPC unary call.
	AuthTransportGRPC AuthTransport = "grpc"
)

// AuthOutcome is the host-sealed terminal result of the request that selected a post-action. Post-actions run after
// the response boundary, so this value reflects what the client was answered, not the request state at the moment
// Policy selected the effect. When Known is false, Decision is AuthOutcomeUnknown, only the transport facts may be set,
// and every other field is empty.
type AuthOutcome struct {
	// Decision is the terminal result.
	Decision AuthOutcomeDecision
	// Operation is the Policy operation, for example authenticate, lookup_identity, or list_accounts.
	Operation string
	// Stage is the Policy stage of the rule that presented the result; empty without a presenting rule.
	Stage string
	// OutcomeMarker and ResponseMarker are the stable Policy markers of the presented result.
	OutcomeMarker  string
	ResponseMarker string
	// PolicyRule names the presenting rule.
	PolicyRule string
	// TempFailReason, TempFailCheckpoint, and PolicyStatus describe why a temporary failure was answered; they are
	// empty for other decisions.
	TempFailReason     string
	TempFailCheckpoint string
	PolicyStatus       string
	// FSMState is the terminal auth FSM state.
	FSMState string
	// StatusMessage is the client-visible status text.
	StatusMessage string
	// Transport names the delivery boundary; it is empty when unknown.
	Transport AuthTransport
	// HTTPStatus is the host status code configured for the decision; it does not prove what the transport sent.
	HTTPStatus int
	// TransportStatus is the committed HTTP status, or zero for gRPC and unknown transports.
	TransportStatus int
	// Known reports whether the host sealed a terminal outcome before the post-action executed.
	Known bool
}
