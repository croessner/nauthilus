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

package policy

const (
	// AuthnNamespace owns the builtin authentication target family.
	AuthnNamespace = "authn"

	// AuthnFactOperation identifies the host-selected authentication operation.
	AuthnFactOperation = "nauthilus.auth.operation"
	// AuthnFactService identifies the host-selected authentication response surface.
	AuthnFactService = "nauthilus.auth.service"
	// AuthnFactCurrentDecision records the current pipeline outcome before candidate mapping.
	AuthnFactCurrentDecision = "nauthilus.auth.current_decision"

	// AuthnFactUsername identifies the caller-asserted authentication subject.
	AuthnFactUsername = "input.auth.username"
	// AuthnFactProtocol identifies the caller-asserted application protocol.
	AuthnFactProtocol = "environment.protocol"
	// AuthnFactMethod identifies the caller-asserted authentication method.
	AuthnFactMethod = "input.auth.method"
	// AuthnFactUserAgent identifies the caller-asserted user agent.
	AuthnFactUserAgent = "input.auth.user_agent"
	// AuthnFactClientIP identifies the caller-asserted end-client address.
	AuthnFactClientIP = "input.auth.client_ip"
	// AuthnFactClientPort identifies the caller-asserted end-client port.
	AuthnFactClientPort = "input.auth.client_port"
	// AuthnFactClientHostname identifies the caller-asserted end-client hostname.
	AuthnFactClientHostname = "input.auth.client_hostname"
	// AuthnFactClientID identifies the caller-asserted application client.
	AuthnFactClientID = "input.auth.client_id"
	// AuthnFactLocalIP identifies the caller-asserted local endpoint address.
	AuthnFactLocalIP = "input.auth.local_ip"
	// AuthnFactLocalPort identifies the caller-asserted local endpoint port.
	AuthnFactLocalPort = "input.auth.local_port"
	// AuthnFactIDPClientID identifies the request-bound OIDC client when present.
	AuthnFactIDPClientID = "input.auth.idp_client_id"
	// AuthnFactSAMLServiceProviderID identifies the request-bound SAML service provider.
	AuthnFactSAMLServiceProviderID = "input.auth.saml_service_provider_id"
	// AuthnFactLoginAttempt identifies the caller-supplied normalized login attempt ordinal.
	AuthnFactLoginAttempt = "input.auth.login_attempt"

	// AuthnFactBackend identifies the backend that produced the current result.
	AuthnFactBackend = "backend.kind"
	// AuthnFactAuthenticated records a successful password authentication result.
	AuthnFactAuthenticated = "backend.authenticated"
	// AuthnFactIdentityFound records a successful identity lookup result.
	AuthnFactIdentityFound = "backend.identity_found"
	// AuthnFactAccountField identifies the backend account attribute.
	AuthnFactAccountField = "backend.account_field"
	// AuthnFactGroups records backend-resolved group names.
	AuthnFactGroups = "backend.groups"
	// AuthnFactGroupDistinguishedNames records backend-resolved group distinguished names.
	AuthnFactGroupDistinguishedNames = "backend.group_distinguished_names"
	// AuthnFactAccountCount records the bounded account-provider result size.
	AuthnFactAccountCount = "backend.account_count"
	// AuthnFactAccountProviderCompleted records whether the account provider completed reliably.
	AuthnFactAccountProviderCompleted = "backend.account_provider_completed"
)
