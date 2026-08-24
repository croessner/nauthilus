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

package admission

import (
	"context"
	"slices"

	"github.com/croessner/nauthilus/v3/server/definitions"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

var _ policyruntime.AdmissionAuthority = (*authority)(nil)

// Admit resolves one exact profile, validates the request, and acquires its lifetime permit.
func (a *authority) Admit(
	ctx context.Context,
	caller decision.CallerContext,
	request decision.DecisionRequest,
) (policyruntime.AdmissionPermit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	profile, exists := a.profile(caller.Principal())
	if !exists {
		return nil, admissionError(ErrPermissionDenied, "authenticated principal has no admission profile")
	}

	if !sameCaller(caller, request.Caller()) {
		return nil, admissionError(ErrInvalidRequest, "trusted caller does not match the request binding")
	}

	if !profile.permitsCaller(caller) {
		return nil, admissionError(ErrPermissionDenied, "authentication kind or internal status is not permitted")
	}

	if !profile.permitsBearerScopes(caller) {
		return nil, admissionError(ErrPermissionDenied, "Bearer caller lacks the required Policy scope")
	}

	grant, exists := profile.grants[request.Target().String()]
	if !exists {
		return nil, admissionError(ErrPermissionDenied, "request target is not granted")
	}

	if !profile.permitsDiagnostics(caller, request.Options().IncludeDiagnostics) {
		return nil, admissionError(ErrPermissionDenied, "requested diagnostics are not permitted")
	}

	if submittedFactCount(request) > profile.limits.MaxFacts {
		return nil, admissionError(ErrRequestLimitExceeded, "submitted fact count exceeds the profile limit")
	}

	if logicalRequestSize(request) > profile.limits.MaxRequestBytes {
		return nil, admissionError(ErrRequestLimitExceeded, "logical request size exceeds the profile limit")
	}

	facts, err := buildAdmittedFacts(caller, request, profile.fields, grant.schema)
	if err != nil {
		return nil, err
	}

	return profile.acquire(facts)
}

// profile resolves one exact principal without fallback or normalization.
func (a *authority) profile(principal string) (*compiledProfile, bool) {
	if a == nil {
		return nil, false
	}

	profile, exists := a.profiles[principal]

	return profile, exists
}

// permitsCaller checks both exact credential kind and explicit internal profile status.
func (p *compiledProfile) permitsCaller(caller decision.CallerContext) bool {
	if p == nil || caller.Internal() != p.internal {
		return false
	}

	return containsKey(p.kinds, caller.AuthenticationKind())
}

// permitsBearerScopes applies the evaluate-scope defense in depth only to Bearer callers.
func (p *compiledProfile) permitsBearerScopes(caller decision.CallerContext) bool {
	if caller.AuthenticationKind() != policy.CallerAuthenticationKindBearer {
		return true
	}

	return slices.Contains(caller.Scopes(), definitions.ScopePolicyEvaluate)
}

// permitsDiagnostics enforces explicit profile permission and Bearer diagnostic scope.
func (p *compiledProfile) permitsDiagnostics(caller decision.CallerContext, requested bool) bool {
	if !requested {
		return true
	}

	if !p.diagnostics {
		return false
	}

	return caller.AuthenticationKind() != policy.CallerAuthenticationKindBearer ||
		slices.Contains(caller.Scopes(), definitions.ScopePolicyDiagnostics)
}

// acquire nonblockingly owns concurrency and rate capacity for one full permit lifetime.
func (p *compiledProfile) acquire(facts decision.FactSet) (policyruntime.AdmissionPermit, error) {
	select {
	case p.concurrency <- struct{}{}:
	default:
		return nil, admissionError(ErrCapacityLimitExceeded, "profile concurrency is exhausted")
	}

	if !p.limiter.Allow() {
		<-p.concurrency

		return nil, admissionError(ErrCapacityLimitExceeded, "profile request rate is exhausted")
	}

	return &permit{facts: facts, concurrency: p.concurrency}, nil
}

// submittedFactCount counts only caller assertion entries, excluding trusted facts.
func submittedFactCount(request decision.DecisionRequest) int {
	return request.Subject().Attributes().Len() +
		request.Resource().Attributes().Len() +
		request.Environment().Attributes().Len() +
		request.Attributes().Len()
}

// sameCaller rejects any split authority between the explicit and request-bound trusted context.
func sameCaller(first decision.CallerContext, second decision.CallerContext) bool {
	return sameCallerIdentity(first, second) && sameCallerTransport(first, second)
}

// sameCallerIdentity compares principal and authenticator-owned trusted identity evidence.
func sameCallerIdentity(first decision.CallerContext, second decision.CallerContext) bool {
	return first.Principal() == second.Principal() &&
		first.ClientID() == second.ClientID() &&
		first.Subject() == second.Subject() &&
		first.Issuer() == second.Issuer() &&
		slices.Equal(first.Scopes(), second.Scopes()) &&
		first.AuthenticationKind() == second.AuthenticationKind() &&
		first.Internal() == second.Internal()
}

// sameCallerTransport compares every server-observed trusted transport field.
func sameCallerTransport(first decision.CallerContext, second decision.CallerContext) bool {
	return first.SourceIP() == second.SourceIP() &&
		first.MTLSIdentity() == second.MTLSIdentity() &&
		first.TransportKind() == second.TransportKind() &&
		first.Listener() == second.Listener() &&
		first.HTTPRoute() == second.HTTPRoute() &&
		first.GRPCMethod() == second.GRPCMethod()
}
