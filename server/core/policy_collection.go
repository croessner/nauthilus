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

package core

import (
	"context"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	"github.com/croessner/nauthilus/server/policy/evaluation"
	"github.com/croessner/nauthilus/server/policy/observability"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const policyCollectionContextKey = "policy_collection"

type policyCheckResult struct {
	Err          error
	Reason       string
	Status       policy.CheckStatus
	DecisionHint policy.Decision
	Matched      bool
	Attributes   []policycollection.AttributeValue
}

func (a *AuthState) requestPolicyContext(ctx *gin.Context) *policycollection.DecisionContext {
	if a == nil || ctx == nil {
		return nil
	}

	if policyCtx := existingPolicyContext(ctx); policyCtx != nil {
		return policyCtx
	}

	snapshot := policyruntime.DefaultStore().Active()
	if snapshot == nil {
		return nil
	}

	operation := a.policyOperation()
	policyCtx := policycollection.NewDecisionContext(snapshot, operation, observability.DefaultRecorder())
	policyCtx.Report().SessionID = a.Runtime.GUID
	policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestOperation, policy.StagePreAuth, operation, string(operation)))
	policyCtx.RecordAttribute(policycollection.TimeAttribute(policy.AttributeRequestTime, policy.StagePreAuth, operation, time.Now()))
	policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestClientIP, policy.StagePreAuth, operation, a.Request.ClientIP))
	policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestProtocol, policy.StagePreAuth, operation, a.requestProtocol()))
	ctx.Set(policyCollectionContextKey, policyCtx)

	return policyCtx
}

func (a *AuthState) policyOperation() policy.Operation {
	if a == nil {
		return policy.OperationAuthenticate
	}

	if a.Request.ListAccounts {
		return policy.OperationListAccounts
	}

	if a.Request.NoAuth {
		return policy.OperationLookupIdentity
	}

	return policy.OperationAuthenticate
}

func (a *AuthState) requestProtocol() string {
	if a == nil || a.Request.Protocol == nil {
		return ""
	}

	return a.Request.Protocol.Get()
}

func (a *AuthState) policyAuthState() policycollection.AuthState {
	if a != nil && a.Runtime.Authenticated {
		return policycollection.AuthStateAuthenticated
	}

	return policycollection.AuthStateUnauthenticated
}

func (a *AuthState) completePolicyStage(ctx *gin.Context, stage policy.Stage) {
	if policyCtx := a.requestPolicyContext(ctx); policyCtx != nil {
		policyCtx.CompleteStage(stage, a.policyAuthState())
	}
}

func (a *AuthState) beginPolicyCheck(ctx *gin.Context, selector policycollection.CheckSelector) *policycollection.ActiveCheck {
	policyCtx := a.requestPolicyContext(ctx)
	if policyCtx == nil {
		return nil
	}

	return policyCtx.BeginCheck(contextFromGin(ctx), selector)
}

func (a *AuthState) finishPolicyCheck(check *policycollection.ActiveCheck, result policyCheckResult) {
	if check == nil {
		return
	}

	check.Finish(policycollection.CheckResult{
		Err:          result.Err,
		Status:       result.Status,
		Reason:       result.Reason,
		Matched:      result.Matched,
		DecisionHint: result.DecisionHint,
		Attributes:   result.Attributes,
	})
}

func (a *AuthState) markPolicyUnavailable(ctx *gin.Context, name string, reason string) {
	if policyCtx := a.requestPolicyContext(ctx); policyCtx != nil {
		policyCtx.MarkUnavailable(name, reason)
	}
}

func (a *AuthState) comparePolicyDecision(ctx *gin.Context, production evaluation.ProductionOutcome) {
	policyCtx := existingPolicyContext(ctx)
	if policyCtx == nil {
		return
	}

	if production.Surface == "" {
		production.Surface = a.policyResponseSurface()
	}

	mode, defaultPolicy, generation := policyCtx.SnapshotMetadata()
	result := evaluation.CompareWithProduction(contextFromGin(ctx), policyCtx.Report(), evaluation.CompareInput{
		Mode:          mode,
		Set:           defaultPolicy,
		Generation:    generation,
		Recorder:      observability.DefaultRecorder(),
		Logger:        a.logger(),
		Production:    production,
		ProductionSet: true,
	})

	if !result.Mismatch || result.Shadow == nil {
		return
	}

	observability.Debug(
		contextFromGin(ctx),
		a.Cfg(),
		a.Logger(),
		observability.ComponentObserve,
		definitions.LogKeyGUID, a.Runtime.GUID,
		"operation", string(policyCtx.Report().Operation),
		"stage", string(result.Shadow.Stage),
		"mismatch_type", result.MismatchType,
	)
}

func (a *AuthState) policyResponseSurface() string {
	if a == nil {
		return "http_json"
	}

	if a.Request.ListAccounts {
		if a.Request.Service == definitions.ServGRPC {
			return "grpc_list_accounts"
		}

		return "http_list_accounts"
	}

	if a.Request.NoAuth && a.Request.Service == definitions.ServGRPC {
		return "grpc_lookup_identity"
	}

	switch a.Request.Service {
	case definitions.ServCBOR:
		return "http_cbor"
	case definitions.ServNginx:
		return "nginx_auth_request"
	case definitions.ServHeader:
		return "http_header"
	case definitions.ServGRPC:
		return "grpc_auth_service"
	case definitions.ServIdP:
		return "idp_browser"
	case definitions.ServJSON:
		return "http_json"
	default:
		return "http_plain"
	}
}

func existingPolicyContext(ctx *gin.Context) *policycollection.DecisionContext {
	if ctx == nil {
		return nil
	}

	value, ok := ctx.Get(policyCollectionContextKey)
	if !ok {
		return nil
	}

	policyCtx, ok := value.(*policycollection.DecisionContext)
	if !ok {
		return nil
	}

	return policyCtx
}

// PolicyScriptRecorder returns the request-local Lua script result sink.
func (a *AuthState) PolicyScriptRecorder(ctx *gin.Context) policycollection.ScriptRecorder {
	policyCtx := a.requestPolicyContext(ctx)
	if policyCtx == nil {
		return nil
	}

	return policycollection.NewScriptSink(policyCtx)
}

func (a *AuthState) recordPolicyTLS(ctx *gin.Context, triggered bool) {
	check := a.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: policy.CheckTypeTLSEncryption,
		Stage:     policy.StagePreAuth,
		Name:      "tls_encryption",
		ConfigRef: "auth.controls.tls_encryption",
	})
	a.finishPolicyCheck(check, policyCheckResult{
		Matched:      triggered,
		DecisionHint: policyDecision(triggered, policy.DecisionTempFail),
		Attributes: []policycollection.AttributeValue{
			policycollection.BoolAttribute(policy.AttributeTLSSecure, policy.StagePreAuth, a.policyOperation(), !triggered, nil),
		},
	})
}

func (a *AuthState) recordPolicyRelayDomains(ctx *gin.Context, triggered bool) {
	domain, present := usernameDomain(a.Request.Username)
	known := present && !triggered
	details := map[string]policycollection.DetailValue{}
	if domain != "" {
		details["domain"] = policycollection.InternalDetail(domain)
	}

	check := a.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: policy.CheckTypeRelayDomains,
		Stage:     policy.StagePreAuth,
		Name:      "relay_domains",
		ConfigRef: "auth.controls.relay_domains",
	})
	a.finishPolicyCheck(check, policyCheckResult{
		Matched:      triggered,
		DecisionHint: policyDecision(triggered, policy.DecisionDeny),
		Attributes: []policycollection.AttributeValue{
			policycollection.BoolAttribute(policy.AttributeRelayDomainPresent, policy.StagePreAuth, a.policyOperation(), present, details),
			policycollection.BoolAttribute(policy.AttributeRelayDomainKnown, policy.StagePreAuth, a.policyOperation(), known, details),
			policycollection.BoolAttribute(policy.AttributeRelayDomainError, policy.StagePreAuth, a.policyOperation(), false, nil),
		},
	})
}

func (a *AuthState) recordPolicyRBL(ctx *gin.Context, triggered bool, err error) {
	status := policy.CheckStatusOK
	reason := ""
	attributes := []policycollection.AttributeValue{
		policycollection.BoolAttribute(policy.AttributeRBLThresholdReached, policy.StagePreAuth, a.policyOperation(), triggered, nil),
	}

	if err != nil {
		status = policy.CheckStatusError
		reason = "rbl_error"
		attributes = append(attributes, policycollection.BoolAttribute(policy.AttributeRBLError, policy.StagePreAuth, a.policyOperation(), true, map[string]policycollection.DetailValue{
			"reason_code": policycollection.InternalDetail(reason),
			"retryable":   policycollection.InternalDetail(true),
		}))
	} else {
		attributes = append(attributes, policycollection.BoolAttribute(policy.AttributeRBLError, policy.StagePreAuth, a.policyOperation(), false, nil))
	}

	check := a.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: policy.CheckTypeRBL,
		Stage:     policy.StagePreAuth,
		Name:      "rbl",
		ConfigRef: "auth.controls.rbl",
	})
	a.finishPolicyCheck(check, policyCheckResult{
		Err:          err,
		Status:       status,
		Reason:       reason,
		Matched:      triggered || err != nil,
		DecisionHint: rblDecision(triggered, err),
		Attributes:   attributes,
	})
}

func (a *AuthState) recordPolicyBruteForce(ctx *gin.Context, triggered bool) {
	details := map[string]policycollection.DetailValue{}
	if a.Security.BruteForceName != "" {
		details["rule"] = policycollection.InternalDetail(a.Security.BruteForceName)
	}

	if a.Runtime.BFClientNet != "" {
		details["client_net"] = policycollection.InternalDetail(a.Runtime.BFClientNet)
	}

	details["repeating"] = policycollection.InternalDetail(a.Runtime.BFRepeating)

	check := a.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: policy.CheckTypeBruteForce,
		Stage:     policy.StagePreAuth,
		Name:      "brute_force",
		ConfigRef: "auth.controls.brute_force",
	})
	a.finishPolicyCheck(check, policyCheckResult{
		Matched:      triggered,
		DecisionHint: policyDecision(triggered, policy.DecisionDeny),
		Attributes: []policycollection.AttributeValue{
			policycollection.BoolAttribute(policy.AttributeBruteForceTriggered, policy.StagePreAuth, a.policyOperation(), triggered, details),
			policycollection.BoolAttribute(policy.AttributeBruteForceError, policy.StagePreAuth, a.policyOperation(), false, nil),
		},
	})
}

func (a *AuthState) recordPolicyBackendResult(ctx *gin.Context, authResult definitions.AuthResult, passDBResult *PassDBResult, err error) {
	checkType, name, configRef := backendPolicySelector(a.Runtime.UsedPassDBBackend, passDBResult)
	status := policy.CheckStatusOK
	reason := ""
	details := backendPolicyDetails(name)
	attributes := make([]policycollection.AttributeValue, 0, 3)

	if err != nil || authResult == definitions.AuthResultTempFail {
		status = policy.CheckStatusError
		reason = "backend_tempfail"
		attributes = append(attributes, policycollection.BoolAttribute(policy.AttributeBackendTempFail, policy.StageAuthBackend, a.policyOperation(), true, map[string]policycollection.DetailValue{
			"backend":     policycollection.InternalDetail(name),
			"reason_code": policycollection.InternalDetail(reason),
			"retryable":   policycollection.InternalDetail(true),
		}))
	} else {
		attributes = append(attributes, policycollection.BoolAttribute(policy.AttributeBackendTempFail, policy.StageAuthBackend, a.policyOperation(), false, details))
	}

	attributes = append(attributes, backendOutcomeAttributes(a, authResult, passDBResult, details)...)

	check := a.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: checkType,
		Stage:     policy.StageAuthBackend,
		Name:      name,
		ConfigRef: configRef,
	})
	a.finishPolicyCheck(check, policyCheckResult{
		Err:          err,
		Status:       status,
		Reason:       reason,
		Matched:      backendPolicyMatched(authResult, passDBResult, err),
		DecisionHint: backendPolicyDecision(authResult, err),
		Attributes:   attributes,
	})
}

func (a *AuthState) recordPolicyAccountProvider(ctx *gin.Context, count int, errSeen bool) {
	status := policy.CheckStatusOK
	reason := ""
	attributes := []policycollection.AttributeValue{
		policycollection.BoolAttribute(policy.AttributeAccountProviderCompleted, policy.StageAccountProvider, policy.OperationListAccounts, !errSeen, map[string]policycollection.DetailValue{
			"count": policycollection.InternalDetail(count),
		}),
	}

	if errSeen {
		status = policy.CheckStatusError
		reason = "account_provider_tempfail"
		attributes = append(attributes, policycollection.BoolAttribute(policy.AttributeAccountProviderTempFail, policy.StageAccountProvider, policy.OperationListAccounts, true, map[string]policycollection.DetailValue{
			"reason_code": policycollection.InternalDetail(reason),
			"retryable":   policycollection.InternalDetail(true),
		}))
	} else {
		attributes = append(attributes, policycollection.BoolAttribute(policy.AttributeAccountProviderTempFail, policy.StageAccountProvider, policy.OperationListAccounts, false, nil))
	}

	check := a.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: policy.CheckTypeAccountProvider,
		Stage:     policy.StageAccountProvider,
		Name:      "account_provider",
		ConfigRef: "auth.backends",
	})
	a.finishPolicyCheck(check, policyCheckResult{
		Status:       status,
		Reason:       reason,
		Matched:      true,
		DecisionHint: accountProviderDecision(errSeen),
		Attributes:   attributes,
	})
}

func usernameDomain(username string) (string, bool) {
	_, domain, ok := strings.Cut(username, "@")
	if !ok || domain == "" || strings.Contains(domain, "@") {
		return "", false
	}

	return domain, true
}

func policyDecision(matched bool, decision policy.Decision) policy.Decision {
	if matched {
		return decision
	}

	return policy.DecisionNeutral
}

func rblDecision(triggered bool, err error) policy.Decision {
	if err != nil {
		return policy.DecisionTempFail
	}

	return policyDecision(triggered, policy.DecisionDeny)
}

func accountProviderDecision(errSeen bool) policy.Decision {
	if errSeen {
		return policy.DecisionTempFail
	}

	return policy.DecisionPermit
}

func backendPolicySelector(runtimeBackend definitions.Backend, passDBResult *PassDBResult) (string, string, string) {
	backendType := runtimeBackend
	if passDBResult != nil && passDBResult.Backend != definitions.BackendUnknown {
		backendType = passDBResult.Backend
	}

	switch backendType {
	case definitions.BackendLua:
		return policy.CheckTypeLuaBackend, "lua_backend", "auth.backends.lua.backend"
	default:
		return policy.CheckTypeLDAPBackend, "ldap_backend", "auth.backends.ldap"
	}
}

func backendPolicyDetails(name string) map[string]policycollection.DetailValue {
	return map[string]policycollection.DetailValue{
		"backend": policycollection.InternalDetail(name),
	}
}

func backendOutcomeAttributes(
	auth *AuthState,
	authResult definitions.AuthResult,
	passDBResult *PassDBResult,
	details map[string]policycollection.DetailValue,
) []policycollection.AttributeValue {
	operation := auth.policyOperation()
	attributes := []policycollection.AttributeValue{
		policycollection.BoolAttribute(policy.AttributeBackendEmptyUsername, policy.StageAuthBackend, operation, authResult == definitions.AuthResultEmptyUsername, nil),
	}

	if operation == policy.OperationAuthenticate {
		authenticated := passDBResult != nil && passDBResult.Authenticated
		attributes = append(attributes,
			policycollection.BoolAttribute(policy.AttributeBackendEmptyPassword, policy.StageAuthBackend, operation, authResult == definitions.AuthResultEmptyPassword, nil),
			policycollection.BoolAttribute(policy.AttributeAuthenticated, policy.StageAuthBackend, operation, authenticated, details),
		)

		return attributes
	}

	found := passDBResult != nil && passDBResult.UserFound
	attributes = append(attributes, policycollection.BoolAttribute(policy.AttributeIdentityFound, policy.StageAuthBackend, operation, found, details))

	return attributes
}

func backendPolicyMatched(authResult definitions.AuthResult, passDBResult *PassDBResult, err error) bool {
	if err != nil {
		return true
	}

	if authResult == definitions.AuthResultEmptyUsername || authResult == definitions.AuthResultEmptyPassword || authResult == definitions.AuthResultTempFail {
		return true
	}

	return passDBResult != nil
}

func backendPolicyDecision(authResult definitions.AuthResult, err error) policy.Decision {
	if err != nil || authResult == definitions.AuthResultTempFail || authResult == definitions.AuthResultEmptyUsername {
		return policy.DecisionTempFail
	}

	if authResult == definitions.AuthResultEmptyPassword || authResult == definitions.AuthResultFail {
		return policy.DecisionDeny
	}

	if authResult == definitions.AuthResultOK {
		return policy.DecisionPermit
	}

	return policy.DecisionNeutral
}

func contextFromGin(ctx *gin.Context) context.Context {
	if ctx == nil || ctx.Request == nil {
		return context.Background()
	}

	return ctx.Request.Context()
}
