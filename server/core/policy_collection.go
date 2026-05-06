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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	"github.com/croessner/nauthilus/server/policy/evaluation"
	"github.com/croessner/nauthilus/server/policy/observability"
	"github.com/croessner/nauthilus/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const (
	policyCollectionContextKey = "policy_collection"
	policyAttributeSuffixError = "error"
	policyDetailError          = "error"
)

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
	policyCtx := a.requestPolicyContext(ctx)
	if policyCtx == nil {
		return
	}

	policyCtx.CompleteStage(stage, a.policyAuthState())
	a.emitPolicyReport(ctx, policyCtx, stage)
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

func (a *AuthState) observeConfiguredPolicyDecision(ctx *gin.Context) {
	policyCtx := existingPolicyContext(ctx)
	if policyCtx == nil {
		return
	}

	mode, defaultPolicy, generation := policyCtx.SnapshotMetadata()
	result := evaluation.CompareCustomObserve(contextFromGin(ctx), policyCtx.Snapshot(), policyCtx.Report(), evaluation.CompareInput{
		Mode:       mode,
		Set:        defaultPolicy,
		Generation: generation,
		Recorder:   observability.DefaultRecorder(),
		Logger:     a.logger(),
		Surface:    a.policyResponseSurface(),
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
		"snapshot_generation", generation,
		"mismatch_type", result.MismatchType,
		"default_policy_name", result.Production.PolicyName,
		"custom_policy_name", result.Shadow.PolicyName,
		"default_effect", string(result.Production.Effect),
		"custom_effect", string(result.Shadow.Effect),
		"default_response_marker", result.Production.ResponseMarker,
		"custom_response_marker", result.Shadow.ResponseMarker,
		"default_fsm_event_marker", result.Production.FSMEventMarker,
		"custom_fsm_event_marker", result.Shadow.FSMEventMarker,
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

// PolicyDecisionContext returns the request-local policy collection context.
func (a *AuthState) PolicyDecisionContext(ctx *gin.Context) *policycollection.DecisionContext {
	return a.requestPolicyContext(ctx)
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
	fact := a.Runtime.RelayDomainPolicy
	if fact == (RelayDomainPolicyFact{}) {
		fact = a.relayDomainPolicyFact(a.handleMasterUserMode(), a.cfg().GetRelayDomains(), false)
		fact.Rejected = triggered
	}

	details := relayDomainPolicyDetails(fact)
	known := fact.Known || (fact.Present && !triggered && !fact.SoftAllowlisted)

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
			policycollection.BoolAttribute(policy.AttributeRelayDomainPresent, policy.StagePreAuth, a.policyOperation(), fact.Present, details),
			policycollection.BoolAttribute(policy.AttributeRelayDomainKnown, policy.StagePreAuth, a.policyOperation(), known, details),
			policycollection.StringAttributeWithDetails(policy.AttributeRelayDomainValue, policy.StagePreAuth, a.policyOperation(), fact.Value, details),
			policycollection.BoolAttribute(policy.AttributeRelayDomainRejected, policy.StagePreAuth, a.policyOperation(), fact.Rejected || triggered, details),
			policycollection.BoolAttribute(policy.AttributeRelayDomainStaticMatch, policy.StagePreAuth, a.policyOperation(), fact.StaticMatch, details),
			policycollection.BoolAttribute(policy.AttributeRelayDomainSoftAllowlisted, policy.StagePreAuth, a.policyOperation(), fact.SoftAllowlisted, details),
			policycollection.NumberAttribute(policy.AttributeRelayDomainConfiguredCount, policy.StagePreAuth, a.policyOperation(), float64(fact.ConfiguredCount), details),
			policycollection.BoolAttribute(policy.AttributeRelayDomainError, policy.StagePreAuth, a.policyOperation(), false, nil),
		},
	})
}

func relayDomainPolicyDetails(fact RelayDomainPolicyFact) map[string]policycollection.DetailValue {
	details := map[string]policycollection.DetailValue{
		"configured_count": policycollection.InternalDetail(float64(fact.ConfiguredCount)),
		"present":          policycollection.InternalDetail(fact.Present),
		"known":            policycollection.InternalDetail(fact.Known),
		"rejected":         policycollection.InternalDetail(fact.Rejected),
		"static_match":     policycollection.InternalDetail(fact.StaticMatch),
		"soft_allowlisted": policycollection.InternalDetail(fact.SoftAllowlisted),
	}

	if fact.Value != "" {
		details["domain"] = policycollection.InternalDetail(fact.Value)
	}

	if fact.MatchedDomain != "" {
		details["matched_domain"] = policycollection.InternalDetail(fact.MatchedDomain)
	}

	return details
}

func (a *AuthState) recordPolicyRBL(ctx *gin.Context, triggered bool, err error) {
	status := policy.CheckStatusOK
	reason := ""
	fact := a.Runtime.RBLPolicy
	if fact.Threshold == 0 {
		if rbls := a.cfg().GetRBLs(); rbls != nil {
			fact.Threshold = rbls.GetThreshold()
			fact.ListCount = len(rbls.GetLists())
		}
	}

	details := rblPolicyDetails(fact)
	attributes := []policycollection.AttributeValue{
		policycollection.BoolAttribute(policy.AttributeRBLThresholdReached, policy.StagePreAuth, a.policyOperation(), triggered, details),
		policycollection.NumberAttribute(policy.AttributeRBLScore, policy.StagePreAuth, a.policyOperation(), float64(fact.Score), details),
		policycollection.NumberAttribute(policy.AttributeRBLThreshold, policy.StagePreAuth, a.policyOperation(), float64(fact.Threshold), details),
		policycollection.NumberAttribute(policy.AttributeRBLMatchedCount, policy.StagePreAuth, a.policyOperation(), float64(fact.MatchedCount), details),
		policycollection.StringListAttribute(policy.AttributeRBLMatchedLists, policy.StagePreAuth, a.policyOperation(), fact.MatchedLists, details),
		policycollection.NumberAttribute(policy.AttributeRBLListCount, policy.StagePreAuth, a.policyOperation(), float64(fact.ListCount), details),
		policycollection.NumberAttribute(policy.AttributeRBLAllowFailureErrorCount, policy.StagePreAuth, a.policyOperation(), float64(fact.AllowFailureErrorCount), details),
		policycollection.BoolAttribute(policy.AttributeRBLEffectiveError, policy.StagePreAuth, a.policyOperation(), fact.EffectiveError || (err != nil), details),
		policycollection.BoolAttribute(policy.AttributeRBLSoftAllowlisted, policy.StagePreAuth, a.policyOperation(), fact.SoftAllowlisted, details),
		policycollection.BoolAttribute(policy.AttributeRBLIPAllowlisted, policy.StagePreAuth, a.policyOperation(), fact.IPAllowlisted, details),
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

	attributes = append(attributes, rblListPolicyAttributes(fact.Lists, a.policyOperation())...)

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

func rblPolicyDetails(fact RBLPolicyFact) map[string]policycollection.DetailValue {
	return map[string]policycollection.DetailValue{
		"lists":                     policycollection.InternalDetail(append([]string(nil), fact.MatchedLists...)),
		"score":                     policycollection.InternalDetail(float64(fact.Score)),
		"threshold":                 policycollection.InternalDetail(float64(fact.Threshold)),
		"matched_count":             policycollection.InternalDetail(float64(fact.MatchedCount)),
		"list_count":                policycollection.InternalDetail(float64(fact.ListCount)),
		"allow_failure_error_count": policycollection.InternalDetail(float64(fact.AllowFailureErrorCount)),
		"effective_error":           policycollection.InternalDetail(fact.EffectiveError),
		"soft_allowlisted":          policycollection.InternalDetail(fact.SoftAllowlisted),
		"ip_allowlisted":            policycollection.InternalDetail(fact.IPAllowlisted),
	}
}

func rblListPolicyAttributes(facts []RBLListPolicyFact, operation policy.Operation) []policycollection.AttributeValue {
	attributes := make([]policycollection.AttributeValue, 0, len(facts)*4)
	for i := range facts {
		fact := facts[i]
		identifier := policy.IdentifierSegment(fact.Name)
		details := rblListPolicyDetails(identifier, fact)
		stage := policy.StagePreAuth

		attributes = append(attributes,
			policycollection.BoolAttribute(policy.RBLListAttributeID(identifier, "listed"), stage, operation, fact.Listed, details),
			policycollection.NumberAttribute(policy.RBLListAttributeID(identifier, "weight"), stage, operation, float64(fact.Weight), details),
			policycollection.BoolAttribute(policy.RBLListAttributeID(identifier, policyAttributeSuffixError), stage, operation, fact.Error, details),
			policycollection.BoolAttribute(policy.RBLListAttributeID(identifier, "allow_failure"), stage, operation, fact.AllowFailure, details),
		)
	}

	return attributes
}

func rblListPolicyDetails(identifier string, fact RBLListPolicyFact) map[string]policycollection.DetailValue {
	details := map[string]policycollection.DetailValue{
		"list":            policycollection.InternalDetail(fact.Name),
		"list_id":         policycollection.InternalDetail(identifier),
		"host":            policycollection.InternalDetail(fact.Host),
		"listed":          policycollection.InternalDetail(fact.Listed),
		policyDetailError: policycollection.InternalDetail(fact.Error),
		"allow_failure":   policycollection.InternalDetail(fact.AllowFailure),
		"weight":          policycollection.InternalDetail(float64(fact.Weight)),
	}

	if fact.Query != "" {
		details["query"] = policycollection.InternalDetail(fact.Query)
	}

	if fact.ReturnCode != "" {
		details["return_code"] = policycollection.InternalDetail(fact.ReturnCode)
	}

	if fact.ReasonCode != "" {
		details["reason_code"] = policycollection.InternalDetail(fact.ReasonCode)
	}

	if fact.IPFamily != "" {
		details["ip_family"] = policycollection.InternalDetail(fact.IPFamily)
	}

	return details
}

func (a *AuthState) recordPolicyBruteForce(ctx *gin.Context, triggered bool) {
	operation := a.policyOperation()
	summary := summarizeBruteForceBucketFacts(a.Runtime.BruteForceBuckets)
	details := map[string]policycollection.DetailValue{}
	if a.Security.BruteForceName != "" {
		details["rule"] = policycollection.InternalDetail(a.Security.BruteForceName)
	}

	if a.Runtime.BFClientNet != "" {
		details["client_net"] = policycollection.InternalDetail(a.Runtime.BFClientNet)
	} else if summary.hasFact && summary.fact.ClientNet != "" {
		details["client_net"] = policycollection.InternalDetail(summary.fact.ClientNet)
	}

	if summary.hasFact {
		if a.Security.BruteForceName == "" {
			details["rule"] = policycollection.InternalDetail(summary.fact.Name)
		}

		details["bucket_id"] = policycollection.InternalDetail(policy.IdentifierSegment(summary.fact.Name))
		details["bucket_count"] = policycollection.InternalDetail(summary.fact.Count)
		details["bucket_ratio"] = policycollection.InternalDetail(summary.fact.Ratio)
		details["effective_limit"] = policycollection.InternalDetail(summary.fact.EffectiveLimit)
	}

	repeating := a.Runtime.BFRepeating || summary.repeating
	details["repeating"] = policycollection.InternalDetail(repeating)
	details["rwp_active"] = policycollection.InternalDetail(a.Runtime.BFRWP)
	addTolerationPolicyDetails(details, a.Runtime.BruteForceToleration)

	attributes := []policycollection.AttributeValue{
		policycollection.BoolAttribute(policy.AttributeBruteForceTriggered, policy.StagePreAuth, operation, triggered, details),
		policycollection.BoolAttribute(policy.AttributeBruteForceRepeating, policy.StagePreAuth, operation, repeating, details),
		policycollection.BoolAttribute(policy.AttributeBruteForceRWPActive, policy.StagePreAuth, operation, a.Runtime.BFRWP, details),
		policycollection.BoolAttribute(policy.AttributeBruteForceRWPEnforceBucketUpdate, policy.StagePreAuth, operation, !a.Runtime.BFRWP, details),
		policycollection.BoolAttribute(policy.AttributeBruteForceTolerationActive, policy.StagePreAuth, operation, a.Runtime.BruteForceToleration.Active, details),
		policycollection.StringAttributeWithDetails(policy.AttributeBruteForceTolerationMode, policy.StagePreAuth, operation, a.Runtime.BruteForceToleration.Mode, details),
		policycollection.BoolAttribute(policy.AttributeBruteForceTolerationCustom, policy.StagePreAuth, operation, a.Runtime.BruteForceToleration.Custom, details),
		policycollection.NumberAttribute(policy.AttributeBruteForceTolerationPositive, policy.StagePreAuth, operation, float64(a.Runtime.BruteForceToleration.Positive), details),
		policycollection.NumberAttribute(policy.AttributeBruteForceTolerationNegative, policy.StagePreAuth, operation, float64(a.Runtime.BruteForceToleration.Negative), details),
		policycollection.NumberAttribute(policy.AttributeBruteForceTolerationMaxNegative, policy.StagePreAuth, operation, float64(a.Runtime.BruteForceToleration.MaxNegative), details),
		policycollection.NumberAttribute(policy.AttributeBruteForceTolerationPercent, policy.StagePreAuth, operation, float64(a.Runtime.BruteForceToleration.Percent), details),
		policycollection.NumberAttribute(policy.AttributeBruteForceTolerationTTLSeconds, policy.StagePreAuth, operation, a.Runtime.BruteForceToleration.TTL.Seconds(), details),
		policycollection.BoolAttribute(policy.AttributeBruteForceTolerationSuppressedBlock, policy.StagePreAuth, operation, a.Runtime.BruteForceToleration.SuppressedBlock, details),
		policycollection.NumberAttribute(policy.AttributeBruteForceBucketMatchedCount, policy.StagePreAuth, operation, summary.matchedCount, details),
		policycollection.NumberAttribute(policy.AttributeBruteForceBucketTriggeredCount, policy.StagePreAuth, operation, summary.triggeredCount, details),
		policycollection.NumberAttribute(policy.AttributeBruteForceBucketMaxCount, policy.StagePreAuth, operation, summary.maxCount, details),
		policycollection.NumberAttribute(policy.AttributeBruteForceBucketMaxRatio, policy.StagePreAuth, operation, summary.maxRatio, details),
		policycollection.BoolAttribute(policy.AttributeBruteForceError, policy.StagePreAuth, operation, false, nil),
	}

	attributes = append(attributes, bruteForceBucketPolicyAttributes(a.Runtime.BruteForceBuckets, operation)...)

	check := a.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: policy.CheckTypeBruteForce,
		Stage:     policy.StagePreAuth,
		Name:      "brute_force",
		ConfigRef: "auth.controls.brute_force",
	})
	a.finishPolicyCheck(check, policyCheckResult{
		Matched:      triggered,
		DecisionHint: policyDecision(triggered, policy.DecisionDeny),
		Attributes:   attributes,
	})
}

func addTolerationPolicyDetails(details map[string]policycollection.DetailValue, fact tolerate.PolicyFact) {
	if details == nil {
		return
	}

	details["toleration_mode"] = policycollection.InternalDetail(fact.Mode)
	details["custom"] = policycollection.InternalDetail(fact.Custom)
	details["active"] = policycollection.InternalDetail(fact.Active)
	details["suppressed_block"] = policycollection.InternalDetail(fact.SuppressedBlock)
	details["positive"] = policycollection.InternalDetail(float64(fact.Positive))
	details["negative"] = policycollection.InternalDetail(float64(fact.Negative))
	details["max_negative"] = policycollection.InternalDetail(float64(fact.MaxNegative))
	details["percent"] = policycollection.InternalDetail(float64(fact.Percent))
	details["ttl_seconds"] = policycollection.InternalDetail(fact.TTL.Seconds())
}

type bruteForceBucketSummary struct {
	fact           bruteforce.BucketPolicyFact
	matchedCount   float64
	triggeredCount float64
	maxCount       float64
	maxRatio       float64
	hasFact        bool
	repeating      bool
}

func summarizeBruteForceBucketFacts(facts []bruteforce.BucketPolicyFact) bruteForceBucketSummary {
	var summary bruteForceBucketSummary

	for i := range facts {
		fact := facts[i]
		if fact.Matched {
			summary.matchedCount++
		}

		if fact.OverLimit || fact.AlreadyBanned {
			summary.triggeredCount++
		}

		if fact.Repeating {
			summary.repeating = true
		}

		if !fact.Matched {
			continue
		}

		if !summary.hasFact || fact.Ratio > summary.maxRatio || (fact.Ratio == summary.maxRatio && fact.Count > summary.maxCount) {
			summary.fact = fact
			summary.maxCount = fact.Count
			summary.maxRatio = fact.Ratio
			summary.hasFact = true
		}
	}

	return summary
}

func bruteForceBucketPolicyAttributes(
	facts []bruteforce.BucketPolicyFact,
	operation policy.Operation,
) []policycollection.AttributeValue {
	attributes := make([]policycollection.AttributeValue, 0, len(facts)*9)

	for i := range facts {
		fact := facts[i]
		identifier := policy.IdentifierSegment(fact.Name)
		details := bruteForceBucketPolicyDetails(identifier, fact)
		stage := policy.StagePreAuth

		attributes = append(attributes,
			policycollection.BoolAttribute(policy.BruteForceBucketAttributeID(identifier, "matched"), stage, operation, fact.Matched, details),
			policycollection.NumberAttribute(policy.BruteForceBucketAttributeID(identifier, "count"), stage, operation, fact.Count, details),
			policycollection.NumberAttribute(policy.BruteForceBucketAttributeID(identifier, "limit"), stage, operation, fact.Limit, details),
			policycollection.NumberAttribute(policy.BruteForceBucketAttributeID(identifier, "effective_limit"), stage, operation, fact.EffectiveLimit, details),
			policycollection.NumberAttribute(policy.BruteForceBucketAttributeID(identifier, "remaining"), stage, operation, fact.Remaining, details),
			policycollection.NumberAttribute(policy.BruteForceBucketAttributeID(identifier, "ratio"), stage, operation, fact.Ratio, details),
			policycollection.BoolAttribute(policy.BruteForceBucketAttributeID(identifier, "over_limit"), stage, operation, fact.OverLimit, details),
			policycollection.BoolAttribute(policy.BruteForceBucketAttributeID(identifier, "already_banned"), stage, operation, fact.AlreadyBanned, details),
			policycollection.BoolAttribute(policy.BruteForceBucketAttributeID(identifier, "repeating"), stage, operation, fact.Repeating, details),
		)
	}

	return attributes
}

func bruteForceBucketPolicyDetails(identifier string, fact bruteforce.BucketPolicyFact) map[string]policycollection.DetailValue {
	details := map[string]policycollection.DetailValue{
		"rule":             policycollection.InternalDetail(fact.Name),
		"bucket_id":        policycollection.InternalDetail(identifier),
		"matched":          policycollection.InternalDetail(fact.Matched),
		"over_limit":       policycollection.InternalDetail(fact.OverLimit),
		"already_banned":   policycollection.InternalDetail(fact.AlreadyBanned),
		"repeating":        policycollection.InternalDetail(fact.Repeating),
		"limit":            policycollection.InternalDetail(fact.Limit),
		"effective_limit":  policycollection.InternalDetail(fact.EffectiveLimit),
		"remaining":        policycollection.InternalDetail(fact.Remaining),
		"ratio":            policycollection.InternalDetail(fact.Ratio),
		"period_seconds":   policycollection.InternalDetail(fact.Period.Seconds()),
		"ban_time_seconds": policycollection.InternalDetail(fact.BanTime.Seconds()),
		"cidr":             policycollection.InternalDetail(float64(fact.CIDR)),
	}

	if fact.ClientNet != "" {
		details["client_net"] = policycollection.InternalDetail(fact.ClientNet)
	}

	return details
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
	attributes = append(attributes, subjectAttributePolicyAttributes(a, passDBResult)...)

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

type authPolicyConfigProvider interface {
	GetAuthPolicy() config.AuthPolicySection
}

func subjectAttributePolicyAttributes(
	auth *AuthState,
	passDBResult *PassDBResult,
) []policycollection.AttributeValue {
	if auth == nil {
		return nil
	}

	exports := auth.policyAttributeExports()
	if len(exports) == 0 {
		return nil
	}

	source := auth.GetAttributesCopy()
	if passDBResult != nil && len(passDBResult.Attributes) > 0 {
		source = passDBResult.Attributes.Clone()
	}

	operation := auth.policyOperation()
	attributes := make([]policycollection.AttributeValue, 0, len(exports))
	for _, exportConfig := range exports {
		attributes = append(attributes, subjectAttributePolicyAttribute(exportConfig, source, operation))
	}

	return attributes
}

func (a *AuthState) policyAttributeExports() []config.PolicyAttributeExportConfig {
	if a == nil || a.cfg() == nil {
		return nil
	}

	provider, ok := a.cfg().(authPolicyConfigProvider)
	if !ok {
		return nil
	}

	policyConfig := provider.GetAuthPolicy()

	return policyConfig.AttributeExports
}

func subjectAttributePolicyAttribute(
	exportConfig config.PolicyAttributeExportConfig,
	source bktype.AttributeMapping,
	operation policy.Operation,
) policycollection.AttributeValue {
	identifier := policy.IdentifierSegment(exportConfig.Name)
	values, present := source[exportConfig.Attribute]
	details := subjectAttributePolicyDetails(exportConfig, values, present)

	return policycollection.BoolAttribute(
		policy.SubjectAttributeID(identifier),
		policy.StageAuthBackend,
		operation,
		present && len(values) > 0,
		details,
	)
}

func subjectAttributePolicyDetails(
	exportConfig config.PolicyAttributeExportConfig,
	values []any,
	present bool,
) map[string]policycollection.DetailValue {
	sensitivity := policyDetailSensitivity(exportConfig.Sensitivity)
	details := map[string]policycollection.DetailValue{
		"attribute": policycollection.InternalDetail(exportConfig.Attribute),
		"count":     policycollection.InternalDetail(float64(len(values))),
	}

	if !present || len(values) == 0 {
		return details
	}

	switch strings.TrimSpace(exportConfig.Type) {
	case "bool":
		if value, ok := boolPolicyValue(values[0]); ok {
			details["value"] = sensitivePolicyDetail(value, sensitivity)
		}
	case "number":
		if value, ok := numberPolicyValue(values[0]); ok {
			details["value"] = sensitivePolicyDetail(value, sensitivity)
		}
	case "string_list":
		details["values"] = sensitivePolicyDetail(stringPolicyValues(values), sensitivity)
	default:
		details["value"] = sensitivePolicyDetail(stringPolicyValue(values[0]), sensitivity)
	}

	return details
}

func policyDetailSensitivity(value string) report.Sensitivity {
	switch strings.TrimSpace(value) {
	case string(report.SensitivityPublic):
		return report.SensitivityPublic
	case string(report.SensitivitySecret):
		return report.SensitivitySecret
	default:
		return report.SensitivityInternal
	}
}

func sensitivePolicyDetail(value any, sensitivity report.Sensitivity) policycollection.DetailValue {
	return policycollection.DetailValue{Value: value, Sensitivity: sensitivity}
}

func boolPolicyValue(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))

		return parsed, err == nil
	default:
		number, ok := numberPolicyValue(value)

		return number != 0, ok
	}
}

func numberPolicyValue(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)

		return parsed, err == nil
	default:
		return 0, false
	}
}

func stringPolicyValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}

func stringPolicyValues(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, stringPolicyValue(value))
	}

	return result
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
