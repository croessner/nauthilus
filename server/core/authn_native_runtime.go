// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/policy"
	policycollection "github.com/croessner/nauthilus/v4/server/policy/collection"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// AuthnNativeCaptureInput selects request-owned projection without selecting a plugin component.
type AuthnNativeCaptureInput struct {
	Auth         *AuthState
	Capabilities []pluginapi.Capability
	Detached     bool
}

// AuthnNativeCapture owns the public request values prepared for one exact generation binding.
type AuthnNativeCapture struct {
	Runtime      pluginapi.RuntimeContext
	Credentials  pluginapi.CredentialProvider
	Snapshot     pluginapi.RequestSnapshot
	PasswordHash string
}

// AuthnNativeRuntime projects and applies request-owned public plugin values without component lookup.
type AuthnNativeRuntime interface {
	Capture(context.Context, AuthnNativeCaptureInput) (AuthnNativeCapture, error)
	ApplyRuntimeDelta(*AuthState, pluginapi.RuntimeDelta) error
}

type authnNativeObligationProgram interface {
	decisionservice.AuthnNativeEffectProgram
	ExecuteObligation(context.Context, pluginapi.ObligationRequest) (pluginapi.ObligationResult, error)
}

type authnNativePostActionProgram interface {
	decisionservice.AuthnNativeEffectProgram
	Capabilities() []pluginapi.Capability
	EnqueuePostAction(context.Context, pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error)
}

type authnNativePostActionWork struct {
	program authnNativePostActionProgram
	request pluginapi.PostActionRequest
	once    sync.Once
}

// ExecuteAuthnNativeObligation applies one exact selected generation-owned public obligation.
func (e *authnCandidateExecution) ExecuteAuthnNativeObligation(
	ctx context.Context,
	program decisionservice.AuthnNativeEffectProgram,
	execution policyruntime.EffectExecution,
) effectsupervisor.Result {
	owner, ok := program.(authnNativeObligationProgram)
	if !ok || e == nil || program == nil || program.ID() != execution.EffectID() ||
		execution.Provider() != execution.EffectID() {
		return effectsupervisor.Failed("authn_native_obligation_binding")
	}

	capture, err := e.captureAuthnNativeRequest(nil, false)
	if err != nil {
		return effectsupervisor.Failed("authn_native_obligation_capture")
	}

	request, err := authnNativeObligationRequest(capture, execution)
	if err != nil {
		return effectsupervisor.Failed("authn_native_obligation_request")
	}

	result, err := owner.ExecuteObligation(ctx, request)
	if err != nil {
		return effectsupervisor.Failed("authn_native_obligation_execute")
	}

	if err = e.applyAuthnNativeObligationResult(result); err != nil {
		return effectsupervisor.Failed("authn_native_obligation_result")
	}

	if result.Applied || !result.Temporary {
		return effectsupervisor.Succeeded()
	}

	return effectsupervisor.Failed("authn_native_obligation_temporary")
}

// PrepareAuthnNativePostAction captures one exact selected request before supervisor acceptance.
func (e *authnCandidateExecution) PrepareAuthnNativePostAction(
	_ context.Context,
	program decisionservice.AuthnNativeEffectProgram,
	execution policyruntime.EffectExecution,
) (effectsupervisor.Work, error) {
	owner, ok := program.(authnNativePostActionProgram)
	if !ok || e == nil || program == nil || program.ID() != execution.EffectID() ||
		execution.Provider() != execution.EffectID() {
		return nil, fmt.Errorf("authn native post-action binding is unavailable")
	}

	capture, err := e.captureAuthnNativeRequest(owner.Capabilities(), true)
	if err != nil {
		return nil, err
	}

	request, err := authnNativePostActionRequest(capture, execution)
	if err != nil {
		return nil, err
	}

	if err = effectsupervisor.ValidateBoundedValue(request, effectsupervisor.DefaultWorkBounds()); err != nil {
		return nil, err
	}

	return &authnNativePostActionWork{program: owner, request: request}, nil
}

// Validate confirms detached work has an exact immutable owner and public request capture.
func (w *authnNativePostActionWork) Validate() error {
	if w == nil || w.program == nil || w.request.Args == nil || w.request.Runtime == nil {
		return effectsupervisor.ErrInvalidWork
	}

	return nil
}

// Execute invokes the captured public post-action at most once.
func (w *authnNativePostActionWork) Execute(ctx context.Context) effectsupervisor.Result {
	if err := w.Validate(); err != nil {
		return effectsupervisor.Failed("authn_native_post_action_invalid")
	}

	result := effectsupervisor.Failed("authn_native_post_action_reused")

	w.once.Do(func() {
		response, err := w.program.EnqueuePostAction(ctx, w.request)
		switch {
		case err != nil && response.Enqueued:
			result = effectsupervisor.OutcomeUnknown("authn_native_post_action_ambiguous")
		case err != nil:
			result = effectsupervisor.Failed("authn_native_post_action_execute")
		case response.Enqueued || !response.Temporary:
			result = effectsupervisor.Succeeded()
		default:
			result = effectsupervisor.Failed("authn_native_post_action_temporary")
		}
	})

	return result
}

// Cleanup releases detached secret-bearing request owners after supervisor completion.
func (w *authnNativePostActionWork) Cleanup() {
	if w == nil {
		return
	}

	w.program = nil
	w.request = pluginapi.PostActionRequest{}
}

// authnNativeObligationRequest maps immutable selected parameters and facts.
func authnNativeObligationRequest(
	capture AuthnNativeCapture,
	execution policyruntime.EffectExecution,
) (pluginapi.ObligationRequest, error) {
	args, err := authnNativeEffectArgs(execution)
	if err != nil {
		return pluginapi.ObligationRequest{}, err
	}

	return pluginapi.ObligationRequest{
		Snapshot: capture.Snapshot, Runtime: capture.Runtime, Args: pluginregistry.NewArgsView(args),
		Facts: authnNativeEffectFacts(execution),
	}, nil
}

// authnNativePostActionRequest maps one fully detached public post-action request.
func authnNativePostActionRequest(
	capture AuthnNativeCapture,
	execution policyruntime.EffectExecution,
) (pluginapi.PostActionRequest, error) {
	args, err := authnNativeEffectArgs(execution)
	if err != nil {
		return pluginapi.PostActionRequest{}, err
	}

	return pluginapi.PostActionRequest{
		Snapshot: capture.Snapshot, Runtime: capture.Runtime, Credentials: capture.Credentials,
		PasswordHash: capture.PasswordHash, Args: pluginregistry.NewArgsView(args),
		Facts: authnNativeEffectFacts(execution),
	}, nil
}

// authnNativeEffectArgs converts strict selected parameters without aliases or coercion.
func authnNativeEffectArgs(execution policyruntime.EffectExecution) (map[string]any, error) {
	values := execution.Parameters().Values()

	result := make(map[string]any, len(values))
	for key, value := range values {
		projected, ok := value.Any()
		if !ok {
			return nil, fmt.Errorf("native authn effect parameter %q is invalid", key)
		}

		result[key] = projected
	}

	return result, nil
}

// authnNativeEffectFacts exposes only Lua/native facts from the exact selected decision.
func authnNativeEffectFacts(execution policyruntime.EffectExecution) []pluginapi.PolicyFact {
	facts := execution.Facts().Facts()

	result := make([]pluginapi.PolicyFact, 0, len(facts))
	for _, fact := range facts {
		source := fact.Provenance().Source()
		if source != decision.FactSourceLua && source != decision.FactSourcePlugin {
			continue
		}

		value, ok := fact.Value().Any()
		if !ok {
			continue
		}

		result = append(result, pluginapi.PolicyFact{Attribute: fact.ID(), Value: value})
	}

	return result
}

// applyAuthnNativeObligationResult applies synchronous public mutations to the live request only.
func (e *authnCandidateExecution) applyAuthnNativeObligationResult(result pluginapi.ObligationResult) error {
	policyCtx := e.auth.requestPolicyContext(e.ginCtx)
	if policyCtx == nil {
		return fmt.Errorf("authn Policy context is unavailable")
	}

	if err := recordAuthnNativeFacts(policyCtx, policy.StageAuthDecision, e.operation, result.Facts); err != nil {
		return err
	}

	applyAuthnNativeStatus(e.auth, result.Status)
	applyAuthnNativeLogs(e.auth, result.Logs)
	e.auth.ApplyPluginResponseMutation(e.ginCtx, result.Response)

	return e.auth.deps.NativeRuntime.ApplyRuntimeDelta(e.auth, result.RuntimeDelta)
}

// prepareNativeEnvironmentSource executes one exact session-yielded public environment source.
func (e *authnCandidateExecution) prepareNativeEnvironmentSource(
	providerID string,
	provider decisionservice.AuthnNativeEnvironmentProvider,
) (bool, error) {
	capture, err := e.captureAuthnNativeRequest(provider.Capabilities(), false)
	if err != nil {
		return false, err
	}

	result, callErr := provider.EvaluateEnvironment(e.ginCtx.Request.Context(), pluginapi.EnvironmentRequest{
		Snapshot: capture.Snapshot, Runtime: capture.Runtime, Credentials: capture.Credentials,
	})
	e.environmentRun = true

	if err = e.recordAuthnNativeEnvironmentResult(providerID, result, callErr); err != nil {
		return false, err
	}

	if callErr != nil {
		return false, callErr
	}

	if result.Triggered {
		e.auth.Runtime.EnvironmentName = providerID
		markEnvironmentRejected(e.ginCtx, true)
		e.preAuthResult = definitions.AuthResultFail

		return true, nil
	}

	if result.Abort {
		e.preAuthResult = definitions.AuthResultOK
	}

	return false, nil
}

// prepareNativeSubjectSource executes one exact session-yielded public subject source.
func (e *authnCandidateExecution) prepareNativeSubjectSource(
	providerID string,
	provider decisionservice.AuthnNativeSubjectProvider,
) (bool, error) {
	if e.backendResult == nil || !e.backendReady {
		return false, fmt.Errorf("generation-owned native subject provider has no backend result")
	}

	capture, err := e.captureAuthnNativeRequest(provider.Capabilities(), false)
	if err != nil {
		return false, err
	}

	result, callErr := provider.EvaluateSubject(e.ginCtx.Request.Context(), pluginapi.SubjectRequest{
		Snapshot: capture.Snapshot, Runtime: capture.Runtime,
		BackendResult: authnNativeBackendResult(e.backendResult), Credentials: capture.Credentials,
	})
	if err = e.recordAuthnNativeSubjectResult(providerID, result, callErr); err != nil {
		return false, err
	}

	if callErr != nil {
		return false, callErr
	}

	e.subjectReady = true

	e.finalReady = true
	if result.Rejected {
		e.auth.Runtime.Authorized = false
		e.auth.Runtime.Authenticated = false
		e.authResult = definitions.AuthResultFail
	} else if e.backendResult.Authenticated {
		e.auth.Runtime.Authorized = true
		e.authResult = definitions.AuthResultOK
	} else {
		e.auth.Runtime.Authorized = false
		e.authResult = definitions.AuthResultFail
	}

	e.finishTypedBackendProvider()

	return e.authResult != definitions.AuthResultOK && e.authResult != definitions.AuthResultUnset, nil
}

// captureAuthnNativeRequest projects values only after the exact provider has been selected.
func (e *authnCandidateExecution) captureAuthnNativeRequest(
	capabilities []pluginapi.Capability,
	detached bool,
) (AuthnNativeCapture, error) {
	if e == nil || e.auth == nil || e.ginCtx == nil || e.auth.deps.NativeRuntime == nil {
		return AuthnNativeCapture{}, fmt.Errorf("%w: authn native request runtime", ErrAuthApplicationDependencyMissing)
	}

	ctx := context.Background()
	if e.ginCtx.Request != nil {
		ctx = e.ginCtx.Request.Context()
	}

	return e.auth.deps.NativeRuntime.Capture(ctx, AuthnNativeCaptureInput{
		Auth: e.auth, Capabilities: append([]pluginapi.Capability(nil), capabilities...), Detached: detached,
	})
}

// recordAuthnNativeEnvironmentResult stores exact source evidence before checkpoint evaluation.
func (e *authnCandidateExecution) recordAuthnNativeEnvironmentResult(
	providerID string,
	result pluginapi.EnvironmentResult,
	callErr error,
) error {
	module, component, err := authnNativeSourceIdentity(providerID, "environment")
	if err != nil {
		return err
	}

	policyCtx := e.auth.requestPolicyContext(e.ginCtx)
	if policyCtx == nil {
		return fmt.Errorf("authn Policy context is unavailable")
	}

	details := authnNativeStatusDetails(result.Status)
	policyCtx.RecordAttributes([]policycollection.AttributeValue{
		policycollection.BoolAttribute(
			policy.PluginEnvironmentAttributeID(module, component, "triggered"),
			policy.StagePreAuth,
			e.operation,
			result.Triggered,
			details,
		),
		policycollection.BoolAttribute(
			policy.PluginEnvironmentAttributeID(module, component, "abort"),
			policy.StagePreAuth,
			e.operation,
			result.Abort,
			nil,
		),
		policycollection.BoolAttribute(
			policy.PluginEnvironmentAttributeID(module, component, "error"),
			policy.StagePreAuth,
			e.operation,
			callErr != nil,
			nil,
		),
	})

	if err = recordAuthnNativeFacts(policyCtx, policy.StagePreAuth, e.operation, result.Facts); err != nil {
		return err
	}

	applyAuthnNativeStatus(e.auth, result.Status)
	applyAuthnNativeLogs(e.auth, result.Logs)

	return e.auth.deps.NativeRuntime.ApplyRuntimeDelta(e.auth, result.RuntimeDelta)
}

// recordAuthnNativeSubjectResult applies one captured result before releasing backend state.
func (e *authnCandidateExecution) recordAuthnNativeSubjectResult(
	providerID string,
	result pluginapi.SubjectResult,
	callErr error,
) error {
	module, component, err := authnNativeSourceIdentity(providerID, "subject")
	if err != nil {
		return err
	}

	policyCtx := e.auth.requestPolicyContext(e.ginCtx)
	if policyCtx == nil {
		return fmt.Errorf("authn Policy context is unavailable")
	}

	policyCtx.RecordAttributes([]policycollection.AttributeValue{
		policycollection.BoolAttribute(
			policy.PluginSubjectAttributeID(module, component, "rejected"),
			policy.StageSubjectAnalysis,
			e.operation,
			result.Rejected,
			authnNativeStatusDetails(result.Status),
		),
		policycollection.BoolAttribute(
			policy.PluginSubjectAttributeID(module, component, "error"),
			policy.StageSubjectAnalysis,
			e.operation,
			callErr != nil,
			nil,
		),
	})

	if err = recordAuthnNativeFacts(policyCtx, policy.StageSubjectAnalysis, e.operation, result.Facts); err != nil {
		return err
	}

	applyAuthnNativeStatus(e.auth, result.Status)
	applyAuthnNativeLogs(e.auth, result.Logs)
	e.auth.ApplyPluginResponseMutation(e.ginCtx, result.Response)
	applyAuthnNativeAttributePatch(e.auth, e.backendResult, result.BackendAttributes)
	applyAuthnNativeBackendRef(e.auth, e.backendResult, result.SelectedBackend)

	if err = applyAuthnNativeBackendResultPatch(e.auth, e.backendResult, result.BackendResultPatch); err != nil {
		return err
	}

	return e.auth.deps.NativeRuntime.ApplyRuntimeDelta(e.auth, result.RuntimeDelta)
}

// authnNativeBackendResult maps the request-owned backend result to detached public values.
func authnNativeBackendResult(result *PassDBResult) pluginapi.BackendResult {
	if result == nil {
		return pluginapi.BackendResult{}
	}

	return pluginapi.BackendResult{
		Attributes: authnNativeAttributes(result.Attributes),
		Identity: pluginapi.BackendIdentityResult{
			UniqueUserIDField: result.UniqueUserIDField, DisplayNameField: result.DisplayNameField,
			TOTPSecretField: result.TOTPSecretField, TOTPRecoveryField: result.TOTPRecoveryField,
			Groups:                  append([]string(nil), result.Groups...),
			GroupDistinguishedNames: append([]string(nil), result.GroupDistinguishedNames...),
		},
		Account: result.Account, AccountField: result.AccountField,
		Authenticated: result.Authenticated, UserFound: result.UserFound,
		BackendServer: authnNativePublicBackendRef(result.BackendRef),
	}
}

// authnNativeAttributes projects string backend attributes without exposing mutable slices.
func authnNativeAttributes(attributes bktype.AttributeMapping) map[string][]string {
	if len(attributes) == 0 {
		return nil
	}

	result := make(map[string][]string, len(attributes))
	for key, values := range attributes {
		for _, value := range values {
			if text, ok := value.(string); ok {
				result[key] = append(result[key], text)
			}
		}
	}

	return result
}

// authnNativePublicBackendRef detaches one internal backend target reference.
func authnNativePublicBackendRef(ref RemoteBackendRef) *pluginapi.BackendServerRef {
	if ref.IsZero() {
		return nil
	}

	address, port := splitAuthnNativeBackendToken(ref.OpaqueToken)

	return &pluginapi.BackendServerRef{
		Name: ref.Name, Protocol: ref.Protocol, Authority: ref.Authority, Address: address, Port: port,
	}
}

// splitAuthnNativeBackendToken separates bounded host and port metadata.
func splitAuthnNativeBackendToken(token string) (string, string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", ""
	}

	if host, port, err := net.SplitHostPort(token); err == nil {
		return host, port
	}

	if strings.Count(token, ":") > 1 {
		return token, ""
	}

	host, port, found := strings.Cut(token, ":")
	if !found {
		return token, ""
	}

	return host, port
}

// applyAuthnNativeAttributePatch updates backend and request attributes together.
func applyAuthnNativeAttributePatch(auth *AuthState, result *PassDBResult, patch pluginapi.AttributePatch) {
	if auth == nil || result == nil {
		return
	}

	if result.Attributes == nil {
		result.Attributes = make(bktype.AttributeMapping)
	}

	for _, name := range patch.Delete {
		delete(result.Attributes, name)
		auth.DeleteAttribute(name)
	}

	for name, values := range patch.Set {
		converted := make([]any, len(values))
		for index, value := range values {
			converted[index] = value
		}

		result.Attributes[name] = converted
		auth.SetAttributeValues(name, converted)
	}
}

// applyAuthnNativeBackendResultPatch applies bounded subject-owned backend changes.
func applyAuthnNativeBackendResultPatch(
	auth *AuthState,
	result *PassDBResult,
	patch *pluginapi.BackendResultPatch,
) error {
	if patch == nil || result == nil {
		return nil
	}

	applyAuthnNativeAttributePatch(auth, result, patch.Attributes)

	if patch.AccountField != "" {
		if err := pluginapi.ValidateBackendAttributeName(patch.AccountField); err != nil {
			return err
		}

		result.AccountField = patch.AccountField
	}

	if patch.Account != "" {
		result.Account = patch.Account
		if result.AccountField != "" {
			values := []any{patch.Account}

			if result.Attributes == nil {
				result.Attributes = make(bktype.AttributeMapping)
			}

			result.Attributes[result.AccountField] = values
			auth.SetAttributeValues(result.AccountField, values)
		}
	}

	if patch.Authenticated != nil {
		result.Authenticated = *patch.Authenticated
		auth.Runtime.Authenticated = *patch.Authenticated
	}

	if patch.UserFound != nil {
		result.UserFound = *patch.UserFound
		auth.Runtime.UserFound = *patch.UserFound
	}

	applyAuthnNativeBackendRef(auth, result, patch.SelectedBackend)

	return nil
}

// applyAuthnNativeBackendRef records one selected public backend reference in request state.
func applyAuthnNativeBackendRef(auth *AuthState, result *PassDBResult, ref *pluginapi.BackendServerRef) {
	if ref == nil {
		return
	}

	token := ref.Address
	if ref.Address != "" && ref.Port != "" {
		token = net.JoinHostPort(ref.Address, ref.Port)
	} else if token == "" {
		token = ref.Port
	}

	mapped := RemoteBackendRef{
		Type: definitions.BackendPluginName, Name: ref.Name, Protocol: ref.Protocol,
		Authority: ref.Authority, OpaqueToken: token,
	}
	if result != nil {
		result.BackendRef = mapped
	}

	if auth == nil {
		return
	}

	auth.Runtime.RemoteBackendRef = mapped

	auth.Runtime.UsedBackendIP = ref.Address
	if port, err := strconv.Atoi(strings.TrimSpace(ref.Port)); err == nil {
		auth.Runtime.UsedBackendPort = port
	}
}

// authnNativeSourceIdentity parses only the frozen authn provider identity grammar.
func authnNativeSourceIdentity(providerID string, wantFamily string) (string, string, error) {
	local := strings.TrimPrefix(providerID, policy.AuthnNamespace+"/")

	module, family, component, ok := policyconfig.ParseAuthnPluginProviderLocal(local)
	if !ok || family != wantFamily {
		return "", "", fmt.Errorf("configured authn native provider %q has invalid identity", providerID)
	}

	return module, component, nil
}

// recordAuthnNativeFacts validates public values against the captured request registry.
func recordAuthnNativeFacts(
	policyCtx *policycollection.DecisionContext,
	stage policy.Stage,
	operation policy.Operation,
	facts []pluginapi.PolicyFact,
) error {
	for _, fact := range facts {
		attributeID := strings.TrimSpace(fact.Attribute)

		definition, ok := policyCtx.AttributeDefinition(attributeID)
		if attributeID == "" || !ok || definition.Source != policyregistry.SourcePlugin ||
			definition.Stage != stage || len(definition.Operations) > 0 && !containsAuthnNativeOperation(definition.Operations, operation) {
			return fmt.Errorf("native authn policy fact %q is outside the captured registry", attributeID)
		}

		value := normalizeAuthnNativeFactValue(fact.Value)
		if _, err := authnPolicyFactValue(definition.Type, value); err != nil {
			return fmt.Errorf("native authn policy fact %q: %w", attributeID, err)
		}

		policyCtx.RecordAttribute(policycollection.AttributeValue{
			ID: attributeID, Stage: stage, Operation: operation, Value: value,
		})
	}

	return nil
}

// containsAuthnNativeOperation checks one immutable operation allowlist.
func containsAuthnNativeOperation(operations []policy.Operation, operation policy.Operation) bool {
	for _, candidate := range operations {
		if candidate == operation {
			return true
		}
	}

	return false
}

// normalizeAuthnNativeFactValue accepts the public JSON-compatible list representation.
func normalizeAuthnNativeFactValue(value any) any {
	items, ok := value.([]any)
	if !ok {
		return value
	}

	stringsOnly := make([]string, 0, len(items))
	for _, item := range items {
		text, textOK := item.(string)
		if !textOK {
			return value
		}

		stringsOnly = append(stringsOnly, text)
	}

	return stringsOnly
}

// authnNativeStatusDetails exposes only the bounded public default message to Policy presentation.
func authnNativeStatusDetails(status *pluginapi.StatusMessage) map[string]policycollection.DetailValue {
	if status == nil || strings.TrimSpace(status.DefaultText) == "" {
		return nil
	}

	return map[string]policycollection.DetailValue{
		"status_message": policycollection.PublicMessageDetail(status.DefaultText),
	}
}

// applyAuthnNativeStatus updates the request-local response presentation fields.
func applyAuthnNativeStatus(auth *AuthState, status *pluginapi.StatusMessage) {
	if auth == nil || status == nil {
		return
	}

	if status.DefaultText != "" {
		auth.Runtime.StatusMessage = status.DefaultText
	}

	if status.MessageKey != "" {
		auth.Runtime.StatusMessageI18NKey = status.MessageKey
	}
}

// applyAuthnNativeLogs appends only explicit public structured fields to request-local logs.
func applyAuthnNativeLogs(auth *AuthState, fields []pluginapi.LogField) {
	if auth == nil {
		return
	}

	for _, field := range fields {
		if strings.TrimSpace(field.Key) == "" {
			continue
		}

		auth.Runtime.AdditionalLogs = append(auth.Runtime.AdditionalLogs, field.Key, field.Value)
	}
}
