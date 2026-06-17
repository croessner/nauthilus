// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"slices"
	"strings"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	servererrors "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/pluginregistry"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	pluginBackendAccountField           = "account"
	pluginBackendStatusCodeAttribute    = "plugin_status_code"
	pluginBackendStatusTextAttribute    = "plugin_status_text"
	pluginBackendStatusMessageAttribute = "plugin_status_message_key"
)

var (
	_ core.BackendManager           = (*BackendManager)(nil)
	_ core.PublicMFAStateProvider   = (*BackendManager)(nil)
	_ core.RemoteMFAOperations      = (*BackendManager)(nil)
	_ core.TOTPRecoveryCodeConsumer = (*BackendManager)(nil)
)

func init() {
	core.RegisterBackendManagerFactory(definitions.BackendPlugin, NewBackendManager)
}

// BackendManager adapts one native plugin backend into the internal backend contract.
type BackendManager struct {
	runner        *Runner
	deps          core.AuthDeps
	qualifiedName string
}

// NewBackendManager constructs a backend manager for a fully qualified plugin backend.
func NewBackendManager(backendName string, deps core.AuthDeps) core.BackendManager {
	runner, _ := DefaultRunner()

	return &BackendManager{
		runner:        runner,
		deps:          deps,
		qualifiedName: backendName,
	}
}

// PassDB authenticates a user through one native plugin backend.
func (m *BackendManager) PassDB(auth *core.AuthState) (*core.PassDBResult, error) {
	if auth == nil {
		return nil, servererrors.ErrNoPassDBResult
	}

	ctx, request, err := m.backendAuthRequest(auth)
	if err != nil {
		return nil, err
	}

	result, err := m.runner.VerifyPassword(ctx, m.qualifiedName, request)
	if err != nil {
		return nil, m.temporaryError()
	}

	applyPluginStatus(auth, result.Status)

	if result.Status != nil && result.Status.Temporary {
		return nil, m.temporaryError()
	}

	return m.passDBResult(auth, result)
}

// AccountDB lists accounts through one native plugin backend.
func (m *BackendManager) AccountDB(auth *core.AuthState) (core.AccountList, error) {
	if auth == nil {
		return nil, servererrors.ErrNoPassDBResult
	}

	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return nil, err
	}

	result, err := m.runner.ListAccounts(ctx, m.qualifiedName, pluginapi.AccountListRequest{
		Snapshot: snapshot,
		Runtime:  runtimeContext,
		Username: auth.GetUsername(),
	})
	if err != nil {
		return nil, m.temporaryError()
	}

	applyPluginStatus(auth, result.Status)

	if result.Status != nil && result.Status.Temporary {
		return nil, m.temporaryError()
	}

	facts, err := validatePluginPolicyFacts(result.Facts)
	if err != nil {
		return nil, m.temporaryError()
	}

	if len(facts) > 0 {
		auth.Runtime.AccountProviderPluginFacts = append(auth.Runtime.AccountProviderPluginFacts, facts...)
	}

	return core.AccountList(slices.Clone(result.Accounts)), nil
}

// AddTOTPSecret rejects edge-selected TOTP secrets; plugin-owned registration must use Begin/FinishTOTPRegistration.
func (m *BackendManager) AddTOTPSecret(*core.AuthState, *mfa.TOTPSecret) error {
	return servererrors.ErrUnknownDatabaseBackend
}

// DeleteTOTPSecret deletes TOTP state when the plugin implements TOTPBackend.
func (m *BackendManager) DeleteTOTPSecret(auth *core.AuthState) error {
	return m.DeleteTOTP(auth, m.idempotencyKey(auth, "delete-totp"))
}

// AddTOTPRecoveryCodes rejects edge-selected recovery-code values; plugin-owned generation must be used.
func (m *BackendManager) AddTOTPRecoveryCodes(*core.AuthState, *mfa.TOTPRecovery) error {
	return servererrors.ErrUnknownDatabaseBackend
}

// DeleteTOTPRecoveryCodes deletes recovery-code state when the plugin implements RecoveryCodeBackend.
func (m *BackendManager) DeleteTOTPRecoveryCodes(auth *core.AuthState) error {
	return m.DeleteRecoveryCodes(auth, m.idempotencyKey(auth, "delete-recovery"))
}

// BeginTOTPRegistration starts a plugin-owned TOTP registration flow.
func (m *BackendManager) BeginTOTPRegistration(auth *core.AuthState, idempotencyKey string) (core.TOTPRegistration, error) {
	if idempotencyKey == "" {
		return core.TOTPRegistration{}, servererrors.ErrUnknownDatabaseBackend
	}

	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return core.TOTPRegistration{}, err
	}

	result, err := invokeTypedComponent(ctx, m.runner, m.qualifiedName, pluginregistry.ComponentKindBackend, "BeginTOTP", func(callCtx context.Context, backend pluginapi.TOTPBackend) (pluginapi.TOTPBeginResult, error) {
		return backend.BeginTOTP(callCtx, pluginapi.TOTPBeginRequest{
			Snapshot:       snapshot,
			Runtime:        runtimeContext,
			IdempotencyKey: idempotencyKey,
			Username:       usernameFromAuth(auth),
		})
	})
	if err != nil {
		return core.TOTPRegistration{}, m.mapOptionalError(err)
	}

	applyPluginStatus(auth, result.Status)
	applyPluginBackendServerRef(auth, result.BackendServer)

	return core.TOTPRegistration{
		ExpiresAt:             result.ExpiresAt,
		PendingRegistrationID: result.PendingRegistrationID,
		OTPAuthURL:            result.OTPAuthURL,
	}, nil
}

// FinishTOTPRegistration completes a plugin-owned TOTP registration flow.
func (m *BackendManager) FinishTOTPRegistration(
	auth *core.AuthState,
	pendingRegistrationID string,
	code string,
	idempotencyKey string,
) error {
	if idempotencyKey == "" {
		return servererrors.ErrUnknownDatabaseBackend
	}

	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return err
	}

	result, err := invokeTypedComponent(ctx, m.runner, m.qualifiedName, pluginregistry.ComponentKindBackend, "FinishTOTP", func(callCtx context.Context, backend pluginapi.TOTPBackend) (pluginapi.TOTPFinishResult, error) {
		return backend.FinishTOTP(callCtx, pluginapi.TOTPFinishRequest{
			Snapshot:              snapshot,
			Runtime:               runtimeContext,
			IdempotencyKey:        idempotencyKey,
			Username:              usernameFromAuth(auth),
			PendingRegistrationID: pendingRegistrationID,
			Code:                  code,
		})
	})
	if err != nil {
		return m.mapOptionalError(err)
	}

	applyPluginStatus(auth, result.Status)
	applyPluginBackendServerRef(auth, result.BackendServer)

	if !result.Verified {
		return servererrors.ErrTOTPCodeInvalid
	}

	return nil
}

// VerifyTOTP verifies a code when the plugin implements TOTPBackend.
func (m *BackendManager) VerifyTOTP(auth *core.AuthState, code string) (bool, error) {
	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return false, err
	}

	result, err := invokeTypedComponent(ctx, m.runner, m.qualifiedName, pluginregistry.ComponentKindBackend, "VerifyTOTP", func(callCtx context.Context, backend pluginapi.TOTPBackend) (pluginapi.TOTPVerifyResult, error) {
		return backend.VerifyTOTP(callCtx, pluginapi.TOTPVerifyRequest{
			Snapshot: snapshot,
			Runtime:  runtimeContext,
			Username: usernameFromAuth(auth),
			Code:     code,
		})
	})
	if err != nil {
		return false, m.mapOptionalError(err)
	}

	applyPluginStatus(auth, result.Status)
	applyPluginBackendServerRef(auth, result.BackendServer)

	return result.Verified, nil
}

// DeleteTOTP removes TOTP state when the plugin implements TOTPBackend.
func (m *BackendManager) DeleteTOTP(auth *core.AuthState, idempotencyKey string) error {
	return m.deletePluginMFAState(auth, idempotencyKey, "DeleteTOTP", m.invokeDeleteTOTP)
}

// GenerateRecoveryCodes asks a plugin backend to create recovery codes.
func (m *BackendManager) GenerateRecoveryCodes(auth *core.AuthState, count uint32, idempotencyKey string) ([]string, error) {
	if idempotencyKey == "" {
		return nil, servererrors.ErrUnknownDatabaseBackend
	}

	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return nil, err
	}

	result, err := invokeTypedComponent(ctx, m.runner, m.qualifiedName, pluginregistry.ComponentKindBackend, "GenerateRecoveryCodes", func(callCtx context.Context, backend pluginapi.RecoveryCodeBackend) (pluginapi.RecoveryCodeGenerateResult, error) {
		return backend.GenerateRecoveryCodes(callCtx, pluginapi.RecoveryCodeGenerateRequest{
			Snapshot:       snapshot,
			Runtime:        runtimeContext,
			IdempotencyKey: idempotencyKey,
			Username:       usernameFromAuth(auth),
			Count:          count,
		})
	})
	if err != nil {
		return nil, m.mapOptionalError(err)
	}

	applyPluginStatus(auth, result.Status)
	applyPluginBackendServerRef(auth, result.BackendServer)

	return slices.Clone(result.Codes), nil
}

// UseRecoveryCode consumes a recovery code when the plugin implements RecoveryCodeBackend.
func (m *BackendManager) UseRecoveryCode(auth *core.AuthState, code string, idempotencyKey string) (bool, error) {
	valid, _, err := m.consumeRecoveryCode(auth, code, idempotencyKey)

	return valid, err
}

// ConsumeTOTPRecoveryCode consumes one recovery code and returns the remaining count when available.
func (m *BackendManager) ConsumeTOTPRecoveryCode(auth *core.AuthState, code string) (bool, int, error) {
	return m.consumeRecoveryCode(auth, code, m.idempotencyKey(auth, "use-recovery"))
}

// DeleteRecoveryCodes removes recovery-code state when the plugin implements RecoveryCodeBackend.
func (m *BackendManager) DeleteRecoveryCodes(auth *core.AuthState, idempotencyKey string) error {
	return m.deletePluginMFAState(auth, idempotencyKey, "DeleteRecoveryCodes", m.invokeDeleteRecoveryCodes)
}

// GetPublicMFAState loads public MFA state when the plugin implements PublicMFAStateBackend.
func (m *BackendManager) GetPublicMFAState(auth *core.AuthState, includeWebAuthn bool) (core.PublicMFAState, error) {
	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return core.PublicMFAState{}, err
	}

	result, err := invokeTypedComponent(ctx, m.runner, m.qualifiedName, pluginregistry.ComponentKindBackend, "PublicMFAState", func(callCtx context.Context, backend pluginapi.PublicMFAStateBackend) (pluginapi.PublicMFAStateResult, error) {
		return backend.PublicMFAState(callCtx, pluginapi.PublicMFAStateRequest{
			Snapshot:        snapshot,
			Runtime:         runtimeContext,
			Username:        usernameFromAuth(auth),
			IncludeWebAuthn: includeWebAuthn,
		})
	})
	if err != nil {
		return core.PublicMFAState{}, m.mapOptionalError(err)
	}

	applyPluginStatus(auth, result.Status)
	applyPluginBackendServerRef(auth, result.BackendServer)

	return core.PublicMFAState{
		WebAuthnCredentials: webAuthnCredentialsFromPlugin(result.WebAuthnCredentials),
		RecoveryCodeCount:   result.RecoveryCodeCount,
		HasTOTP:             result.HasTOTP,
		HasWebAuthn:         result.HasWebAuthn,
	}, nil
}

// GetWebAuthnCredentials retrieves WebAuthn credentials when the plugin implements WebAuthnBackend.
func (m *BackendManager) GetWebAuthnCredentials(auth *core.AuthState) ([]mfa.PersistentCredential, error) {
	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return nil, err
	}

	result, err := invokeTypedComponent(ctx, m.runner, m.qualifiedName, pluginregistry.ComponentKindBackend, "ListWebAuthnCredentials", func(callCtx context.Context, backend pluginapi.WebAuthnBackend) (pluginapi.WebAuthnListResult, error) {
		return backend.ListWebAuthnCredentials(callCtx, pluginapi.WebAuthnListRequest{
			Snapshot: snapshot,
			Runtime:  runtimeContext,
			Username: usernameFromAuth(auth),
		})
	})
	if err != nil {
		return nil, m.mapOptionalError(err)
	}

	applyPluginStatus(auth, result.Status)
	applyPluginBackendServerRef(auth, result.BackendServer)

	return webAuthnCredentialsFromPlugin(result.Credentials), nil
}

// SaveWebAuthnCredential saves one WebAuthn credential when the plugin implements WebAuthnBackend.
func (m *BackendManager) SaveWebAuthnCredential(auth *core.AuthState, credential *mfa.PersistentCredential) error {
	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return err
	}

	err = invokeOptionalBackend(ctx, m.runner, m.qualifiedName, "SaveWebAuthnCredential", func(callCtx context.Context, backend pluginapi.WebAuthnBackend) error {
		return backend.SaveWebAuthnCredential(callCtx, pluginapi.WebAuthnSaveRequest{
			Snapshot:   snapshot,
			Runtime:    runtimeContext,
			Username:   usernameFromAuth(auth),
			Credential: webAuthnCredentialToPlugin(credential),
		})
	})
	if err != nil {
		return m.mapOptionalError(err)
	}

	return nil
}

// DeleteWebAuthnCredential deletes one WebAuthn credential when the plugin implements WebAuthnBackend.
func (m *BackendManager) DeleteWebAuthnCredential(auth *core.AuthState, credential *mfa.PersistentCredential) error {
	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return err
	}

	var credentialID []byte
	if credential != nil {
		credentialID = append([]byte(nil), credential.ID...)
	}

	err = invokeOptionalBackend(ctx, m.runner, m.qualifiedName, "DeleteWebAuthnCredential", func(callCtx context.Context, backend pluginapi.WebAuthnBackend) error {
		return backend.DeleteWebAuthnCredential(callCtx, pluginapi.WebAuthnDeleteRequest{
			Snapshot:     snapshot,
			Runtime:      runtimeContext,
			Username:     usernameFromAuth(auth),
			CredentialID: credentialID,
		})
	})
	if err != nil {
		return m.mapOptionalError(err)
	}

	return nil
}

// UpdateWebAuthnCredential updates one WebAuthn credential when the plugin implements WebAuthnBackend.
func (m *BackendManager) UpdateWebAuthnCredential(
	auth *core.AuthState,
	oldCredential *mfa.PersistentCredential,
	newCredential *mfa.PersistentCredential,
) error {
	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return err
	}

	err = invokeOptionalBackend(ctx, m.runner, m.qualifiedName, "UpdateWebAuthnCredential", func(callCtx context.Context, backend pluginapi.WebAuthnBackend) error {
		return backend.UpdateWebAuthnCredential(callCtx, pluginapi.WebAuthnUpdateRequest{
			Snapshot:      snapshot,
			Runtime:       runtimeContext,
			Username:      usernameFromAuth(auth),
			OldCredential: webAuthnCredentialToPlugin(oldCredential),
			NewCredential: webAuthnCredentialToPlugin(newCredential),
		})
	})
	if err != nil {
		return m.mapOptionalError(err)
	}

	return nil
}

// backendAuthRequest constructs a credential-gated password verification request.
func (m *BackendManager) backendAuthRequest(auth *core.AuthState) (context.Context, pluginapi.BackendAuthRequest, error) {
	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return nil, pluginapi.BackendAuthRequest{}, err
	}

	moduleName, err := moduleNameFromQualified(m.qualifiedName)
	if err != nil {
		return nil, pluginapi.BackendAuthRequest{}, m.temporaryError()
	}

	return ctx, pluginapi.BackendAuthRequest{
		Snapshot:    snapshot,
		Runtime:     runtimeContext,
		Credentials: NewCredentialProvider(ctx, auth.GetPassword(), m.runner.ModuleCapabilities(moduleName)),
		Username:    auth.GetUsername(),
	}, nil
}

// requestContext creates the common plugin request context and immutable runtime view.
func (m *BackendManager) requestContext(auth *core.AuthState) (context.Context, pluginapi.RequestSnapshot, pluginapi.RuntimeContext, error) {
	if m == nil || m.runner == nil || !m.runner.Ready() {
		return nil, pluginapi.RequestSnapshot{}, nil, m.temporaryError()
	}

	if auth == nil {
		return nil, pluginapi.RequestSnapshot{}, nil, servererrors.ErrNoPassDBResult
	}

	runtimeValues := map[string]any{}
	if auth.Runtime.Context != nil {
		runtimeValues = auth.Runtime.Context.Snapshot()
	}

	runtimeContext, err := NewRuntimeContext(runtimeValues)
	if err != nil {
		return nil, pluginapi.RequestSnapshot{}, nil, m.temporaryError()
	}

	return auth.Ctx(), NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg())), runtimeContext, nil
}

// passDBResult maps a plugin backend result into the internal PassDBResult model.
func (m *BackendManager) passDBResult(auth *core.AuthState, result pluginapi.BackendResult) (*core.PassDBResult, error) {
	facts, err := validatePluginPolicyFacts(result.Facts)
	if err != nil {
		return nil, m.temporaryError()
	}

	passDBResult := core.GetPassDBResultFromPool()
	passDBResult.Authenticated = result.Authenticated
	passDBResult.UserFound = result.UserFound
	passDBResult.Account = result.Account
	passDBResult.Backend = definitions.BackendPlugin
	passDBResult.BackendName = m.qualifiedName
	passDBResult.BackendRef = pluginBackendServerRef(result.BackendServer)
	passDBResult.Attributes = pluginAttributeMapping(result.Attributes)
	passDBResult.AdditionalAttributes = pluginAdditionalAttributes(result.Status, facts)

	if passDBResult.Account != "" {
		passDBResult.AccountField = pluginBackendAccountField
		if _, ok := passDBResult.Attributes[pluginBackendAccountField]; !ok {
			passDBResult.Attributes[pluginBackendAccountField] = []any{passDBResult.Account}
		}
	}

	applyPluginBackendServerRef(auth, result.BackendServer)

	return passDBResult, nil
}

// temporaryError returns a secret-safe temporary backend failure.
func (m *BackendManager) temporaryError() error {
	name := ""
	if m != nil {
		name = m.qualifiedName
	}

	return servererrors.ErrBackendTemporaryFailure.WithDetail(fmt.Sprintf("plugin backend %q could not complete the request", name))
}

// mapOptionalError maps optional-interface errors without exposing plugin panic details.
func (m *BackendManager) mapOptionalError(err error) error {
	if err == nil {
		return nil
	}

	if stderrors.Is(err, ErrComponentKindMismatch) {
		return servererrors.ErrUnknownDatabaseBackend
	}

	return m.temporaryError()
}

type pluginMFADeleteRequest struct {
	snapshot       pluginapi.RequestSnapshot
	runtime        pluginapi.RuntimeContext
	idempotencyKey string
	username       string
}

type pluginMFADeleteFields struct {
	Snapshot       pluginapi.RequestSnapshot
	Runtime        pluginapi.RuntimeContext
	IdempotencyKey string
	Username       string
}

// fields returns the public delete request fields shared by MFA delete APIs.
func (r pluginMFADeleteRequest) fields() pluginMFADeleteFields {
	return pluginMFADeleteFields{
		Snapshot:       r.snapshot,
		Runtime:        r.runtime,
		IdempotencyKey: r.idempotencyKey,
		Username:       r.username,
	}
}

// totpRequest maps common MFA delete fields to the TOTP API request.
func (r pluginMFADeleteRequest) totpRequest() pluginapi.TOTPDeleteRequest {
	return pluginapi.TOTPDeleteRequest(r.fields())
}

// recoveryCodeRequest maps common MFA delete fields to the recovery-code API request.
func (r pluginMFADeleteRequest) recoveryCodeRequest() pluginapi.RecoveryCodeDeleteRequest {
	return pluginapi.RecoveryCodeDeleteRequest(r.fields())
}

// deletePluginMFAState handles shared validation and error mapping for MFA delete calls.
func (m *BackendManager) deletePluginMFAState(
	auth *core.AuthState,
	idempotencyKey string,
	method string,
	call func(context.Context, pluginMFADeleteRequest) error,
) error {
	if idempotencyKey == "" {
		return servererrors.ErrUnknownDatabaseBackend
	}

	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return err
	}

	request := pluginMFADeleteRequest{
		snapshot:       snapshot,
		runtime:        runtimeContext,
		idempotencyKey: idempotencyKey,
		username:       usernameFromAuth(auth),
	}

	if err := call(ctx, request); err != nil {
		return fmt.Errorf("%s: %w", method, m.mapOptionalError(err))
	}

	return nil
}

// invokeDeleteTOTP calls the optional plugin TOTP delete implementation.
func (m *BackendManager) invokeDeleteTOTP(ctx context.Context, request pluginMFADeleteRequest) error {
	return invokeOptionalBackend(ctx, m.runner, m.qualifiedName, "DeleteTOTP", func(callCtx context.Context, backend pluginapi.TOTPBackend) error {
		return backend.DeleteTOTP(callCtx, request.totpRequest())
	})
}

// invokeDeleteRecoveryCodes calls the optional plugin recovery-code delete implementation.
func (m *BackendManager) invokeDeleteRecoveryCodes(ctx context.Context, request pluginMFADeleteRequest) error {
	return invokeOptionalBackend(ctx, m.runner, m.qualifiedName, "DeleteRecoveryCodes", func(callCtx context.Context, backend pluginapi.RecoveryCodeBackend) error {
		return backend.DeleteRecoveryCodes(callCtx, request.recoveryCodeRequest())
	})
}

// consumeRecoveryCode consumes a recovery code through a plugin recovery-code backend.
func (m *BackendManager) consumeRecoveryCode(auth *core.AuthState, code string, idempotencyKey string) (bool, int, error) {
	if idempotencyKey == "" {
		return false, 0, servererrors.ErrUnknownDatabaseBackend
	}

	ctx, snapshot, runtimeContext, err := m.requestContext(auth)
	if err != nil {
		return false, 0, err
	}

	result, err := invokeTypedComponent(ctx, m.runner, m.qualifiedName, pluginregistry.ComponentKindBackend, "UseRecoveryCode", func(callCtx context.Context, backend pluginapi.RecoveryCodeBackend) (pluginapi.RecoveryCodeUseResult, error) {
		return backend.UseRecoveryCode(callCtx, pluginapi.RecoveryCodeUseRequest{
			Snapshot:       snapshot,
			Runtime:        runtimeContext,
			IdempotencyKey: idempotencyKey,
			Username:       usernameFromAuth(auth),
			Code:           code,
		})
	})
	if err != nil {
		return false, 0, m.mapOptionalError(err)
	}

	applyPluginStatus(auth, result.Status)
	applyPluginBackendServerRef(auth, result.BackendServer)

	return result.Valid, result.Remaining, nil
}

// idempotencyKey builds a stable operation key for plugin-owned MFA mutations.
func (m *BackendManager) idempotencyKey(auth *core.AuthState, operation string) string {
	username := usernameFromAuth(auth)

	guid := ""
	if auth != nil {
		guid = auth.Runtime.GUID
	}

	if guid == "" {
		guid = "request"
	}

	return fmt.Sprintf("%s:%s:%s", operation, username, guid)
}

// validatePluginPolicyFacts normalizes plugin facts before core policy collection consumes them.
func validatePluginPolicyFacts(facts []pluginapi.PolicyFact) ([]pluginapi.PolicyFact, error) {
	if len(facts) == 0 {
		return nil, nil
	}

	validated := make([]pluginapi.PolicyFact, 0, len(facts))
	for _, fact := range facts {
		attribute := strings.TrimSpace(fact.Attribute)
		if attribute == "" {
			return nil, fmt.Errorf("%w: policy fact attribute is empty", ErrInvalidRuntimeKey)
		}

		value, err := normalizeRuntimeValue(attribute, fact.Value)
		if err != nil {
			return nil, err
		}

		validated = append(validated, pluginapi.PolicyFact{
			Attribute: attribute,
			Value:     value,
		})
	}

	return validated, nil
}

// pluginAttributeMapping converts plugin string attributes to backend attributes.
func pluginAttributeMapping(attributes map[string][]string) bktype.AttributeMapping {
	mapped := make(bktype.AttributeMapping, len(attributes))

	for key, values := range attributes {
		if key == "" {
			continue
		}

		mapped[key] = stringsToAnySlice(values)
	}

	return mapped
}

// pluginAdditionalAttributes preserves status and policy facts alongside mapped backend attributes.
func pluginAdditionalAttributes(status *pluginapi.StatusMessage, facts []pluginapi.PolicyFact) map[string]any {
	attributes := make(map[string]any)

	if status != nil {
		if status.Code != "" {
			attributes[pluginBackendStatusCodeAttribute] = status.Code
		}

		if status.DefaultText != "" {
			attributes[pluginBackendStatusTextAttribute] = status.DefaultText
		}

		if status.MessageKey != "" {
			attributes[pluginBackendStatusMessageAttribute] = status.MessageKey
		}
	}

	if len(facts) > 0 {
		attributes[core.PassDBAdditionalAttributePluginFacts] = facts
	}

	if len(attributes) == 0 {
		return nil
	}

	return attributes
}

// applyPluginStatus mirrors plugin status metadata into the active auth runtime.
func applyPluginStatus(auth *core.AuthState, status *pluginapi.StatusMessage) {
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

// applyPluginBackendServerRef records the selected backend reference for follow-up calls.
func applyPluginBackendServerRef(auth *core.AuthState, ref *pluginapi.BackendServerRef) {
	if auth == nil || ref == nil {
		return
	}

	mapped := pluginBackendServerRef(ref)
	if mapped.IsZero() {
		return
	}

	auth.Runtime.RemoteBackendRef = mapped
}

// pluginBackendServerRef maps a public plugin backend reference to the internal session-safe reference.
func pluginBackendServerRef(ref *pluginapi.BackendServerRef) core.RemoteBackendRef {
	if ref == nil {
		return core.RemoteBackendRef{}
	}

	return core.RemoteBackendRef{
		Type:        definitions.BackendPluginName,
		Name:        ref.Name,
		Protocol:    ref.Protocol,
		Authority:   ref.Authority,
		OpaqueToken: pluginBackendServerToken(ref),
	}
}

// pluginBackendServerToken builds a non-secret backend locator from address and port.
func pluginBackendServerToken(ref *pluginapi.BackendServerRef) string {
	switch {
	case ref == nil:
		return ""
	case ref.Address != "" && ref.Port != "":
		return net.JoinHostPort(ref.Address, ref.Port)
	case ref.Address != "":
		return ref.Address
	default:
		return ref.Port
	}
}

// moduleNameFromQualified extracts the module segment from a validated qualified name.
func moduleNameFromQualified(qualifiedName string) (string, error) {
	if err := pluginapi.ValidateQualifiedComponentName(qualifiedName); err != nil {
		return "", err
	}

	moduleName, _, _ := strings.Cut(qualifiedName, ".")

	return moduleName, nil
}

// usernameFromAuth safely reads the request username.
func usernameFromAuth(auth *core.AuthState) string {
	if auth == nil {
		return ""
	}

	return auth.GetUsername()
}

// stringsToAnySlice converts plugin string slices to backend attribute values.
func stringsToAnySlice(values []string) []any {
	if len(values) == 0 {
		return nil
	}

	converted := make([]any, 0, len(values))
	for _, value := range values {
		converted = append(converted, value)
	}

	return converted
}

// invokeOptionalBackend invokes an optional backend capability behind the plugin boundary.
func invokeOptionalBackend[T any](ctx context.Context, runner *Runner, qualifiedName string, method string, call func(context.Context, T) error) error {
	_, err := invokeTypedComponent(ctx, runner, qualifiedName, pluginregistry.ComponentKindBackend, method, func(callCtx context.Context, backend T) (struct{}, error) {
		return struct{}{}, call(callCtx, backend)
	})

	return err
}

// webAuthnCredentialsFromPlugin converts plugin credentials to persistent credentials.
func webAuthnCredentialsFromPlugin(credentials []pluginapi.WebAuthnCredential) []mfa.PersistentCredential {
	if len(credentials) == 0 {
		return nil
	}

	mapped := make([]mfa.PersistentCredential, 0, len(credentials))
	for _, credential := range credentials {
		mapped = append(mapped, webAuthnCredentialFromPlugin(credential))
	}

	return mapped
}

// webAuthnCredentialFromPlugin converts one plugin WebAuthn credential.
func webAuthnCredentialFromPlugin(credential pluginapi.WebAuthnCredential) mfa.PersistentCredential {
	return mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID:              append([]byte(nil), credential.ID...),
			PublicKey:       append([]byte(nil), credential.PublicKey...),
			AttestationType: credential.Attestation,
			Transport:       authenticatorTransportsFromPlugin(credential.Transports),
			Flags: webauthn.CredentialFlags{
				BackupEligible: credential.BackupEligible,
				BackupState:    credential.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    []byte(credential.AAGUID),
				SignCount: credential.SignCount,
				Attachment: protocol.AuthenticatorAttachment(
					credential.Authenticator,
				),
			},
		},
		LastUsed: credential.LastUsed,
	}
}

// webAuthnCredentialToPlugin converts one persistent credential for plugin storage calls.
func webAuthnCredentialToPlugin(credential *mfa.PersistentCredential) pluginapi.WebAuthnCredential {
	if credential == nil {
		return pluginapi.WebAuthnCredential{}
	}

	return pluginapi.WebAuthnCredential{
		LastUsed:       credential.LastUsed,
		ID:             append([]byte(nil), credential.ID...),
		PublicKey:      append([]byte(nil), credential.PublicKey...),
		Transports:     authenticatorTransportsToPlugin(credential.Transport),
		AAGUID:         string(credential.Authenticator.AAGUID),
		Attestation:    credential.AttestationType,
		Authenticator:  string(credential.Authenticator.Attachment),
		SignCount:      credential.Authenticator.SignCount,
		BackupState:    credential.Flags.BackupState,
		BackupEligible: credential.Flags.BackupEligible,
	}
}

// authenticatorTransportsFromPlugin converts transport strings to WebAuthn transport values.
func authenticatorTransportsFromPlugin(values []string) []protocol.AuthenticatorTransport {
	if len(values) == 0 {
		return nil
	}

	transports := make([]protocol.AuthenticatorTransport, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}

		transports = append(transports, protocol.AuthenticatorTransport(value))
	}

	return transports
}

// authenticatorTransportsToPlugin converts WebAuthn transport values to strings.
func authenticatorTransportsToPlugin(values []protocol.AuthenticatorTransport) []string {
	if len(values) == 0 {
		return nil
	}

	transports := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}

		transports = append(transports, string(value))
	}

	return transports
}
