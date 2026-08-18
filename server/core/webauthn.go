// Copyright (C) 2024 Christian Rößner
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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
	"go.opentelemetry.io/otel/attribute"
)

var webAuthn *webauthn.WebAuthn

// jsonIter is a package-level variable for jsoniter with standard configuration
var jsonIter = jsoniter.ConfigFastest

type webAuthnLoginAssertion struct {
	credential          *webauthn.Credential
	existingCredentials []mfa.PersistentCredential
}

type webAuthnSignCountAudit struct {
	oldSignCount       *uint32
	credentialIDHash   string
	aaguid             string
	isResidentKey      bool
	signCountZero      bool
	signCountMonotonic bool
	newSignCount       uint32
}

type webAuthnTraceSpan interface {
	SetAttributes(...attribute.KeyValue)
}

// updateUser refreshes the WebAuthn user cache after credential changes.
func (a *AuthState) updateUser(user *backend.User) error {
	return backend.SaveWebAuthnToRedis(a.Ctx(), a.Logger(), a.Cfg(), a.Redis(), user, a.Cfg().GetServer().Redis.PosCacheTTL)
}

// beginRegistrationOptions starts the WebAuthn registration ceremony.
func beginRegistrationOptions(deps AuthDeps, user *backend.User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return webAuthn.BeginRegistration(
		user,
		webauthn.WithAuthenticatorSelection(buildAuthenticatorSelection(deps.Cfg.GetIDP().WebAuthn)),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
}

// beginWebAuthnLoginOptions starts either discoverable or user-bound login.
func beginWebAuthnLoginOptions(user *backend.User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if user == nil {
		return webAuthn.BeginDiscoverableLogin()
	}

	return webAuthn.BeginLogin(user)
}

// parseRegistrationFinishResponse parses the registration finish payload and optional device name.
func parseRegistrationFinishResponse(ctx *gin.Context) (string, *protocol.ParsedCredentialCreationData, bool) {
	requestBody, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())

		return "", nil, false
	}

	var finishRequest struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}

	var response *protocol.ParsedCredentialCreationData
	if err = jsonIter.Unmarshal(requestBody, &finishRequest); err == nil && len(finishRequest.Credential) > 0 {
		response, err = protocol.ParseCredentialCreationResponseBody(bytes.NewReader(finishRequest.Credential))

		return strings.TrimSpace(finishRequest.Name), response, registrationParseOK(ctx, err)
	}

	response, err = protocol.ParseCredentialCreationResponseBody(bytes.NewReader(requestBody))

	return "", response, registrationParseOK(ctx, err)
}

// registrationParseOK writes the protocol parse error response when parsing failed.
func registrationParseOK(ctx *gin.Context, err error) bool {
	if err == nil {
		return true
	}

	ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%+v", util.ProtoErrToFields(err)))

	return false
}

// persistRegistrationCredential stores the new credential in the configured backend.
func persistRegistrationCredential(ctx *gin.Context, deps AuthDeps, authState *AuthState, credential *webauthn.Credential, deviceName string) bool {
	persistentCredential := &mfa.PersistentCredential{
		Credential: *credential,
		Name:       deviceName,
	}

	if err := authState.SaveWebAuthnCredential(persistentCredential); err != nil {
		level.Error(deps.Logger).Log(
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Failed to persist WebAuthn credential to backend",
			definitions.LogKeyError, err,
		)
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return false
	}

	return true
}

// updateRegistrationUserCache refreshes the Redis WebAuthn user cache when needed.
func updateRegistrationUserCache(ctx *gin.Context, deps AuthDeps, authState *AuthState, user *backend.User) bool {
	if !shouldPersistWebAuthnCache(authState) {
		return true
	}

	if err := authState.updateUser(user); err != nil {
		level.Error(deps.Logger).Log(
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Failed to update WebAuthn user cache",
			definitions.LogKeyError, err,
		)
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return false
	}

	return true
}

// finishWebAuthnLoginAssertion validates the assertion and rejects sign-count rollbacks.
func finishWebAuthnLoginAssertion(
	ctx *gin.Context,
	deps AuthDeps,
	protocolContext IDPMFAProtocolContext,
	authState *AuthState,
	user *backend.User,
	sessionData *webauthn.SessionData,
	sp webAuthnTraceSpan,
) (webAuthnLoginAssertion, bool) {
	credential, err := webAuthn.FinishLogin(user, *sessionData, ctx.Request)
	if err != nil {
		LogIDPMFAuthResult(ctx, deps, protocolContext, user.Name, definitions.MFAMethodWebAuthn, err.Error(), false)
		ctx.JSON(http.StatusBadRequest, err.Error())

		return webAuthnLoginAssertion{}, false
	}

	assertion := webAuthnLoginAssertion{
		credential:          credential,
		existingCredentials: user.Credentials,
	}
	audit := newWebAuthnSignCountAudit(assertion.existingCredentials, credential, sessionData)
	recordWebAuthnSignCountAudit(sp, authState, credential, audit)

	if audit.oldSignCount != nil && !audit.signCountMonotonic {
		LogIDPMFAuthResult(ctx, deps, protocolContext, user.Name, definitions.MFAMethodWebAuthn, "WebAuthn sign count rollback detected", false)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "webauthn", "fail").Inc()
		ctx.JSON(http.StatusBadRequest, "WebAuthn sign count rollback detected")

		return webAuthnLoginAssertion{}, false
	}

	return assertion, true
}

// newWebAuthnSignCountAudit derives observability fields from a completed assertion.
func newWebAuthnSignCountAudit(
	existingCredentials []mfa.PersistentCredential,
	credential *webauthn.Credential,
	sessionData *webauthn.SessionData,
) webAuthnSignCountAudit {
	newSignCount := credential.Authenticator.SignCount
	oldSignCount := findWebAuthnOldSignCount(existingCredentials, credential.ID)

	signCountMonotonic := true
	if oldSignCount != nil {
		signCountMonotonic = isWebAuthnSignCountMonotonic(*oldSignCount, newSignCount)
	}

	return webAuthnSignCountAudit{
		oldSignCount:       oldSignCount,
		credentialIDHash:   hashCredentialID(credential.ID),
		aaguid:             hex.EncodeToString(credential.Authenticator.AAGUID),
		isResidentKey:      len(sessionData.AllowedCredentialIDs) == 0,
		signCountZero:      newSignCount == 0,
		signCountMonotonic: signCountMonotonic,
		newSignCount:       newSignCount,
	}
}

// findWebAuthnOldSignCount returns the stored counter for the asserted credential.
func findWebAuthnOldSignCount(credentials []mfa.PersistentCredential, credentialID []byte) *uint32 {
	for i := range credentials {
		if bytes.Equal(credentials[i].ID, credentialID) {
			oldValue := credentials[i].Authenticator.SignCount

			return &oldValue
		}
	}

	return nil
}

// recordWebAuthnSignCountAudit emits trace, debug, and anomaly logs for assertion counters.
func recordWebAuthnSignCountAudit(
	sp webAuthnTraceSpan,
	authState *AuthState,
	credential *webauthn.Credential,
	audit webAuthnSignCountAudit,
) {
	setWebAuthnSignCountTrace(sp, credential, audit)
	logWebAuthnSignCountDebug(authState, credential, audit)

	if audit.signCountZero || (audit.oldSignCount != nil && !audit.signCountMonotonic) {
		level.Warn(authState.Logger()).Log(webAuthnSignCountLogFields(authState, credential, audit, "WebAuthn sign count anomaly")...)
	}
}

// setWebAuthnSignCountTrace stores assertion counter details on the active span.
func setWebAuthnSignCountTrace(sp webAuthnTraceSpan, credential *webauthn.Credential, audit webAuthnSignCountAudit) {
	sp.SetAttributes(
		attribute.Int64("webauthn.sign_count", int64(audit.newSignCount)),
		attribute.Bool("webauthn.flags.up", credential.Flags.UserPresent),
		attribute.Bool("webauthn.flags.uv", credential.Flags.UserVerified),
		attribute.Bool("webauthn.is_resident_key", audit.isResidentKey),
		attribute.String("webauthn.credential_id_hash", audit.credentialIDHash),
		attribute.String("webauthn.aaguid", audit.aaguid),
		attribute.Bool("webauthn.sign_count_zero", audit.signCountZero),
	)

	if audit.oldSignCount != nil {
		sp.SetAttributes(
			attribute.Int64("webauthn.sign_count_previous", int64(*audit.oldSignCount)),
			attribute.Bool("webauthn.sign_count_monotonic", audit.signCountMonotonic),
		)
	}
}

// logWebAuthnSignCountDebug writes assertion counter details to the WebAuthn debug module.
func logWebAuthnSignCountDebug(authState *AuthState, credential *webauthn.Credential, audit webAuthnSignCountAudit) {
	util.DebugModuleWithCfg(
		authState.Ctx(),
		authState.Cfg(),
		authState.Logger(),
		definitions.DbgWebAuthn,
		webAuthnSignCountLogFields(authState, credential, audit, "WebAuthn login assertion details")...,
	)
}

// webAuthnSignCountLogFields builds the shared log fields for WebAuthn counter observability.
func webAuthnSignCountLogFields(authState *AuthState, credential *webauthn.Credential, audit webAuthnSignCountAudit, message string) []any {
	keyvals := []any{
		definitions.LogKeyGUID, authState.Runtime.GUID,
		definitions.LogKeyMsg, message,
		webAuthnDebugSignCount, audit.newSignCount,
		webAuthnDebugFlagsUP, credential.Flags.UserPresent,
		webAuthnDebugFlagsUV, credential.Flags.UserVerified,
		webAuthnDebugCredentialIDHash, audit.credentialIDHash,
		webAuthnDebugIsResidentKey, audit.isResidentKey,
		webAuthnDebugAAGUID, audit.aaguid,
		webAuthnDebugSignCountZero, audit.signCountZero,
	}

	if audit.oldSignCount != nil {
		keyvals = append(
			keyvals,
			"sign_count_previous", *audit.oldSignCount,
			"sign_count_monotonic", audit.signCountMonotonic,
		)
	}

	return keyvals
}

// persistWebAuthnLoginCredentialUpdate stores last-used and counter changes after login.
func persistWebAuthnLoginCredentialUpdate(
	ctx *gin.Context,
	deps AuthDeps,
	protocolContext IDPMFAProtocolContext,
	authState *AuthState,
	user *backend.User,
	assertion webAuthnLoginAssertion,
) bool {
	oldCredential, newPersistentCredential := updateWebAuthnCredentialAfterLogin(
		assertion.existingCredentials,
		assertion.credential,
		time.Now(),
	)
	if oldCredential == nil {
		return true
	}

	if err := persistWebAuthnLoginUpdate(authState, user, oldCredential, newPersistentCredential); err != nil {
		LogIDPMFAuthResult(ctx, deps, protocolContext, user.Name, definitions.MFAMethodWebAuthn, err.Error(), false)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "webauthn", "fail").Inc()

		_ = level.Error(authState.Logger()).Log(
			definitions.LogKeyGUID, authState.Runtime.GUID,
			definitions.LogKeyMsg, "Failed to persist WebAuthn login credential update",
			definitions.LogKeyError, err,
		)
		ctx.JSON(http.StatusInternalServerError, err.Error())

		return false
	}

	return true
}

// buildAuthenticatorSelection constructs the protocol.AuthenticatorSelection from the
// WebAuthn configuration. It maps string-based config values to their protocol equivalents.
func buildAuthenticatorSelection(webAuthnCfg config.WebAuthn) protocol.AuthenticatorSelection {
	authSelect := protocol.AuthenticatorSelection{
		UserVerification: mapUserVerification(webAuthnCfg.GetUserVerification()),
		ResidentKey:      mapResidentKey(webAuthnCfg.GetResidentKey()),
	}

	switch webAuthnCfg.GetAuthenticatorAttachment() {
	case "":
		// Do not select an authenticator attachment. Let the browser make the decision.
	case "platform":
		authSelect.AuthenticatorAttachment = protocol.Platform
	case "cross-platform":
		authSelect.AuthenticatorAttachment = protocol.CrossPlatform
	}

	if authSelect.ResidentKey == protocol.ResidentKeyRequirementRequired {
		authSelect.RequireResidentKey = protocol.ResidentKeyRequired()
	} else {
		authSelect.RequireResidentKey = protocol.ResidentKeyNotRequired()
	}

	return authSelect
}

// mapResidentKey converts a string resident key requirement to the protocol type.
func mapResidentKey(value string) protocol.ResidentKeyRequirement {
	switch value {
	case "preferred":
		return protocol.ResidentKeyRequirementPreferred
	case authInputReasonRequired:
		return protocol.ResidentKeyRequirementRequired
	default:
		return protocol.ResidentKeyRequirementDiscouraged
	}
}

// mapUserVerification converts a string user verification requirement to the protocol type.
func mapUserVerification(value string) protocol.UserVerificationRequirement {
	switch value {
	case "discouraged":
		return protocol.VerificationDiscouraged
	case authInputReasonRequired:
		return protocol.VerificationRequired
	default:
		return protocol.VerificationPreferred
	}
}

func updateWebAuthnCredentialAfterLogin(credentials []mfa.PersistentCredential, credential *webauthn.Credential, now time.Time) (*mfa.PersistentCredential, *mfa.PersistentCredential) {
	if credential == nil {
		return nil, nil
	}

	var oldCredential *mfa.PersistentCredential

	for i := range credentials {
		if bytes.Equal(credentials[i].ID, credential.ID) {
			oldCredential = &credentials[i]
			break
		}
	}

	if oldCredential == nil {
		return nil, nil
	}

	if !isWebAuthnSignCountMonotonic(oldCredential.Authenticator.SignCount, credential.Authenticator.SignCount) {
		return nil, nil
	}

	newCredential := &mfa.PersistentCredential{
		Credential: *credential,
		Name:       oldCredential.Name,
		LastUsed:   now,
	}

	return oldCredential, newCredential
}

func isWebAuthnSignCountMonotonic(oldSignCount uint32, newSignCount uint32) bool {
	if newSignCount == 0 && oldSignCount == 0 {
		return true
	}

	return newSignCount > oldSignCount
}

type webAuthnCredentialUpdater interface {
	UpdateWebAuthnCredential(oldCredential *mfa.PersistentCredential, newCredential *mfa.PersistentCredential) error
}

func persistWebAuthnLoginUpdate(
	updater webAuthnCredentialUpdater,
	user *backend.User,
	oldCredential *mfa.PersistentCredential,
	newCredential *mfa.PersistentCredential,
) error {
	if updater == nil || user == nil || oldCredential == nil || newCredential == nil {
		return nil
	}

	if err := updater.UpdateWebAuthnCredential(oldCredential, newCredential); err != nil {
		return err
	}

	for index, credential := range user.Credentials {
		if bytes.Equal(credential.ID, newCredential.ID) {
			user.Credentials[index] = *newCredential

			break
		}
	}

	return nil
}

func shouldPersistWebAuthnCache(auth *AuthState) bool {
	if auth == nil {
		return true
	}

	if !auth.Runtime.RemoteBackendRef.IsZero() || auth.Runtime.UsedPassDBBackend == definitions.BackendRemote {
		return false
	}

	return true
}

func hashCredentialID(credentialID []byte) string {
	if len(credentialID) == 0 {
		return ""
	}

	sum := sha256.Sum256(credentialID)

	return hex.EncodeToString(sum[:])
}
