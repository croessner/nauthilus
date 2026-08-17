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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

var errWebAuthnCeremonyRestart = errors.New("webauthn ceremony restart required")

const (
	webAuthnCeremonyTTL      = 5 * time.Minute
	webAuthnCeremonyKeyPart  = "webauthn:ceremony:"
	webAuthnCeremonyLogin    = "login"
	webAuthnCeremonyRegister = "register"
	webAuthnCeremonySuccess  = "success"
	webAuthnCeremonyFailure  = "failure"
	webAuthnCeremonyMissing  = "missing"
)

// webAuthnCeremonyStore owns short-lived, one-time WebAuthn ceremony state.
type webAuthnCeremonyStore struct {
	prefix string
	deps   AuthDeps
}

// webAuthnCeremonyRecord is the server-side payload selected by a browser-held reference.
type webAuthnCeremonyRecord struct {
	Kind        string               `json:"kind"`
	Binding     string               `json:"binding"`
	SessionData webauthn.SessionData `json:"session_data"`
}

// newWebAuthnCeremonyStore constructs the Redis-backed ceremony owner.
func newWebAuthnCeremonyStore(deps AuthDeps) (*webAuthnCeremonyStore, error) {
	if deps.Cfg == nil || deps.Cfg.GetServer() == nil || deps.Redis == nil || deps.Redis.GetWriteHandle() == nil {
		return nil, fmt.Errorf("webauthn ceremony store is unavailable")
	}

	return &webAuthnCeremonyStore{
		prefix: deps.Cfg.GetServer().GetRedis().GetPrefix(),
		deps:   deps,
	}, nil
}

// Store writes ceremony data before returning options and saves only its opaque reference in the browser session.
func (s *webAuthnCeremonyStore) Store(ctx *gin.Context, mgr cookie.Manager, kind string, sessionData *webauthn.SessionData) (err error) {
	defer func() {
		recordWebAuthnCeremonyOperation("store", err)
	}()

	if s == nil || ctx == nil || mgr == nil || sessionData == nil {
		return fmt.Errorf("invalid webauthn ceremony state")
	}

	previousState := webAuthnCeremonyReferenceState(mgr)
	previousReferences := webAuthnCeremonyCleanupReferences(previousState)
	reference, err := util.GenerateRandomString(32)
	if err != nil {
		return fmt.Errorf("generate webauthn ceremony reference: %w", err)
	}

	payload, err := jsonIter.Marshal(webAuthnCeremonyRecord{
		Kind:        kind,
		Binding:     webAuthnCeremonyBinding(mgr, kind),
		SessionData: *sessionData,
	})
	if err != nil {
		return fmt.Errorf("encode webauthn ceremony: %w", err)
	}

	if err = s.deps.Redis.GetWriteHandle().Set(ctx.Request.Context(), s.redisKey(reference), payload, webAuthnCeremonyTTL).Err(); err != nil {
		return fmt.Errorf("store webauthn ceremony: %w", err)
	}

	mgr.Delete(definitions.SessionKeyRegistration)
	mgr.Set(definitions.SessionKeyWebAuthnCeremony, reference)

	if err = mgr.Save(ctx); err != nil {
		_ = s.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), s.redisKey(reference)).Err()
		mgr.Delete(definitions.SessionKeyWebAuthnCeremony)

		return fmt.Errorf("save webauthn ceremony reference: %w", err)
	}

	if err = s.deleteReferences(ctx, previousReferences); err != nil {
		s.cleanupFailedReplacement(ctx, mgr, reference, previousReferences)

		return fmt.Errorf("replace webauthn ceremony: %w", err)
	}

	return nil
}

// DeleteWebAuthnCeremony removes the active browser ceremony before a flow abort or logout clears its reference.
func DeleteWebAuthnCeremony(ctx *gin.Context, deps AuthDeps, mgr cookie.Manager) {
	if mgr == nil {
		recordWebAuthnCeremonyDelete(webAuthnCeremonyFailure)

		return
	}

	references := webAuthnCeremonyCleanupReferences(webAuthnCeremonyReferenceState(mgr))
	mgr.Delete(definitions.SessionKeyWebAuthnCeremony)
	mgr.Delete(definitions.SessionKeyRegistration)

	if len(references) == 0 {
		recordWebAuthnCeremonyDelete(webAuthnCeremonyMissing)

		return
	}

	store, err := newWebAuthnCeremonyStore(deps)
	if err != nil || ctx == nil {
		recordWebAuthnCeremonyDelete(webAuthnCeremonyFailure)

		return
	}

	if err = store.deleteReferences(ctx, references); err != nil {
		recordWebAuthnCeremonyDelete(webAuthnCeremonyFailure)

		return
	}

	recordWebAuthnCeremonyDelete(webAuthnCeremonySuccess)
}

// Take consumes a ceremony reference so WebAuthn assertions cannot replay it.
func (s *webAuthnCeremonyStore) Take(ctx *gin.Context, mgr cookie.Manager, kind string) (sessionData *webauthn.SessionData, err error) {
	defer func() {
		recordWebAuthnCeremonyOperation("take", err)
	}()

	if s == nil || ctx == nil || mgr == nil {
		return nil, fmt.Errorf("invalid webauthn ceremony lookup")
	}

	state := webAuthnCeremonyReferenceState(mgr)

	references := webAuthnCeremonyCleanupReferences(state)
	if state.Dedicated == "" || state.Legacy != "" || !validWebAuthnCeremonyReference(state.Dedicated) {
		cleanupErr := s.failClosed(ctx, mgr, references)

		return nil, webAuthnCeremonyRestartError("invalid browser reference state", cleanupErr)
	}

	reference := state.Dedicated

	payload, err := s.deps.Redis.GetWriteHandle().GetDel(ctx.Request.Context(), s.redisKey(reference)).Bytes()
	if err != nil {
		cleanupErr := s.failClosed(ctx, mgr, references)

		return nil, webAuthnCeremonyRestartError(fmt.Sprintf("load webauthn ceremony: %v", err), cleanupErr)
	}

	if err = clearAndSaveWebAuthnCeremony(ctx, mgr); err != nil {
		return nil, webAuthnCeremonyRestartError("save consumed browser reference cleanup", err)
	}

	record := &webAuthnCeremonyRecord{}
	if err = jsonIter.Unmarshal(payload, record); err != nil {
		return nil, webAuthnCeremonyRestartError(fmt.Sprintf("decode webauthn ceremony: %v", err), nil)
	}

	if record.Kind != kind {
		return nil, webAuthnCeremonyRestartError("webauthn ceremony kind mismatch", nil)
	}

	if record.Binding != webAuthnCeremonyBinding(mgr, kind) {
		return nil, webAuthnCeremonyRestartError("webauthn ceremony binding mismatch", nil)
	}

	return &record.SessionData, nil
}

// recordWebAuthnCeremonyOperation emits one bounded store or take result.
func recordWebAuthnCeremonyOperation(operation string, err error) {
	outcome := webAuthnCeremonySuccess
	if err != nil {
		outcome = webAuthnCeremonyFailure
	}

	stats.GetMetrics().GetWebAuthnCeremonyReferenceOperationsTotal().WithLabelValues(operation, outcome).Inc()
}

// recordWebAuthnCeremonyDelete emits one bounded delete result.
func recordWebAuthnCeremonyDelete(outcome string) {
	stats.GetMetrics().GetWebAuthnCeremonyReferenceOperationsTotal().WithLabelValues("delete", outcome).Inc()
}

// webAuthnCeremonyReferenceState returns the canonical dedicated reference and
// any legacy primary-cookie remnant that is eligible only for cleanup.
func webAuthnCeremonyReferenceState(mgr cookie.Manager) cookie.WebAuthnCeremonyReferenceState {
	if mgr == nil {
		return cookie.WebAuthnCeremonyReferenceState{}
	}

	if stateManager, ok := mgr.(cookie.WebAuthnCeremonyReferenceStateManager); ok {
		return stateManager.WebAuthnCeremonyReferenceState()
	}

	return cookie.WebAuthnCeremonyReferenceState{
		Dedicated: mgr.GetString(definitions.SessionKeyWebAuthnCeremony, ""),
	}
}

// webAuthnCeremonyCleanupReferences returns unique non-empty browser references.
func webAuthnCeremonyCleanupReferences(state cookie.WebAuthnCeremonyReferenceState) []string {
	references := make([]string, 0, 2)
	if state.Dedicated != "" {
		references = append(references, state.Dedicated)
	}

	if state.Legacy != "" && state.Legacy != state.Dedicated {
		references = append(references, state.Legacy)
	}

	return references
}

// validWebAuthnCeremonyReference accepts only values emitted by GenerateRandomString.
func validWebAuthnCeremonyReference(reference string) bool {
	if len(reference) != 32 {
		return false
	}

	for _, character := range reference {
		if character >= '0' && character <= '9' ||
			character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' {
			continue
		}

		return false
	}

	return true
}

// webAuthnCeremonyRestartError preserves one stable restart contract without
// exposing Redis or browser-session details to callers.
func webAuthnCeremonyRestartError(reason string, cleanupErr error) error {
	if cleanupErr != nil {
		return fmt.Errorf("%w: %s; cleanup failed: %v", errWebAuthnCeremonyRestart, reason, cleanupErr)
	}

	return fmt.Errorf("%w: %s", errWebAuthnCeremonyRestart, reason)
}

// deleteReferences removes every supplied Redis reference and reports the first failure.
func (s *webAuthnCeremonyStore) deleteReferences(ctx *gin.Context, references []string) error {
	var firstErr error

	for _, reference := range references {
		if reference == "" {
			continue
		}

		if err := s.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), s.redisKey(reference)).Err(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// cleanupFailedReplacement removes new and previous records after a replacement failure.
func (s *webAuthnCeremonyStore) cleanupFailedReplacement(
	ctx *gin.Context,
	mgr cookie.Manager,
	reference string,
	previousReferences []string,
) {
	_ = s.deleteReferences(ctx, append(previousReferences, reference))

	mgr.Delete(definitions.SessionKeyWebAuthnCeremony)
	mgr.Delete(definitions.SessionKeyRegistration)
	_ = mgr.Save(ctx)
}

// failClosed clears both browser representations, persists the deletion, and
// removes every identifiable Redis remnant without permitting continuation.
func (s *webAuthnCeremonyStore) failClosed(ctx *gin.Context, mgr cookie.Manager, references []string) error {
	redisErr := s.deleteReferences(ctx, references)
	saveErr := clearAndSaveWebAuthnCeremony(ctx, mgr)

	return errors.Join(redisErr, saveErr)
}

// clearAndSaveWebAuthnCeremony persists targeted ceremony cleanup while keeping
// the surrounding OIDC or SAML flow available for a fresh begin request.
func clearAndSaveWebAuthnCeremony(ctx *gin.Context, mgr cookie.Manager) error {
	mgr.Delete(definitions.SessionKeyWebAuthnCeremony)
	mgr.Delete(definitions.SessionKeyRegistration)

	return mgr.Save(ctx)
}

// webAuthnCeremonyBinding binds a ceremony reference to its current browser identity and IDP flow.
func webAuthnCeremonyBinding(mgr cookie.Manager, kind string) string {
	if mgr == nil {
		return kind
	}

	identity := sessionWebAuthnLoginIdentity(mgr)
	if kind == webAuthnCeremonyRegister {
		identity.userName = webAuthnRegistrationUserName(mgr)
	}

	return strings.Join([]string{
		kind,
		mgr.GetString(definitions.SessionKeyIDPFlowID, ""),
		identity.userName,
		identity.uniqueUserID,
	}, "\x00")
}

// redisKey builds the isolated Redis key for one opaque ceremony reference.
func (s *webAuthnCeremonyStore) redisKey(reference string) string {
	return s.prefix + webAuthnCeremonyKeyPart + reference
}
