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
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	webAuthnCeremonyTTL      = 5 * time.Minute
	webAuthnCeremonyKeyPart  = "webauthn:ceremony:"
	webAuthnCeremonyLogin    = "login"
	webAuthnCeremonyRegister = "register"
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
func (s *webAuthnCeremonyStore) Store(ctx *gin.Context, mgr cookie.Manager, kind string, sessionData *webauthn.SessionData) error {
	if s == nil || ctx == nil || mgr == nil || sessionData == nil {
		return fmt.Errorf("invalid webauthn ceremony state")
	}

	previousReference := mgr.GetString(definitions.SessionKeyWebAuthnCeremony, "")
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

	if previousReference != "" {
		if err = s.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), s.redisKey(previousReference)).Err(); err != nil {
			_ = s.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), s.redisKey(reference)).Err()

			return fmt.Errorf("replace webauthn ceremony: %w", err)
		}
	}

	mgr.Delete(definitions.SessionKeyRegistration)
	mgr.Set(definitions.SessionKeyWebAuthnCeremony, reference)

	if err = mgr.Save(ctx); err != nil {
		_ = s.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), s.redisKey(reference)).Err()
		mgr.Delete(definitions.SessionKeyWebAuthnCeremony)

		return fmt.Errorf("save webauthn ceremony reference: %w", err)
	}

	return nil
}

// DeleteWebAuthnCeremony removes the active browser ceremony before a flow abort or logout clears its reference.
func DeleteWebAuthnCeremony(ctx *gin.Context, deps AuthDeps, mgr cookie.Manager) {
	store, err := newWebAuthnCeremonyStore(deps)
	if err != nil || mgr == nil {
		return
	}

	reference := mgr.GetString(definitions.SessionKeyWebAuthnCeremony, "")
	if reference == "" {
		return
	}

	_ = store.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), store.redisKey(reference)).Err()
	mgr.Delete(definitions.SessionKeyWebAuthnCeremony)
	mgr.Delete(definitions.SessionKeyRegistration)
}

// Take consumes a ceremony reference so WebAuthn assertions cannot replay it.
func (s *webAuthnCeremonyStore) Take(ctx *gin.Context, mgr cookie.Manager, kind string) (*webauthn.SessionData, error) {
	if s == nil || ctx == nil || mgr == nil {
		return nil, fmt.Errorf("invalid webauthn ceremony lookup")
	}

	reference := mgr.GetString(definitions.SessionKeyWebAuthnCeremony, "")
	if reference == "" {
		return nil, fmt.Errorf("missing webauthn ceremony reference")
	}

	payload, err := s.deps.Redis.GetWriteHandle().GetDel(ctx.Request.Context(), s.redisKey(reference)).Bytes()
	mgr.Delete(definitions.SessionKeyWebAuthnCeremony)
	mgr.Delete(definitions.SessionKeyRegistration)
	if err != nil {
		return nil, fmt.Errorf("load webauthn ceremony: %w", err)
	}

	record := &webAuthnCeremonyRecord{}
	if err = jsonIter.Unmarshal(payload, record); err != nil {
		return nil, fmt.Errorf("decode webauthn ceremony: %w", err)
	}

	if record.Kind != kind {
		return nil, fmt.Errorf("webauthn ceremony kind mismatch")
	}

	if record.Binding != webAuthnCeremonyBinding(mgr, kind) {
		return nil, fmt.Errorf("webauthn ceremony binding mismatch")
	}

	return &record.SessionData, nil
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
