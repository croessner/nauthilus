// Copyright (C) 2025 Christian Rößner
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

package idp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	flowdomain "github.com/croessner/nauthilus/server/idp/flow"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

// MFAProvider defines the interface for MFA management operations.
type MFAProvider interface {
	GenerateTOTPSecret(ctx *gin.Context, username string) (string, string, error)
	VerifyAndSaveTOTP(ctx *gin.Context, username string, secret string, code string, sourceBackend uint8) error
	VerifyTOTP(ctx *gin.Context, username string, code string, sourceBackend uint8) (bool, error)
	DeleteTOTP(ctx *gin.Context, username string, sourceBackend uint8) error
	GenerateRecoveryCodes(ctx *gin.Context, username string, sourceBackend uint8) ([]string, error)
	SaveRecoveryCodes(ctx *gin.Context, username string, codes []string, sourceBackend uint8) error
	UseRecoveryCode(ctx *gin.Context, username string, code string, sourceBackend uint8) (bool, error)
	DeleteWebAuthnCredential(ctx *gin.Context, username string, credentialID string, sourceBackend uint8) error
}

// MFAService implements MFAProvider.
type MFAService struct {
	deps *deps.Deps
}

type remoteTOTPRegistration struct {
	pendingID   string
	operationID string
}

const (
	remoteTOTPPendingRegistrationMetadata = "remote_totp_pending_registration"
	remoteTOTPOperationIDMetadata         = "remote_totp_operation_id"
)

// NewMFAService creates a new MFAService.
func NewMFAService(d *deps.Deps) *MFAService {
	return &MFAService{deps: d}
}

// GenerateTOTPSecret generates a new TOTP secret and returns the secret and QR code URL.
func (s *MFAService) GenerateTOTPSecret(ctx *gin.Context, username string) (string, string, error) {
	sourceBackend := sourceBackendFromSession(ctx, uint8(definitions.BackendLDAP))
	if sourceBackend == uint8(definitions.BackendRemote) {
		auth, operations, err := s.remoteMFAOperations(ctx, username, sourceBackend)
		if err != nil {
			return "", "", err
		}

		beginKey, err := newMFAOperationID("totp-begin")
		if err != nil {
			return "", "", err
		}

		registration, err := operations.BeginTOTPRegistration(auth, beginKey)
		if err != nil {
			return "", "", err
		}

		if mgr := cookie.GetManager(ctx); mgr != nil {
			finishKey, keyErr := newMFAOperationID("totp-finish")
			if keyErr != nil {
				return "", "", keyErr
			}

			s.storeRemoteTOTPRegistration(ctx, registration.PendingRegistrationID, finishKey)
		}

		return registration.Secret, registration.OTPAuthURL, nil
	}

	registration, err := core.NewTOTPSettings(s.deps.Cfg).Generate(username)
	if err != nil {
		return "", "", err
	}

	return registration.Secret, registration.OTPAuthURL, nil
}

// VerifyAndSaveTOTP verifies the TOTP code and saves the secret to the backend.
func (s *MFAService) VerifyAndSaveTOTP(ctx *gin.Context, username string, secret string, code string, sourceBackend uint8) error {
	if sourceBackend == uint8(definitions.BackendRemote) {
		auth, operations, err := s.remoteMFAOperations(ctx, username, sourceBackend)
		if err != nil {
			return err
		}

		pendingID := ""
		idempotencyKey := ""

		if registration, ok := s.loadRemoteTOTPRegistration(ctx); ok {
			pendingID = registration.pendingID
			idempotencyKey = registration.operationID
		}

		if pendingID == "" || idempotencyKey == "" {
			return errors.New("missing pending TOTP registration")
		}

		if err := operations.FinishTOTPRegistration(auth, pendingID, code, idempotencyKey); err != nil {
			return err
		}

		s.clearRemoteTOTPRegistration(ctx)

		return nil
	}

	if err := core.ValidateTOTPCode(code, secret, s.deps.Auth()); err != nil {
		return err
	}

	authDeps := s.deps.Auth()

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return err
	}

	mgr, err := s.getBackendManager(ctx, sourceBackend, authDeps, dummyAuth)
	if err != nil {
		return err
	}

	if err := mgr.AddTOTPSecret(dummyAuth, core.NewTOTPSecret(secret)); err != nil {
		return err
	}

	return nil
}

// VerifyTOTP verifies a login TOTP code against the selected backend.
func (s *MFAService) VerifyTOTP(ctx *gin.Context, username string, code string, sourceBackend uint8) (bool, error) {
	if sourceBackend == uint8(definitions.BackendRemote) {
		auth, operations, err := s.remoteMFAOperations(ctx, username, sourceBackend)
		if err != nil {
			return false, err
		}

		return operations.VerifyTOTP(auth, code)
	}

	authDeps := s.deps.Auth()

	auth, err := s.getAuthState(ctx, username)
	if err != nil {
		return false, err
	}

	idpInstance := NewNauthilusIdP(s.deps)
	oidcCID, samlEntityID := flowClientIdentifiers(ctx)

	user, err := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID)
	if err != nil {
		return false, err
	}

	auth.ReplaceAllAttributes(user.Attributes)
	auth.SetTOTPSecretField(user.TOTPSecretField)
	auth.SetTOTPRecoveryField(user.TOTPRecoveryField)

	if err = core.TotpValidation(ctx, auth, code, authDeps); err != nil {
		return false, err
	}

	return true, nil
}

// DeleteTOTP removes the TOTP secret from the backend.
func (s *MFAService) DeleteTOTP(ctx *gin.Context, username string, sourceBackend uint8) error {
	authDeps := s.deps.Auth()

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return err
	}

	mgr, err := s.getBackendManager(ctx, sourceBackend, authDeps, dummyAuth)
	if err != nil {
		return err
	}

	if operations, ok := mgr.(core.RemoteMFAOperations); ok {
		key, err := newMFAOperationID("totp-delete")
		if err != nil {
			return err
		}

		return operations.DeleteTOTP(dummyAuth, key)
	}

	return mgr.DeleteTOTPSecret(dummyAuth)
}

// GenerateRecoveryCodes generates new recovery codes and saves them to the backend.
func (s *MFAService) GenerateRecoveryCodes(ctx *gin.Context, username string, sourceBackend uint8) ([]string, error) {
	authDeps := s.deps.Auth()

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return nil, err
	}

	mgr, err := s.getBackendManager(ctx, sourceBackend, authDeps, dummyAuth)
	if err != nil {
		return nil, err
	}

	if operations, ok := mgr.(core.RemoteMFAOperations); ok {
		key, err := newMFAOperationID("recovery-generate")
		if err != nil {
			return nil, err
		}

		return operations.GenerateRecoveryCodes(dummyAuth, 0, key)
	}

	recovery, err := core.GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	if err := mgr.AddTOTPRecoveryCodes(dummyAuth, recovery); err != nil {
		return nil, err
	}

	return recovery.GetCodes(), nil
}

// SaveRecoveryCodes stores the provided recovery codes in the backend.
func (s *MFAService) SaveRecoveryCodes(ctx *gin.Context, username string, codes []string, sourceBackend uint8) error {
	authDeps := s.deps.Auth()

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return err
	}

	mgr, err := s.getBackendManager(ctx, sourceBackend, authDeps, dummyAuth)
	if err != nil {
		return err
	}

	if _, ok := mgr.(core.RemoteMFAOperations); ok {
		return nil
	}

	recovery := mfa.NewTOTPRecovery(codes)

	if err := mgr.AddTOTPRecoveryCodes(dummyAuth, recovery); err != nil {
		return err
	}

	return nil
}

// UseRecoveryCode verifies a recovery code and removes it from the backend if valid.
func (s *MFAService) UseRecoveryCode(ctx *gin.Context, username string, code string, sourceBackend uint8) (bool, error) {
	authDeps := s.deps.Auth()

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return false, err
	}

	mgr, err := s.getBackendManager(ctx, sourceBackend, authDeps, dummyAuth)
	if err != nil {
		return false, err
	}

	if operations, ok := mgr.(core.RemoteMFAOperations); ok {
		key, err := newMFAOperationID("recovery-use")
		if err != nil {
			return false, err
		}

		return operations.UseRecoveryCode(dummyAuth, code, key)
	}

	// We need to fetch the current codes.
	// In the current architecture, we get them by doing a "Password login" without actual password verification
	// or by fetching the user attributes.
	// Since we are already authenticated (password-wise), we can just get the user.
	idpInstance := NewNauthilusIdP(s.deps)
	user, err := idpInstance.GetUserByUsername(ctx, username, "", "")
	if err != nil {
		return false, err
	}

	dummyAuth.ReplaceAllAttributes(user.Attributes)
	dummyAuth.SetTOTPRecoveryField(user.TOTPRecoveryField)

	recoveryCodes := dummyAuth.GetTOTPRecoveryCodes()

	if !slices.Contains(recoveryCodes, code) {
		return false, nil
	}

	newCodes := make([]string, 0, len(recoveryCodes)-1)
	for _, c := range recoveryCodes {
		if c != code {
			newCodes = append(newCodes, c)
		}
	}

	// Save updated codes
	if err := mgr.AddTOTPRecoveryCodes(dummyAuth, mfa.NewTOTPRecovery(newCodes)); err != nil {
		return true, err // Code was valid, but failed to update backend
	}

	return true, nil
}

// DeleteWebAuthnCredential removes a WebAuthn credential from the backend.
func (s *MFAService) DeleteWebAuthnCredential(ctx *gin.Context, username string, credentialID string, sourceBackend uint8) error {
	authDeps := s.deps.Auth()

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return err
	}

	mgr, err := s.getBackendManager(ctx, sourceBackend, authDeps, dummyAuth)
	if err != nil {
		return err
	}

	return mgr.DeleteWebAuthnCredential(dummyAuth, &mfa.PersistentCredential{Credential: webauthn.Credential{ID: []byte(credentialID)}})
}

func (s *MFAService) getAuthState(ctx *gin.Context, username string) (*core.AuthState, error) {
	authDeps := s.deps.Auth()
	state := core.NewAuthStateFromContextWithDeps(ctx, authDeps)
	authState := state.(*core.AuthState)

	svc := ctx.GetString(definitions.CtxServiceKey)
	if svc == "" {
		svc = definitions.ServIdP
	}

	authState.SetStatusCodes(svc)

	authState.WithClientInfo(ctx)
	authState.WithLocalInfo(ctx)
	authState.WithUserAgent(ctx)
	authState.WithXSSL(ctx)
	authState.InitMethodAndUserAgent()
	authState.WithDefaults(ctx)

	authState.SetUsername(username)

	if mgr := cookie.GetManager(ctx); mgr != nil {
		protocol := mgr.GetString(definitions.SessionKeyProtocol, "")
		if protocol != "" {
			authState.SetProtocol(config.NewProtocol(protocol))
		}

		if ref, ok := core.RemoteBackendRefFromSession(mgr); ok {
			authState.Runtime.RemoteBackendRef = ref
		}
	}

	return authState, nil
}

func (s *MFAService) getBackendManager(ctx *gin.Context, sourceBackend uint8, authDeps core.AuthDeps, authState *core.AuthState) (core.BackendManager, error) {
	switch sourceBackend {
	case uint8(definitions.BackendLDAP):
		return core.NewLDAPManager(definitions.DefaultBackendName, authDeps), nil
	case uint8(definitions.BackendLua):
		return core.NewLuaManager(definitions.DefaultBackendName, authDeps), nil
	case uint8(definitions.BackendRemote):
		backendName := definitions.DefaultBackendName
		if mgr := cookie.GetManager(ctx); mgr != nil {
			backendName = mgr.GetString(definitions.SessionKeyUserBackendName, backendName)
		}

		manager := authState.GetBackendManager(definitions.BackendRemote, backendName)
		if manager != nil {
			return manager, nil
		}

		return nil, errors.New("remote backend manager is unavailable")
	default:
		return nil, errors.New("unsupported backend")
	}
}

func (s *MFAService) remoteMFAOperations(ctx *gin.Context, username string, sourceBackend uint8) (*core.AuthState, core.RemoteMFAOperations, error) {
	authDeps := s.deps.Auth()

	auth, err := s.getAuthState(ctx, username)
	if err != nil {
		return nil, nil, err
	}

	manager, err := s.getBackendManager(ctx, sourceBackend, authDeps, auth)
	if err != nil {
		return nil, nil, err
	}

	operations, ok := manager.(core.RemoteMFAOperations)
	if !ok {
		return nil, nil, errors.New("remote backend does not support MFA operations")
	}

	return auth, operations, nil
}

func (s *MFAService) storeRemoteTOTPRegistration(ctx *gin.Context, pendingID string, operationID string) {
	if mgr := cookie.GetManager(ctx); mgr != nil {
		mgr.Set(definitions.SessionKeyTOTPPendingRegistration, pendingID)
		mgr.Set(definitions.SessionKeyTOTPOperationID, operationID)
	}

	state, store, ok := s.loadRemoteTOTPFlowState(ctx)
	if !ok {
		return
	}

	if state.Metadata == nil {
		state.Metadata = make(map[string]string)
	}

	state.Metadata[remoteTOTPPendingRegistrationMetadata] = pendingID
	state.Metadata[remoteTOTPOperationIDMetadata] = operationID
	_ = store.Save(mfaContext(ctx), state)
}

func (s *MFAService) loadRemoteTOTPRegistration(ctx *gin.Context) (remoteTOTPRegistration, bool) {
	if mgr := cookie.GetManager(ctx); mgr != nil {
		registration := remoteTOTPRegistration{
			pendingID:   mgr.GetString(definitions.SessionKeyTOTPPendingRegistration, ""),
			operationID: mgr.GetString(definitions.SessionKeyTOTPOperationID, ""),
		}
		if registration.pendingID != "" && registration.operationID != "" {
			return registration, true
		}
	}

	state, _, ok := s.loadRemoteTOTPFlowState(ctx)
	if !ok || state.Metadata == nil {
		return remoteTOTPRegistration{}, false
	}

	registration := remoteTOTPRegistration{
		pendingID:   state.Metadata[remoteTOTPPendingRegistrationMetadata],
		operationID: state.Metadata[remoteTOTPOperationIDMetadata],
	}
	if registration.pendingID == "" || registration.operationID == "" {
		return remoteTOTPRegistration{}, false
	}

	return registration, true
}

func (s *MFAService) clearRemoteTOTPRegistration(ctx *gin.Context) {
	if mgr := cookie.GetManager(ctx); mgr != nil {
		mgr.Delete(definitions.SessionKeyTOTPPendingRegistration)
		mgr.Delete(definitions.SessionKeyTOTPOperationID)
	}

	state, store, ok := s.loadRemoteTOTPFlowState(ctx)
	if !ok || state.Metadata == nil {
		return
	}

	delete(state.Metadata, remoteTOTPPendingRegistrationMetadata)
	delete(state.Metadata, remoteTOTPOperationIDMetadata)
	_ = store.Save(mfaContext(ctx), state)
}

func (s *MFAService) loadRemoteTOTPFlowState(ctx *gin.Context) (*flowdomain.State, *flowdomain.RedisStore, bool) {
	if s == nil || s.deps == nil || s.deps.Redis == nil || s.deps.Redis.GetWriteHandle() == nil || s.deps.Cfg == nil {
		return nil, nil, false
	}

	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return nil, nil, false
	}

	flowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
	if flowID == "" {
		return nil, nil, false
	}

	store := flowdomain.NewRedisStore(
		s.deps.Redis.GetWriteHandle(),
		s.deps.Cfg.GetServer().GetRedis().GetPrefix()+"idp:flow",
		0,
	)

	state, err := store.Load(mfaContext(ctx), flowID)
	if err != nil || state == nil {
		return nil, nil, false
	}

	return state, store, true
}

func mfaContext(ctx *gin.Context) context.Context {
	if ctx != nil && ctx.Request != nil {
		return ctx.Request.Context()
	}

	return context.Background()
}

func sourceBackendFromSession(ctx *gin.Context, fallback uint8) uint8 {
	if mgr := cookie.GetManager(ctx); mgr != nil {
		return mgr.GetUint8(definitions.SessionKeyUserBackend, fallback)
	}

	return fallback
}

func flowClientIdentifiers(ctx *gin.Context) (string, string) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return "", ""
	}

	switch mgr.GetString(definitions.SessionKeyIdPFlowType, "") {
	case definitions.ProtoOIDC:
		return mgr.GetString(definitions.SessionKeyIdPClientID, ""), ""
	case definitions.ProtoSAML:
		return "", mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
	default:
		return "", ""
	}
}

func newMFAOperationID(prefix string) (string, error) {
	token := make([]byte, 18)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}

	return prefix + ":" + base64.RawURLEncoding.EncodeToString(token), nil
}
