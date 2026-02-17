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
	"errors"
	"slices"

	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
)

// MFAProvider defines the interface for MFA management operations.
type MFAProvider interface {
	GenerateTOTPSecret(ctx *gin.Context, username string) (string, string, error)
	VerifyAndSaveTOTP(ctx *gin.Context, username string, secret string, code string, sourceBackend uint8) error
	DeleteTOTP(ctx *gin.Context, username string, sourceBackend uint8) error
	GenerateRecoveryCodes(ctx *gin.Context, username string, sourceBackend uint8) ([]string, error)
	UseRecoveryCode(ctx *gin.Context, username string, code string, sourceBackend uint8) (bool, error)
	DeleteWebAuthnCredential(ctx *gin.Context, username string, credentialID string, sourceBackend uint8) error
}

// MFAService implements MFAProvider.
type MFAService struct {
	deps *deps.Deps
}

// NewMFAService creates a new MFAService.
func NewMFAService(d *deps.Deps) *MFAService {
	return &MFAService{deps: d}
}

// GenerateTOTPSecret generates a new TOTP secret and returns the secret and QR code URL.
func (s *MFAService) GenerateTOTPSecret(_ *gin.Context, username string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.deps.Cfg.GetServer().Frontend.GetTotpIssuer(),
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}

	return key.Secret(), key.URL(), nil
}

// VerifyAndSaveTOTP verifies the TOTP code and saves the secret to the backend.
func (s *MFAService) VerifyAndSaveTOTP(ctx *gin.Context, username string, secret string, code string, sourceBackend uint8) error {
	if !totp.Validate(code, secret) {
		return errors.New("invalid OTP code")
	}

	authDeps := s.deps.Auth()
	mgr, err := s.getBackendManager(sourceBackend, authDeps)
	if err != nil {
		return err
	}

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return err
	}

	if err := mgr.AddTOTPSecret(dummyAuth, core.NewTOTPSecret(secret)); err != nil {
		return err
	}

	return nil
}

// DeleteTOTP removes the TOTP secret from the backend.
func (s *MFAService) DeleteTOTP(ctx *gin.Context, username string, sourceBackend uint8) error {
	authDeps := s.deps.Auth()
	mgr, err := s.getBackendManager(sourceBackend, authDeps)
	if err != nil {
		return err
	}

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return err
	}

	return mgr.DeleteTOTPSecret(dummyAuth)
}

// GenerateRecoveryCodes generates new recovery codes and saves them to the backend.
func (s *MFAService) GenerateRecoveryCodes(ctx *gin.Context, username string, sourceBackend uint8) ([]string, error) {
	authDeps := s.deps.Auth()
	mgr, err := s.getBackendManager(sourceBackend, authDeps)
	if err != nil {
		return nil, err
	}

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return nil, err
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

// UseRecoveryCode verifies a recovery code and removes it from the backend if valid.
func (s *MFAService) UseRecoveryCode(ctx *gin.Context, username string, code string, sourceBackend uint8) (bool, error) {
	authDeps := s.deps.Auth()
	mgr, err := s.getBackendManager(sourceBackend, authDeps)
	if err != nil {
		return false, err
	}

	dummyAuth, err := s.getAuthState(ctx, username)
	if err != nil {
		return false, err
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
	mgr, err := s.getBackendManager(sourceBackend, authDeps)
	if err != nil {
		return err
	}

	dummyAuth, err := s.getAuthState(ctx, username)
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

	return authState, nil
}

func (s *MFAService) getBackendManager(sourceBackend uint8, authDeps core.AuthDeps) (core.BackendManager, error) {
	switch sourceBackend {
	case uint8(definitions.BackendLDAP):
		return core.NewLDAPManager(definitions.DefaultBackendName, authDeps), nil
	case uint8(definitions.BackendLua):
		return core.NewLuaManager(definitions.DefaultBackendName, authDeps), nil
	default:
		return nil, errors.New("unsupported backend")
	}
}
