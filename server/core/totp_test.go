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

package core

import (
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockBackend struct {
	mock.Mock
	BackendManager
}

func (m *mockBackend) AddTOTPRecoveryCodes(auth *AuthState, recovery *mfa.TOTPRecovery) error {
	args := m.Called(auth, recovery)
	return args.Error(0)
}

func (m *mockBackend) DeleteTOTPRecoveryCodes(auth *AuthState) error {
	args := m.Called(auth)
	return args.Error(0)
}

func (m *mockBackend) AccountDB(auth *AuthState) (AccountList, error) {
	args := m.Called(auth)
	return args.Get(0).(AccountList), args.Error(1)
}

type mockTotpConfig struct {
	config.File
	issuer string
	skew   uint
}

func (m *mockTotpConfig) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Frontend: config.Frontend{
			TotpIssuer: m.issuer,
			TotpSkew:   m.skew,
		},
		Log: config.Log{
			// Default values
		},
	}
}

type mockEnv struct {
	config.Environment
}

func (m *mockEnv) GetDevMode() bool {
	return true
}

func TestTotpValidation(t *testing.T) {
	fixture := newTOTPValidationFixture(t)

	t.Run("ValidCode", func(t *testing.T) {
		auth := fixture.newAuthState()

		hardcodedSecret := "JBSWY3DPEHPK3PXP"
		auth.SetTOTPSecret(hardcodedSecret)

		codeNow, _ := totp.GenerateCode(hardcodedSecret, time.Now())
		err := TotpValidation(fixture.ctx, auth, codeNow, fixture.deps)
		assert.NoError(t, err)
	})

	t.Run("InvalidCode", func(t *testing.T) {
		auth := fixture.newAuthState()
		auth.SetTOTPSecret(fixture.generatedSecret)

		err := TotpValidation(fixture.ctx, auth, "000000", fixture.deps)
		assert.Error(t, err)
	})

	t.Run("RecoveryCode", func(t *testing.T) {
		fixture.assertRecoveryCode(t)
	})
}

type totpValidationFixture struct {
	deps            AuthDeps
	ctx             *gin.Context
	account         string
	generatedSecret string
}

// newTOTPValidationFixture creates shared TOTP validation test state.
func newTOTPValidationFixture(t *testing.T) totpValidationFixture {
	t.Helper()

	issuer := "NauthilusTest"
	account := "testuser"
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	assert.NoError(t, err)

	deps := AuthDeps{
		Cfg:    &mockTotpConfig{issuer: issuer, skew: 1},
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		Env:    &mockEnv{},
	}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/", nil)
	ctx.Set(definitions.CtxServiceKey, "test")
	ctx.Set(definitions.CtxGUIDKey, "test-guid")
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	return totpValidationFixture{
		deps:            deps,
		ctx:             ctx,
		account:         account,
		generatedSecret: secret.Secret(),
	}
}

// newAuthState creates an AuthState initialized with the fixture account.
func (f totpValidationFixture) newAuthState() *AuthState {
	auth := NewAuthStateFromContextWithDeps(f.ctx, f.deps).(*AuthState)
	auth.SetUsername(f.account)
	auth.SetAccount(f.account)

	return auth
}

// assertRecoveryCode verifies successful recovery-code consumption.
func (f totpValidationFixture) assertRecoveryCode(t *testing.T) {
	t.Helper()

	mBackend := new(mockBackend)
	auth := f.newAuthState()
	auth.SetTOTPSecret(f.generatedSecret)
	auth.Attributes.Attributes = bktype.AttributeMapping{
		"totp_recovery": {"recovery1", "recovery2"},
	}
	auth.Runtime.TOTPRecoveryField = "totp_recovery"

	mBackend.On("DeleteTOTPRecoveryCodes", auth).Return(nil)
	mBackend.On("AddTOTPRecoveryCodes", auth, mock.MatchedBy(func(r *mfa.TOTPRecovery) bool {
		return len(r.GetCodes()) == 1 && r.GetCodes()[0] == "recovery2"
	})).Return(nil)

	deps := f.deps
	deps.Backend = mBackend

	err := TotpValidation(f.ctx, auth, "recovery1", deps)
	assert.NoError(t, err)
	mBackend.AssertExpectations(t)
}

func TestValidateTOTPCodeNormalizesAuthenticatorInput(t *testing.T) {
	cfg := &mockTotpConfig{issuer: "NauthilusTest", skew: 1}
	deps := AuthDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		Env:    &mockEnv{},
	}

	secret := "JBSWY3DPEHPK3PXP"
	codeNow, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	groupedCode := codeNow[:3] + " " + codeNow[3:]
	assert.NoError(t, ValidateTOTPCode(groupedCode, secret, deps))

	dashedCode := codeNow[:3] + "-" + codeNow[3:]
	assert.NoError(t, ValidateTOTPCode(dashedCode, secret, deps))
}

func TestValidateTOTPCodeAcceptsStoredOTPAuthURL(t *testing.T) {
	issuer := "NauthilusTest"
	account := "testuser"
	cfg := &mockTotpConfig{issuer: issuer, skew: 1}
	deps := AuthDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		Env:    &mockEnv{},
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	assert.NoError(t, err)

	codeNow, err := totp.GenerateCode(key.Secret(), time.Now())
	assert.NoError(t, err)
	assert.NoError(t, ValidateTOTPCode(codeNow, key.URL(), deps))
}
