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

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/mfa"
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
	issuer := "NauthilusTest"
	account := "testuser"
	secret, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})

	cfg := &mockTotpConfig{issuer: issuer, skew: 1}
	deps := AuthDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		Env:    &mockEnv{},
	}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/", nil)
	ctx.Set(definitions.CtxServiceKey, "test")
	ctx.Set(definitions.CtxGUIDKey, "test-guid")
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	t.Run("ValidCode", func(t *testing.T) {
		auth := NewAuthStateFromContextWithDeps(ctx, deps).(*AuthState)
		auth.SetUsername(account)
		auth.SetAccount(account)

		// Use a hardcoded secret
		hardcodedSecret := "JBSWY3DPEHPK3PXP"
		auth.SetTOTPSecret(hardcodedSecret)

		codeNow, _ := totp.GenerateCode(hardcodedSecret, time.Now())
		err := TotpValidation(ctx, auth, codeNow, deps)
		assert.NoError(t, err)
	})

	t.Run("InvalidCode", func(t *testing.T) {
		auth := NewAuthStateFromContextWithDeps(ctx, deps).(*AuthState)
		auth.SetUsername(account)
		auth.SetAccount(account)
		auth.SetTOTPSecret(secret.Secret())

		err := TotpValidation(ctx, auth, "000000", deps)
		assert.Error(t, err)
	})

	t.Run("RecoveryCode", func(t *testing.T) {
		mBackend := new(mockBackend)
		auth := NewAuthStateFromContextWithDeps(ctx, deps).(*AuthState)
		auth.SetUsername(account)
		auth.SetAccount(account)
		auth.SetTOTPSecret(secret.Secret())

		// Setup recovery codes in AuthState attributes
		auth.Attributes.Attributes = bktype.AttributeMapping{
			"totp_recovery": {"recovery1", "recovery2"},
		}
		// We need to make sure auth.GetTOTPRecoveryField() returns "totp_recovery"
		// In AuthState, it depends on PassDBResult.TOTPRecoveryField
		auth.Runtime.TOTPRecoveryField = "totp_recovery"

		// Mock expectations
		mBackend.On("DeleteTOTPRecoveryCodes", auth).Return(nil)
		mBackend.On("AddTOTPRecoveryCodes", auth, mock.MatchedBy(func(r *mfa.TOTPRecovery) bool {
			return len(r.GetCodes()) == 1 && r.GetCodes()[0] == "recovery2"
		})).Return(nil)

		// Inject mock backend
		deps.Backend = mBackend

		err := TotpValidation(ctx, auth, "recovery1", deps)
		assert.NoError(t, err)
		mBackend.AssertExpectations(t)
	})
}
