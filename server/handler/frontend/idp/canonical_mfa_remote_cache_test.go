// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonv1 "github.com/croessner/nauthilus/v4/api/common/v1"
	identityv1 "github.com/croessner/nauthilus/v4/api/identity/v1"
	"github.com/croessner/nauthilus/v4/server/backend/remote"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// successfulMFACacheAuthority provides authority writes while preserving the existing read fixture.
type successfulMFACacheAuthority struct {
	*remoteBackendDataAuthorityClient
	err error
}

// FinishTOTPRegistration models an authority-owned TOTP write.
func (a *successfulMFACacheAuthority) FinishTOTPRegistration(context.Context, *identityv1.FinishTOTPRegistrationRequest) (*identityv1.MFAWriteResponse, error) {
	return &identityv1.MFAWriteResponse{Status: mfaCacheOperationStatus(), Changed: true}, a.err
}

// DeleteTOTP models an authority-owned TOTP deletion.
func (a *successfulMFACacheAuthority) DeleteTOTP(context.Context, *identityv1.DeleteTOTPRequest) (*identityv1.MFAWriteResponse, error) {
	return &identityv1.MFAWriteResponse{Status: mfaCacheOperationStatus(), Changed: true}, a.err
}

// GenerateRecoveryCodes persists generated codes at the authority before browser acknowledgement.
func (a *successfulMFACacheAuthority) GenerateRecoveryCodes(context.Context, *identityv1.GenerateRecoveryCodesRequest) (*identityv1.GenerateRecoveryCodesResponse, error) {
	return &identityv1.GenerateRecoveryCodesResponse{Status: mfaCacheOperationStatus(), Codes: []string{"new-code"}}, a.err
}

// UseRecoveryCode models a successful atomic authority consumption.
func (a *successfulMFACacheAuthority) UseRecoveryCode(context.Context, *identityv1.UseRecoveryCodeRequest) (*identityv1.UseRecoveryCodeResponse, error) {
	return &identityv1.UseRecoveryCodeResponse{Status: mfaCacheOperationStatus(), Valid: true}, a.err
}

// mfaCacheOperationStatus builds the successful authority status shared by write fixtures.
func mfaCacheOperationStatus() *commonv1.OperationStatus {
	return &commonv1.OperationStatus{Result: commonv1.OperationResult_OPERATION_RESULT_OK}
}

// TestCanonicalRemoteMFAWritesPurgeOnlyAfterSuccess covers authority mutations and failures.
func TestCanonicalRemoteMFAWritesPurgeOnlyAfterSuccess(t *testing.T) {
	for _, operation := range []string{"totp-enroll", "recovery-enroll", "totp-delete", "recovery-generate", "recovery-use"} {
		for _, failed := range []bool{false, true} {
			name := operation
			if failed {
				name += "-failure"
			}

			t.Run(name, func(t *testing.T) {
				fixture := newBackendDataRemoteFixture(t)
				remoteConfig := fixture.cfg.Auth.Backends.Remote[remoteBackendDataAuthorityBackend]
				remoteConfig.AllowedOperations = append(remoteConfig.AllowedOperations, config.RemoteBackendOperationMFAWrite, config.RemoteBackendOperationMFAVerify)

				authority := &successfulMFACacheAuthority{remoteBackendDataAuthorityClient: newRemoteBackendDataAuthorityClient()}
				if failed {
					authority.err = errors.New("authority write failed")
				}

				t.Cleanup(remote.SetAuthorityClientForTest(remoteBackendDataAuthority, authority))
				fixture.mock.ExpectDel(fixture.cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + backendDataUniqueUserID).SetVal(0)
				h := newBackendDataFrontendHandler(fixture.backendDataBaseFixture)
				cache := &canonicalMFACacheFixture{}
				h.deps.HostServices = newMFACacheHostServices(t, cache)
				ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
				ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/register", nil)
				ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)

				selection := canonicalEnrollmentSelectionState{identity: cookie.SessionIdentity{
					Account: backendDataUsername, Reference: backendDataUniqueUserID, Protocol: definitions.ProtoIDP,
				}}

				err := runCanonicalRemoteMFAWrite(h, ctx, selection, operation)

				assert.NoError(t, fixture.mock.ExpectationsWereMet())

				if failed {
					assert.Error(t, err)
					assert.Empty(t, cache.purged)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, []string{backendDataUsername}, cache.purged)
				}
			})
		}
	}
}

// runCanonicalRemoteMFAWrite exercises the production write boundary selected by the table.
func runCanonicalRemoteMFAWrite(h *FrontendHandler, ctx *gin.Context, selection canonicalEnrollmentSelectionState, operation string) error {
	var err error

	switch operation {
	case "totp-enroll":
		_, err = h.finishCanonicalTOTPEnrollment(ctx, selection, canonicalTOTPEnrollmentPending{Remote: true, PendingRegistrationID: "pending"}, "operation", "123456")
	case "recovery-enroll":
		_, err = h.generateCanonicalRecoveryEnrollment(ctx, selection, "operation")
	case "recovery-use":
		_, err = h.verifyCanonicalRecovery(ctx, canonicalMFASelectionState{identity: selection.identity}, "code")
	default:
		data, lookupErr := h.canonicalEnrollmentBackendData(ctx, selection)
		if lookupErr != nil {
			return lookupErr
		}

		if operation == "totp-delete" {
			err = h.deleteCanonicalSelfServiceTOTP(ctx, data)
		} else {
			_, err = h.generateCanonicalSelfServiceRecoveryCodes(ctx, data)
		}
	}

	return err
}
