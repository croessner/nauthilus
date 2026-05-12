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

package grpcauthority

import (
	"context"
	"errors"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/croessner/nauthilus/server/model/mfa"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BackendManagerIdentityServiceDeps contains domain dependencies for authority identity operations.
type BackendManagerIdentityServiceDeps struct {
	AuthService core.AuthApplicationService
	AuthDeps    core.AuthDeps
}

type backendManagerIdentityService struct {
	authService core.AuthApplicationService
	authDeps    core.AuthDeps
}

// NewBackendManagerIdentityService constructs the default authority identity service.
func NewBackendManagerIdentityService(deps BackendManagerIdentityServiceDeps) AuthorityIdentityService {
	return &backendManagerIdentityService{
		authService: deps.AuthService,
		authDeps:    deps.AuthDeps,
	}
}

func (s *backendManagerIdentityService) ResolveUser(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	if s == nil || s.authService == nil {
		return nil, status.Error(codes.Internal, "auth application service is not configured")
	}

	authInput := core.NewAuthInputFromStructuredRequest(definitions.ServGRPC, core.AuthModeLookupIdentity, identityRequestToAuthDTO(input))

	outcome, err := s.authService.LookupIdentity(ctx, authInput)
	if err != nil {
		return nil, err
	}

	if outcome == nil {
		return nil, status.Error(codes.Internal, "lookup identity returned no outcome")
	}

	backend := BackendRefPayload{
		Type:              outcome.Backend.String(),
		Name:              definitions.DefaultBackendName,
		Protocol:          input.Context.GetProtocol(),
		Username:          input.Username,
		Account:           firstAttributeValue(outcome.Attributes, outcome.AccountField, input.Username),
		ServicePrincipal:  authorityCallerFromContext(ctx).Principal,
		EdgeClusterID:     authorityCallerFromContext(ctx).EdgeClusterID,
		EdgeInstanceID:    input.Context.GetEdgeInstance(),
		EdgeRequestID:     input.Context.GetEdgeRequestId(),
		AllowedOperations: allowedOperationsAfterAuth(AuthorityOperationLookupIdentity),
	}

	return &AuthorityIdentityResult{
		Status: authDecisionStatus(outcome.Decision, outcome.StatusMessage, outcome.Error),
		User: &AuthorityUserSnapshot{
			Username:   input.Username,
			Account:    backend.Account,
			Attributes: releasedAttributes(outcome.Attributes, input.Attributes),
			Backend:    backend,
		},
		Backend: backend,
	}, nil
}

func (s *backendManagerIdentityService) GetMFAState(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if passDBResult, passErr := manager.PassDB(auth); passErr == nil && passDBResult != nil {
		applyPassDBResult(auth, passDBResult)
	}

	credentials, err := manager.GetWebAuthnCredentials(auth)
	if err != nil {
		return nil, err
	}

	state := AuthorityMFAState{
		HasTOTP:           auth.GetTOTPSecret() != "",
		RecoveryCodeCount: uint32(len(auth.GetTOTPRecoveryCodes())),
		HasWebAuthn:       len(credentials) > 0,
		Credentials:       credentials,
	}

	return &AuthorityIdentityResult{
		Status:  okOperationStatus(),
		MFA:     state,
		Backend: input.Backend,
	}, nil
}

func (s *backendManagerIdentityService) BeginTOTPRegistration(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Nauthilus",
		AccountName: input.Username,
	})
	if err != nil {
		return nil, err
	}

	secret := key.Secret()

	return &AuthorityIdentityResult{
		Status:                okOperationStatus(),
		Backend:               input.Backend,
		PendingRegistrationID: secret,
		TOTPSecret:            secret,
		OTPAuthURL:            key.URL(),
		ExpiresAt:             time.Now().Add(10 * time.Minute),
	}, nil
}

func (s *backendManagerIdentityService) FinishTOTPRegistration(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	if !totp.Validate(input.Code, input.PendingRegistrationID) {
		return &AuthorityIdentityResult{
			Status:  validationOperationStatus("totp_invalid", "TOTP code is invalid"),
			Backend: input.Backend,
		}, nil
	}

	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if err = manager.AddTOTPSecret(auth, core.NewTOTPSecret(input.PendingRegistrationID)); err != nil {
		return nil, err
	}

	return changedMFAResult(input.Backend), nil
}

func (s *backendManagerIdentityService) VerifyTOTP(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	result, err := s.GetMFAState(ctx, input)
	if err != nil {
		return nil, err
	}

	auth, _, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	valid := core.TotpValidation(&gin.Context{}, auth, input.Code, s.authDeps) == nil
	result.Valid = valid

	return result, nil
}

func (s *backendManagerIdentityService) DeleteTOTP(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if err = manager.DeleteTOTPSecret(auth); err != nil {
		return nil, err
	}

	return changedMFAResult(input.Backend), nil
}

func (s *backendManagerIdentityService) GenerateRecoveryCodes(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	recovery, err := core.GenerateBackupCodes()
	if err != nil {
		return nil, err
	}

	codes := recovery.GetCodes()
	if input.Count > 0 && int(input.Count) < len(codes) {
		codes = codes[:input.Count]
		recovery = mfa.NewTOTPRecovery(codes)
	}

	if err = manager.AddTOTPRecoveryCodes(auth, recovery); err != nil {
		return nil, err
	}

	return &AuthorityIdentityResult{
		Status:            okOperationStatus(),
		Backend:           input.Backend,
		Changed:           true,
		RecoveryCodes:     append([]string(nil), codes...),
		RecoveryCodeCount: uint32(len(codes)),
	}, nil
}

func (s *backendManagerIdentityService) UseRecoveryCode(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	result, err := s.VerifyTOTP(ctx, input)
	if err != nil {
		return nil, err
	}

	result.Changed = result.Valid
	result.RemainingRecoveryCodeCount = result.MFA.RecoveryCodeCount

	return result, nil
}

func (s *backendManagerIdentityService) DeleteRecoveryCodes(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if err = manager.DeleteTOTPRecoveryCodes(auth); err != nil {
		return nil, err
	}

	return changedMFAResult(input.Backend), nil
}

func (s *backendManagerIdentityService) GetWebAuthnCredentials(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	credentials, err := manager.GetWebAuthnCredentials(auth)
	if err != nil {
		return nil, err
	}

	return &AuthorityIdentityResult{
		Status:      okOperationStatus(),
		Backend:     input.Backend,
		Credentials: credentials,
		MFA: AuthorityMFAState{
			HasWebAuthn: len(credentials) > 0,
			Credentials: credentials,
		},
	}, nil
}

func (s *backendManagerIdentityService) SaveWebAuthnCredential(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if err = manager.SaveWebAuthnCredential(auth, input.Credential); err != nil {
		return nil, err
	}

	return changedMFAResult(input.Backend), nil
}

func (s *backendManagerIdentityService) UpdateWebAuthnCredential(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if err = manager.UpdateWebAuthnCredential(auth, input.OldCredential, input.NewCredential); err != nil {
		return nil, err
	}

	return changedMFAResult(input.Backend), nil
}

func (s *backendManagerIdentityService) DeleteWebAuthnCredential(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if err = manager.DeleteWebAuthnCredential(auth, &mfa.PersistentCredential{
		Credential: webauthn.Credential{ID: append([]byte(nil), input.CredentialID...)},
	}); err != nil {
		return nil, err
	}

	return changedMFAResult(input.Backend), nil
}

func (s *backendManagerIdentityService) authAndManager(input AuthorityIdentityInput) (*core.AuthState, core.BackendManager, error) {
	auth := core.NewAuthStateFromContextWithDeps(nil, s.authDeps).(*core.AuthState)
	auth.SetUsername(input.Username)
	auth.SetAccount(nonEmpty(input.Backend.Account, input.Username))
	auth.SetProtocol(config.NewProtocol(nonEmpty(input.Backend.Protocol, definitions.ProtoDefault)))
	auth.SetNoAuth(true)
	auth.Runtime.UsedPassDBBackend = backendTypeFromRef(input.Backend.Type)
	auth.Runtime.SourcePassDBBackend = auth.Runtime.UsedPassDBBackend
	auth.Runtime.BackendName = input.Backend.Name

	manager := auth.GetBackendManager(auth.Runtime.UsedPassDBBackend, input.Backend.Name)
	if manager == nil {
		return nil, nil, errors.New("identity backend manager is not available")
	}

	return auth, manager, nil
}

func identityRequestToAuthDTO(input AuthorityIdentityInput) authdto.Request {
	request := authdto.Request{
		Username: input.Username,
		Protocol: definitions.ProtoDefault,
	}

	if input.Context == nil {
		return request
	}

	request.ClientIP = input.Context.GetClientIp()
	request.ClientPort = input.Context.GetClientPort()
	request.ClientHostname = input.Context.GetClientHostname()
	request.ClientID = input.Context.GetClientId()
	request.ExternalSessionID = input.Context.GetExternalSessionId()
	request.UserAgent = input.Context.GetUserAgent()
	request.LocalIP = input.Context.GetLocalIp()
	request.LocalPort = input.Context.GetLocalPort()
	request.Protocol = nonEmpty(input.Context.GetProtocol(), definitions.ProtoDefault)
	request.Method = input.Context.GetMethod()
	request.OIDCCID = input.Context.GetOidcCid()
	request.AuthLoginAttempt = uint(input.Context.GetAuthLoginAttempt())

	return request
}

func backendTypeFromRef(value string) definitions.Backend {
	switch value {
	case definitions.BackendLDAPName:
		return definitions.BackendLDAP
	case definitions.BackendLuaName:
		return definitions.BackendLua
	case definitions.BackendTestName:
		return definitions.BackendTest
	default:
		return definitions.BackendTest
	}
}

func releasedAttributes(attributes bktype.AttributeMapping, request *identityv1.AttributeRequest) map[string][]string {
	if len(attributes) == 0 {
		return nil
	}

	if request == nil || len(request.GetNames()) == 0 {
		return allAttributes(attributes)
	}

	result := make(map[string][]string, len(request.GetNames()))
	for _, name := range request.GetNames() {
		if values, ok := attributes[name]; ok {
			result[name] = stringifyAttributeValues(values)
		}
	}

	return result
}

func allAttributes(attributes bktype.AttributeMapping) map[string][]string {
	result := make(map[string][]string, len(attributes))
	for name, values := range attributes {
		result[name] = stringifyAttributeValues(values)
	}

	return result
}

func firstAttributeValue(attributes bktype.AttributeMapping, field string, fallback string) string {
	if field == "" {
		return fallback
	}

	values := stringifyAttributeValues(attributes[field])
	if len(values) == 0 {
		return fallback
	}

	return values[0]
}

func applyPassDBResult(auth *core.AuthState, result *core.PassDBResult) {
	if auth == nil || result == nil {
		return
	}

	auth.Runtime.UsedPassDBBackend = result.Backend
	auth.Runtime.BackendName = result.BackendName
	auth.Runtime.AccountName = result.Account
	auth.Runtime.AccountField = result.AccountField
	auth.Runtime.TOTPSecretField = result.TOTPSecretField
	auth.Runtime.TOTPRecoveryField = result.TOTPRecoveryField
	auth.Runtime.UniqueUserIDField = result.UniqueUserIDField
	auth.Runtime.DisplayNameField = result.DisplayNameField
	auth.Runtime.Authenticated = result.Authenticated
	auth.Runtime.UserFound = result.UserFound
	auth.ReplaceAllAttributes(result.Attributes)
	auth.Groups.Groups = append([]string(nil), result.Groups...)
	auth.Groups.GroupDNs = append([]string(nil), result.GroupDNs...)
}

func authDecisionStatus(decision core.AuthDecision, message string, errText string) *commonv1.OperationStatus {
	switch decision {
	case core.AuthDecisionOK:
		return okOperationStatus()
	case core.AuthDecisionFail:
		return &commonv1.OperationStatus{
			Result:      commonv1.OperationResult_OPERATION_RESULT_FAIL,
			ErrorCode:   errText,
			SafeMessage: message,
		}
	case core.AuthDecisionTempFail:
		return &commonv1.OperationStatus{
			Result:      commonv1.OperationResult_OPERATION_RESULT_TEMPFAIL,
			ErrorCode:   errText,
			SafeMessage: message,
		}
	default:
		return &commonv1.OperationStatus{Result: commonv1.OperationResult_OPERATION_RESULT_UNSPECIFIED}
	}
}

func validationOperationStatus(code string, message string) *commonv1.OperationStatus {
	return &commonv1.OperationStatus{
		Result:      commonv1.OperationResult_OPERATION_RESULT_DENIED,
		ErrorCode:   code,
		SafeMessage: message,
	}
}

func okOperationStatus() *commonv1.OperationStatus {
	return &commonv1.OperationStatus{Result: commonv1.OperationResult_OPERATION_RESULT_OK}
}

func changedMFAResult(backend BackendRefPayload) *AuthorityIdentityResult {
	return &AuthorityIdentityResult{
		Status:  okOperationStatus(),
		Backend: backend,
		Changed: true,
	}
}
