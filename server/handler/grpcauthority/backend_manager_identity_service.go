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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/croessner/nauthilus/server/model/mfa"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrWebAuthnCredentialStateMismatch reports a stale or missing persistent credential during compare-and-update.
var ErrWebAuthnCredentialStateMismatch = errors.New("webauthn credential state mismatch")

// BackendManagerIdentityServiceDeps contains domain dependencies for authority identity operations.
type BackendManagerIdentityServiceDeps struct {
	AuthService core.AuthApplicationService
	AuthDeps    core.AuthDeps
}

type backendManagerIdentityService struct {
	authService core.AuthApplicationService
	authDeps    core.AuthDeps
	totpPending *pendingTOTPStore
}

// NewBackendManagerIdentityService constructs the default authority identity service.
func NewBackendManagerIdentityService(deps BackendManagerIdentityServiceDeps) AuthorityIdentityService {
	return &backendManagerIdentityService{
		authService: deps.AuthService,
		authDeps:    deps.AuthDeps,
		totpPending: newPendingTOTPStore(10 * time.Minute),
	}
}

type pendingTOTPRegistration struct {
	expiresAt time.Time
	backend   BackendRefPayload
	username  string
	secret    string
}

type pendingTOTPStore struct {
	ttl     time.Duration
	mu      sync.Mutex
	entries map[string]pendingTOTPRegistration
}

func newPendingTOTPStore(ttl time.Duration) *pendingTOTPStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	return &pendingTOTPStore{
		ttl:     ttl,
		entries: make(map[string]pendingTOTPRegistration),
	}
}

func (s *pendingTOTPStore) create(username string, backend BackendRefPayload, secret string) (string, time.Time, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, err
	}

	id := base64.RawURLEncoding.EncodeToString(tokenBytes)
	expiresAt := time.Now().UTC().Add(s.ttl)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneLocked(time.Now().UTC())
	s.entries[id] = pendingTOTPRegistration{
		expiresAt: expiresAt,
		backend:   backend,
		username:  username,
		secret:    secret,
	}

	return id, expiresAt, nil
}

func (s *pendingTOTPStore) consume(id string, username string, backend BackendRefPayload) (string, bool) {
	if s == nil || id == "" {
		return "", false
	}

	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneLocked(now)

	registration, ok := s.entries[id]
	if !ok || registration.username != username || !sameBackendBinding(registration.backend, backend) {
		return "", false
	}

	delete(s.entries, id)

	return registration.secret, true
}

func (s *pendingTOTPStore) pruneLocked(now time.Time) {
	for id, registration := range s.entries {
		if !now.Before(registration.expiresAt) {
			delete(s.entries, id)
		}
	}
}

func sameBackendBinding(left BackendRefPayload, right BackendRefPayload) bool {
	return left.Type == right.Type &&
		left.Name == right.Name &&
		left.Protocol == right.Protocol &&
		left.Authority == right.Authority &&
		left.Username == right.Username &&
		left.ServicePrincipal == right.ServicePrincipal
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

	backend := backendPayloadFromOutcome(ctx, input, outcome)

	mfaState, err := s.resolveMFAStateForSnapshot(ctx, input, backend)
	if err != nil {
		return nil, err
	}

	return &AuthorityIdentityResult{
		Status:  authDecisionStatus(outcome.Decision, outcome.StatusMessage, outcome.Error),
		User:    userSnapshotFromOutcome(input, outcome, backend, mfaState),
		Backend: backend,
	}, nil
}

func (s *backendManagerIdentityService) resolveMFAStateForSnapshot(
	ctx context.Context,
	input AuthorityIdentityInput,
	backend BackendRefPayload,
) (AuthorityMFAState, error) {
	if !input.IncludeMFAState {
		return AuthorityMFAState{}, nil
	}

	result, err := s.GetMFAState(ctx, AuthorityIdentityInput{
		Operation:                  AuthorityOperationGetMFAState,
		Context:                    input.Context,
		Username:                   input.Username,
		Backend:                    backend,
		IncludeWebAuthnCredentials: input.IncludeWebAuthnCredentials,
	})
	if err != nil {
		return AuthorityMFAState{}, err
	}

	return result.GetMFA(), nil
}

func backendPayloadFromOutcome(ctx context.Context, input AuthorityIdentityInput, outcome *core.AuthOutcome) BackendRefPayload {
	caller := authorityCallerFromContext(ctx)

	return BackendRefPayload{
		Type:              outcome.Backend.String(),
		Name:              definitions.DefaultBackendName,
		Protocol:          input.Context.GetProtocol(),
		Username:          input.Username,
		Account:           firstAttributeValue(outcome.Attributes, outcome.AccountField, input.Username),
		ServicePrincipal:  caller.Principal,
		EdgeClusterID:     caller.EdgeClusterID,
		EdgeInstanceID:    input.Context.GetEdgeInstance(),
		EdgeRequestID:     input.Context.GetEdgeRequestId(),
		AllowedOperations: allowedOperationsAfterAuth(AuthorityOperationLookupIdentity),
	}
}

func userSnapshotFromOutcome(
	input AuthorityIdentityInput,
	outcome *core.AuthOutcome,
	backend BackendRefPayload,
	mfaState AuthorityMFAState,
) *AuthorityUserSnapshot {
	return &AuthorityUserSnapshot{
		Username:     input.Username,
		Account:      backend.Account,
		UniqueUserID: firstAttributeValue(outcome.Attributes, outcome.UniqueUserIDField, ""),
		DisplayName:  firstAttributeValue(outcome.Attributes, outcome.DisplayNameField, backend.Account),
		Attributes: releasedAttributes(
			outcome.Attributes,
			input.Attributes,
			outcome.TOTPSecretField,
			outcome.TOTPRecoveryField,
		),
		Groups:   groupsForRequest(outcome.Groups, input.Attributes),
		GroupDNS: groupDNSForRequest(outcome.GroupDNS, input.Attributes),
		Backend:  backend,
		MFA:      mfaState,
	}
}

func (s *backendManagerIdentityService) GetMFAState(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	passDBResult, passErr := manager.PassDB(auth)
	if passErr != nil {
		return nil, passErr
	}

	if passDBResult != nil {
		applyPassDBResult(auth, passDBResult)
	}

	var credentials []mfa.PersistentCredential
	if input.IncludeWebAuthnCredentials {
		credentials, err = manager.GetWebAuthnCredentials(auth)
		if err != nil {
			return nil, err
		}
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

	pendingID, expiresAt, err := s.totpPending.create(input.Username, input.Backend, secret)
	if err != nil {
		return nil, err
	}

	return &AuthorityIdentityResult{
		Status:                okOperationStatus(),
		Backend:               input.Backend,
		PendingRegistrationID: pendingID,
		TOTPSecret:            secret,
		OTPAuthURL:            key.URL(),
		ExpiresAt:             expiresAt,
	}, nil
}

func (s *backendManagerIdentityService) FinishTOTPRegistration(_ context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	secret, ok := s.totpPending.consume(input.PendingRegistrationID, input.Username, input.Backend)
	if !ok {
		return &AuthorityIdentityResult{
			Status:  validationOperationStatus("totp_pending_invalid", "TOTP registration is invalid or expired"),
			Backend: input.Backend,
		}, nil
	}

	if !totp.Validate(input.Code, secret) {
		return &AuthorityIdentityResult{
			Status:  validationOperationStatus("totp_invalid", "TOTP code is invalid"),
			Backend: input.Backend,
		}, nil
	}

	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if err = manager.AddTOTPSecret(auth, core.NewTOTPSecret(secret)); err != nil {
		return nil, err
	}

	return changedMFAResult(input.Backend), nil
}

func (s *backendManagerIdentityService) VerifyTOTP(ctx context.Context, input AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	passDBResult, passErr := manager.PassDB(auth)
	if passErr != nil {
		return nil, passErr
	}

	if passDBResult != nil {
		applyPassDBResult(auth, passDBResult)
	}

	err = core.ValidateTOTPCode(input.Code, auth.GetTOTPSecret(), s.authDeps)
	valid := err == nil

	result := &AuthorityIdentityResult{
		Status:  okOperationStatus(),
		Backend: input.Backend,
		Valid:   valid,
		MFA: AuthorityMFAState{
			HasTOTP:           auth.GetTOTPSecret() != "",
			RecoveryCodeCount: uint32(len(auth.GetTOTPRecoveryCodes())),
		},
	}

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
	_ = ctx

	auth, manager, err := s.authAndManager(input)
	if err != nil {
		return nil, err
	}

	if consumer, ok := manager.(core.TOTPRecoveryCodeConsumer); ok {
		valid, remaining, consumeErr := consumer.ConsumeTOTPRecoveryCode(auth, input.Code)
		if consumeErr != nil {
			return nil, consumeErr
		}

		return recoveryUseResult(input.Backend, valid, remaining), nil
	}

	passDBResult, passErr := manager.PassDB(auth)
	if passErr != nil {
		return nil, passErr
	}

	if passDBResult != nil {
		applyPassDBResult(auth, passDBResult)
	}

	valid, remaining, err := consumeRecoveryCodeFallback(auth, manager, input.Code)
	if err != nil {
		return nil, err
	}

	return recoveryUseResult(input.Backend, valid, remaining), nil
}

func consumeRecoveryCodeFallback(auth *core.AuthState, manager core.BackendManager, code string) (bool, int, error) {
	recoveryCodes := auth.GetTOTPRecoveryCodes()

	for index, recoveryCode := range recoveryCodes {
		if recoveryCode != code {
			continue
		}

		remainingCodes := append([]string(nil), recoveryCodes[:index]...)
		remainingCodes = append(remainingCodes, recoveryCodes[index+1:]...)

		if len(remainingCodes) == 0 {
			if err := manager.DeleteTOTPRecoveryCodes(auth); err != nil {
				return true, len(recoveryCodes), err
			}

			return true, 0, nil
		}

		if err := manager.AddTOTPRecoveryCodes(auth, mfa.NewTOTPRecovery(remainingCodes)); err != nil {
			return true, len(recoveryCodes), err
		}

		return true, len(remainingCodes), nil
	}

	return false, len(recoveryCodes), nil
}

func recoveryUseResult(backend BackendRefPayload, valid bool, remaining int) *AuthorityIdentityResult {
	return &AuthorityIdentityResult{
		Status:                     okOperationStatus(),
		Backend:                    backend,
		Changed:                    valid,
		Valid:                      valid,
		RemainingRecoveryCodeCount: uint32(remaining),
		MFA: AuthorityMFAState{
			RecoveryCodeCount: uint32(remaining),
		},
	}
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

	if err = compareWebAuthnCredentialState(manager, auth, input.OldCredential, input.NewCredential); err != nil {
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

func compareWebAuthnCredentialState(
	manager core.BackendManager,
	auth *core.AuthState,
	oldCredential *mfa.PersistentCredential,
	newCredential *mfa.PersistentCredential,
) error {
	if manager == nil || auth == nil || oldCredential == nil || newCredential == nil {
		return ErrWebAuthnCredentialStateMismatch
	}

	if !bytes.Equal(oldCredential.ID, newCredential.ID) {
		return ErrWebAuthnCredentialStateMismatch
	}

	credentials, err := manager.GetWebAuthnCredentials(auth)
	if err != nil {
		return err
	}

	for index := range credentials {
		stored := credentials[index]
		if !bytes.Equal(stored.ID, oldCredential.ID) {
			continue
		}

		if stored.Authenticator.SignCount != oldCredential.Authenticator.SignCount {
			return ErrWebAuthnCredentialStateMismatch
		}

		return nil
	}

	return ErrWebAuthnCredentialStateMismatch
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

func releasedAttributes(attributes bktype.AttributeMapping, request *identityv1.AttributeRequest, deniedNames ...string) map[string][]string {
	if len(attributes) == 0 {
		return nil
	}

	denied := deniedAttributeSet(deniedNames...)
	if request == nil || len(request.GetNames()) == 0 {
		return allAttributes(attributes, denied)
	}

	result := make(map[string][]string, len(request.GetNames()))
	for _, name := range request.GetNames() {
		if _, deny := denied[name]; deny {
			continue
		}

		if values, ok := attributes[name]; ok {
			result[name] = stringifyAttributeValues(values)
		}
	}

	return result
}

func allAttributes(attributes bktype.AttributeMapping, denied map[string]struct{}) map[string][]string {
	result := make(map[string][]string, len(attributes))
	for name, values := range attributes {
		if _, deny := denied[name]; deny {
			continue
		}

		result[name] = stringifyAttributeValues(values)
	}

	return result
}

func deniedAttributeSet(names ...string) map[string]struct{} {
	if len(names) == 0 {
		return nil
	}

	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name != "" {
			result[name] = struct{}{}
		}
	}

	return result
}

func groupsForRequest(groups []string, request *identityv1.AttributeRequest) []string {
	if request == nil || request.GetIncludeGroups() {
		return append([]string(nil), groups...)
	}

	return nil
}

func groupDNSForRequest(groupDNS []string, request *identityv1.AttributeRequest) []string {
	if request == nil || request.GetIncludeGroupDns() {
		return append([]string(nil), groupDNS...)
	}

	return nil
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
