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

	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/server/model/mfa"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ResolveUser resolves a user and releases allowed identity data.
func (h *Handler) ResolveUser(
	ctx context.Context,
	request *identityv1.ResolveUserRequest,
) (*identityv1.UserSnapshotResponse, error) {
	input := AuthorityIdentityInput{
		Operation:                  AuthorityOperationResolveUser,
		Context:                    request.GetContext(),
		Username:                   identityUsername(request.GetUsername(), request.GetContext()),
		Attributes:                 request.GetAttributes(),
		IncludeMFAState:            request.GetIncludeMfaState(),
		IncludeWebAuthnCredentials: request.GetIncludeWebauthnCredentials(),
	}
	if request.GetBackend().GetOpaqueToken() != "" {
		payload, err := h.validateBackendRef(ctx, request.GetBackend(), input.Username, AuthorityOperationResolveUser)
		if err != nil {
			return nil, err
		}

		input.Backend = *payload
	}

	result, err := h.resolveIdentityService().ResolveUser(ctx, input)
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	user, err := h.userSnapshotToProto(ctx, result.GetUser(), input)
	if err != nil {
		return nil, err
	}

	return &identityv1.UserSnapshotResponse{
		Status:            operationStatus(result),
		User:              user,
		MissingAttributes: append([]string(nil), result.GetMissingAttributes()...),
		DeniedAttributes:  append([]string(nil), result.GetDeniedAttributes()...),
	}, nil
}

// GetMFAState returns public MFA state for a validated backend reference.
func (h *Handler) GetMFAState(
	ctx context.Context,
	request *identityv1.GetMFAStateRequest,
) (*identityv1.MFAStateResponse, error) {
	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationGetMFAState)
	if err != nil {
		return nil, err
	}

	input.IncludeWebAuthnCredentials = request.GetIncludeWebauthnCredentials()

	result, err := h.resolveIdentityService().GetMFAState(ctx, input)
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	return &identityv1.MFAStateResponse{
		Status:  operationStatus(result),
		Mfa:     mfaStateToProto(result.GetMFA()),
		Backend: backendRefFromPayload(result.GetBackend(), request.GetBackend().GetOpaqueToken()),
	}, nil
}

// BeginTOTPRegistration starts a TOTP registration through the authority service.
func (h *Handler) BeginTOTPRegistration(
	ctx context.Context,
	request *identityv1.BeginTOTPRegistrationRequest,
) (*identityv1.BeginTOTPRegistrationResponse, error) {
	if err := h.reserveIdempotency(ctx, AuthorityOperationBeginTOTPRegistration, request.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationBeginTOTPRegistration)
	if err != nil {
		return nil, err
	}

	input.IdempotencyKey = request.GetIdempotencyKey()

	result, err := h.resolveIdentityService().BeginTOTPRegistration(ctx, input)
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	return &identityv1.BeginTOTPRegistrationResponse{
		Status:                operationStatus(result),
		PendingRegistrationId: result.GetPendingRegistrationID(),
		TotpSecret:            result.GetTOTPSecret(),
		OtpauthUrl:            result.GetOTPAuthURL(),
		ExpiresAt:             timestampFromResult(result.GetExpiresAt()),
		Backend:               backendRefFromPayload(result.GetBackend(), request.GetBackend().GetOpaqueToken()),
	}, nil
}

// FinishTOTPRegistration persists a verified TOTP registration.
func (h *Handler) FinishTOTPRegistration(
	ctx context.Context,
	request *identityv1.FinishTOTPRegistrationRequest,
) (*identityv1.MFAWriteResponse, error) {
	if err := h.reserveIdempotency(ctx, AuthorityOperationFinishTOTPRegistration, request.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationFinishTOTPRegistration)
	if err != nil {
		return nil, err
	}

	input.PendingRegistrationID = request.GetPendingRegistrationId()
	input.Code = request.GetCode()
	input.IdempotencyKey = request.GetIdempotencyKey()

	result, err := h.resolveIdentityService().FinishTOTPRegistration(ctx, input)

	return h.mfaWriteResponse(result, request.GetBackend(), err)
}

// VerifyTOTP verifies a TOTP code against the selected backend.
func (h *Handler) VerifyTOTP(
	ctx context.Context,
	request *identityv1.VerifyTOTPRequest,
) (*identityv1.VerifyTOTPResponse, error) {
	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationVerifyTOTP)
	if err != nil {
		return nil, err
	}

	input.Code = request.GetCode()

	result, err := h.resolveIdentityService().VerifyTOTP(ctx, input)
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	return &identityv1.VerifyTOTPResponse{
		Status:  operationStatus(result),
		Valid:   result.GetValid(),
		Backend: backendRefFromPayload(result.GetBackend(), request.GetBackend().GetOpaqueToken()),
	}, nil
}

// DeleteTOTP deletes persisted TOTP state for the selected backend.
func (h *Handler) DeleteTOTP(
	ctx context.Context,
	request *identityv1.DeleteTOTPRequest,
) (*identityv1.MFAWriteResponse, error) {
	return h.runMFAWrite(
		ctx,
		request.GetBackend(),
		request.GetUsername(),
		request.GetContext(),
		AuthorityOperationDeleteTOTP,
		request.GetIdempotencyKey(),
		h.resolveIdentityService().DeleteTOTP,
	)
}

// GenerateRecoveryCodes creates a fresh recovery-code set.
func (h *Handler) GenerateRecoveryCodes(
	ctx context.Context,
	request *identityv1.GenerateRecoveryCodesRequest,
) (*identityv1.GenerateRecoveryCodesResponse, error) {
	if err := h.reserveIdempotency(ctx, AuthorityOperationGenerateRecoveryCodes, request.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationGenerateRecoveryCodes)
	if err != nil {
		return nil, err
	}

	input.Count = request.GetCount()
	input.IdempotencyKey = request.GetIdempotencyKey()

	result, err := h.resolveIdentityService().GenerateRecoveryCodes(ctx, input)
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	return &identityv1.GenerateRecoveryCodesResponse{
		Status:            operationStatus(result),
		Codes:             append([]string(nil), result.GetRecoveryCodes()...),
		RecoveryCodeCount: result.GetRecoveryCodeCount(),
		Backend:           backendRefFromPayload(result.GetBackend(), request.GetBackend().GetOpaqueToken()),
	}, nil
}

// UseRecoveryCode verifies and consumes a recovery code.
func (h *Handler) UseRecoveryCode(
	ctx context.Context,
	request *identityv1.UseRecoveryCodeRequest,
) (*identityv1.UseRecoveryCodeResponse, error) {
	if err := h.reserveIdempotency(ctx, AuthorityOperationUseRecoveryCode, request.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationUseRecoveryCode)
	if err != nil {
		return nil, err
	}

	input.Code = request.GetCode()
	input.IdempotencyKey = request.GetIdempotencyKey()

	result, err := h.resolveIdentityService().UseRecoveryCode(ctx, input)
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	return &identityv1.UseRecoveryCodeResponse{
		Status:                     operationStatus(result),
		Valid:                      result.GetValid(),
		RemainingRecoveryCodeCount: result.GetRemainingRecoveryCodeCount(),
		Backend:                    backendRefFromPayload(result.GetBackend(), request.GetBackend().GetOpaqueToken()),
	}, nil
}

// DeleteRecoveryCodes removes all recovery codes for a user.
func (h *Handler) DeleteRecoveryCodes(
	ctx context.Context,
	request *identityv1.DeleteRecoveryCodesRequest,
) (*identityv1.MFAWriteResponse, error) {
	return h.runMFAWrite(
		ctx,
		request.GetBackend(),
		request.GetUsername(),
		request.GetContext(),
		AuthorityOperationDeleteRecoveryCodes,
		request.GetIdempotencyKey(),
		h.resolveIdentityService().DeleteRecoveryCodes,
	)
}

// GetWebAuthnCredentials returns public WebAuthn credentials.
func (h *Handler) GetWebAuthnCredentials(
	ctx context.Context,
	request *identityv1.GetWebAuthnCredentialsRequest,
) (*identityv1.WebAuthnCredentialsResponse, error) {
	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationGetWebAuthnCredentials)
	if err != nil {
		return nil, err
	}

	result, err := h.resolveIdentityService().GetWebAuthnCredentials(ctx, input)
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	return &identityv1.WebAuthnCredentialsResponse{
		Status:      operationStatus(result),
		Credentials: credentialsToProto(result.GetCredentials()),
		Backend:     backendRefFromPayload(result.GetBackend(), request.GetBackend().GetOpaqueToken()),
	}, nil
}

// SaveWebAuthnCredential persists a new WebAuthn credential.
func (h *Handler) SaveWebAuthnCredential(
	ctx context.Context,
	request *identityv1.SaveWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	if err := h.reserveIdempotency(ctx, AuthorityOperationSaveWebAuthnCredential, request.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationSaveWebAuthnCredential)
	if err != nil {
		return nil, err
	}

	input.Credential = identityv1.WebAuthnCredentialToPersistent(request.GetCredential())
	input.IdempotencyKey = request.GetIdempotencyKey()

	result, err := h.resolveIdentityService().SaveWebAuthnCredential(ctx, input)

	return h.mfaWriteResponse(result, request.GetBackend(), err)
}

// UpdateWebAuthnCredential updates an existing WebAuthn credential.
func (h *Handler) UpdateWebAuthnCredential(
	ctx context.Context,
	request *identityv1.UpdateWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	if err := h.reserveIdempotency(ctx, AuthorityOperationUpdateWebAuthnCredential, request.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationUpdateWebAuthnCredential)
	if err != nil {
		return nil, err
	}

	input.OldCredential = identityv1.WebAuthnCredentialToPersistent(request.GetOldCredential())
	input.NewCredential = identityv1.WebAuthnCredentialToPersistent(request.GetNewCredential())
	input.IdempotencyKey = request.GetIdempotencyKey()

	result, err := h.resolveIdentityService().UpdateWebAuthnCredential(ctx, input)

	return h.mfaWriteResponse(result, request.GetBackend(), err)
}

// DeleteWebAuthnCredential deletes a WebAuthn credential by identifier.
func (h *Handler) DeleteWebAuthnCredential(
	ctx context.Context,
	request *identityv1.DeleteWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	if err := h.reserveIdempotency(ctx, AuthorityOperationDeleteWebAuthnCredential, request.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	input, err := h.backendInput(ctx, request.GetBackend(), request.GetUsername(), request.GetContext(), AuthorityOperationDeleteWebAuthnCredential)
	if err != nil {
		return nil, err
	}

	input.CredentialID = append([]byte(nil), request.GetCredentialId()...)
	input.IdempotencyKey = request.GetIdempotencyKey()

	result, err := h.resolveIdentityService().DeleteWebAuthnCredential(ctx, input)

	return h.mfaWriteResponse(result, request.GetBackend(), err)
}

func (h *Handler) resolveIdentityService() AuthorityIdentityService {
	if h == nil || h.identityService == nil {
		return missingAuthorityIdentityService{}
	}

	return h.identityService
}

func (h *Handler) backendInput(
	ctx context.Context,
	ref *commonv1.BackendRef,
	username string,
	requestContext *identityv1.RequestContext,
	operation AuthorityOperation,
) (AuthorityIdentityInput, error) {
	effectiveUsername := identityUsername(username, requestContext)

	payload, err := h.validateBackendRef(ctx, ref, effectiveUsername, operation)
	if err != nil {
		return AuthorityIdentityInput{}, err
	}

	return AuthorityIdentityInput{
		Operation: operation,
		Context:   requestContext,
		Username:  effectiveUsername,
		Backend:   *payload,
	}, nil
}

func (h *Handler) validateBackendRef(
	ctx context.Context,
	ref *commonv1.BackendRef,
	username string,
	operation AuthorityOperation,
) (*BackendRefPayload, error) {
	if h == nil || h.backendRefs == nil {
		return nil, status.Error(codes.FailedPrecondition, "backend reference store is not configured")
	}

	caller := authorityCallerFromContext(ctx)

	payload, err := h.backendRefs.Validate(ctx, ref, BackendRefValidation{
		Operation:          operation,
		Username:           username,
		ServicePrincipal:   caller.Principal,
		MTLSClientIdentity: caller.MTLSClientIdentity,
		EdgeClusterID:      caller.EdgeClusterID,
	})
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	return payload, nil
}

func (h *Handler) userSnapshotToProto(
	ctx context.Context,
	user *AuthorityUserSnapshot,
	input AuthorityIdentityInput,
) (*identityv1.UserSnapshot, error) {
	if user == nil {
		return nil, nil
	}

	backend := backendRefFromPayload(user.Backend, "")
	if h != nil && h.backendRefs != nil && user.Backend.Type != "" {
		ref, err := h.backendRefs.Issue(ctx, user.Backend)
		if err != nil {
			return nil, grpcErrorFromAuthorityError(err)
		}

		backend = ref
	}

	return &identityv1.UserSnapshot{
		Username:     nonEmpty(user.Username, input.Username),
		Account:      user.Account,
		UniqueUserId: user.UniqueUserID,
		DisplayName:  user.DisplayName,
		Attributes:   stringAttributesToProto(user.Attributes),
		Groups:       append([]string(nil), user.Groups...),
		GroupDns:     append([]string(nil), user.GroupDNS...),
		Backend:      backend,
		Mfa:          mfaStateToProto(user.MFA),
	}, nil
}

func (h *Handler) mfaWriteResponse(
	result *AuthorityIdentityResult,
	ref *commonv1.BackendRef,
	err error,
) (*identityv1.MFAWriteResponse, error) {
	if err != nil {
		return nil, grpcErrorFromAuthorityError(err)
	}

	return &identityv1.MFAWriteResponse{
		Status:  operationStatus(result),
		Changed: result.GetChanged(),
		Mfa:     mfaStateToProto(result.GetMFA()),
		Backend: backendRefFromPayload(result.GetBackend(), ref.GetOpaqueToken()),
	}, nil
}

func (h *Handler) runMFAWrite(
	ctx context.Context,
	ref *commonv1.BackendRef,
	username string,
	requestContext *identityv1.RequestContext,
	operation AuthorityOperation,
	idempotencyKey string,
	run func(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error),
) (*identityv1.MFAWriteResponse, error) {
	if err := h.reserveIdempotency(ctx, operation, idempotencyKey); err != nil {
		return nil, err
	}

	input, err := h.backendInput(ctx, ref, username, requestContext, operation)
	if err != nil {
		return nil, err
	}

	input.IdempotencyKey = idempotencyKey
	result, err := run(ctx, input)

	return h.mfaWriteResponse(result, ref, err)
}

func (h *Handler) reserveIdempotency(ctx context.Context, operation AuthorityOperation, key string) error {
	store := h.idempotency
	if store == nil {
		store = newMemoryIdempotencyStore(defaultMFAIdempotencyTTL)
		h.idempotency = store
	}

	principal := authorityCallerFromContext(ctx).Principal

	err := store.Reserve(ctx, operation, principal, key)
	if errors.Is(err, ErrIdempotencyKeyMissing) {
		return status.Error(codes.InvalidArgument, "idempotency key is required")
	}

	if errors.Is(err, ErrIdempotencyKeyReplay) {
		return status.Error(codes.AlreadyExists, "idempotency key replay")
	}

	if err != nil {
		return status.Error(codes.Internal, "idempotency key check failed")
	}

	return nil
}

func identityUsername(username string, requestContext *identityv1.RequestContext) string {
	if username != "" {
		return username
	}

	return requestContext.GetUsername()
}

func operationStatus(result *AuthorityIdentityResult) *commonv1.OperationStatus {
	if result != nil && result.Status != nil {
		return result.Status
	}

	return &commonv1.OperationStatus{Result: commonv1.OperationResult_OPERATION_RESULT_OK}
}

func backendRefFromPayload(payload BackendRefPayload, token string) *commonv1.BackendRef {
	if payload.Type == "" && payload.Name == "" && payload.Protocol == "" && token == "" {
		return nil
	}

	return payload.backendRef(token)
}

func mfaStateToProto(state AuthorityMFAState) *identityv1.MFAState {
	return &identityv1.MFAState{
		HasTotp:             state.HasTOTP,
		RecoveryCodeCount:   state.RecoveryCodeCount,
		HasWebauthn:         state.HasWebAuthn || len(state.Credentials) > 0,
		WebauthnCredentials: credentialsToProto(state.Credentials),
		PreferredMethod:     state.PreferredMethod,
	}
}

func credentialsToProto(credentials []mfa.PersistentCredential) []*identityv1.WebAuthnCredential {
	if len(credentials) == 0 {
		return nil
	}

	result := make([]*identityv1.WebAuthnCredential, 0, len(credentials))
	for i := range credentials {
		result = append(result, identityv1.PersistentCredentialToProto(&credentials[i]))
	}

	return result
}

func timestampFromResult(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}

	return timestamppb.New(value)
}

func nonEmpty(value string, fallback string) string {
	if value != "" {
		return value
	}

	return fallback
}

type missingAuthorityIdentityService struct{}

func (missingAuthorityIdentityService) ResolveUser(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) GetMFAState(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) BeginTOTPRegistration(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) FinishTOTPRegistration(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) VerifyTOTP(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) DeleteTOTP(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) GenerateRecoveryCodes(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) UseRecoveryCode(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) DeleteRecoveryCodes(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) GetWebAuthnCredentials(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) SaveWebAuthnCredential(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) UpdateWebAuthnCredential(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func (missingAuthorityIdentityService) DeleteWebAuthnCredential(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error) {
	return nil, status.Error(codes.Internal, "authority identity service is not configured")
}

func grpcErrorFromAuthorityError(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := status.FromError(err); ok {
		return err
	}

	switch {
	case errors.Is(err, ErrBackendRefPrincipalMismatch), errors.Is(err, ErrBackendRefEdgeClusterMismatch):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, ErrWebAuthnCredentialStateMismatch):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrBackendRefInvalid),
		errors.Is(err, ErrBackendRefExpired),
		errors.Is(err, ErrBackendRefOperationDenied),
		errors.Is(err, ErrBackendRefUsernameMismatch):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return grpcErrorFromServiceError(err)
	}
}
