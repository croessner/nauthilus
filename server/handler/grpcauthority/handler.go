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

// Package grpcauthority adapts authority-side gRPC APIs to application services.
package grpcauthority

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus/v3/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/v3/server/grpcapi/identity/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Handler implements the authority-side gRPC service contracts.
type Handler struct {
	authv1.UnimplementedAuthServiceServer
	identityv1.UnimplementedIdentityBackendServiceServer

	service         core.AuthApplicationService
	identityService AuthorityIdentityService
	backendRefs     BackendRefStore
	idempotency     idempotencyStore
	resolver        localization.MessageResolver
}

// New constructs the authority handler around the application service.
func New(service core.AuthApplicationService) *Handler {
	return NewWithResolver(service, nil)
}

// NewWithResolver constructs the authority handler with response localization.
func NewWithResolver(service core.AuthApplicationService, resolver localization.MessageResolver) *Handler {
	return &Handler{
		service:     service,
		resolver:    resolver,
		idempotency: newMemoryIdempotencyStore(defaultMFAIdempotencyTTL),
	}
}

// NewWithServices constructs the authority handler with all application services.
func NewWithServices(
	service core.AuthApplicationService,
	resolver localization.MessageResolver,
	identityService AuthorityIdentityService,
	backendRefs BackendRefStore,
) *Handler {
	return &Handler{
		service:         service,
		resolver:        resolver,
		identityService: identityService,
		backendRefs:     backendRefs,
		idempotency:     newMemoryIdempotencyStore(defaultMFAIdempotencyTTL),
	}
}

// Authenticate maps the gRPC request into the auth application service.
func (h *Handler) Authenticate(ctx context.Context, request *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	if h == nil || h.service == nil {
		return nil, status.Error(codes.Internal, "auth application service is not configured")
	}

	dto := authv1.AuthRequestToDTO(request)
	input := core.NewAuthInputFromStructuredRequest(definitions.ServGRPC, core.AuthModeAuthenticate, dto)
	input = authInputWithIncomingMetadata(ctx, input)
	ctx = core.ContextWithGRPCMethod(ctx, authv1.AuthService_Authenticate_FullMethodName)
	dto.Password = ""

	if request != nil {
		request.Password = ""
	}

	outcome, err := h.service.Authenticate(ctx, input)
	if err != nil {
		return nil, grpcErrorFromServiceError(err)
	}

	if outcome == nil {
		return nil, status.Error(codes.Internal, "auth application service returned no outcome")
	}

	outcome = h.localizedAuthOutcome(ctx, outcome)

	response := authOutcomeToProto(outcome)
	h.attachAuthBackendRef(ctx, response, outcome, input, AuthorityOperationAuthenticate)

	return response, nil
}

// LookupIdentity maps the gRPC request into the trusted identity lookup application path.
func (h *Handler) LookupIdentity(
	ctx context.Context,
	request *authv1.LookupIdentityRequest,
) (*authv1.AuthResponse, error) {
	if h == nil || h.service == nil {
		return nil, status.Error(codes.Internal, "auth application service is not configured")
	}

	dto := authv1.LookupIdentityRequestToDTO(request)
	input := core.NewAuthInputFromStructuredRequest(definitions.ServGRPC, core.AuthModeLookupIdentity, dto)
	input = authInputWithIncomingMetadata(ctx, input)
	ctx = core.ContextWithGRPCMethod(ctx, authv1.AuthService_LookupIdentity_FullMethodName)

	outcome, err := h.service.LookupIdentity(ctx, input)
	if err != nil {
		return nil, grpcErrorFromServiceError(err)
	}

	if outcome == nil {
		return nil, status.Error(codes.Internal, "auth application service returned no lookup-identity outcome")
	}

	outcome = h.localizedAuthOutcome(ctx, outcome)

	response := authOutcomeToProto(outcome)
	h.attachAuthBackendRef(ctx, response, outcome, input, AuthorityOperationLookupIdentity)

	return response, nil
}

// ListAccounts maps the gRPC request into the account-provider application path.
func (h *Handler) ListAccounts(
	ctx context.Context,
	request *authv1.ListAccountsRequest,
) (*authv1.ListAccountsResponse, error) {
	if h == nil || h.service == nil {
		return nil, status.Error(codes.Internal, "auth application service is not configured")
	}

	dto := authv1.ListAccountsRequestToDTO(request)
	input := core.NewAuthInputFromStructuredRequest(definitions.ServGRPC, core.AuthModeListAccounts, dto)
	input = authInputWithIncomingMetadata(ctx, input)
	ctx = core.ContextWithGRPCMethod(ctx, authv1.AuthService_ListAccounts_FullMethodName)

	outcome, err := h.service.ListAccounts(ctx, input)
	if err != nil {
		return nil, grpcErrorFromServiceError(err)
	}

	if outcome == nil {
		return nil, status.Error(codes.Internal, "auth application service returned no list-accounts outcome")
	}

	outcome = h.localizedListAccountsOutcome(ctx, outcome)

	if listAccountsDenied(outcome) {
		setListAccountsHeaders(ctx, outcome)

		return &authv1.ListAccountsResponse{
			Session: outcome.Session,
		}, nil
	}

	return &authv1.ListAccountsResponse{
		Accounts: []string(outcome.Accounts),
		Session:  outcome.Session,
	}, nil
}

func listAccountsDenied(outcome *core.ListAccountsOutcome) bool {
	return outcome != nil &&
		outcome.Decision != "" &&
		outcome.Decision != core.AuthDecisionOK
}

func setListAccountsHeaders(ctx context.Context, outcome *core.ListAccountsOutcome) {
	pairs := make([]string, 0, 6)
	if outcome.StatusMessage != "" {
		pairs = append(pairs, "auth-status", outcome.StatusMessage)
	}

	if outcome.Error != "" {
		pairs = append(pairs, "auth-error", outcome.Error)
	}

	if outcome.Session != "" {
		pairs = append(pairs, "x-nauthilus-session", outcome.Session)
	}

	if len(pairs) == 0 {
		return
	}

	_ = grpc.SetHeader(ctx, metadata.Pairs(pairs...))
}

func (h *Handler) localizedAuthOutcome(ctx context.Context, outcome *core.AuthOutcome) *core.AuthOutcome {
	if outcome == nil {
		return outcome
	}

	statusMessage, ok := h.resolvePolicyStatusMessage(ctx, grpcStatusMessageFields{
		text:     outcome.StatusMessage,
		i18nKey:  outcome.StatusMessageI18NKey,
		language: outcome.ResponseLanguage,
	})
	if !ok {
		return outcome
	}

	localized := *outcome
	localized.StatusMessage = statusMessage

	return &localized
}

func (h *Handler) localizedListAccountsOutcome(
	ctx context.Context,
	outcome *core.ListAccountsOutcome,
) *core.ListAccountsOutcome {
	if outcome == nil {
		return outcome
	}

	statusMessage, ok := h.resolvePolicyStatusMessage(ctx, grpcStatusMessageFields{
		text:     outcome.StatusMessage,
		i18nKey:  outcome.StatusMessageI18NKey,
		language: outcome.ResponseLanguage,
	})
	if !ok {
		return outcome
	}

	localized := *outcome
	localized.StatusMessage = statusMessage

	return &localized
}

type grpcStatusMessageFields struct {
	text     string
	i18nKey  string
	language string
}

func (h *Handler) resolvePolicyStatusMessage(ctx context.Context, fields grpcStatusMessageFields) (string, bool) {
	key := strings.TrimSpace(fields.i18nKey)
	if key == "" || h.resolver == nil {
		return fields.text, false
	}

	resolved := h.resolver.ResolveStatusMessage(
		ctx,
		localization.StatusMessage{
			Text:    fields.text,
			I18NKey: key,
		},
		localization.LanguagePreference{
			Policy: fields.language,
			Header: acceptLanguageMetadata(ctx),
		},
	)
	setContentLanguageMetadata(ctx, resolved)

	return resolvedStatusText(resolved, fields.text), true
}

func resolvedStatusText(resolved localization.ResolvedStatusMessage, fallback string) string {
	if resolved.Text == "" {
		return fallback
	}

	return resolved.Text
}

func setContentLanguageMetadata(ctx context.Context, resolved localization.ResolvedStatusMessage) {
	if strings.TrimSpace(resolved.Language) == "" {
		return
	}

	_ = grpc.SetHeader(ctx, metadata.Pairs("content-language", resolved.Language))
}

func acceptLanguageMetadata(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	values := metadata.ValueFromIncomingContext(ctx, "accept-language")
	if len(values) == 0 {
		return ""
	}

	return strings.Join(values, ",")
}

func authInputWithIncomingMetadata(ctx context.Context, input core.AuthInput) core.AuthInput {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md) == 0 {
		return input
	}

	input.Context.RequestMetadata = cloneIncomingMetadata(md)

	return input
}

func cloneIncomingMetadata(md metadata.MD) map[string][]string {
	values := make(map[string][]string, len(md))
	for key, entries := range md {
		values[key] = append([]string(nil), entries...)
	}

	return values
}

func authOutcomeToProto(outcome *core.AuthOutcome) *authv1.AuthResponse {
	return &authv1.AuthResponse{
		Ok:              outcome.Decision == core.AuthDecisionOK,
		Decision:        authDecisionToProto(outcome.Decision),
		Session:         outcome.Session,
		AccountField:    outcome.AccountField,
		TotpSecretField: outcome.TOTPSecretField,
		Backend:         uint32(outcome.Backend),
		Attributes:      attributeMappingToProto(outcome.Attributes),
		StatusMessage:   outcome.StatusMessage,
		Error:           outcome.Error,
	}
}

func (h *Handler) attachAuthBackendRef(
	ctx context.Context,
	response *authv1.AuthResponse,
	outcome *core.AuthOutcome,
	input core.AuthInput,
	operation AuthorityOperation,
) {
	if h == nil || h.backendRefs == nil || response == nil || outcome == nil || outcome.Decision != core.AuthDecisionOK {
		return
	}

	username := authBackendRefUsername(outcome, input)
	payload := BackendRefPayload{
		Type:              outcome.Backend.String(),
		Name:              definitions.DefaultBackendName,
		Protocol:          input.Context.Protocol,
		Username:          username,
		Account:           username,
		ServicePrincipal:  authorityCallerFromContext(ctx).Principal,
		EdgeClusterID:     authorityCallerFromContext(ctx).EdgeClusterID,
		EdgeInstanceID:    authorityCallerFromContext(ctx).EdgeInstanceID,
		AllowedOperations: allowedOperationsAfterAuth(operation),
	}

	ref, err := h.backendRefs.Issue(ctx, payload)
	if err != nil {
		return
	}

	response.BackendRef = ref
}

// authBackendRefUsername binds successful auth references to the resolved account.
func authBackendRefUsername(outcome *core.AuthOutcome, input core.AuthInput) string {
	fallback := input.Credentials.Username
	if outcome == nil {
		return fallback
	}

	return firstAttributeValue(outcome.Attributes, outcome.AccountField, fallback)
}

func allowedOperationsAfterAuth(operation AuthorityOperation) []AuthorityOperation {
	if operation == AuthorityOperationLookupIdentity {
		return []AuthorityOperation{
			AuthorityOperationResolveUser,
			AuthorityOperationGetMFAState,
			AuthorityOperationBeginTOTPRegistration,
			AuthorityOperationFinishTOTPRegistration,
			AuthorityOperationVerifyTOTP,
			AuthorityOperationDeleteTOTP,
			AuthorityOperationGenerateRecoveryCodes,
			AuthorityOperationUseRecoveryCode,
			AuthorityOperationDeleteRecoveryCodes,
			AuthorityOperationGetWebAuthnCredentials,
			AuthorityOperationSaveWebAuthnCredential,
			AuthorityOperationUpdateWebAuthnCredential,
			AuthorityOperationDeleteWebAuthnCredential,
		}
	}

	return []AuthorityOperation{
		AuthorityOperationResolveUser,
		AuthorityOperationGetMFAState,
		AuthorityOperationBeginTOTPRegistration,
		AuthorityOperationFinishTOTPRegistration,
		AuthorityOperationVerifyTOTP,
		AuthorityOperationDeleteTOTP,
		AuthorityOperationGenerateRecoveryCodes,
		AuthorityOperationUseRecoveryCode,
		AuthorityOperationDeleteRecoveryCodes,
		AuthorityOperationGetWebAuthnCredentials,
		AuthorityOperationSaveWebAuthnCredential,
		AuthorityOperationUpdateWebAuthnCredential,
		AuthorityOperationDeleteWebAuthnCredential,
	}
}

func authDecisionToProto(decision core.AuthDecision) authv1.AuthDecision {
	switch decision {
	case core.AuthDecisionOK:
		return authv1.AuthDecision_AUTH_DECISION_OK
	case core.AuthDecisionFail:
		return authv1.AuthDecision_AUTH_DECISION_FAIL
	case core.AuthDecisionTempFail:
		return authv1.AuthDecision_AUTH_DECISION_TEMPFAIL
	default:
		return authv1.AuthDecision_AUTH_DECISION_UNSPECIFIED
	}
}

func attributeMappingToProto(attributes bktype.AttributeMapping) map[string]*authv1.AttributeValues {
	if len(attributes) == 0 {
		return nil
	}

	result := make(map[string]*authv1.AttributeValues, len(attributes))
	for key, values := range attributes {
		result[key] = &authv1.AttributeValues{Values: stringifyAttributeValues(values)}
	}

	return result
}

func stringAttributesToProto(attributes map[string][]string) map[string]*commonv1.AttributeValues {
	if len(attributes) == 0 {
		return nil
	}

	result := make(map[string]*commonv1.AttributeValues, len(attributes))
	for key, values := range attributes {
		result[key] = &commonv1.AttributeValues{Values: append([]string(nil), values...)}
	}

	return result
}

func stringifyAttributeValues(values []any) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			result = append(result, typed)
		case fmt.Stringer:
			result = append(result, typed.String())
		default:
			result = append(result, fmt.Sprint(typed))
		}
	}

	return result
}

func grpcErrorFromServiceError(err error) error {
	if err == nil {
		return nil
	}

	if inputErr, ok := stderrors.AsType[*core.AuthInputError](err); ok {
		return status.Error(codes.InvalidArgument, inputErr.Error())
	}

	if rejectedErr, ok := stderrors.AsType[*core.AuthPreprocessRejectedError](err); ok {
		return status.Error(codes.PermissionDenied, rejectedErr.Error())
	}

	if permissionErr, ok := stderrors.AsType[*core.AuthPermissionDeniedError](err); ok {
		return status.Error(codes.PermissionDenied, permissionErr.Error())
	}

	if stderrors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, err.Error())
	}

	if stderrors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, err.Error())
	}

	return status.Error(codes.Internal, err.Error())
}
