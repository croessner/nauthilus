// Package remote implements edge-side backends backed by a Nauthilus authority.
package remote

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	authv1 "github.com/croessner/nauthilus/server/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/server/grpcapi/identity/v1"
	authorityclient "github.com/croessner/nauthilus/server/grpcclient/authority"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/croessner/nauthilus/server/model/mfa"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Remote backend errors are returned to the core pipeline as temporary failures.
var (
	ErrRemoteAuthorityUnavailable = stderrors.New("remote authority unavailable")
	ErrRemoteOperationDenied      = stderrors.New("remote backend operation denied")
)

const (
	remoteIdentityAccountField      = "__nauthilus_remote_account__"
	remoteIdentityUniqueUserIDField = "__nauthilus_remote_unique_user_id__"
	remoteIdentityDisplayNameField  = "__nauthilus_remote_display_name__"
)

// Manager implements core.BackendManager through an outbound authority client.
type Manager struct {
	client        authorityclient.Client
	cfg           *config.RemoteBackendSection
	backendName   string
	authorityName string
}

var _ core.BackendManager = (*Manager)(nil)
var _ core.PublicMFAStateProvider = (*Manager)(nil)
var _ core.RemoteMFAOperations = (*Manager)(nil)

type remoteConfigProvider interface {
	GetRemoteBackend(name string) (*config.RemoteBackendSection, bool)
	GetNauthilusAuthorityClient(name string) (*config.NauthilusAuthorityClientSection, bool)
}

func init() {
	core.RegisterBackendManagerFactory(definitions.BackendRemote, NewBackendManager)
}

// NewBackendManager constructs a remote backend manager from core dependencies.
func NewBackendManager(backendName string, deps core.AuthDeps) core.BackendManager {
	if backendName == "" {
		backendName = definitions.DefaultBackendName
	}

	provider, ok := deps.Cfg.(remoteConfigProvider)
	if deps.Cfg == nil || !ok {
		return nil
	}

	remoteCfg, ok := provider.GetRemoteBackend(backendName)
	if !ok {
		return &Manager{backendName: backendName}
	}

	authorityCfg, ok := provider.GetNauthilusAuthorityClient(remoteCfg.GetAuthority())
	if !ok {
		return &Manager{cfg: remoteCfg, backendName: backendName, authorityName: remoteCfg.GetAuthority()}
	}

	tokenSource := newAuthorityTokenSource(remoteCfg.GetAuthority(), authorityCfg, deps)

	client, err := authorityClientFor(remoteCfg.GetAuthority(), authorityCfg, tokenSource)
	if err != nil {
		return &Manager{cfg: remoteCfg, backendName: backendName, authorityName: remoteCfg.GetAuthority()}
	}

	return &Manager{
		client:        client,
		cfg:           remoteCfg,
		backendName:   backendName,
		authorityName: remoteCfg.GetAuthority(),
	}
}

func newAuthorityTokenSource(
	authorityName string,
	authorityCfg *config.NauthilusAuthorityClientSection,
	deps core.AuthDeps,
) authorityclient.BearerTokenSource {
	oidc := authorityCfg.GetCallerAuth().OIDCBearer
	if !oidc.IsEnabled() && oidc.GetStaticTokenFile() == "" {
		return nil
	}

	return authorityclient.NewBearerTokenSource(authorityclient.BearerTokenSourceOptions{
		AuthorityName:    authorityName,
		Config:           &oidc,
		Redis:            deps.Redis,
		StrictSplitMode:  authorityCfg.IsSplitStrictMode(),
		StaticTokenFiles: oidc.GetStaticTokenFile() != "",
	})
}

// NewManagerForTest constructs a manager around a fake or bufconn authority client.
func NewManagerForTest(
	backendName string,
	authorityName string,
	cfg *config.RemoteBackendSection,
	client authorityclient.Client,
) *Manager {
	return &Manager{
		client:        client,
		cfg:           cfg,
		backendName:   backendName,
		authorityName: authorityName,
	}
}

// PassDB authenticates or looks up an identity through the authority.
func (m *Manager) PassDB(auth *core.AuthState) (*core.PassDBResult, error) {
	if auth == nil {
		return nil, errors.ErrNoPassDBResult
	}

	if m == nil || m.cfg == nil || m.client == nil {
		return nil, fmt.Errorf("%w: missing authority client", ErrRemoteAuthorityUnavailable)
	}

	dto := authDTOFromState(auth)

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	if auth.Request.NoAuth {
		if !m.cfg.AllowsOperation(config.RemoteBackendOperationLookupIdentity) {
			return nil, ErrRemoteOperationDenied
		}

		if m.shouldResolveUserSnapshot(auth) {
			response, err := m.client.ResolveUser(ctx, m.resolveUserRequest(dto, false))
			if err != nil {
				return nil, mapAuthorityError(err)
			}

			return m.passDBResultFromUserSnapshot(response)
		}

		response, err := m.client.LookupIdentity(ctx, authv1.DTOToLookupIdentityRequest(dto))
		if err != nil {
			return nil, mapAuthorityError(err)
		}

		return m.passDBResultFromResponse(response, false)
	}

	if !m.cfg.AllowsOperation(config.RemoteBackendOperationAuth) {
		return nil, ErrRemoteOperationDenied
	}

	response, err := m.client.Authenticate(ctx, authv1.DTOToAuthRequest(dto))
	if err != nil {
		return nil, mapAuthorityError(err)
	}

	return m.passDBResultFromResponse(response, true)
}

// AccountDB lists accounts through the authority.
func (m *Manager) AccountDB(auth *core.AuthState) (core.AccountList, error) {
	if m == nil || m.cfg == nil || m.client == nil {
		return nil, fmt.Errorf("%w: missing authority client", ErrRemoteAuthorityUnavailable)
	}

	if !m.cfg.AllowsOperation(config.RemoteBackendOperationListAccounts) {
		return nil, ErrRemoteOperationDenied
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	response, err := m.client.ListAccounts(ctx, authv1.DTOToListAccountsRequest(authDTOFromState(auth)))
	if err != nil {
		return nil, mapAuthorityError(err)
	}

	if response == nil {
		return nil, fmt.Errorf("%w: empty list-accounts response", ErrRemoteAuthorityUnavailable)
	}

	return core.AccountList(response.GetAccounts()), nil
}

// BeginTOTPRegistration starts an authority-owned TOTP setup and returns one-time setup material.
func (m *Manager) BeginTOTPRegistration(auth *core.AuthState, idempotencyKey string) (core.TOTPRegistration, error) {
	if err := m.ensureRemoteMFAOperation(config.RemoteBackendOperationMFAWrite, idempotencyKey); err != nil {
		return core.TOTPRegistration{}, err
	}

	ref, err := backendRefToProto(auth)
	if err != nil {
		return core.TOTPRegistration{}, err
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	response, err := m.client.BeginTOTPRegistration(ctx, &identityv1.BeginTOTPRegistrationRequest{
		Context:        identityv1.DTOToRequestContext(authDTOFromState(auth)),
		Username:       auth.GetUsername(),
		Backend:        ref,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return core.TOTPRegistration{}, mapAuthorityError(err)
	}

	if err = operationStatusError(response.GetStatus()); err != nil {
		return core.TOTPRegistration{}, err
	}

	return core.TOTPRegistration{
		PendingRegistrationID: response.GetPendingRegistrationId(),
		Secret:                response.GetTotpSecret(),
		OTPAuthURL:            response.GetOtpauthUrl(),
		ExpiresAt:             response.GetExpiresAt().AsTime(),
	}, nil
}

// FinishTOTPRegistration completes an authority-owned TOTP setup.
func (m *Manager) FinishTOTPRegistration(
	auth *core.AuthState,
	pendingRegistrationID string,
	code string,
	idempotencyKey string,
) error {
	if err := m.ensureRemoteMFAOperation(config.RemoteBackendOperationMFAWrite, idempotencyKey); err != nil {
		return err
	}

	ref, err := backendRefToProto(auth)
	if err != nil {
		return err
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	response, err := m.client.FinishTOTPRegistration(ctx, &identityv1.FinishTOTPRegistrationRequest{
		Context:               identityv1.DTOToRequestContext(authDTOFromState(auth)),
		Username:              auth.GetUsername(),
		Backend:               ref,
		PendingRegistrationId: pendingRegistrationID,
		Code:                  code,
		IdempotencyKey:        idempotencyKey,
	})
	if err != nil {
		return mapAuthorityError(err)
	}

	return operationStatusError(response.GetStatus())
}

// VerifyTOTP verifies a TOTP code through the authority without exposing the stored secret.
func (m *Manager) VerifyTOTP(auth *core.AuthState, code string) (bool, error) {
	if err := m.ensureRemoteMFAOperation(config.RemoteBackendOperationMFAVerify, "verify"); err != nil {
		return false, err
	}

	ref, err := backendRefToProto(auth)
	if err != nil {
		return false, err
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	response, err := m.client.VerifyTOTP(ctx, &identityv1.VerifyTOTPRequest{
		Context:  identityv1.DTOToRequestContext(authDTOFromState(auth)),
		Username: auth.GetUsername(),
		Backend:  ref,
		Code:     code,
	})
	if err != nil {
		return false, mapAuthorityError(err)
	}

	if err = operationStatusError(response.GetStatus()); err != nil {
		return false, err
	}

	return response.GetValid(), nil
}

// DeleteTOTP deletes persisted TOTP state through the authority.
func (m *Manager) DeleteTOTP(auth *core.AuthState, idempotencyKey string) error {
	return m.runRemoteMFADelete(auth, idempotencyKey, remoteMFADeleteTOTP)
}

// GenerateRecoveryCodes replaces recovery codes through the authority and returns plaintext values once.
func (m *Manager) GenerateRecoveryCodes(auth *core.AuthState, count uint32, idempotencyKey string) ([]string, error) {
	if err := m.ensureRemoteMFAOperation(config.RemoteBackendOperationMFAWrite, idempotencyKey); err != nil {
		return nil, err
	}

	ref, err := backendRefToProto(auth)
	if err != nil {
		return nil, err
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	response, err := m.client.GenerateRecoveryCodes(ctx, &identityv1.GenerateRecoveryCodesRequest{
		Context:        identityv1.DTOToRequestContext(authDTOFromState(auth)),
		Username:       auth.GetUsername(),
		Backend:        ref,
		Count:          count,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return nil, mapAuthorityError(err)
	}

	if err = operationStatusError(response.GetStatus()); err != nil {
		return nil, err
	}

	return append([]string(nil), response.GetCodes()...), nil
}

// UseRecoveryCode verifies and atomically consumes one recovery code through the authority.
func (m *Manager) UseRecoveryCode(auth *core.AuthState, code string, idempotencyKey string) (bool, error) {
	if err := m.ensureRemoteMFAOperation(config.RemoteBackendOperationMFAVerify, idempotencyKey); err != nil {
		return false, err
	}

	if !m.cfg.AllowsOperation(config.RemoteBackendOperationMFAWrite) {
		return false, ErrRemoteOperationDenied
	}

	ref, err := backendRefToProto(auth)
	if err != nil {
		return false, err
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	response, err := m.client.UseRecoveryCode(ctx, &identityv1.UseRecoveryCodeRequest{
		Context:        identityv1.DTOToRequestContext(authDTOFromState(auth)),
		Username:       auth.GetUsername(),
		Backend:        ref,
		Code:           code,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return false, mapAuthorityError(err)
	}

	if err = operationStatusError(response.GetStatus()); err != nil {
		return false, err
	}

	return response.GetValid(), nil
}

// DeleteRecoveryCodes deletes persisted recovery-code state through the authority.
func (m *Manager) DeleteRecoveryCodes(auth *core.AuthState, idempotencyKey string) error {
	return m.runRemoteMFADelete(auth, idempotencyKey, remoteMFADeleteRecoveryCodes)
}

// AddTOTPSecret rejects edge-selected TOTP secrets; remote registration must use Begin/FinishTOTPRegistration.
func (m *Manager) AddTOTPSecret(*core.AuthState, *mfa.TOTPSecret) error {
	return ErrRemoteOperationDenied
}

// DeleteTOTPSecret deletes TOTP state with a manager-generated idempotency key.
func (m *Manager) DeleteTOTPSecret(auth *core.AuthState) error {
	return m.DeleteTOTP(auth, m.idempotencyKey(auth, "delete-totp"))
}

// AddTOTPRecoveryCodes rejects edge-selected recovery-code values; remote generation must stay authority-owned.
func (m *Manager) AddTOTPRecoveryCodes(*core.AuthState, *mfa.TOTPRecovery) error {
	return ErrRemoteOperationDenied
}

// DeleteTOTPRecoveryCodes deletes recovery codes with a manager-generated idempotency key.
func (m *Manager) DeleteTOTPRecoveryCodes(auth *core.AuthState) error {
	return m.DeleteRecoveryCodes(auth, m.idempotencyKey(auth, "delete-recovery"))
}

// GetPublicMFAState loads public MFA state from the authority without exposing secrets.
func (m *Manager) GetPublicMFAState(auth *core.AuthState, includeWebAuthn bool) (core.PublicMFAState, error) {
	if m == nil || m.cfg == nil || m.client == nil {
		return core.PublicMFAState{}, fmt.Errorf("%w: missing authority client", ErrRemoteAuthorityUnavailable)
	}

	if !m.cfg.AllowsOperation(config.RemoteBackendOperationMFARead) {
		return core.PublicMFAState{}, ErrRemoteOperationDenied
	}

	if includeWebAuthn && !m.cfg.AllowsOperation(config.RemoteBackendOperationWebAuthnRead) {
		return core.PublicMFAState{}, ErrRemoteOperationDenied
	}

	ref, err := backendRefToProto(auth)
	if err != nil {
		return core.PublicMFAState{}, err
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	response, err := m.client.GetMFAState(ctx, &identityv1.GetMFAStateRequest{
		Context:                    identityv1.DTOToRequestContext(authDTOFromState(auth)),
		Username:                   auth.GetUsername(),
		Backend:                    ref,
		IncludeWebauthnCredentials: includeWebAuthn,
	})
	if err != nil {
		return core.PublicMFAState{}, mapAuthorityError(err)
	}

	return publicMFAStateFromResponse(response)
}

// GetWebAuthnCredentials retrieves public WebAuthn credentials from the authority.
func (m *Manager) GetWebAuthnCredentials(auth *core.AuthState) ([]mfa.PersistentCredential, error) {
	if m == nil || m.cfg == nil || m.client == nil {
		return nil, fmt.Errorf("%w: missing authority client", ErrRemoteAuthorityUnavailable)
	}

	if !m.cfg.AllowsOperation(config.RemoteBackendOperationWebAuthnRead) {
		return nil, ErrRemoteOperationDenied
	}

	ref, err := backendRefToProto(auth)
	if err != nil {
		return nil, err
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	response, err := m.client.GetWebAuthnCredentials(ctx, &identityv1.GetWebAuthnCredentialsRequest{
		Context:  identityv1.DTOToRequestContext(authDTOFromState(auth)),
		Username: auth.GetUsername(),
		Backend:  ref,
	})
	if err != nil {
		return nil, mapAuthorityError(err)
	}

	if err = operationStatusError(response.GetStatus()); err != nil {
		return nil, err
	}

	return persistentCredentialsFromProto(response.GetCredentials()), nil
}

// SaveWebAuthnCredential is intentionally not implemented by this edge slice.
func (m *Manager) SaveWebAuthnCredential(*core.AuthState, *mfa.PersistentCredential) error {
	return ErrRemoteOperationDenied
}

// DeleteWebAuthnCredential is intentionally not implemented by this edge slice.
func (m *Manager) DeleteWebAuthnCredential(*core.AuthState, *mfa.PersistentCredential) error {
	return ErrRemoteOperationDenied
}

// UpdateWebAuthnCredential is intentionally not implemented by this edge slice.
func (m *Manager) UpdateWebAuthnCredential(*core.AuthState, *mfa.PersistentCredential, *mfa.PersistentCredential) error {
	return ErrRemoteOperationDenied
}

type remoteMFADeleteOperation uint8

const (
	remoteMFADeleteTOTP remoteMFADeleteOperation = iota
	remoteMFADeleteRecoveryCodes
)

func (m *Manager) runRemoteMFADelete(auth *core.AuthState, idempotencyKey string, operation remoteMFADeleteOperation) error {
	if err := m.ensureRemoteMFAOperation(config.RemoteBackendOperationMFAWrite, idempotencyKey); err != nil {
		return err
	}

	ref, err := backendRefToProto(auth)
	if err != nil {
		return err
	}

	ctx, cancel := m.requestContext(auth)
	defer cancel()

	requestContext := identityv1.DTOToRequestContext(authDTOFromState(auth))
	username := auth.GetUsername()

	var response *identityv1.MFAWriteResponse

	switch operation {
	case remoteMFADeleteTOTP:
		response, err = m.client.DeleteTOTP(ctx, &identityv1.DeleteTOTPRequest{
			Context:        requestContext,
			Username:       username,
			Backend:        ref,
			IdempotencyKey: idempotencyKey,
		})
	case remoteMFADeleteRecoveryCodes:
		response, err = m.client.DeleteRecoveryCodes(ctx, &identityv1.DeleteRecoveryCodesRequest{
			Context:        requestContext,
			Username:       username,
			Backend:        ref,
			IdempotencyKey: idempotencyKey,
		})
	default:
		return ErrRemoteOperationDenied
	}

	if err != nil {
		return mapAuthorityError(err)
	}

	return operationStatusError(response.GetStatus())
}

func (m *Manager) requestContext(auth *core.AuthState) (context.Context, context.CancelFunc) {
	ctx := context.Background()
	if auth != nil {
		ctx = auth.Ctx()
	}

	if m != nil && m.cfg != nil && m.cfg.GetTimeout() > 0 {
		return context.WithTimeout(ctx, m.cfg.GetTimeout())
	}

	return ctx, func() {}
}

func (m *Manager) ensureRemoteMFAOperation(operation string, idempotencyKey string) error {
	if m == nil || m.cfg == nil || m.client == nil {
		return fmt.Errorf("%w: missing authority client", ErrRemoteAuthorityUnavailable)
	}

	if idempotencyKey == "" {
		return fmt.Errorf("%w: missing idempotency key", ErrRemoteOperationDenied)
	}

	if !m.cfg.AllowsOperation(operation) {
		return ErrRemoteOperationDenied
	}

	return nil
}

func (m *Manager) idempotencyKey(auth *core.AuthState, operation string) string {
	username := ""
	guid := ""

	if auth != nil {
		username = auth.GetUsername()
		guid = auth.Runtime.GUID
	}

	if guid == "" {
		guid = "request"
	}

	return fmt.Sprintf("%s:%s:%s", operation, username, guid)
}

func (m *Manager) shouldResolveUserSnapshot(auth *core.AuthState) bool {
	if auth == nil || auth.Request.Protocol == nil {
		return false
	}

	return auth.Request.Protocol.Get() == definitions.ProtoIDP
}

func (m *Manager) resolveUserRequest(dto authdto.Request, includeMFAState bool) *identityv1.ResolveUserRequest {
	return &identityv1.ResolveUserRequest{
		Context:                    identityv1.DTOToRequestContext(dto),
		Username:                   dto.Username,
		Attributes:                 &identityv1.AttributeRequest{IncludeStandardIdentity: true, IncludeGroups: true, IncludeGroupDns: true},
		IncludeMfaState:            includeMFAState,
		IncludeWebauthnCredentials: includeMFAState,
	}
}

func (m *Manager) passDBResultFromResponse(response *authv1.AuthResponse, passwordAuth bool) (*core.PassDBResult, error) {
	if response == nil {
		return nil, fmt.Errorf("%w: empty auth response", ErrRemoteAuthorityUnavailable)
	}

	switch response.GetDecision() {
	case authv1.AuthDecision_AUTH_DECISION_OK:
	case authv1.AuthDecision_AUTH_DECISION_FAIL:
		return m.failedPassDBResult(response), nil
	case authv1.AuthDecision_AUTH_DECISION_TEMPFAIL:
		return nil, fmt.Errorf("%w: %s", ErrRemoteAuthorityUnavailable, response.GetError())
	default:
		return nil, fmt.Errorf("%w: unspecified authority decision", ErrRemoteAuthorityUnavailable)
	}

	result := core.GetPassDBResultFromPool()
	result.Authenticated = passwordAuth && response.GetOk()
	result.UserFound = true
	result.Backend = definitions.BackendRemote
	result.BackendName = m.backendName
	result.AccountField = response.GetAccountField()
	result.TOTPSecretField = response.GetTotpSecretField()
	result.Attributes = attributeMappingFromProto(response.GetAttributes())
	result.BackendRef = backendRefFromProto(response.GetBackendRef())

	return result, nil
}

func (m *Manager) passDBResultFromUserSnapshot(response *identityv1.UserSnapshotResponse) (*core.PassDBResult, error) {
	if response == nil {
		return nil, fmt.Errorf("%w: empty resolve-user response", ErrRemoteAuthorityUnavailable)
	}

	switch response.GetStatus().GetResult() {
	case commonv1.OperationResult_OPERATION_RESULT_OK:
	case commonv1.OperationResult_OPERATION_RESULT_FAIL, commonv1.OperationResult_OPERATION_RESULT_NOT_FOUND:
		return m.failedPassDBResultFromStatus(response.GetStatus()), nil
	case commonv1.OperationResult_OPERATION_RESULT_DENIED:
		return nil, statusError(ErrRemoteOperationDenied, response.GetStatus())
	default:
		return nil, statusError(ErrRemoteAuthorityUnavailable, response.GetStatus())
	}

	user := response.GetUser()
	if user == nil {
		return nil, fmt.Errorf("%w: resolve-user response has no user", ErrRemoteAuthorityUnavailable)
	}

	backendRef := backendRefFromProto(user.GetBackend())
	if backendRef.IsZero() {
		return nil, fmt.Errorf("%w: resolve-user response has no backend reference", ErrRemoteOperationDenied)
	}

	result := core.GetPassDBResultFromPool()
	result.Authenticated = false
	result.UserFound = true
	result.Backend = definitions.BackendRemote
	result.BackendName = m.backendName
	result.Account = user.GetAccount()
	result.AccountField = remoteIdentityAccountField
	result.UniqueUserIDField = remoteIdentityUniqueUserIDField
	result.DisplayNameField = remoteIdentityDisplayNameField
	result.Attributes = userSnapshotAttributes(user)
	result.Groups = append([]string(nil), user.GetGroups()...)
	result.GroupDNs = append([]string(nil), user.GetGroupDns()...)
	result.BackendRef = backendRef

	return result, nil
}

func (m *Manager) failedPassDBResult(response *authv1.AuthResponse) *core.PassDBResult {
	result := core.GetPassDBResultFromPool()
	result.Authenticated = false
	result.UserFound = response.GetOk()
	result.Backend = definitions.BackendRemote
	result.BackendName = m.backendName
	result.AccountField = response.GetAccountField()
	result.Attributes = attributeMappingFromProto(response.GetAttributes())

	return result
}

func (m *Manager) failedPassDBResultFromStatus(operationStatus *commonv1.OperationStatus) *core.PassDBResult {
	result := core.GetPassDBResultFromPool()
	result.Authenticated = false
	result.UserFound = false
	result.Backend = definitions.BackendRemote
	result.BackendName = m.backendName

	if operationStatus != nil {
		result.AdditionalAttributes = map[string]any{
			"remote_status": operationStatus.GetErrorCode(),
		}
	}

	return result
}

func mapAuthorityError(err error) error {
	if err == nil {
		return nil
	}

	if stderrors.Is(err, context.DeadlineExceeded) || stderrors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %v", ErrRemoteAuthorityUnavailable, err)
	}

	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.DeadlineExceeded, codes.Unavailable, codes.ResourceExhausted:
			return fmt.Errorf("%w: %v", ErrRemoteAuthorityUnavailable, err)
		case codes.PermissionDenied, codes.Unauthenticated:
			return fmt.Errorf("%w: %v", ErrRemoteOperationDenied, err)
		default:
			return fmt.Errorf("%w: %v", ErrRemoteAuthorityUnavailable, err)
		}
	}

	return fmt.Errorf("%w: %v", ErrRemoteAuthorityUnavailable, err)
}

func authDTOFromState(auth *core.AuthState) authdto.Request {
	if auth == nil {
		return authdto.Request{}
	}

	var password string

	auth.Request.Password.WithString(func(value string) {
		password = value
	})

	protocol := ""
	if auth.Request.Protocol != nil {
		protocol = auth.Request.Protocol.Get()
	}

	return authdto.Request{
		Username:            auth.Request.Username,
		Password:            password,
		ClientIP:            auth.Request.ClientIP,
		ClientPort:          auth.Request.XClientPort,
		ClientHostname:      auth.Request.ClientHost,
		ClientID:            auth.Request.XClientID,
		ExternalSessionID:   auth.Request.ExternalSessionID,
		UserAgent:           auth.Request.UserAgent,
		LocalIP:             auth.Request.XLocalIP,
		LocalPort:           auth.Request.XPort,
		Protocol:            protocol,
		Method:              auth.Request.Method,
		XSSL:                auth.Request.XSSL,
		XSSLSessionID:       auth.Request.XSSLSessionID,
		XSSLClientVerify:    auth.Request.XSSLClientVerify,
		XSSLClientDN:        auth.Request.XSSLClientDN,
		XSSLClientCN:        auth.Request.XSSLClientCN,
		XSSLIssuer:          auth.Request.XSSLIssuer,
		XSSLClientNotBefore: auth.Request.XSSLClientNotBefore,
		XSSLClientNotAfter:  auth.Request.XSSLClientNotAfter,
		XSSLSubjectDN:       auth.Request.XSSLSubjectDN,
		XSSLIssuerDN:        auth.Request.XSSLIssuerDN,
		XSSLClientSubjectDN: auth.Request.XSSLClientSubjectDN,
		XSSLClientIssuerDN:  auth.Request.XSSLClientIssuerDN,
		XSSLProtocol:        auth.Request.XSSLProtocol,
		XSSLCipher:          auth.Request.XSSLCipher,
		SSLSerial:           auth.Request.SSLSerial,
		SSLFingerprint:      auth.Request.SSLFingerprint,
		OIDCCID:             auth.Request.OIDCCID,
		AuthLoginAttempt:    auth.Request.AuthLoginAttempt,
	}
}

func attributeMappingFromProto(attributes map[string]*commonv1.AttributeValues) bktype.AttributeMapping {
	if len(attributes) == 0 {
		return nil
	}

	result := make(bktype.AttributeMapping, len(attributes))
	for name, values := range attributes {
		if values == nil {
			continue
		}

		mapped := make([]any, 0, len(values.GetValues()))
		for _, value := range values.GetValues() {
			mapped = append(mapped, value)
		}

		result[name] = mapped
	}

	return result
}

func backendRefFromProto(ref *commonv1.BackendRef) core.RemoteBackendRef {
	if ref == nil {
		return core.RemoteBackendRef{}
	}

	return core.RemoteBackendRef{
		Type:        ref.GetType(),
		Name:        ref.GetName(),
		Protocol:    ref.GetProtocol(),
		Authority:   ref.GetAuthority(),
		OpaqueToken: ref.GetOpaqueToken(),
	}
}

func backendRefToProto(auth *core.AuthState) (*commonv1.BackendRef, error) {
	if auth == nil || auth.Runtime.RemoteBackendRef.IsZero() {
		return nil, fmt.Errorf("%w: missing backend reference", ErrRemoteOperationDenied)
	}

	ref := auth.Runtime.RemoteBackendRef
	if ref.OpaqueToken == "" {
		return nil, fmt.Errorf("%w: missing backend reference token", ErrRemoteOperationDenied)
	}

	return &commonv1.BackendRef{
		Type:        ref.Type,
		Name:        ref.Name,
		Protocol:    ref.Protocol,
		Authority:   ref.Authority,
		OpaqueToken: ref.OpaqueToken,
	}, nil
}

func publicMFAStateFromResponse(response *identityv1.MFAStateResponse) (core.PublicMFAState, error) {
	if response == nil {
		return core.PublicMFAState{}, fmt.Errorf("%w: empty MFA state response", ErrRemoteAuthorityUnavailable)
	}

	if err := operationStatusError(response.GetStatus()); err != nil {
		return core.PublicMFAState{}, err
	}

	state := response.GetMfa()
	if state == nil {
		return core.PublicMFAState{}, nil
	}

	credentials := persistentCredentialsFromProto(state.GetWebauthnCredentials())

	return core.PublicMFAState{
		WebAuthnCredentials: credentials,
		RecoveryCodeCount:   int(state.GetRecoveryCodeCount()),
		HasTOTP:             state.GetHasTotp(),
		HasWebAuthn:         state.GetHasWebauthn() || len(credentials) > 0,
	}, nil
}

func persistentCredentialsFromProto(credentials []*identityv1.WebAuthnCredential) []mfa.PersistentCredential {
	if len(credentials) == 0 {
		return nil
	}

	result := make([]mfa.PersistentCredential, 0, len(credentials))
	for _, credential := range credentials {
		persistent := identityv1.WebAuthnCredentialToPersistent(credential)
		if persistent != nil {
			result = append(result, *persistent)
		}
	}

	return result
}

func userSnapshotAttributes(user *identityv1.UserSnapshot) bktype.AttributeMapping {
	if user == nil {
		return nil
	}

	attributes := attributeMappingFromProto(user.GetAttributes())
	if attributes == nil {
		attributes = bktype.AttributeMapping{}
	}

	setSingleAttribute(attributes, remoteIdentityAccountField, user.GetAccount())
	setSingleAttribute(attributes, remoteIdentityUniqueUserIDField, user.GetUniqueUserId())
	setSingleAttribute(attributes, remoteIdentityDisplayNameField, user.GetDisplayName())

	return attributes
}

func setSingleAttribute(attributes bktype.AttributeMapping, name string, value string) {
	if value == "" {
		return
	}

	attributes[name] = []any{value}
}

func operationStatusError(operationStatus *commonv1.OperationStatus) error {
	if operationStatus == nil {
		return nil
	}

	switch operationStatus.GetResult() {
	case commonv1.OperationResult_OPERATION_RESULT_OK:
		return nil
	case commonv1.OperationResult_OPERATION_RESULT_DENIED:
		return statusError(ErrRemoteOperationDenied, operationStatus)
	default:
		return statusError(ErrRemoteAuthorityUnavailable, operationStatus)
	}
}

func statusError(base error, operationStatus *commonv1.OperationStatus) error {
	if operationStatus == nil {
		return base
	}

	if operationStatus.GetSafeMessage() != "" {
		return fmt.Errorf("%w: %s", base, operationStatus.GetSafeMessage())
	}

	if operationStatus.GetErrorCode() != "" {
		return fmt.Errorf("%w: %s", base, operationStatus.GetErrorCode())
	}

	return base
}
