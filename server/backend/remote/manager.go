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

// Manager implements core.BackendManager through an outbound authority client.
type Manager struct {
	client        authorityclient.Client
	cfg           *config.RemoteBackendSection
	backendName   string
	authorityName string
}

var _ core.BackendManager = (*Manager)(nil)

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

// AddTOTPSecret is intentionally not implemented by this edge slice.
func (m *Manager) AddTOTPSecret(*core.AuthState, *mfa.TOTPSecret) error {
	return ErrRemoteOperationDenied
}

// DeleteTOTPSecret is intentionally not implemented by this edge slice.
func (m *Manager) DeleteTOTPSecret(*core.AuthState) error {
	return ErrRemoteOperationDenied
}

// AddTOTPRecoveryCodes is intentionally not implemented by this edge slice.
func (m *Manager) AddTOTPRecoveryCodes(*core.AuthState, *mfa.TOTPRecovery) error {
	return ErrRemoteOperationDenied
}

// DeleteTOTPRecoveryCodes is intentionally not implemented by this edge slice.
func (m *Manager) DeleteTOTPRecoveryCodes(*core.AuthState) error {
	return ErrRemoteOperationDenied
}

// GetWebAuthnCredentials is intentionally not implemented by this edge slice.
func (m *Manager) GetWebAuthnCredentials(*core.AuthState) ([]mfa.PersistentCredential, error) {
	return nil, ErrRemoteOperationDenied
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
