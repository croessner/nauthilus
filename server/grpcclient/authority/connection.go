// Package authority contains outbound gRPC authority client helpers.
package authority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/croessner/nauthilus/server/config"
	authv1 "github.com/croessner/nauthilus/server/grpcapi/auth/v1"
	identityv1 "github.com/croessner/nauthilus/server/grpcapi/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Client is the edge-facing subset of authority auth RPCs used by remote backends.
type Client interface {
	Authenticate(ctx context.Context, request *authv1.AuthRequest) (*authv1.AuthResponse, error)
	LookupIdentity(ctx context.Context, request *authv1.LookupIdentityRequest) (*authv1.AuthResponse, error)
	ListAccounts(ctx context.Context, request *authv1.ListAccountsRequest) (*authv1.ListAccountsResponse, error)
	ResolveUser(ctx context.Context, request *identityv1.ResolveUserRequest) (*identityv1.UserSnapshotResponse, error)
	GetMFAState(ctx context.Context, request *identityv1.GetMFAStateRequest) (*identityv1.MFAStateResponse, error)
	BeginTOTPRegistration(ctx context.Context, request *identityv1.BeginTOTPRegistrationRequest) (*identityv1.BeginTOTPRegistrationResponse, error)
	FinishTOTPRegistration(ctx context.Context, request *identityv1.FinishTOTPRegistrationRequest) (*identityv1.MFAWriteResponse, error)
	VerifyTOTP(ctx context.Context, request *identityv1.VerifyTOTPRequest) (*identityv1.VerifyTOTPResponse, error)
	DeleteTOTP(ctx context.Context, request *identityv1.DeleteTOTPRequest) (*identityv1.MFAWriteResponse, error)
	GenerateRecoveryCodes(ctx context.Context, request *identityv1.GenerateRecoveryCodesRequest) (*identityv1.GenerateRecoveryCodesResponse, error)
	UseRecoveryCode(ctx context.Context, request *identityv1.UseRecoveryCodeRequest) (*identityv1.UseRecoveryCodeResponse, error)
	DeleteRecoveryCodes(ctx context.Context, request *identityv1.DeleteRecoveryCodesRequest) (*identityv1.MFAWriteResponse, error)
	GetWebAuthnCredentials(ctx context.Context, request *identityv1.GetWebAuthnCredentialsRequest) (*identityv1.WebAuthnCredentialsResponse, error)
	SaveWebAuthnCredential(ctx context.Context, request *identityv1.SaveWebAuthnCredentialRequest) (*identityv1.MFAWriteResponse, error)
	UpdateWebAuthnCredential(ctx context.Context, request *identityv1.UpdateWebAuthnCredentialRequest) (*identityv1.MFAWriteResponse, error)
	DeleteWebAuthnCredential(ctx context.Context, request *identityv1.DeleteWebAuthnCredentialRequest) (*identityv1.MFAWriteResponse, error)
}

// ConnectionManagerOptions contains dependencies for an authority connection.
type ConnectionManagerOptions struct {
	Config            *config.NauthilusAuthorityClientSection
	TokenSource       BearerTokenSource
	StaticTokenSource BearerTokenSource
	DialOptions       []grpc.DialOption
	AuthorityName     string
}

// ConnectionManager owns an outbound authority gRPC connection.
type ConnectionManager struct {
	conn          *grpc.ClientConn
	client        Client
	tokenSource   BearerTokenSource
	cfg           *config.NauthilusAuthorityClientSection
	authorityName string
}

type serviceClientAdapter struct {
	auth     authv1.AuthServiceClient
	identity identityv1.IdentityBackendServiceClient
}

func (a serviceClientAdapter) Authenticate(ctx context.Context, request *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	return a.auth.Authenticate(ctx, request)
}

func (a serviceClientAdapter) LookupIdentity(
	ctx context.Context,
	request *authv1.LookupIdentityRequest,
) (*authv1.AuthResponse, error) {
	return a.auth.LookupIdentity(ctx, request)
}

func (a serviceClientAdapter) ListAccounts(
	ctx context.Context,
	request *authv1.ListAccountsRequest,
) (*authv1.ListAccountsResponse, error) {
	return a.auth.ListAccounts(ctx, request)
}

func (a serviceClientAdapter) ResolveUser(
	ctx context.Context,
	request *identityv1.ResolveUserRequest,
) (*identityv1.UserSnapshotResponse, error) {
	return a.identity.ResolveUser(ctx, request)
}

func (a serviceClientAdapter) GetMFAState(
	ctx context.Context,
	request *identityv1.GetMFAStateRequest,
) (*identityv1.MFAStateResponse, error) {
	return a.identity.GetMFAState(ctx, request)
}

func (a serviceClientAdapter) BeginTOTPRegistration(
	ctx context.Context,
	request *identityv1.BeginTOTPRegistrationRequest,
) (*identityv1.BeginTOTPRegistrationResponse, error) {
	return a.identity.BeginTOTPRegistration(ctx, request)
}

func (a serviceClientAdapter) FinishTOTPRegistration(
	ctx context.Context,
	request *identityv1.FinishTOTPRegistrationRequest,
) (*identityv1.MFAWriteResponse, error) {
	return a.identity.FinishTOTPRegistration(ctx, request)
}

func (a serviceClientAdapter) VerifyTOTP(
	ctx context.Context,
	request *identityv1.VerifyTOTPRequest,
) (*identityv1.VerifyTOTPResponse, error) {
	return a.identity.VerifyTOTP(ctx, request)
}

func (a serviceClientAdapter) DeleteTOTP(
	ctx context.Context,
	request *identityv1.DeleteTOTPRequest,
) (*identityv1.MFAWriteResponse, error) {
	return a.identity.DeleteTOTP(ctx, request)
}

func (a serviceClientAdapter) GenerateRecoveryCodes(
	ctx context.Context,
	request *identityv1.GenerateRecoveryCodesRequest,
) (*identityv1.GenerateRecoveryCodesResponse, error) {
	return a.identity.GenerateRecoveryCodes(ctx, request)
}

func (a serviceClientAdapter) UseRecoveryCode(
	ctx context.Context,
	request *identityv1.UseRecoveryCodeRequest,
) (*identityv1.UseRecoveryCodeResponse, error) {
	return a.identity.UseRecoveryCode(ctx, request)
}

func (a serviceClientAdapter) DeleteRecoveryCodes(
	ctx context.Context,
	request *identityv1.DeleteRecoveryCodesRequest,
) (*identityv1.MFAWriteResponse, error) {
	return a.identity.DeleteRecoveryCodes(ctx, request)
}

func (a serviceClientAdapter) GetWebAuthnCredentials(
	ctx context.Context,
	request *identityv1.GetWebAuthnCredentialsRequest,
) (*identityv1.WebAuthnCredentialsResponse, error) {
	return a.identity.GetWebAuthnCredentials(ctx, request)
}

func (a serviceClientAdapter) SaveWebAuthnCredential(
	ctx context.Context,
	request *identityv1.SaveWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	return a.identity.SaveWebAuthnCredential(ctx, request)
}

func (a serviceClientAdapter) UpdateWebAuthnCredential(
	ctx context.Context,
	request *identityv1.UpdateWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	return a.identity.UpdateWebAuthnCredential(ctx, request)
}

func (a serviceClientAdapter) DeleteWebAuthnCredential(
	ctx context.Context,
	request *identityv1.DeleteWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	return a.identity.DeleteWebAuthnCredential(ctx, request)
}

// NewConnectionManager creates an outbound authority gRPC client connection.
func NewConnectionManager(opts ConnectionManagerOptions) (*ConnectionManager, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("authority client config is nil")
	}

	tokenSource := opts.TokenSource
	if tokenSource == nil {
		tokenSource = opts.StaticTokenSource
	}

	dialOptions := append([]grpc.DialOption{}, opts.DialOptions...)
	if len(dialOptions) == 0 {
		transport, err := transportCredentials(opts.Config)
		if err != nil {
			return nil, err
		}

		dialOptions = append(dialOptions, grpc.WithTransportCredentials(transport))
	}

	manager := &ConnectionManager{
		tokenSource:   tokenSource,
		cfg:           opts.Config,
		authorityName: opts.AuthorityName,
	}

	dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(manager.unaryInterceptor()))

	conn, err := grpc.NewClient(opts.Config.GetAddress(), dialOptions...)
	if err != nil {
		return nil, err
	}

	manager.conn = conn
	manager.client = serviceClientAdapter{
		auth:     authv1.NewAuthServiceClient(conn),
		identity: identityv1.NewIdentityBackendServiceClient(conn),
	}

	return manager, nil
}

// Client returns the authority auth service client.
func (m *ConnectionManager) Client() Client {
	if m == nil {
		return nil
	}

	return m.client
}

// Close closes the underlying gRPC connection.
func (m *ConnectionManager) Close() error {
	if m == nil || m.conn == nil {
		return nil
	}

	return m.conn.Close()
}

func (m *ConnectionManager) unaryInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		request any,
		reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc

			ctx, cancel = context.WithTimeout(ctx, m.cfg.GetTimeout())
			defer cancel()
		}

		md := metadata.Pairs(
			"x-nauthilus-authority", m.authorityName,
			"x-nauthilus-edge-cluster", m.cfg.GetEdgeClusterID(),
			"x-nauthilus-edge-instance", m.cfg.GetEdgeInstanceID(),
		)

		if m.tokenSource != nil {
			token, err := m.tokenSource.Token(ctx)
			if err != nil {
				return fmt.Errorf("authority caller token: %w", err)
			}

			if token != "" {
				md.Append("authorization", "Bearer "+token)
			}
		}

		if basic := m.cfg.GetCallerAuth().BasicAuth; basic.IsEnabled() {
			var password string

			basic.GetPassword().WithString(func(value string) {
				password = value
			})
			encoded := base64.StdEncoding.EncodeToString([]byte(basic.GetUsername() + ":" + password))
			md.Set("authorization", "Basic "+encoded)
		}

		ctx = metadata.NewOutgoingContext(ctx, md)

		return invoker(ctx, method, request, reply, cc, opts...)
	}
}

func transportCredentials(cfg *config.NauthilusAuthorityClientSection) (credentials.TransportCredentials, error) {
	tlsConfig := cfg.GetTLS()
	if !tlsConfig.IsEnabled() {
		return insecure.NewCredentials(), nil
	}

	conf := &tls.Config{
		MinVersion: tlsVersion(tlsConfig.GetMinTLSVersion()),
		ServerName: tlsConfig.ServerName,
	}

	if tlsConfig.CA != "" {
		raw, err := os.ReadFile(tlsConfig.CA)
		if err != nil {
			return nil, fmt.Errorf("read authority CA: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("authority CA file contains no certificates")
		}

		conf.RootCAs = pool
	}

	if tlsConfig.Cert != "" || tlsConfig.Key != "" {
		cert, err := tls.LoadX509KeyPair(tlsConfig.Cert, tlsConfig.Key)
		if err != nil {
			return nil, fmt.Errorf("load authority client certificate: %w", err)
		}

		conf.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(conf), nil
}

func tlsVersion(version string) uint16 {
	if version == "TLS1.3" {
		return tls.VersionTLS13
	}

	return tls.VersionTLS12
}
