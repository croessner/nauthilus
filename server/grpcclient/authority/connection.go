// Package authority contains outbound gRPC authority client helpers.
package authority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	identityv1 "github.com/croessner/nauthilus/v4/api/identity/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	Artifacts         *config.ArtifactSnapshot
	TokenSource       BearerTokenSource
	StaticTokenSource BearerTokenSource
	DialOptions       []grpc.DialOption
	Logger            *slog.Logger
	AuthorityName     string
}

// ConnectionManager owns an outbound authority gRPC connection.
type ConnectionManager struct {
	conn          *grpc.ClientConn
	client        Client
	tokenSource   BearerTokenSource
	cfg           *config.NauthilusAuthorityClientSection
	logger        *slog.Logger
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
		transport, err := transportCredentials(opts.Config, opts.Artifacts)
		if err != nil {
			return nil, err
		}

		dialOptions = append(dialOptions, grpc.WithTransportCredentials(transport))
	}

	manager := &ConnectionManager{
		tokenSource:   tokenSource,
		cfg:           opts.Config,
		logger:        opts.Logger,
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

// unaryInterceptor attaches caller metadata and credentials to every authority RPC.
//
// When the authority answers UNAUTHENTICATED to a bearer token from a replaceable token source, the
// interceptor discards that token and repeats the RPC exactly once with a replacement token. A second
// rejection is returned to the caller, so a permanently rejected client never loops on the token endpoint.
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

		md, bearer, err := m.outgoingMetadata(ctx)
		if err != nil {
			return err
		}

		err = invoker(metadata.NewOutgoingContext(ctx, md), method, request, reply, cc, opts...)

		replacement, ok := m.replacementForRejectedToken(ctx, method, bearer, err)
		if !ok {
			return err
		}

		md.Set("authorization", "Bearer "+replacement)

		return invoker(metadata.NewOutgoingContext(ctx, md), method, request, reply, cc, opts...)
	}
}

// outgoingMetadata builds the caller metadata and returns the bearer token it carries, if any.
// Basic auth replaces the bearer header, so the returned bearer token is empty in that case.
func (m *ConnectionManager) outgoingMetadata(ctx context.Context) (metadata.MD, string, error) {
	md := metadata.Pairs(
		"x-nauthilus-authority", m.authorityName,
		"x-nauthilus-edge-cluster", m.cfg.GetEdgeClusterID(),
		"x-nauthilus-edge-instance", m.cfg.GetEdgeInstanceID(),
	)

	var bearer string

	if m.tokenSource != nil {
		token, err := m.tokenSource.Token(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("authority caller token: %w", err)
		}

		if token != "" {
			bearer = token
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

		bearer = ""
	}

	return md, bearer, nil
}

// replacementForRejectedToken returns a new bearer token when the authority rejected the one just sent.
// It reports false when the RPC did not fail with UNAUTHENTICATED, no bearer token was sent, the token
// source cannot replace tokens, or no different token is available.
func (m *ConnectionManager) replacementForRejectedToken(ctx context.Context, method string, bearer string, rpcErr error) (string, bool) {
	if bearer == "" || status.Code(rpcErr) != codes.Unauthenticated {
		return "", false
	}

	replacer, ok := m.tokenSource.(RejectedTokenReplacer)
	if !ok {
		return "", false
	}

	replacement, err := replacer.ReplaceRejectedToken(ctx, bearer)
	if err != nil || replacement == "" || replacement == bearer {
		m.logRejectedToken("Authority rejected the caller token and no replacement token is available", method, err)

		return "", false
	}

	m.logRejectedToken("Authority rejected the cached caller token; retrying once with a replacement token", method, nil)

	return replacement, true
}

// logRejectedToken reports a caller-token rejection when the manager has a logger.
func (m *ConnectionManager) logRejectedToken(message string, method string, err error) {
	if m.logger == nil {
		return
	}

	keyvals := []any{definitions.LogKeyMsg, message, "authority", m.authorityName, "method", method}
	if err != nil {
		keyvals = append(keyvals, definitions.LogKeyError, err)
	}

	level.Warn(m.logger).Log(keyvals...)
}

func transportCredentials(
	cfg *config.NauthilusAuthorityClientSection,
	artifacts *config.ArtifactSnapshot,
) (credentials.TransportCredentials, error) {
	tlsConfig := cfg.GetTLS()
	if !tlsConfig.IsEnabled() {
		return insecure.NewCredentials(), nil
	}

	conf := &tls.Config{
		MinVersion: tlsVersion(tlsConfig.GetMinTLSVersion()),
		ServerName: tlsConfig.ServerName,
	}

	if tlsConfig.CA != "" {
		raw, err := readSealedAuthorityArtifact(artifacts, tlsConfig.CA, "authority CA")
		if err != nil {
			return nil, err
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("authority CA file contains no certificates")
		}

		conf.RootCAs = pool
	}

	if tlsConfig.Cert != "" || tlsConfig.Key != "" {
		certificatePEM, err := readSealedAuthorityArtifact(artifacts, tlsConfig.Cert, "authority client certificate")
		if err != nil {
			return nil, err
		}

		keyPEM, err := readSealedAuthorityArtifact(artifacts, tlsConfig.Key, "authority client key")
		if err != nil {
			return nil, err
		}

		cert, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("load authority client certificate: %w", err)
		}

		conf.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(conf), nil
}

// readSealedAuthorityArtifact returns only candidate-captured authority credential bytes.
func readSealedAuthorityArtifact(
	artifacts *config.ArtifactSnapshot,
	path string,
	label string,
) ([]byte, error) {
	if artifacts == nil {
		return nil, fmt.Errorf("read %s: %w", label, config.ErrArtifactNotCaptured)
	}

	raw, err := artifacts.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}

	return raw, nil
}

func tlsVersion(version string) uint16 {
	if version == "TLS1.3" {
		return tls.VersionTLS13
	}

	return tls.VersionTLS12
}
