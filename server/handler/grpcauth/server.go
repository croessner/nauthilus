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

package grpcauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	authv1 "github.com/croessner/nauthilus/server/grpcapi/auth/v1"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/log/level"
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const authorizationMetadataKey = "authorization"

// ServerDeps contains the dependencies required by the gRPC AuthService server.
type ServerDeps struct {
	Cfg           config.File
	Env           config.Environment
	Logger        *slog.Logger
	Redis         rediscli.Client
	AccountCache  *accountcache.Manager
	Channel       backend.Channel
	AuthService   core.AuthApplicationService
	OIDCValidator oidcbearer.TokenValidator
	Listener      net.Listener
}

type grpcAuthServerConfigProvider interface {
	GetRuntimeGRPCAuthServer() *config.RuntimeGRPCAuthServerSection
}

// StartServer starts the optional gRPC AuthService listener and returns a done
// channel that is closed after graceful shutdown completes. A nil done channel
// means the listener is disabled.
func StartServer(ctx context.Context, deps ServerDeps) (<-chan struct{}, error) {
	grpcAuthConfig := runtimeGRPCAuthServerConfig(deps.Cfg)
	if !grpcAuthConfig.IsEnabled() {
		return nil, nil
	}

	if err := validateServerConfig(deps.Cfg); err != nil {
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	listener := deps.Listener
	if listener == nil {
		var err error
		listener, err = net.Listen("tcp", grpcAuthConfig.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("listen on runtime.servers.grpc.auth.address %q: %w", grpcAuthConfig.GetAddress(), err)
		}
	}

	server, err := NewServer(deps)
	if err != nil {
		_ = listener.Close()

		return nil, err
	}

	done := make(chan struct{})
	go serveGRPCAuth(ctx, deps.effectiveLogger(), server, listener, done)

	_ = level.Info(deps.effectiveLogger()).Log(
		definitions.LogKeyMsg, "Starting Nauthilus gRPC AuthService server",
		"address", grpcAuthConfig.GetAddress(),
		"tls", grpcAuthConfig.GetTLS().IsEnabled(),
	)

	return done, nil
}

// NewServer builds a gRPC server and registers the AuthService.
func NewServer(deps ServerDeps) (*grpc.Server, error) {
	if err := validateServerConfig(deps.Cfg); err != nil {
		return nil, err
	}

	grpcAuthConfig := runtimeGRPCAuthServerConfig(deps.Cfg)
	options := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(UnaryServerInterceptor(deps)),
	}

	if grpcAuthConfig.GetTLS().IsEnabled() {
		tlsConfig, err := buildServerTLSConfig(grpcAuthConfig.GetTLS())
		if err != nil {
			return nil, err
		}

		options = append(options, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	server := grpc.NewServer(options...)
	authv1.RegisterAuthServiceServer(server, New(deps.authApplicationService()))

	return server, nil
}

// UnaryServerInterceptor returns the complete Phase-5 unary interceptor chain.
func UnaryServerInterceptor(deps ServerDeps) grpc.UnaryServerInterceptor {
	return chainUnaryInterceptors(
		recoveryInterceptor(deps),
		loggingTracingInterceptor(deps),
		mtlsInterceptor(deps),
		backchannelAuthInterceptor(deps),
	)
}

func serveGRPCAuth(
	ctx context.Context,
	logger *slog.Logger,
	server *grpc.Server,
	listener net.Listener,
	done chan<- struct{},
) {
	defer close(done)

	go func() {
		<-ctx.Done()

		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
		case <-time.After(30 * time.Second):
			server.Stop()
		}
	}()

	if err := server.Serve(listener); err != nil && !stderrors.Is(err, grpc.ErrServerStopped) {
		_ = level.Error(logger).Log(
			definitions.LogKeyMsg, "gRPC AuthService server failed",
			definitions.LogKeyError, err,
		)
	}
}

func validateServerConfig(cfg config.File) error {
	provider, ok := cfg.(config.RuntimeGRPCAuthServerProvider)
	if !ok {
		return nil
	}

	return config.ValidateGRPCAuthServerConfig(provider)
}

func runtimeGRPCAuthServerConfig(cfg config.File) *config.RuntimeGRPCAuthServerSection {
	provider, ok := cfg.(grpcAuthServerConfigProvider)
	if !ok {
		return &config.RuntimeGRPCAuthServerSection{}
	}

	return provider.GetRuntimeGRPCAuthServer()
}

func (d ServerDeps) authApplicationService() core.AuthApplicationService {
	if d.AuthService != nil {
		return d.AuthService
	}

	return core.NewAuthApplicationService(core.AuthDeps{
		Cfg:          d.Cfg,
		Env:          d.Env,
		Logger:       d.effectiveLogger(),
		Redis:        d.Redis,
		AccountCache: d.AccountCache,
		Channel:      d.Channel,
	})
}

func (d ServerDeps) effectiveLogger() *slog.Logger {
	if d.Logger == nil {
		return slog.Default()
	}

	return d.Logger
}

func (d ServerDeps) effectiveOIDCValidator() oidcbearer.TokenValidator {
	if d.OIDCValidator != nil {
		return d.OIDCValidator
	}

	if d.Cfg == nil || d.Redis == nil {
		return nil
	}

	deps := &handlerdeps.Deps{
		Cfg:          d.Cfg,
		Env:          d.Env,
		Logger:       d.effectiveLogger(),
		Redis:        d.Redis,
		AccountCache: d.AccountCache,
		Channel:      d.Channel,
	}

	return idp.NewNauthilusIdP(deps)
}

func buildServerTLSConfig(tlsSection *config.RuntimeGRPCTLSSection) (*tls.Config, error) {
	if tlsSection == nil || !tlsSection.IsEnabled() {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(tlsSection.GetCert(), tlsSection.GetKey())
	if err != nil {
		return nil, fmt.Errorf("load runtime.servers.grpc.auth.tls certificate: %w", err)
	}

	var clientCAs *x509.CertPool
	if tlsSection.GetClientCA() != "" {
		pem, err := os.ReadFile(tlsSection.GetClientCA())
		if err != nil {
			return nil, fmt.Errorf("read runtime.servers.grpc.auth.tls.client_ca: %w", err)
		}

		clientCAs = x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse runtime.servers.grpc.auth.tls.client_ca: invalid PEM data")
		}
	}

	clientAuth := tls.NoClientCert
	if tlsSection.RequiresClientCert() {
		clientAuth = tls.RequireAndVerifyClientCert
	} else if clientCAs != nil {
		clientAuth = tls.VerifyClientCertIfGiven
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
		MinVersion:   config.TLSMinVersionValue(tlsSection.GetMinTLSVersion()),
		NextProtos:   []string{"h2"},
	}, nil
}

func chainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		chainedHandler := handler

		for i := len(interceptors) - 1; i >= 0; i-- {
			current := interceptors[i]
			next := chainedHandler
			chainedHandler = func(interceptor grpc.UnaryServerInterceptor, nextHandler grpc.UnaryHandler) grpc.UnaryHandler {
				return func(ctx context.Context, req any) (any, error) {
					return interceptor(ctx, req, info, nextHandler)
				}
			}(current, next)
		}

		return chainedHandler(ctx, req)
	}
}

func recoveryInterceptor(deps ServerDeps) grpc.UnaryServerInterceptor {
	logger := deps.effectiveLogger()

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (response any, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				_ = level.Error(logger).Log(
					definitions.LogKeyMsg, "Recovered panic in gRPC AuthService request",
					definitions.LogKeyError, fmt.Sprint(recovered),
					"method", grpcFullMethod(info),
					"stack", string(debug.Stack()),
				)

				response = nil
				err = status.Error(codes.Internal, "internal gRPC AuthService error")
			}
		}()

		return handler(ctx, req)
	}
}

func loggingTracingInterceptor(deps ServerDeps) grpc.UnaryServerInterceptor {
	logger := deps.effectiveLogger()
	tracer := monittrace.New("nauthilus/grpc")

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		method := grpcFullMethod(info)
		start := time.Now()
		traceCtx, span := tracer.Start(ctx, grpcSpanName(method))
		defer span.End()

		response, err := handler(traceCtx, req)
		code := status.Code(err)
		logFields := []any{
			definitions.LogKeyMsg, "gRPC AuthService request completed",
			"method", method,
			"status", code.String(),
			"duration", time.Since(start).String(),
		}
		logFields = append(logFields, grpcRequestLogFields(req)...)
		logFields = append(logFields, grpcResponseLogFields(response)...)

		util.DebugModuleWithCfg(traceCtx, deps.Cfg, logger, definitions.DbgAuth, logFields...)

		return response, err
	}
}

func grpcRequestLogFields(req any) []any {
	switch typed := req.(type) {
	case *authv1.AuthRequest:
		fields := grpcStructuredRequestLogFields(typed)

		return appendNonZeroUint32LogField(fields, definitions.LogKeyAuthLoginAttempt, typed.GetAuthLoginAttempt())
	case *authv1.LookupIdentityRequest:
		return grpcStructuredRequestLogFields(typed)
	case *authv1.ListAccountsRequest:
		return grpcCommonRequestLogFields(typed)
	default:
		return nil
	}
}

type grpcCommonRequestLogSource interface {
	GetUsername() string
	GetClientIp() string
	GetClientPort() string
	GetClientHostname() string
	GetClientId() string
	GetExternalSessionId() string
	GetUserAgent() string
	GetLocalIp() string
	GetLocalPort() string
	GetProtocol() string
	GetMethod() string
	GetOidcCid() string
}

type grpcStructuredRequestLogSource interface {
	grpcCommonRequestLogSource
	GetSsl() string
	GetSslSessionId() string
	GetSslClientVerify() string
	GetSslClientDn() string
	GetSslClientCn() string
	GetSslIssuer() string
	GetSslClientNotbefore() string
	GetSslClientNotafter() string
	GetSslSubjectDn() string
	GetSslIssuerDn() string
	GetSslClientSubjectDn() string
	GetSslClientIssuerDn() string
	GetSslProtocol() string
	GetSslCipher() string
	GetSslSerial() string
	GetSslFingerprint() string
}

func grpcCommonRequestLogFields(req grpcCommonRequestLogSource) []any {
	fields := make([]any, 0, 28)
	fields = appendNonEmptyLogField(fields, definitions.LogKeyUsername, req.GetUsername())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyClientIP, req.GetClientIp())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyClientPort, req.GetClientPort())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyClientHost, req.GetClientHostname())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyClientID, req.GetClientId())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyExternalSession, req.GetExternalSessionId())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyUserAgent, req.GetUserAgent())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyLocalIP, req.GetLocalIp())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyPort, req.GetLocalPort())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyProtocol, req.GetProtocol())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyAuthMethod, req.GetMethod())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyOIDCCID, req.GetOidcCid())

	return fields
}

func grpcStructuredRequestLogFields(req grpcStructuredRequestLogSource) []any {
	fields := grpcCommonRequestLogFields(req)
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSL, req.GetSsl())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLSessionID, req.GetSslSessionId())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLClientVerify, req.GetSslClientVerify())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLClientDN, req.GetSslClientDn())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLClientCN, req.GetSslClientCn())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLIssuer, req.GetSslIssuer())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLClientNotBefore, req.GetSslClientNotbefore())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLClientNotAfter, req.GetSslClientNotafter())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLSubjectDN, req.GetSslSubjectDn())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLIssuerDN, req.GetSslIssuerDn())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLClientSubjectDN, req.GetSslClientSubjectDn())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLClientIssuerDN, req.GetSslClientIssuerDn())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyTLSSecure, req.GetSslProtocol())
	fields = appendNonEmptyLogField(fields, definitions.LogKeyTLSCipher, req.GetSslCipher())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLSerial, req.GetSslSerial())
	fields = appendNonEmptyLogField(fields, definitions.LogKeySSLFingerprint, req.GetSslFingerprint())

	return fields
}

func grpcResponseLogFields(response any) []any {
	switch typed := response.(type) {
	case *authv1.AuthResponse:
		fields := make([]any, 0, 4)
		fields = appendNonEmptyLogField(fields, definitions.LogKeyGUID, typed.GetSession())
		fields = appendNonEmptyLogField(fields, "decision", typed.GetDecision().String())

		return fields
	case *authv1.ListAccountsResponse:
		return appendNonEmptyLogField(nil, definitions.LogKeyGUID, typed.GetSession())
	default:
		return nil
	}
}

func appendNonEmptyLogField(fields []any, key, value string) []any {
	if value == "" {
		return fields
	}

	return append(fields, key, value)
}

func appendNonZeroUint32LogField(fields []any, key string, value uint32) []any {
	if value == 0 {
		return fields
	}

	return append(fields, key, value)
}

func mtlsInterceptor(deps ServerDeps) grpc.UnaryServerInterceptor {
	tlsSection := runtimeGRPCAuthServerConfig(deps.Cfg).GetTLS()

	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !tlsSection.RequiresClientCert() {
			return handler(ctx, req)
		}

		requestPeer, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing gRPC peer information")
		}

		tlsInfo, ok := requestPeer.AuthInfo.(credentials.TLSInfo)
		if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
			return nil, status.Error(codes.Unauthenticated, "client certificate is required")
		}

		return handler(ctx, req)
	}
}

func backchannelAuthInterceptor(deps ServerDeps) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		result, err := authenticateCaller(ctx, deps, grpcFullMethod(info))
		if err != nil {
			return nil, err
		}

		if result.claims != nil {
			ctx = core.ContextWithOIDCClaims(ctx, result.claims)
		}

		return handler(ctx, req)
	}
}

type callerAuthResult struct {
	claims jwt.MapClaims
}

func authenticateCaller(ctx context.Context, deps ServerDeps, fullMethod string) (callerAuthResult, error) {
	cfg := deps.Cfg
	if cfg == nil || cfg.GetServer() == nil {
		return callerAuthResult{}, status.Error(codes.Unauthenticated, "backchannel authentication is not configured")
	}

	basicEnabled := cfg.GetServer().GetBasicAuth().IsEnabled()
	oidcEnabled := cfg.GetServer().GetOIDCAuth().IsEnabled()
	if !basicEnabled && !oidcEnabled {
		return callerAuthResult{}, status.Error(codes.Unauthenticated, "backchannel authentication is not configured")
	}

	if exceeded, retryAfter := mdauth.MaybeThrottleAuthByIPValue(callerPeerIP(ctx), cfg); exceeded {
		return callerAuthResult{}, status.Errorf(
			codes.ResourceExhausted,
			"too many backchannel authentication failures; retry after %s",
			retryAfter.Truncate(time.Second),
		)
	}

	values := authorizationMetadata(ctx)
	if len(values) == 0 {
		return callerAuthFailure(ctx, "missing authorization metadata")
	}

	for _, value := range values {
		scheme, payload, ok := splitAuthorization(value)
		if ok && scheme == "basic" && basicEnabled && validateBasicAuthorization(cfg, payload) {
			return callerAuthResult{}, nil
		}
	}

	if !oidcEnabled {
		return callerAuthFailure(ctx, "invalid backchannel authorization metadata")
	}

	var permissionErr error
	for _, value := range values {
		scheme, payload, ok := splitAuthorization(value)
		if !ok || scheme != "bearer" {
			continue
		}

		claims, err := validateBearerAuthorization(ctx, deps, payload, fullMethod)
		if err == nil {
			return callerAuthResult{claims: claims}, nil
		}

		if status.Code(err) == codes.PermissionDenied {
			permissionErr = err
		}
	}

	if permissionErr != nil {
		return callerAuthResult{}, permissionErr
	}

	return callerAuthFailure(ctx, "invalid backchannel authorization metadata")
}

func callerAuthFailure(ctx context.Context, message string) (callerAuthResult, error) {
	mdauth.ApplyAuthBackoffOnFailureForIP(callerPeerIP(ctx))

	return callerAuthResult{}, status.Error(codes.Unauthenticated, message)
}

func callerPeerIP(ctx context.Context) string {
	requestPeer, ok := peer.FromContext(ctx)
	if !ok || requestPeer.Addr == nil {
		return ""
	}

	if tcpAddr, ok := requestPeer.Addr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		return tcpAddr.IP.String()
	}

	host, _, err := net.SplitHostPort(requestPeer.Addr.String())
	if err == nil {
		return host
	}

	return requestPeer.Addr.String()
}

func authorizationMetadata(ctx context.Context) []string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	return md.Get(authorizationMetadataKey)
}

func splitAuthorization(value string) (string, string, bool) {
	scheme, payload, ok := strings.Cut(strings.TrimSpace(value), " ")
	if !ok || strings.TrimSpace(payload) == "" {
		return "", "", false
	}

	return strings.ToLower(scheme), strings.TrimSpace(payload), true
}

func validateBasicAuthorization(cfg config.File, payload string) bool {
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	defer zeroBytes(decoded)

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}

	return mdauth.ValidateBasicCredentials(cfg, username, password)
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func validateBearerAuthorization(
	ctx context.Context,
	deps ServerDeps,
	token string,
	fullMethod string,
) (jwt.MapClaims, error) {
	validator := deps.effectiveOIDCValidator()
	if validator == nil {
		return nil, status.Error(codes.Unauthenticated, "OIDC bearer validator is not configured")
	}

	claims, err := validator.ValidateToken(ctx, token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid bearer token")
	}

	if !oidcbearer.HasScope(claims, definitions.ScopeAuthenticate) {
		return nil, status.Error(codes.PermissionDenied, "missing required scope: "+definitions.ScopeAuthenticate)
	}

	if isListAccountsMethod(fullMethod) && !oidcbearer.HasScope(claims, definitions.ScopeListAccounts) {
		return nil, status.Error(codes.PermissionDenied, "missing required scope: "+definitions.ScopeListAccounts)
	}

	return claims, nil
}

func isListAccountsMethod(fullMethod string) bool {
	return fullMethod == authv1.AuthService_ListAccounts_FullMethodName
}

func grpcSpanName(fullMethod string) string {
	switch fullMethod {
	case authv1.AuthService_Authenticate_FullMethodName:
		return "grpc.auth_authenticate"
	case authv1.AuthService_LookupIdentity_FullMethodName:
		return "grpc.auth_lookup_identity"
	case authv1.AuthService_ListAccounts_FullMethodName:
		return "grpc.auth_list_accounts"
	default:
		return "grpc.auth_unknown"
	}
}

func grpcFullMethod(info *grpc.UnaryServerInfo) string {
	if info == nil {
		return ""
	}

	return info.FullMethod
}
