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

package grpcauthority

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

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	identityv1 "github.com/croessner/nauthilus/v3/server/grpcapi/identity/v1"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/log/level"
	mdauth "github.com/croessner/nauthilus/v3/server/middleware/auth"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	authorizationMetadataKey          = "authorization"
	edgeClusterMetadataKey            = "x-nauthilus-edge-cluster"
	edgeInstanceMetadataKey           = "x-nauthilus-edge-instance"
	authorityServicePrincipalFallback = "grpc-authority-caller"
)

// ServerDeps contains the dependencies required by the gRPC authority server.
type ServerDeps struct {
	Cfg             config.File
	Env             config.Environment
	Logger          *slog.Logger
	Redis           rediscli.Client
	AccountCache    *accountcache.Manager
	Channel         backend.Channel
	AuthService     core.AuthApplicationService
	IdentityService AuthorityIdentityService
	BackendRefs     BackendRefStore
	MessageResolver localization.MessageResolver
	OIDCValidator   oidcbearer.TokenValidator
	Listener        net.Listener
}

type grpcAuthorityServerConfigProvider interface {
	GetRuntimeGRPCAuthServer() *config.RuntimeGRPCAuthServerSection
}

// StartServer starts the optional gRPC authority listener and returns a done
// channel that is closed after graceful shutdown completes. A nil done channel
// means the listener is disabled.
func StartServer(ctx context.Context, deps ServerDeps) (<-chan struct{}, error) {
	grpcAuthorityConfig := runtimeGRPCAuthorityServerConfig(deps.Cfg)
	if !grpcAuthorityConfig.IsEnabled() {
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

		listener, err = net.Listen("tcp", grpcAuthorityConfig.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("listen on runtime.servers.grpc.authority.address %q: %w", grpcAuthorityConfig.GetAddress(), err)
		}
	}

	server, err := NewServer(deps)
	if err != nil {
		_ = listener.Close()

		return nil, err
	}

	done := make(chan struct{})
	go serveGRPCAuthority(ctx, deps.effectiveLogger(), server, listener, done)

	_ = level.Info(deps.effectiveLogger()).Log(
		definitions.LogKeyMsg, "Starting Nauthilus gRPC authority server",
		"address", grpcAuthorityConfig.GetAddress(),
		"tls", grpcAuthorityConfig.GetTLS().IsEnabled(),
	)

	return done, nil
}

// NewServer builds a gRPC authority server and registers its services.
func NewServer(deps ServerDeps) (*grpc.Server, error) {
	if err := validateServerConfig(deps.Cfg); err != nil {
		return nil, err
	}

	grpcAuthorityConfig := runtimeGRPCAuthorityServerConfig(deps.Cfg)
	options := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(UnaryServerInterceptor(deps)),
	}

	if grpcAuthorityConfig.GetTLS().IsEnabled() {
		tlsConfig, err := buildServerTLSConfig(grpcAuthorityConfig.GetTLS())
		if err != nil {
			return nil, err
		}

		options = append(options, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	server := grpc.NewServer(options...)
	handler := NewWithServices(
		deps.authApplicationService(),
		deps.MessageResolver,
		deps.authorityIdentityService(),
		deps.backendRefStore(),
	)
	authv1.RegisterAuthServiceServer(server, handler)
	identityv1.RegisterIdentityBackendServiceServer(server, handler)

	return server, nil
}

// UnaryServerInterceptor returns the complete authority unary interceptor chain.
func UnaryServerInterceptor(deps ServerDeps) grpc.UnaryServerInterceptor {
	return chainUnaryInterceptors(
		recoveryInterceptor(deps),
		traceContextInterceptor(),
		loggingTracingInterceptor(deps),
		mtlsInterceptor(deps),
		backchannelAuthInterceptor(deps),
	)
}

func serveGRPCAuthority(
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
			definitions.LogKeyMsg, "gRPC authority server failed",
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

func runtimeGRPCAuthorityServerConfig(cfg config.File) *config.RuntimeGRPCAuthServerSection {
	provider, ok := cfg.(grpcAuthorityServerConfigProvider)
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

func (d ServerDeps) authorityIdentityService() AuthorityIdentityService {
	if d.IdentityService != nil {
		return d.IdentityService
	}

	return NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{
		AuthService: d.authApplicationService(),
		AuthDeps: core.AuthDeps{
			Cfg:          d.Cfg,
			Env:          d.Env,
			Logger:       d.effectiveLogger(),
			Redis:        d.Redis,
			AccountCache: d.AccountCache,
			Channel:      d.Channel,
		},
	})
}

func (d ServerDeps) backendRefStore() BackendRefStore {
	if d.BackendRefs != nil {
		return d.BackendRefs
	}

	if d.Redis == nil {
		return nil
	}

	return NewRedisBackendRefStore(d.Redis, RedisBackendRefStoreOptions{})
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

	return idp.NewNauthilusIDP(deps)
}

func buildServerTLSConfig(tlsSection *config.RuntimeGRPCTLSSection) (*tls.Config, error) {
	if tlsSection == nil || !tlsSection.IsEnabled() {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(tlsSection.GetCert(), tlsSection.GetKey())
	if err != nil {
		return nil, fmt.Errorf("load runtime.servers.grpc.authority.tls certificate: %w", err)
	}

	var clientCAs *x509.CertPool

	if tlsSection.GetClientCA() != "" {
		pem, err := os.ReadFile(tlsSection.GetClientCA())
		if err != nil {
			return nil, fmt.Errorf("read runtime.servers.grpc.authority.tls.client_ca: %w", err)
		}

		clientCAs = x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse runtime.servers.grpc.authority.tls.client_ca: invalid PEM data")
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
					definitions.LogKeyMsg, "Recovered panic in gRPC authority request",
					definitions.LogKeyError, fmt.Sprint(recovered),
					"method", grpcFullMethod(info),
					"stack", string(debug.Stack()),
				)

				response = nil
				err = status.Error(codes.Internal, "internal gRPC authority error")
			}
		}()

		return handler(ctx, req)
	}
}

func traceContextInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok || len(md) == 0 {
			return handler(ctx, req)
		}

		traceCtx := otel.GetTextMapPropagator().Extract(ctx, grpcMetadataCarrier(md))

		return handler(traceCtx, req)
	}
}

type grpcMetadataCarrier metadata.MD

func (c grpcMetadataCarrier) Get(key string) string {
	values := metadata.MD(c).Get(key)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

func (c grpcMetadataCarrier) Set(key string, value string) {
	metadata.MD(c).Set(strings.ToLower(key), value)
}

func (c grpcMetadataCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for key := range c {
		keys = append(keys, key)
	}

	return keys
}

func loggingTracingInterceptor(deps ServerDeps) grpc.UnaryServerInterceptor {
	logger := deps.effectiveLogger()
	tracer := monittrace.New("nauthilus/grpc")

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		method := grpcFullMethod(info)
		start := time.Now()

		traceCtx, span := tracer.StartServer(ctx, grpcSpanName(method))
		defer span.End()

		response, err := handler(traceCtx, req)
		code := status.Code(err)
		logFields := []any{
			definitions.LogKeyMsg, "gRPC authority request completed",
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
	tlsSection := runtimeGRPCAuthorityServerConfig(deps.Cfg).GetTLS()

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
		authCtx := context.WithValue(ctx, authorityRequestContextKey{}, req)

		result, err := authenticateCaller(authCtx, deps, grpcFullMethod(info))
		if err != nil {
			return nil, err
		}

		if result.claims != nil {
			ctx = core.ContextWithOIDCClaims(ctx, result.claims)
		}

		ctx = contextWithAuthorityCaller(ctx, result.caller)

		return handler(ctx, req)
	}
}

type callerAuthResult struct {
	claims jwt.MapClaims
	caller authorityCaller
}

type authorityCaller struct {
	Principal          string
	MTLSClientIdentity string
	EdgeClusterID      string
	EdgeInstanceID     string
	AllScopes          bool
}

type authorityCallerContextKey struct{}

type authorityRequestContextKey struct{}

func contextWithAuthorityCaller(ctx context.Context, caller authorityCaller) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	if caller.Principal == "" {
		caller.Principal = authorityServicePrincipalFallback
	}

	return context.WithValue(ctx, authorityCallerContextKey{}, caller)
}

func authorityCallerFromContext(ctx context.Context) authorityCaller {
	if ctx == nil {
		return authorityCaller{Principal: authorityServicePrincipalFallback}
	}

	caller, ok := ctx.Value(authorityCallerContextKey{}).(authorityCaller)
	if !ok {
		return authorityCaller{Principal: authorityServicePrincipalFallback}
	}

	if caller.Principal == "" {
		caller.Principal = authorityServicePrincipalFallback
	}

	return caller
}

func authorityCallerFromContextValues(ctx context.Context, principal string, allScopes bool) authorityCaller {
	return authorityCaller{
		Principal:      strings.TrimSpace(principal),
		EdgeClusterID:  firstIncomingMetadata(ctx, edgeClusterMetadataKey),
		EdgeInstanceID: firstIncomingMetadata(ctx, edgeInstanceMetadataKey),
		AllScopes:      allScopes,
	}
}

func authorityCallerFromClaims(ctx context.Context, claims jwt.MapClaims) authorityCaller {
	principal := claimString(claims, "sub")
	if principal == "" {
		principal = claimString(claims, "client_id")
	}

	if principal == "" {
		principal = claimString(claims, "azp")
	}

	if principal == "" {
		principal = claimString(claims, "iss")
	}

	return authorityCallerFromContextValues(ctx, principal, false)
}

func claimString(claims jwt.MapClaims, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}

	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func firstIncomingMetadata(ctx context.Context, key string) string {
	values := metadata.ValueFromIncomingContext(ctx, key)
	if len(values) == 0 {
		return ""
	}

	return strings.TrimSpace(values[0])
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

	if result, ok := authenticateBasicCaller(ctx, cfg, values, basicEnabled); ok {
		return result, nil
	}

	if !oidcEnabled {
		return callerAuthFailure(ctx, "invalid backchannel authorization metadata")
	}

	if result, ok, err := authenticateBearerCaller(ctx, deps, fullMethod, values); ok {
		return result, err
	}

	return callerAuthFailure(ctx, "invalid backchannel authorization metadata")
}

// authenticateBasicCaller authenticates the first valid Basic authorization value.
func authenticateBasicCaller(ctx context.Context, cfg config.File, values []string, basicEnabled bool) (callerAuthResult, bool) {
	if !basicEnabled {
		return callerAuthResult{}, false
	}

	for _, value := range values {
		scheme, payload, ok := splitAuthorization(value)
		if !ok || scheme != "basic" {
			continue
		}

		username, valid := validateBasicAuthorization(cfg, payload)
		if valid {
			return callerAuthResult{
				caller: authorityCallerFromContextValues(ctx, username, true),
			}, true
		}
	}

	return callerAuthResult{}, false
}

// authenticateBearerCaller authenticates Bearer authorization values.
func authenticateBearerCaller(ctx context.Context, deps ServerDeps, fullMethod string, values []string) (callerAuthResult, bool, error) {
	var permissionErr error

	for _, value := range values {
		scheme, payload, ok := splitAuthorization(value)
		if !ok || scheme != "bearer" {
			continue
		}

		claims, err := validateBearerAuthorization(ctx, deps, payload, fullMethod)
		if err == nil {
			return callerAuthResult{
				claims: claims,
				caller: authorityCallerFromClaims(ctx, claims),
			}, true, nil
		}

		if status.Code(err) == codes.PermissionDenied {
			permissionErr = err
		}
	}

	if permissionErr != nil {
		return callerAuthResult{}, true, permissionErr
	}

	return callerAuthResult{}, false, nil
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

func validateBasicAuthorization(cfg config.File, payload string) (string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	defer zeroBytes(decoded)

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", false
	}

	return username, mdauth.ValidateBasicCredentials(cfg, username, password)
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

	if !oidcbearer.IsBackchannelAccessToken(claims) {
		return nil, status.Error(codes.Unauthenticated, "invalid bearer token")
	}

	for _, requiredScope := range requiredScopesForRPC(fullMethod, requestFromContext(ctx)) {
		if !oidcbearer.HasScope(claims, requiredScope) {
			return nil, status.Error(codes.PermissionDenied, "missing required scope: "+requiredScope)
		}
	}

	return claims, nil
}

func requiredScopesForRPC(fullMethod string, request any) []string {
	if scopes, ok := staticScopeRequirements[fullMethod]; ok {
		return scopes
	}

	switch fullMethod {
	case identityv1.IdentityBackendService_ResolveUser_FullMethodName:
		return resolveUserRequiredScopes(request)
	case identityv1.IdentityBackendService_GetMFAState_FullMethodName:
		return getMFAStateRequiredScopes(request)
	default:
		return []string{definitions.ScopeAuthenticate}
	}
}

var staticScopeRequirements = map[string][]string{
	authv1.AuthService_Authenticate_FullMethodName:                            definitionsScopes(definitions.ScopeAuthenticate),
	authv1.AuthService_LookupIdentity_FullMethodName:                          definitionsScopes(definitions.ScopeLookupIdentity),
	authv1.AuthService_ListAccounts_FullMethodName:                            definitionsScopes(definitions.ScopeListAccounts),
	identityv1.IdentityBackendService_BeginTOTPRegistration_FullMethodName:    definitionsScopes(definitions.ScopeMFAWrite),
	identityv1.IdentityBackendService_FinishTOTPRegistration_FullMethodName:   definitionsScopes(definitions.ScopeMFAWrite),
	identityv1.IdentityBackendService_DeleteTOTP_FullMethodName:               definitionsScopes(definitions.ScopeMFAWrite),
	identityv1.IdentityBackendService_GenerateRecoveryCodes_FullMethodName:    definitionsScopes(definitions.ScopeMFAWrite),
	identityv1.IdentityBackendService_DeleteRecoveryCodes_FullMethodName:      definitionsScopes(definitions.ScopeMFAWrite),
	identityv1.IdentityBackendService_VerifyTOTP_FullMethodName:               definitionsScopes(definitions.ScopeMFAVerify),
	identityv1.IdentityBackendService_UseRecoveryCode_FullMethodName:          definitionsScopes(definitions.ScopeMFAVerify, definitions.ScopeMFAWrite),
	identityv1.IdentityBackendService_GetWebAuthnCredentials_FullMethodName:   definitionsScopes(definitions.ScopeWebAuthnRead),
	identityv1.IdentityBackendService_SaveWebAuthnCredential_FullMethodName:   definitionsScopes(definitions.ScopeWebAuthnWrite),
	identityv1.IdentityBackendService_UpdateWebAuthnCredential_FullMethodName: definitionsScopes(definitions.ScopeWebAuthnWrite),
	identityv1.IdentityBackendService_DeleteWebAuthnCredential_FullMethodName: definitionsScopes(definitions.ScopeWebAuthnWrite),
}

func definitionsScopes(scopes ...string) []string {
	return scopes
}

func resolveUserRequiredScopes(request any) []string {
	scopes := []string{definitions.ScopeLookupIdentity}
	if resolveRequestNeedsAttributeRead(request) {
		scopes = append(scopes, definitions.ScopeAttributeRead)
	}

	if resolveRequest, ok := request.(resolveUserScopeRequest); ok {
		if resolveRequest.GetIncludeMfaState() {
			scopes = append(scopes, definitions.ScopeMFARead)
		}

		if resolveRequest.GetIncludeWebauthnCredentials() {
			scopes = append(scopes, definitions.ScopeWebAuthnRead)
		}
	}

	return scopes
}

func getMFAStateRequiredScopes(request any) []string {
	scopes := []string{definitions.ScopeMFARead}
	if mfaRequest, ok := request.(getMFAStateScopeRequest); ok && mfaRequest.GetIncludeWebauthnCredentials() {
		scopes = append(scopes, definitions.ScopeWebAuthnRead)
	}

	return scopes
}

type resolveUserScopeRequest interface {
	GetAttributes() *identityv1.AttributeRequest
	GetIncludeMfaState() bool
	GetIncludeWebauthnCredentials() bool
}

type getMFAStateScopeRequest interface {
	GetIncludeWebauthnCredentials() bool
}

func requestFromContext(ctx context.Context) any {
	value := ctx.Value(authorityRequestContextKey{})
	if value == nil {
		return nil
	}

	return value
}

func resolveRequestNeedsAttributeRead(request any) bool {
	resolveRequest, ok := request.(resolveUserScopeRequest)
	if !ok || resolveRequest.GetAttributes() == nil {
		return false
	}

	attributes := resolveRequest.GetAttributes()

	return len(attributes.GetNames()) > 0 ||
		attributes.GetIncludeStandardIdentity() ||
		attributes.GetIncludeGroups() ||
		attributes.GetIncludeGroupDns() ||
		attributes.GetReportMissing()
}

func grpcSpanName(fullMethod string) string {
	switch fullMethod {
	case authv1.AuthService_Authenticate_FullMethodName:
		return "grpc.authority_authenticate"
	case authv1.AuthService_LookupIdentity_FullMethodName:
		return "grpc.authority_lookup_identity"
	case authv1.AuthService_ListAccounts_FullMethodName:
		return "grpc.authority_list_accounts"
	default:
		return "grpc.authority_unknown"
	}
}

func grpcFullMethod(info *grpc.UnaryServerInfo) string {
	if info == nil {
		return ""
	}

	return info.FullMethod
}
