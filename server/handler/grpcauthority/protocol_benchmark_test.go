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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	_ "github.com/croessner/nauthilus/v3/server/core/auth"
	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	handlerauth "github.com/croessner/nauthilus/v3/server/handler/auth"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
	"github.com/segmentio/ksuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	protocolBenchmarkBackendName = "auth_protocol_benchmark"
	protocolBenchmarkClientIP    = "203.0.113.80"
	protocolBenchmarkPassword    = "protocol-benchmark-secret"
	protocolBenchmarkRedisPrefix = "benchmark:auth-protocol:"
	protocolBenchmarkUserAgent   = "nauthilus-protocol-benchmark/1.0"
)

type authProtocolBenchmarkFixture struct {
	httpClient     *http.Client
	grpcWithoutRef authv1.AuthServiceClient
	grpcWithRef    authv1.AuthServiceClient
	httpURL        string
	jsonAPI        jsoniter.API
}

type authProtocolJSONResponse struct {
	OK bool `json:"ok"`
}

type authProtocolBenchmarkScenario struct {
	uniqueUsernames bool
}

var protocolBenchmarkAccountSequence atomic.Uint64

// Benchmark scope: both paths use their production handlers, TLS 1.3, shared
// deterministic auth dependencies, and persistent client connections. Caller
// authentication middleware is excluded symmetrically, and no post-actions are
// configured, so the measurements end with the client-visible auth decision.

// BenchmarkAuthProtocolDecisionPathWarm compares stable successful auth decisions over TLS loopback transports.
func BenchmarkAuthProtocolDecisionPathWarm(b *testing.B) {
	runAuthProtocolDecisionPathBenchmark(b, authProtocolBenchmarkScenario{})
}

// BenchmarkAuthProtocolDecisionPathCold compares successful cold-account auth decisions over TLS loopback transports.
func BenchmarkAuthProtocolDecisionPathCold(b *testing.B) {
	runAuthProtocolDecisionPathBenchmark(b, authProtocolBenchmarkScenario{uniqueUsernames: true})
}

// runAuthProtocolDecisionPathBenchmark runs all transports for one shared cache scenario.
func runAuthProtocolDecisionPathBenchmark(b *testing.B, scenario authProtocolBenchmarkScenario) {
	fixture := newAuthProtocolBenchmarkFixture(b)

	b.Run("json", func(b *testing.B) {
		fixture.benchmarkJSON(b, scenario)
	})
	b.Run("grpc/backend_ref_disabled", func(b *testing.B) {
		fixture.benchmarkGRPC(b, fixture.grpcWithoutRef, "grpc-without-ref-", false, scenario)
	})
	b.Run("grpc/backend_ref_enabled", func(b *testing.B) {
		fixture.benchmarkGRPC(b, fixture.grpcWithRef, "grpc-with-ref-", true, scenario)
	})
}

// benchmarkJSON measures JSON client encoding, HTTP transport, auth handling, and response decoding.
func (f *authProtocolBenchmarkFixture) benchmarkJSON(b *testing.B, scenario authProtocolBenchmarkScenario) {
	b.StopTimer()

	if err := f.authenticateJSON(context.Background(), scenario.warmUsername("json-")); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	pprof.Do(context.Background(), scenario.profileLabels("json", false), func(ctx context.Context) {
		b.StartTimer()

		for iteration := 0; iteration < b.N; iteration++ {
			username := scenario.username("json-", iteration)
			if err := f.authenticateJSON(ctx, username); err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

// benchmarkGRPC measures Protobuf encoding, HTTP/2 transport, auth handling, and response decoding.
func (f *authProtocolBenchmarkFixture) benchmarkGRPC(
	b *testing.B,
	client authv1.AuthServiceClient,
	usernamePrefix string,
	wantBackendRef bool,
	scenario authProtocolBenchmarkScenario,
) {
	b.Helper()
	b.StopTimer()

	if err := authenticateGRPC(context.Background(), client, scenario.warmUsername(usernamePrefix), wantBackendRef); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	pprof.Do(context.Background(), scenario.profileLabels("grpc", wantBackendRef), func(ctx context.Context) {
		b.StartTimer()

		for iteration := 0; iteration < b.N; iteration++ {
			username := scenario.username(usernamePrefix, iteration)
			if err := authenticateGRPC(ctx, client, username, wantBackendRef); err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

// newAuthProtocolBenchmarkFixture builds both protocol servers around shared deterministic dependencies.
func newAuthProtocolBenchmarkFixture(b *testing.B) *authProtocolBenchmarkFixture {
	b.Helper()
	gin.SetMode(gin.TestMode)
	core.InitPassDBResultPool()

	deps := newAuthProtocolBenchmarkDeps(b)
	httpServer := newAuthProtocolHTTPServer(deps)
	service := core.NewAuthApplicationService(deps.Auth())
	certificate := httpServer.TLS.Certificates[0]
	grpcWithoutRef := newAuthProtocolGRPCClient(b, service, nil, certificate)
	backendRefs := NewRedisBackendRefStore(deps.Redis, RedisBackendRefStoreOptions{
		KeyPrefix: protocolBenchmarkRedisPrefix + "backend-ref:",
		Authority: "benchmark-authority",
		TTL:       time.Minute,
	})
	grpcWithRef := newAuthProtocolGRPCClient(b, service, backendRefs, certificate)
	fixture := &authProtocolBenchmarkFixture{
		httpClient:     httpServer.Client(),
		grpcWithoutRef: grpcWithoutRef,
		grpcWithRef:    grpcWithRef,
		httpURL:        httpServer.URL + "/api/v1/auth/json",
		jsonAPI:        jsoniter.ConfigCompatibleWithStandardLibrary,
	}

	b.Cleanup(httpServer.Close)

	return fixture
}

// newAuthProtocolBenchmarkDeps configures the shared in-memory backend and Redis test server.
func newAuthProtocolBenchmarkDeps(b *testing.B) *handlerdeps.Deps {
	b.Helper()

	var backend config.Backend

	backendName := protocolBenchmarkBackendName + "_" + ksuid.New().String()
	if err := backend.Set(fmt.Sprintf("%s(%s)", definitions.BackendTestName, backendName)); err != nil {
		b.Fatalf("configure benchmark backend: %v", err)
	}

	miniRedis, err := miniredis.Run()
	if err != nil {
		b.Fatalf("start benchmark Redis: %v", err)
	}

	redisDB := redis.NewClient(&redis.Options{Addr: miniRedis.Addr()})
	redisClient := rediscli.NewTestClient(redisDB)
	env := config.NewTestEnvironmentConfig()
	cfg := newAuthProtocolBenchmarkConfig(&backend)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	setAuthProtocolBenchmarkDefaults(cfg, env, logger)
	b.Cleanup(func() {
		redisClient.Close()
		miniRedis.Close()
	})

	return &handlerdeps.Deps{
		Cfg:          cfg,
		Env:          env,
		Logger:       logger,
		Redis:        redisClient,
		AccountCache: accountcache.NewManager(cfg),
	}
}

// newAuthProtocolBenchmarkConfig returns the minimal production-shaped auth configuration.
func newAuthProtocolBenchmarkConfig(backend *config.Backend) *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			Backends: []*config.Backend{backend},
			Redis: config.Redis{
				Prefix:      protocolBenchmarkRedisPrefix,
				NegCacheTTL: time.Minute,
				PosCacheTTL: time.Minute,
			},
			DefaultHTTPRequestHeader: config.DefaultHTTPRequestHeader{
				Username:   "X-Username",
				Password:   "X-Password",
				Protocol:   "X-Protocol",
				AuthMethod: "X-Method",
				ClientIP:   "X-Client-IP",
			},
		},
	}
}

// setAuthProtocolBenchmarkDefaults aligns legacy global accessors with injected benchmark dependencies.
func setAuthProtocolBenchmarkDefaults(cfg config.File, env config.Environment, logger *slog.Logger) {
	config.SetTestEnvironmentConfig(env)
	config.SetTestFile(cfg)
	core.SetDefaultConfigFile(cfg)
	core.SetDefaultEnvironment(env)
	core.SetDefaultLogger(logger)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(env)
	util.SetDefaultLogger(logger)
}

// newAuthProtocolHTTPServer starts the real JSON auth handler on a TLS loopback HTTP server.
func newAuthProtocolHTTPServer(deps *handlerdeps.Deps) *httptest.Server {
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxGUIDKey, ksuid.New().String())
		ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
		ctx.Next()
	})
	handlerauth.New(deps).Register(router.Group("/api/v1"))
	server := httptest.NewUnstartedServer(router)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()

	return server
}

// newAuthProtocolGRPCClient starts the real authority handler on a TLS loopback HTTP/2 server.
func newAuthProtocolGRPCClient(
	b *testing.B,
	service core.AuthApplicationService,
	backendRefs BackendRefStore,
	certificate tls.Certificate,
) authv1.AuthServiceClient {
	b.Helper()

	transportCredentials := newAuthProtocolClientCredentials(b, certificate)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen for benchmark gRPC server: %v", err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLS)),
		grpc.UnaryInterceptor(postActionResponseCompletionInterceptor()),
	)
	handler := NewWithServices(service, nil, nil, backendRefs)
	authv1.RegisterAuthServiceServer(server, handler)

	serveErr := make(chan error, 1)

	go func() {
		serveErr <- server.Serve(listener)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///"+listener.Addr().String(),
		grpc.WithTransportCredentials(transportCredentials),
	)
	if err != nil {
		server.Stop()

		_ = listener.Close()

		b.Fatalf("dial benchmark gRPC server: %v", err)
	}

	b.Cleanup(func() {
		_ = conn.Close()

		server.Stop()

		_ = listener.Close()

		<-serveErr
	})

	return authv1.NewAuthServiceClient(conn)
}

// newAuthProtocolClientCredentials trusts the shared loopback certificate for gRPC.
func newAuthProtocolClientCredentials(b *testing.B, certificate tls.Certificate) credentials.TransportCredentials {
	b.Helper()

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		b.Fatalf("parse benchmark gRPC certificate: %v", err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(leaf)

	return credentials.NewTLS(&tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS13,
	})
}

// authenticateJSON performs one complete JSON request and validates the decision response.
func (f *authProtocolBenchmarkFixture) authenticateJSON(ctx context.Context, username string) error {
	payload, err := f.jsonAPI.Marshal(newAuthProtocolJSONRequest(username))
	if err != nil {
		return fmt.Errorf("marshal JSON auth request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.httpURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create JSON auth request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := f.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("execute JSON auth request: %w", err)
	}

	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()

	if readErr != nil {
		return fmt.Errorf("read JSON auth response: %w", readErr)
	}

	if closeErr != nil {
		return fmt.Errorf("close JSON auth response: %w", closeErr)
	}

	var decoded authProtocolJSONResponse
	if err = f.jsonAPI.Unmarshal(body, &decoded); err != nil {
		return fmt.Errorf("decode JSON auth response: %w", err)
	}

	if response.StatusCode != http.StatusOK || !decoded.OK {
		return fmt.Errorf("JSON auth decision status=%d ok=%v", response.StatusCode, decoded.OK)
	}

	return nil
}

// authenticateGRPC performs one complete gRPC request and validates the decision response.
func authenticateGRPC(ctx context.Context, client authv1.AuthServiceClient, username string, wantBackendRef bool) error {
	response, err := client.Authenticate(ctx, newAuthProtocolGRPCRequest(username))
	if err != nil {
		return fmt.Errorf("execute gRPC auth request: %w", err)
	}

	if !response.GetOk() || response.GetDecision() != authv1.AuthDecision_AUTH_DECISION_OK {
		return fmt.Errorf("gRPC auth decision=%s ok=%v", response.GetDecision(), response.GetOk())
	}

	if (response.GetBackendRef() != nil) != wantBackendRef {
		return fmt.Errorf("gRPC backend ref present=%v want=%v", response.GetBackendRef() != nil, wantBackendRef)
	}

	return nil
}

// newAuthProtocolJSONRequest returns the shared authentication scenario as a JSON DTO.
func newAuthProtocolJSONRequest(username string) authdto.Request {
	return authdto.Request{
		Username:  username,
		Password:  protocolBenchmarkPassword,
		ClientIP:  protocolBenchmarkClientIP,
		Protocol:  definitions.ProtoIMAP,
		Method:    "plain",
		UserAgent: protocolBenchmarkUserAgent,
	}
}

// newAuthProtocolGRPCRequest returns the shared authentication scenario as a Protobuf DTO.
func newAuthProtocolGRPCRequest(username string) *authv1.AuthRequest {
	return &authv1.AuthRequest{
		Username:  username,
		Password:  protocolBenchmarkPassword,
		ClientIp:  protocolBenchmarkClientIP,
		Protocol:  definitions.ProtoIMAP,
		Method:    "plain",
		UserAgent: protocolBenchmarkUserAgent,
	}
}

// protocolBenchmarkUsername returns a unique cold-cache account for one benchmark iteration.
func protocolBenchmarkUsername(prefix string, sequence uint64) string {
	return prefix + strconv.FormatUint(sequence, 10) + "@example.test"
}

// username returns either one stable account or a unique cold-cache account.
func (s authProtocolBenchmarkScenario) username(prefix string, _ int) string {
	if s.uniqueUsernames {
		return protocolBenchmarkUsername(prefix, protocolBenchmarkAccountSequence.Add(1))
	}

	return prefix + "steady@example.test"
}

// warmUsername returns the account used to validate and preconnect one protocol path.
func (s authProtocolBenchmarkScenario) warmUsername(prefix string) string {
	if s.uniqueUsernames {
		return prefix + "warmup@example.test"
	}

	return s.username(prefix, 0)
}

// profileLabels identify one benchmark variant in CPU and allocation profiles.
func (s authProtocolBenchmarkScenario) profileLabels(protocol string, backendRef bool) pprof.LabelSet {
	scenario := "warm"
	if s.uniqueUsernames {
		scenario = "cold"
	}

	return pprof.Labels(
		"benchmark", "auth_protocol_decision",
		"scenario", scenario,
		"protocol", protocol,
		"backend_ref", strconv.FormatBool(backendRef),
	)
}
