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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	authv1 "github.com/croessner/nauthilus/server/grpcapi/auth/v1"
	"github.com/croessner/nauthilus/server/secret"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestUnaryServerInterceptorAllowsValidBasicAuth(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{})
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", basicAuthorization("grpc-client", "grpc-secret-1234")),
	)

	response, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, okUnaryHandler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if response != "ok" {
		t.Fatalf("response = %v, want ok", response)
	}
}

func TestUnaryServerInterceptorRejectsInvalidBasicAuth(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{})
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", basicAuthorization("grpc-client", "wrong-secret")),
	)

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, okUnaryHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}

func TestUnaryServerInterceptorRejectsEmptyConfiguredBasicCredentials(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled: true,
	}, config.OIDCAuth{})
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", basicAuthorization("", "")),
	)

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, okUnaryHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}

func TestUnaryServerInterceptorAllowsEitherConfiguredMechanism(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{Enabled: true})
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg: cfg,
		OIDCValidator: staticTokenValidator{
			err: errors.New("invalid bearer token"),
		},
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(
			"authorization", "Bearer invalid-token",
			"authorization", basicAuthorization("grpc-client", "grpc-secret-1234"),
		),
	)

	response, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, okUnaryHandler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if response != "ok" {
		t.Fatalf("response = %v, want ok", response)
	}
}

func TestUnaryServerInterceptorAllowsBearerWithAuthenticateScope(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{}, config.OIDCAuth{Enabled: true})
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg: cfg,
		OIDCValidator: staticTokenValidator{
			claims: jwt.MapClaims{"scope": definitions.ScopeAuthenticate},
		},
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer token-1"),
	)

	response, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, okUnaryHandler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if response != "ok" {
		t.Fatalf("response = %v, want ok", response)
	}
}

func TestUnaryServerInterceptorRejectsBearerListAccountsWithoutScope(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{}, config.OIDCAuth{Enabled: true})
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg: cfg,
		OIDCValidator: staticTokenValidator{
			claims: jwt.MapClaims{"scope": definitions.ScopeAuthenticate},
		},
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer token-1"),
	)

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_ListAccounts_FullMethodName,
	}, okUnaryHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}

func TestUnaryServerInterceptorAllowsBearerListAccountsWithScope(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{}, config.OIDCAuth{Enabled: true})
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg: cfg,
		OIDCValidator: staticTokenValidator{
			claims: jwt.MapClaims{
				"scope": definitions.ScopeAuthenticate + " " + definitions.ScopeListAccounts,
			},
		},
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer token-1"),
	)

	response, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_ListAccounts_FullMethodName,
	}, okUnaryHandler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if response != "ok" {
		t.Fatalf("response = %v, want ok", response)
	}
}

func TestUnaryServerInterceptorMapsPanicsToInternal(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{})
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", basicAuthorization("grpc-client", "grpc-secret-1234")),
	)

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, func(context.Context, any) (any, error) {
		panic("test panic")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Internal)
	}
}

func TestUnaryServerInterceptorRequiresClientCertificateWhenConfigured(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{})
	cfg.Runtime.Servers.GRPC.Auth.TLS.RequireClientCert = true
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", basicAuthorization("grpc-client", "grpc-secret-1234")),
	)

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, okUnaryHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}

func TestUnaryServerInterceptorAllowsClientCertificateWhenConfigured(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{})
	cfg.Runtime.Servers.GRPC.Auth.TLS.RequireClientCert = true
	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", basicAuthorization("grpc-client", "grpc-secret-1234")),
	)
	ctx = peer.NewContext(ctx, &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{}},
			},
		},
	})

	response, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, okUnaryHandler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if response != "ok" {
		t.Fatalf("response = %v, want ok", response)
	}
}

func TestUnaryServerInterceptorThrottlesInvalidCallerAuthByPeerIP(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{})
	enableBruteForceFeature(t, cfg)

	interceptor := UnaryServerInterceptor(ServerDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
	})
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", basicAuthorization("grpc-client", "wrong-secret")),
	)
	ctx = peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.211"), Port: 9444},
	})

	for i := range 5 {
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
			FullMethod: authv1.AuthService_Authenticate_FullMethodName,
		}, okUnaryHandler)
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("attempt %d code = %v, want %v", i+1, status.Code(err), codes.Unauthenticated)
		}
	}

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, okUnaryHandler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.ResourceExhausted)
	}
}

func TestLoggingTracingInterceptorIncludesPhase5Fields(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	interceptor := loggingTracingInterceptor(ServerDeps{
		Cfg:    grpcAuthDebugLogConfig(t, definitions.DbgAuthName),
		Logger: logger,
	})
	request := &authv1.AuthRequest{
		Username:          "log-user@example.test",
		ClientIp:          "203.0.113.44",
		Protocol:          "imap",
		ExternalSessionId: "external-session-44",
	}

	_, err := interceptor(context.Background(), request, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, func(context.Context, any) (any, error) {
		return &authv1.AuthResponse{
			Decision: authv1.AuthDecision_AUTH_DECISION_OK,
			Session:  "session-44",
		}, nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	attrs := decodeSlogJSONRecord(t, logBuffer.Bytes())
	assertLogAttr(t, attrs, "method", authv1.AuthService_Authenticate_FullMethodName)
	assertLogAttr(t, attrs, definitions.LogKeyGUID, "session-44")
	assertLogAttr(t, attrs, definitions.LogKeyExternalSession, "external-session-44")
	assertLogAttr(t, attrs, definitions.LogKeyProtocol, "imap")
	assertLogAttr(t, attrs, definitions.LogKeyClientIP, "203.0.113.44")
	assertLogAttr(t, attrs, definitions.LogKeyUsername, "log-user@example.test")
	assertLogAttr(t, attrs, "decision", authv1.AuthDecision_AUTH_DECISION_OK.String())
	assertLogAttr(t, attrs, "debug_module", definitions.DbgAuthName)
}

func TestLoggingTracingInterceptorUsesAuthDebugModule(t *testing.T) {
	request := &authv1.AuthRequest{Username: "log-user@example.test"}
	handler := func(context.Context, any) (any, error) {
		return &authv1.AuthResponse{
			Decision: authv1.AuthDecision_AUTH_DECISION_OK,
			Session:  "session-44",
		}, nil
	}

	t.Run("suppresses completion log without auth debug module", func(t *testing.T) {
		var logBuffer bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
		interceptor := loggingTracingInterceptor(ServerDeps{
			Cfg:    grpcAuthDebugLogConfig(t, definitions.DbgHTTPName),
			Logger: logger,
		})

		_, err := interceptor(context.Background(), request, &grpc.UnaryServerInfo{
			FullMethod: authv1.AuthService_Authenticate_FullMethodName,
		}, handler)
		if err != nil {
			t.Fatalf("interceptor returned error: %v", err)
		}

		if logBuffer.Len() != 0 {
			t.Fatalf("unexpected completion log without auth debug module: %s", logBuffer.String())
		}
	})

	t.Run("writes completion log with auth debug module", func(t *testing.T) {
		var logBuffer bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
		interceptor := loggingTracingInterceptor(ServerDeps{
			Cfg:    grpcAuthDebugLogConfig(t, definitions.DbgAuthName),
			Logger: logger,
		})

		_, err := interceptor(context.Background(), request, &grpc.UnaryServerInfo{
			FullMethod: authv1.AuthService_Authenticate_FullMethodName,
		}, handler)
		if err != nil {
			t.Fatalf("interceptor returned error: %v", err)
		}

		attrs := decodeSlogJSONRecord(t, logBuffer.Bytes())
		assertLogAttr(t, attrs, "debug_module", definitions.DbgAuthName)
		assertLogAttr(t, attrs, definitions.LogKeyGUID, "session-44")
	})
}

func TestNewServerRegistersAuthService(t *testing.T) {
	server, err := NewServer(ServerDeps{
		Cfg:    grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{}),
		Logger: slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	defer server.Stop()

	if _, found := server.GetServiceInfo()["nauthilus.auth.v1.AuthService"]; !found {
		t.Fatalf("registered services = %#v, want AuthService", server.GetServiceInfo())
	}
}

func TestStartServerStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	listener := newBlockingListener()

	done, err := StartServer(ctx, ServerDeps{
		Cfg:      grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{}),
		Logger:   slog.Default(),
		Listener: listener,
	})
	if err != nil {
		t.Fatalf("StartServer() error = %v", err)
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("gRPC AuthService server did not stop after context cancellation")
	}
}

func TestBufconnAuthServiceAuthenticateDomainOutcomes(t *testing.T) {
	cases := []struct {
		name         string
		outcome      *core.AuthOutcome
		wantDecision authv1.AuthDecision
		wantOK       bool
	}{
		{
			name:         "success",
			outcome:      newBufconnAuthOutcome(core.AuthDecisionOK, "bufconn-session-ok"),
			wantDecision: authv1.AuthDecision_AUTH_DECISION_OK,
			wantOK:       true,
		},
		{
			name:         "failure",
			outcome:      newBufconnAuthOutcome(core.AuthDecisionFail, "bufconn-session-fail"),
			wantDecision: authv1.AuthDecision_AUTH_DECISION_FAIL,
		},
		{
			name:         "tempfail",
			outcome:      newBufconnAuthOutcome(core.AuthDecisionTempFail, "bufconn-session-tempfail"),
			wantDecision: authv1.AuthDecision_AUTH_DECISION_TEMPFAIL,
		},
	}

	for _, testCase := range cases {

		t.Run(testCase.name, func(t *testing.T) {
			service := &recordingService{authOutcome: testCase.outcome}
			client := newBufconnAuthServiceClient(t, service)
			ctx := outgoingBasicAuthContext(context.Background())

			response, err := client.Authenticate(ctx, &authv1.AuthRequest{
				Username: "bufconn-auth@example.test",
				Password: "secret",
				ClientIp: "203.0.113.31",
				Protocol: "imap",
			})
			if err != nil {
				t.Fatalf("Authenticate returned transport error: %v", err)
			}

			if response.GetDecision() != testCase.wantDecision {
				t.Fatalf("decision = %v, want %v", response.GetDecision(), testCase.wantDecision)
			}

			if response.GetOk() != testCase.wantOK {
				t.Fatalf("ok = %v, want %v", response.GetOk(), testCase.wantOK)
			}

			if service.authInput.Mode != core.AuthModeAuthenticate {
				t.Fatalf("mode = %q, want %q", service.authInput.Mode, core.AuthModeAuthenticate)
			}
		})
	}
}

func TestBufconnAuthServiceLookupIdentityDomainOutcomes(t *testing.T) {
	cases := []struct {
		name         string
		outcome      *core.AuthOutcome
		wantDecision authv1.AuthDecision
	}{
		{
			name:         "success",
			outcome:      newBufconnAuthOutcome(core.AuthDecisionOK, "bufconn-lookup-ok"),
			wantDecision: authv1.AuthDecision_AUTH_DECISION_OK,
		},
		{
			name:         "failure",
			outcome:      newBufconnAuthOutcome(core.AuthDecisionFail, "bufconn-lookup-fail"),
			wantDecision: authv1.AuthDecision_AUTH_DECISION_FAIL,
		},
		{
			name:         "tempfail",
			outcome:      newBufconnAuthOutcome(core.AuthDecisionTempFail, "bufconn-lookup-tempfail"),
			wantDecision: authv1.AuthDecision_AUTH_DECISION_TEMPFAIL,
		},
	}

	for _, testCase := range cases {

		t.Run(testCase.name, func(t *testing.T) {
			service := &recordingService{lookupOutcome: testCase.outcome}
			client := newBufconnAuthServiceClient(t, service)
			ctx := outgoingBasicAuthContext(context.Background())

			response, err := client.LookupIdentity(ctx, &authv1.LookupIdentityRequest{
				Username: "bufconn-lookup@example.test",
				ClientIp: "203.0.113.32",
				Protocol: "imap",
			})
			if err != nil {
				t.Fatalf("LookupIdentity returned transport error: %v", err)
			}

			if response.GetDecision() != testCase.wantDecision {
				t.Fatalf("decision = %v, want %v", response.GetDecision(), testCase.wantDecision)
			}

			if service.lookupInput.Mode != core.AuthModeLookupIdentity {
				t.Fatalf("mode = %q, want %q", service.lookupInput.Mode, core.AuthModeLookupIdentity)
			}
		})
	}
}

func newBufconnAuthOutcome(decision core.AuthDecision, session string) *core.AuthOutcome {
	outcome := &core.AuthOutcome{
		Decision: decision,
		Session:  session,
	}

	switch decision {
	case core.AuthDecisionOK:
		outcome.Backend = definitions.BackendTest
		outcome.HTTPStatus = 200
	case core.AuthDecisionFail:
		outcome.StatusMessage = definitions.PasswordFail
		outcome.HTTPStatus = 403
	case core.AuthDecisionTempFail:
		outcome.StatusMessage = definitions.TempFailDefault
		outcome.Error = definitions.TempFailDefault
		outcome.HTTPStatus = 500
	}

	return outcome
}

func TestBufconnAuthServiceListAccountsSuccess(t *testing.T) {
	service := &recordingService{
		listOutcome: &core.ListAccountsOutcome{
			Accounts: core.AccountList{"alpha@example.test", "zeta@example.test"},
			Session:  "bufconn-list-session",
		},
	}
	client := newBufconnAuthServiceClient(t, service)
	ctx := outgoingBasicAuthContext(context.Background())

	response, err := client.ListAccounts(ctx, &authv1.ListAccountsRequest{
		ClientIp: "203.0.113.33",
	})
	if err != nil {
		t.Fatalf("ListAccounts returned transport error: %v", err)
	}

	if got := response.GetAccounts(); len(got) != 2 || got[0] != "alpha@example.test" || got[1] != "zeta@example.test" {
		t.Fatalf("accounts = %#v", got)
	}

	if response.GetSession() != "bufconn-list-session" {
		t.Fatalf("session = %q, want bufconn-list-session", response.GetSession())
	}

	if service.listInput.Mode != core.AuthModeListAccounts {
		t.Fatalf("mode = %q, want %q", service.listInput.Mode, core.AuthModeListAccounts)
	}
}

func TestBufconnAuthServiceRejectsMissingCallerAuth(t *testing.T) {
	service := &recordingService{
		authOutcome: &core.AuthOutcome{
			Decision: core.AuthDecisionOK,
			Session:  "should-not-run",
		},
	}
	client := newBufconnAuthServiceClient(t, service)

	_, err := client.Authenticate(context.Background(), &authv1.AuthRequest{
		Username: "bufconn-auth@example.test",
		Password: "secret",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}

	if service.authInput.Credentials.Username != "" {
		t.Fatalf("service should not have run, captured username %q", service.authInput.Credentials.Username)
	}
}

func newBlockingListener() *blockingListener {
	return &blockingListener{
		closed: make(chan struct{}),
		addr:   testAddr("grpc-auth-test"),
	}
}

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
	addr   net.Addr
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed

	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})

	return nil
}

func (l *blockingListener) Addr() net.Addr {
	return l.addr
}

type testAddr string

func (a testAddr) Network() string {
	return "test"
}

func (a testAddr) String() string {
	return string(a)
}

func newBufconnAuthServiceClient(t *testing.T, service core.AuthApplicationService) authv1.AuthServiceClient {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	server, err := NewServer(ServerDeps{
		Cfg:         grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{}),
		Logger:      slog.Default(),
		AuthService: service,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
			serveErr <- err

			return
		}

		serveErr <- nil
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("bufconn dial failed: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()

		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("bufconn server returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("bufconn server did not stop")
		}
	})

	return authv1.NewAuthServiceClient(conn)
}

func outgoingBasicAuthContext(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, authorizationMetadataKey, basicAuthorization("grpc-client", "grpc-secret-1234"))
}

func grpcAuthTestConfig(basic config.BasicAuth, oidc config.OIDCAuth) *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			BasicAuth: basic,
			OIDCAuth:  oidc,
		},
		Runtime: &config.RuntimeSection{
			Servers: config.RuntimeServersSection{
				GRPC: config.RuntimeGRPCServersSection{
					Auth: config.RuntimeGRPCAuthServerSection{
						Enabled: true,
						Address: "127.0.0.1:9444",
					},
				},
			},
		},
	}
}

func validBasicAuthConfig() config.BasicAuth {
	return config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}
}

func enableBruteForceFeature(t *testing.T, cfg *config.FileSettings) {
	t.Helper()

	var feature config.Feature
	if err := feature.Set(definitions.FeatureBruteForce); err != nil {
		t.Fatalf("set brute-force feature: %v", err)
	}

	cfg.Server.Features = []*config.Feature{&feature}
}

func grpcAuthDebugLogConfig(t *testing.T, debugModuleName string) *config.FileSettings {
	t.Helper()

	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())

	var verbosity config.Verbosity
	if err := verbosity.Set(definitions.LogLevelNameDebug); err != nil {
		t.Fatalf("set debug verbosity: %v", err)
	}

	debugModule := &config.DbgModule{}
	if err := debugModule.Set(debugModuleName); err != nil {
		t.Fatalf("set debug module: %v", err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{
			Log: config.Log{
				Level:      verbosity,
				DbgModules: []*config.DbgModule{debugModule},
			},
		},
	}
}

func decodeSlogJSONRecord(t *testing.T, data []byte) map[string]any {
	t.Helper()

	decoder := json.NewDecoder(bytes.NewReader(data))
	record := make(map[string]any)
	if err := decoder.Decode(&record); err != nil {
		t.Fatalf("decode log record: %v; raw=%q", err, string(data))
	}

	return record
}

func assertLogAttr(t *testing.T, attrs map[string]any, key string, want string) {
	t.Helper()

	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing log key %q in %#v", key, attrs)
	}

	if got != want {
		t.Fatalf("log key %q = %#v, want %q", key, got, want)
	}
}

func okUnaryHandler(context.Context, any) (any, error) {
	return "ok", nil
}

func basicAuthorization(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

type staticTokenValidator struct {
	claims jwt.MapClaims
	err    error
}

func (v staticTokenValidator) ValidateToken(context.Context, string) (jwt.MapClaims, error) {
	if v.err != nil {
		return nil, v.err
	}

	if v.claims == nil {
		return nil, errors.New("missing claims")
	}

	return v.claims, nil
}
