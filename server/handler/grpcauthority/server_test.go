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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	"github.com/croessner/nauthilus/v3/server/secret"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
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
			claims: grpcBackchannelAccessClaims(definitions.ScopeAuthenticate),
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
			claims: grpcBackchannelAccessClaims(definitions.ScopeAuthenticate),
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
			claims: grpcBackchannelAccessClaims(definitions.ScopeAuthenticate + " " + definitions.ScopeListAccounts),
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
	cfg.Runtime.Servers.GRPC.Authority.TLS.RequireClientCert = true
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
	cfg.Runtime.Servers.GRPC.Authority.TLS.RequireClientCert = true
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
	enableBruteForceControl(t, cfg)

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

//nolint:funlen
func TestLoggingTracingInterceptorIncludesAuthorityFields(t *testing.T) {
	var logBuffer bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	interceptor := loggingTracingInterceptor(ServerDeps{
		Cfg:    grpcAuthDebugLogConfig(t, definitions.DbgAuthName),
		Logger: logger,
	})
	request := &authv1.AuthRequest{
		Username:           "log-user@example.test",
		ClientIp:           "203.0.113.44",
		ClientPort:         "43124",
		ClientHostname:     "client.example.test",
		ClientId:           "client-id",
		ExternalSessionId:  "external-session-44",
		UserAgent:          "grpc-client/1.0",
		LocalIp:            "127.0.0.1",
		LocalPort:          "9444",
		Protocol:           "imap",
		Method:             "PLAIN",
		Ssl:                "on",
		SslSessionId:       "ssl-session",
		SslClientVerify:    "SUCCESS",
		SslClientDn:        "CN=client,O=Example",
		SslClientCn:        "client",
		SslIssuer:          "CN=issuer",
		SslClientNotbefore: "2026-01-01T00:00:00Z",
		SslClientNotafter:  "2026-12-31T23:59:59Z",
		SslSubjectDn:       "CN=subject",
		SslIssuerDn:        "CN=issuer-dn",
		SslClientSubjectDn: "CN=client-subject",
		SslClientIssuerDn:  "CN=client-issuer",
		SslProtocol:        "TLSv1.3",
		SslCipher:          "TLS_AES_256_GCM_SHA384",
		SslSerial:          "serial-1",
		SslFingerprint:     "aa:bb:cc",
		OidcCid:            "oidc-client",
		AuthLoginAttempt:   4,
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
	assertLogAttr(t, attrs, definitions.LogKeyClientPort, "43124")
	assertLogAttr(t, attrs, definitions.LogKeyClientHost, "client.example.test")
	assertLogAttr(t, attrs, definitions.LogKeyClientID, "client-id")
	assertLogAttr(t, attrs, definitions.LogKeyUserAgent, "grpc-client/1.0")
	assertLogAttr(t, attrs, definitions.LogKeyLocalIP, "127.0.0.1")
	assertLogAttr(t, attrs, definitions.LogKeyPort, "9444")
	assertLogAttr(t, attrs, definitions.LogKeyAuthMethod, "PLAIN")
	assertLogAttr(t, attrs, definitions.LogKeyOIDCCID, "oidc-client")
	assertLogAttr(t, attrs, definitions.LogKeyTLSSecure, "TLSv1.3")
	assertLogAttr(t, attrs, definitions.LogKeyTLSCipher, "TLS_AES_256_GCM_SHA384")
	assertLogAttr(t, attrs, definitions.LogKeyUsername, "log-user@example.test")
	assertLogAttr(t, attrs, definitions.LogKeySSL, "on")
	assertLogAttr(t, attrs, definitions.LogKeySSLSessionID, "ssl-session")
	assertLogAttr(t, attrs, definitions.LogKeySSLClientVerify, "SUCCESS")
	assertLogAttr(t, attrs, definitions.LogKeySSLClientDN, "CN=client,O=Example")
	assertLogAttr(t, attrs, definitions.LogKeySSLClientCN, "client")
	assertLogAttr(t, attrs, definitions.LogKeySSLIssuer, "CN=issuer")
	assertLogAttr(t, attrs, definitions.LogKeySSLClientNotBefore, "2026-01-01T00:00:00Z")
	assertLogAttr(t, attrs, definitions.LogKeySSLClientNotAfter, "2026-12-31T23:59:59Z")
	assertLogAttr(t, attrs, definitions.LogKeySSLSubjectDN, "CN=subject")
	assertLogAttr(t, attrs, definitions.LogKeySSLIssuerDN, "CN=issuer-dn")
	assertLogAttr(t, attrs, definitions.LogKeySSLClientSubjectDN, "CN=client-subject")
	assertLogAttr(t, attrs, definitions.LogKeySSLClientIssuerDN, "CN=client-issuer")
	assertLogAttr(t, attrs, definitions.LogKeySSLSerial, "serial-1")
	assertLogAttr(t, attrs, definitions.LogKeySSLFingerprint, "aa:bb:cc")
	assertLogAttrValue(t, attrs, definitions.LogKeyAuthLoginAttempt, float64(4))
	assertLogAttr(t, attrs, "decision", authv1.AuthDecision_AUTH_DECISION_OK.String())
	assertLogAttr(t, attrs, "debug_module", definitions.DbgAuthName)
}

func TestUnaryServerInterceptorExtractsIncomingTraceContext(t *testing.T) {
	collector := &grpcTraceSpanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(collector)),
	)

	restore := installGRPCTraceTestGlobals(tp)
	defer restore()

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
		metadata.Pairs(
			"authorization", basicAuthorization("grpc-client", "grpc-secret-1234"),
			"traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		),
	)

	var handlerSpanContext oteltrace.SpanContext

	response, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: authv1.AuthService_Authenticate_FullMethodName,
	}, func(ctx context.Context, _ any) (any, error) {
		handlerSpanContext = oteltrace.SpanContextFromContext(ctx)

		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	if response != "ok" {
		t.Fatalf("response = %v, want ok", response)
	}

	if !handlerSpanContext.IsValid() {
		t.Fatal("handler context did not receive a valid span context")
	}

	assertIncomingGRPCTraceParent(t, collector, handlerSpanContext)
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

func TestBuildServerTLSConfigUsesConfiguredMinimumVersion(t *testing.T) {
	certFile, keyFile := writeGRPCTestTLSKeyPair(t)

	tlsConfig, err := buildServerTLSConfig(&config.RuntimeGRPCTLSSection{
		Enabled:       true,
		Cert:          certFile,
		Key:           keyFile,
		MinTLSVersion: "TLS1.3",
	})
	if err != nil {
		t.Fatalf("buildServerTLSConfig() error = %v", err)
	}

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %v, want %v", tlsConfig.MinVersion, tls.VersionTLS13)
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
		t.Fatal("gRPC authority server did not stop after context cancellation")
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
			Decision: core.AuthDecisionOK,
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

func TestBufconnAuthServiceListAccountsPolicyDenialUsesResponseMetadata(t *testing.T) {
	service := &recordingService{
		listOutcome: &core.ListAccountsOutcome{
			Decision:      core.AuthDecisionFail,
			Session:       "bufconn-list-deny-session",
			StatusMessage: "Custom account listing deny",
			HTTPStatus:    403,
		},
	}
	client := newBufconnAuthServiceClient(t, service)
	ctx := outgoingBasicAuthContext(context.Background())

	var header metadata.MD

	response, err := client.ListAccounts(ctx, &authv1.ListAccountsRequest{
		ClientIp: "203.0.113.34",
	}, grpc.Header(&header))
	if err != nil {
		t.Fatalf("ListAccounts returned transport error: %v", err)
	}

	if len(response.GetAccounts()) != 0 {
		t.Fatalf("accounts = %#v, want empty response data on policy denial", response.GetAccounts())
	}

	if response.GetSession() != "bufconn-list-deny-session" {
		t.Fatalf("session = %q, want bufconn-list-deny-session", response.GetSession())
	}

	if got := header.Get("auth-status"); len(got) != 1 || got[0] != "Custom account listing deny" {
		t.Fatalf("auth-status metadata = %#v, want configured denial message", got)
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
		addr:   testAddr("grpc-authority-test"),
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
					Authority: config.RuntimeGRPCAuthServerSection{
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

func writeGRPCTestTLSKeyPair(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile := dir + "/server.crt"
	keyFile := dir + "/server.key"

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	if err = os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	if err = os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	return certFile, keyFile
}

func enableBruteForceControl(t *testing.T, cfg *config.FileSettings) {
	t.Helper()

	var runtimeModule config.RuntimeModule
	if err := runtimeModule.Set(definitions.ControlBruteForce); err != nil {
		t.Fatalf("set brute-force control: %v", err)
	}

	cfg.Server.RuntimeModules = []*config.RuntimeModule{&runtimeModule}
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

	assertLogAttrValue(t, attrs, key, want)
}

func assertLogAttrValue(t *testing.T, attrs map[string]any, key string, want any) {
	t.Helper()

	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing log key %q in %#v", key, attrs)
	}

	if got != want {
		t.Fatalf("log key %q = %#v, want %#v", key, got, want)
	}
}

type grpcTraceSpanCollector struct {
	mu    sync.Mutex
	spans []sdktrace.ReadOnlySpan
}

func (c *grpcTraceSpanCollector) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.spans = append(c.spans, spans...)

	return nil
}

func (c *grpcTraceSpanCollector) Shutdown(context.Context) error {
	return nil
}

func (c *grpcTraceSpanCollector) findSpan(name string) (sdktrace.ReadOnlySpan, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, span := range c.spans {
		if span.Name() == name {
			return span, true
		}
	}

	return nil, false
}

func installGRPCTraceTestGlobals(tp *sdktrace.TracerProvider) func() {
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return func() {
		_ = tp.Shutdown(context.Background())

		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	}
}

func assertIncomingGRPCTraceParent(
	t *testing.T,
	collector *grpcTraceSpanCollector,
	handlerSpanContext oteltrace.SpanContext,
) {
	t.Helper()

	if got := handlerSpanContext.TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("handler trace id = %s, want incoming trace id", got)
	}

	span, found := collector.findSpan(grpcSpanName(authv1.AuthService_Authenticate_FullMethodName))
	if !found {
		t.Fatalf("gRPC span %q was not recorded", grpcSpanName(authv1.AuthService_Authenticate_FullMethodName))
	}

	if got := span.Parent().SpanID().String(); got != "00f067aa0ba902b7" {
		t.Fatalf("gRPC span parent = %s, want incoming parent span", got)
	}

	if span.SpanKind() != oteltrace.SpanKindServer {
		t.Fatalf("span kind = %v, want %v", span.SpanKind(), oteltrace.SpanKindServer)
	}
}

func okUnaryHandler(context.Context, any) (any, error) {
	return "ok", nil
}

func basicAuthorization(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// grpcBackchannelAccessClaims returns valid access-token claims for gRPC backchannel tests.
func grpcBackchannelAccessClaims(scope string) jwt.MapClaims {
	return jwt.MapClaims{
		"aud":                      definitions.AudienceBackchannelAPI,
		"scope":                    scope,
		"sub":                      "grpc-client",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
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
