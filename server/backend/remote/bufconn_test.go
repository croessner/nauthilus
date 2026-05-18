// Package remote tests bufconn-backed remote backend integration.
package remote

import (
	"context"
	"net"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	authv1 "github.com/croessner/nauthilus/server/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"
	grpcauthority "github.com/croessner/nauthilus/server/grpcclient/authority"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestBufconnRemoteManagerPassDBUsesAuthorityClient(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	authv1.RegisterAuthServiceServer(server, &bufconnAuthServer{})
	t.Cleanup(server.Stop)

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Errorf("bufconn server returned error: %v", err)
		}
	}()

	manager, err := grpcauthority.NewConnectionManager(grpcauthority.ConnectionManagerOptions{
		AuthorityName: remoteTestAuthorityName,
		Config: &config.NauthilusAuthorityClientSection{
			Address: "passthrough:///bufnet",
			CallerAuth: config.AuthorityCallerAuthSection{
				BasicAuth: config.BasicAuth{Enabled: true, Username: remoteTestAuthorityName},
			},
		},
		DialOptions: []grpc.DialOption{
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		},
		StaticTokenSource: grpcauthority.StaticBearerTokenSource("opaque-test-token"),
	})
	if err != nil {
		t.Fatalf("NewConnectionManager() error = %v", err)
	}
	defer func() {
		if closeErr := manager.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	remoteManager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("auth"), manager.Client())

	result, err := remoteManager.PassDB(newRemoteAuthState(t, false))
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if !result.Authenticated || result.BackendRef.OpaqueToken != remoteTestBufconnRefToken {
		t.Fatalf("PassDB() authenticated=%v ref=%#v, want ok bufconn ref", result.Authenticated, result.BackendRef)
	}
}

type bufconnAuthServer struct {
	authv1.UnimplementedAuthServiceServer
}

func (s *bufconnAuthServer) Authenticate(_ context.Context, request *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	return &authv1.AuthResponse{
		Ok:           true,
		Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
		AccountField: remoteTestAccountField,
		Attributes: map[string]*commonv1.AttributeValues{
			remoteTestAccountField: {Values: []string{request.GetUsername() + "@example.test"}},
		},
		BackendRef: &commonv1.BackendRef{
			Type:        remoteTestAuthorityBackendType,
			Name:        remoteTestAuthorityBackendName,
			Protocol:    request.GetProtocol(),
			Authority:   remoteTestAuthorityName,
			OpaqueToken: remoteTestBufconnRefToken,
		},
	}, nil
}
