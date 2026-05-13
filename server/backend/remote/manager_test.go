// Package remote tests edge-side remote backend behavior.
package remote

import (
	"context"
	stderrors "errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	authv1 "github.com/croessner/nauthilus/server/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/go-redis/redismock/v9"
)

const (
	remoteTestAuthorityName        = "edge"
	remoteTestBackendName          = "default"
	remoteTestAccountField         = "mail"
	remoteTestAuthorityBackendType = "ldap"
	remoteTestAuthorityBackendName = "primary"
	remoteTestBackendRefToken      = "opaque-ref"
	remoteTestBufconnRefToken      = "bufconn-ref"
	remoteTestAccountA             = "a@example.test"
	remoteTestAccountB             = "b@example.test"
)

func TestMain(m *testing.M) {
	core.InitPassDBResultPool()

	code := m.Run()
	_ = CloseConnectionManagers()

	os.Exit(code)
}

func TestManagerPassDBAuthenticatesAndBindsBackendRef(t *testing.T) {
	client := &fakeAuthorityClient{
		authResponse: &authv1.AuthResponse{
			Ok:              true,
			Decision:        authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField:    remoteTestAccountField,
			TotpSecretField: "totp",
			Backend:         uint32(definitions.BackendLDAP),
			Attributes: map[string]*commonv1.AttributeValues{
				remoteTestAccountField: {Values: []string{"alice@example.test"}},
			},
			BackendRef: &commonv1.BackendRef{
				Type:        remoteTestAuthorityBackendType,
				Name:        remoteTestAuthorityBackendName,
				Protocol:    "imap",
				Authority:   remoteTestAuthorityName,
				OpaqueToken: remoteTestBackendRefToken,
			},
		},
	}
	manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("auth"), client)
	auth := newRemoteAuthState(t, false)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if !result.Authenticated || !result.UserFound {
		t.Fatalf("PassDB() result authenticated=%v user_found=%v, want both true", result.Authenticated, result.UserFound)
	}

	if result.Backend != definitions.BackendRemote || result.BackendName != remoteTestBackendName {
		t.Fatalf("backend = %s/%q, want remote/default", result.Backend.String(), result.BackendName)
	}

	if got := result.BackendRef.OpaqueToken; got != remoteTestBackendRefToken {
		t.Fatalf("backend ref token = %q, want %s", got, remoteTestBackendRefToken)
	}

	if client.authRequests != 1 || client.lookupRequests != 0 {
		t.Fatalf("auth calls=%d lookup calls=%d, want 1/0", client.authRequests, client.lookupRequests)
	}
}

func TestManagerPassDBUsesLookupForNoAuth(t *testing.T) {
	client := &fakeAuthorityClient{
		lookupResponse: &authv1.AuthResponse{
			Ok:           true,
			Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField: remoteTestAccountField,
			Attributes: map[string]*commonv1.AttributeValues{
				remoteTestAccountField: {Values: []string{"lookup@example.test"}},
			},
		},
	}
	manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("lookup_identity"), client)
	auth := newRemoteAuthState(t, true)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if result.Authenticated || !result.UserFound {
		t.Fatalf("lookup result authenticated=%v user_found=%v, want false/true", result.Authenticated, result.UserFound)
	}

	if client.authRequests != 0 || client.lookupRequests != 1 {
		t.Fatalf("auth calls=%d lookup calls=%d, want 0/1", client.authRequests, client.lookupRequests)
	}
}

func TestManagerAccountDBUsesListAccounts(t *testing.T) {
	client := &fakeAuthorityClient{
		listResponse: &authv1.ListAccountsResponse{Accounts: []string{remoteTestAccountA, remoteTestAccountB}},
	}
	manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("list_accounts"), client)
	auth := newRemoteAuthState(t, false)

	accounts, err := manager.AccountDB(auth)
	if err != nil {
		t.Fatalf("AccountDB() error = %v", err)
	}

	if len(accounts) != 2 || accounts[0] != remoteTestAccountA || accounts[1] != remoteTestAccountB {
		t.Fatalf("AccountDB() = %#v, want two remote accounts", accounts)
	}
}

func TestManagerFailsClosedForDeniedOperationsAndTransientErrors(t *testing.T) {
	t.Run("operation denied", func(t *testing.T) {
		manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("lookup_identity"), &fakeAuthorityClient{})

		_, err := manager.PassDB(newRemoteAuthState(t, false))
		if err == nil || !stderrors.Is(err, ErrRemoteOperationDenied) {
			t.Fatalf("PassDB() error = %v, want ErrRemoteOperationDenied", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("auth"), &fakeAuthorityClient{err: context.DeadlineExceeded})

		_, err := manager.PassDB(newRemoteAuthState(t, false))
		if err == nil || !stderrors.Is(err, ErrRemoteAuthorityUnavailable) {
			t.Fatalf("PassDB() error = %v, want ErrRemoteAuthorityUnavailable", err)
		}
	})

	t.Run("domain tempfail", func(t *testing.T) {
		manager := NewManagerForTest(remoteTestBackendName, remoteTestAuthorityName, remoteBackendConfig("auth"), &fakeAuthorityClient{
			authResponse: &authv1.AuthResponse{Decision: authv1.AuthDecision_AUTH_DECISION_TEMPFAIL, Error: "temporary"},
		})

		_, err := manager.PassDB(newRemoteAuthState(t, false))
		if err == nil || !stderrors.Is(err, ErrRemoteAuthorityUnavailable) {
			t.Fatalf("PassDB() error = %v, want ErrRemoteAuthorityUnavailable", err)
		}
	})
}

func TestCoreRegistryBuildsRemoteBackendManager(t *testing.T) {
	cfg := &config.FileSettings{
		Runtime: &config.RuntimeSection{
			Clients: config.RuntimeClientsSection{
				GRPC: config.RuntimeGRPCClientsSection{
					NauthilusAuthorities: map[string]*config.NauthilusAuthorityClientSection{
						remoteTestAuthorityName: {
							Address: "127.0.0.1:9444",
							CallerAuth: config.AuthorityCallerAuthSection{
								OIDCBearer: config.AuthorityOIDCBearerSection{
									Enabled:                 true,
									Mode:                    config.AuthorityClientCredentialsMode,
									TokenEndpoint:           "https://authority.example.test/oidc/token",
									ClientID:                "edge-client",
									ClientSecret:            secret.New("edge-secret"),
									TokenEndpointAuthMethod: config.AuthorityClientSecretPostAuth,
								},
							},
						},
					},
				},
			},
		},
		Auth: &config.AuthSection{
			Backends: config.AuthBackendsSection{
				Remote: map[string]*config.RemoteBackendSection{
					remoteTestBackendName: remoteBackendConfig("auth"),
				},
			},
		},
	}
	db, _ := redismock.NewClientMock()
	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    cfg,
		Logger: slog.Default(),
		Redis:  rediscli.NewTestClient(db),
	}).(*core.AuthState)

	manager := auth.GetBackendManager(definitions.BackendRemote, remoteTestBackendName)
	if manager == nil {
		t.Fatal("GetBackendManager(remote) = nil, want registered manager")
	}
}

func newRemoteAuthState(t *testing.T, noAuth bool) *core.AuthState {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/auth", nil)
	db, _ := redismock.NewClientMock()
	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{Logger: slog.Default(), Redis: rediscli.NewTestClient(db)}).(*core.AuthState)
	auth.Request.HTTPClientRequest = request
	auth.Request.Username = "alice"
	auth.Request.Password = secret.New("password")
	auth.Request.ClientIP = "192.0.2.20"
	auth.Request.XClientPort = "12345"
	auth.Request.ClientHost = "client.example.test"
	auth.Request.XClientID = "client-id"
	auth.Request.ExternalSessionID = "external-session"
	auth.Request.UserAgent = "remote-test"
	auth.Request.XLocalIP = "192.0.2.10"
	auth.Request.XPort = "993"
	auth.Request.Protocol = &config.Protocol{}
	auth.Request.Protocol.Set("imap")
	auth.Request.Method = "plain"
	auth.Request.OIDCCID = "oidc-client"
	auth.Request.AuthLoginAttempt = 2
	auth.Request.NoAuth = noAuth
	auth.Runtime.GUID = "remote-guid"
	auth.Runtime.StartTime = time.Now()

	return auth
}

func remoteBackendConfig(operations ...string) *config.RemoteBackendSection {
	return &config.RemoteBackendSection{
		Authority:         remoteTestAuthorityName,
		Mode:              "nauthilus",
		AllowedOperations: operations,
		Timeout:           5 * time.Second,
	}
}

type fakeAuthorityClient struct {
	authResponse     *authv1.AuthResponse
	lookupResponse   *authv1.AuthResponse
	listResponse     *authv1.ListAccountsResponse
	resolveResponse  *identityv1.UserSnapshotResponse
	mfaResponse      *identityv1.MFAStateResponse
	webauthnResponse *identityv1.WebAuthnCredentialsResponse
	err              error
	authRequests     int
	lookupRequests   int
	listRequests     int
	resolveRequests  int
	mfaRequests      int
	webauthnRequests int
}

func (c *fakeAuthorityClient) Authenticate(_ context.Context, _ *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	c.authRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.authResponse, nil
}

func (c *fakeAuthorityClient) LookupIdentity(_ context.Context, _ *authv1.LookupIdentityRequest) (*authv1.AuthResponse, error) {
	c.lookupRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.lookupResponse, nil
}

func (c *fakeAuthorityClient) ListAccounts(_ context.Context, _ *authv1.ListAccountsRequest) (*authv1.ListAccountsResponse, error) {
	c.listRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.listResponse, nil
}

func (c *fakeAuthorityClient) ResolveUser(_ context.Context, _ *identityv1.ResolveUserRequest) (*identityv1.UserSnapshotResponse, error) {
	c.resolveRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.resolveResponse, nil
}

func (c *fakeAuthorityClient) GetMFAState(_ context.Context, _ *identityv1.GetMFAStateRequest) (*identityv1.MFAStateResponse, error) {
	c.mfaRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.mfaResponse, nil
}

func (c *fakeAuthorityClient) GetWebAuthnCredentials(
	_ context.Context,
	_ *identityv1.GetWebAuthnCredentialsRequest,
) (*identityv1.WebAuthnCredentialsResponse, error) {
	c.webauthnRequests++

	if c.err != nil {
		return nil, c.err
	}

	return c.webauthnResponse, nil
}
