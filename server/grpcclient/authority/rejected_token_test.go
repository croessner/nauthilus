// Package authority tests outbound authority client helpers.
package authority

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	rejectedTestStaleToken   = "stale-token"
	rejectedTestReplicaToken = "replica-token"
)

// authorityStub answers Authenticate and accepts only one bearer token.
type authorityStub struct {
	authv1.UnimplementedAuthServiceServer

	mu       sync.Mutex
	accepted string
	seen     []string
}

// Authenticate records the presented authorization header and rejects every other bearer token.
func (s *authorityStub) Authenticate(ctx context.Context, _ *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	authorization := ""

	if values := md.Get("authorization"); len(values) > 0 {
		authorization = values[0]
	}

	s.mu.Lock()
	s.seen = append(s.seen, authorization)
	accepted := s.accepted
	s.mu.Unlock()

	if accepted == "" || authorization != "Bearer "+accepted {
		return nil, status.Error(codes.Unauthenticated, "caller token rejected")
	}

	return &authv1.AuthResponse{}, nil
}

// presented returns the authorization headers the stub received in order.
func (s *authorityStub) presented() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.seen...)
}

// tokenEndpointStub issues numbered opaque tokens and records whether the cache was empty at fetch time.
type tokenEndpointStub struct {
	storage  *miniredis.Miniredis
	cacheKey string
	calls    atomic.Int32
	cacheSet atomic.Bool
}

// client returns an HTTP client whose transport serves the token endpoint.
func (e *tokenEndpointStub) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		call := e.calls.Add(1)

		if e.storage.Exists(e.cacheKey) {
			e.cacheSet.Store(true)
		}

		return jsonResponse(fmt.Sprintf(`{"access_token":"fresh-token-%d","token_type":"Bearer","expires_in":3600}`, call)), nil
	})}
}

// rejectedTokenFixture wires a miniredis token cache, a token endpoint and a bufconn authority.
type rejectedTokenFixture struct {
	storage  *miniredis.Miniredis
	source   *bearerTokenSource
	endpoint *tokenEndpointStub
	stub     *authorityStub
	manager  *ConnectionManager
}

// newRejectedTokenFixture builds the fixture; tokenSource overrides the bearer token source when set.
func newRejectedTokenFixture(t *testing.T, tokenSource BearerTokenSource) *rejectedTokenFixture {
	t.Helper()

	storage := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = db.Close() })

	fixture := &rejectedTokenFixture{storage: storage, stub: &authorityStub{}}
	fixture.endpoint = &tokenEndpointStub{storage: storage}
	fixture.source = newTestBearerTokenSource(BearerTokenSourceOptions{
		AuthorityName: tokenSourceAuthorityName,
		Config:        clientCredentialsConfig(tokenSourceEndpoint),
		Redis:         rediscli.NewTestClient(db),
		HTTPClient:    fixture.endpoint.client(),
		Now:           time.Now,
	})
	fixture.endpoint.cacheKey = fixture.source.cacheKey()

	if tokenSource == nil {
		tokenSource = fixture.source
	}

	fixture.manager = startAuthorityStub(t, fixture.stub, tokenSource)

	return fixture
}

// startAuthorityStub serves stub over bufconn and returns a connection manager dialing it.
func startAuthorityStub(t *testing.T, stub *authorityStub, tokenSource BearerTokenSource) *ConnectionManager {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	authv1.RegisterAuthServiceServer(server, stub)

	go func() { _ = server.Serve(listener) }()

	t.Cleanup(server.Stop)

	manager, err := NewConnectionManager(ConnectionManagerOptions{
		Config:        &config.NauthilusAuthorityClientSection{Address: "passthrough:///authority", Timeout: 5 * time.Second},
		TokenSource:   tokenSource,
		AuthorityName: tokenSourceAuthorityName,
		DialOptions: []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewConnectionManager() error = %v", err)
	}

	t.Cleanup(func() { _ = manager.Close() })

	return manager
}

// seedCachedToken stores token in the shared cache with a comfortable lifetime.
func (f *rejectedTokenFixture) seedCachedToken(t *testing.T, token string) {
	t.Helper()

	raw := mustEncodeCachedToken(t, cachedBearerToken{AccessToken: token, ExpiresAt: time.Now().Add(time.Hour)})
	if err := f.storage.Set(f.source.cacheKey(), raw); err != nil {
		t.Fatalf("seed cached token: %v", err)
	}
}

// cachedAccessToken returns the access token currently stored in the shared cache.
func (f *rejectedTokenFixture) cachedAccessToken(t *testing.T) string {
	t.Helper()

	cached, ok := f.source.readCachedToken(context.Background())
	if !ok {
		return ""
	}

	return cached.AccessToken
}

func TestAuthorityRejectedCachedTokenIsReplacedAndRetriedOnce(t *testing.T) {
	fixture := newRejectedTokenFixture(t, nil)
	fixture.seedCachedToken(t, rejectedTestStaleToken)
	fixture.stub.accepted = "fresh-token-1"

	if _, err := fixture.manager.Client().Authenticate(t.Context(), &authv1.AuthRequest{}); err != nil {
		t.Fatalf("Authenticate() error = %v, want success after one retry", err)
	}

	want := []string{"Bearer " + rejectedTestStaleToken, "Bearer fresh-token-1"}
	if got := fixture.stub.presented(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("presented tokens = %v, want %v", got, want)
	}

	if fixture.endpoint.cacheSet.Load() {
		t.Fatal("rejected token was still cached when the replacement was fetched")
	}

	if got := fixture.cachedAccessToken(t); got != "fresh-token-1" {
		t.Fatalf("cached token = %q, want fresh-token-1", got)
	}

	// The next RPC uses the cached replacement without another token request.
	if _, err := fixture.manager.Client().Authenticate(t.Context(), &authv1.AuthRequest{}); err != nil {
		t.Fatalf("second Authenticate() error = %v", err)
	}

	if calls := fixture.endpoint.calls.Load(); calls != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", calls)
	}
}

func TestAuthorityRejectedTokenIsRetriedOnlyOnce(t *testing.T) {
	fixture := newRejectedTokenFixture(t, nil)
	fixture.seedCachedToken(t, rejectedTestStaleToken)

	_, err := fixture.manager.Client().Authenticate(t.Context(), &authv1.AuthRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Authenticate() error = %v, want UNAUTHENTICATED", err)
	}

	if got := len(fixture.stub.presented()); got != 2 {
		t.Fatalf("authority calls = %d, want the original call plus one retry", got)
	}

	if calls := fixture.endpoint.calls.Load(); calls != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", calls)
	}
}

func TestAuthorityStaticTokenIsNeverRetried(t *testing.T) {
	fixture := newRejectedTokenFixture(t, StaticBearerTokenSource(rejectedTestStaleToken))

	_, err := fixture.manager.Client().Authenticate(t.Context(), &authv1.AuthRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Authenticate() error = %v, want UNAUTHENTICATED", err)
	}

	if got := len(fixture.stub.presented()); got != 1 {
		t.Fatalf("authority calls = %d, want no retry for a static token", got)
	}
}

func TestReplaceRejectedTokenKeepsTokenReplacedByAnotherReplica(t *testing.T) {
	fixture := newRejectedTokenFixture(t, nil)
	fixture.seedCachedToken(t, rejectedTestReplicaToken)

	token, err := fixture.source.ReplaceRejectedToken(t.Context(), rejectedTestStaleToken)
	if err != nil {
		t.Fatalf("ReplaceRejectedToken() error = %v", err)
	}

	if token != rejectedTestReplicaToken {
		t.Fatalf("ReplaceRejectedToken() = %q, want the replica token", token)
	}

	if got := fixture.cachedAccessToken(t); got != rejectedTestReplicaToken {
		t.Fatalf("cached token = %q, want the replica token to survive", got)
	}

	if calls := fixture.endpoint.calls.Load(); calls != 0 {
		t.Fatalf("token endpoint calls = %d, want none", calls)
	}
}

func TestReplaceRejectedTokenDeletesOnlyTheRejectedToken(t *testing.T) {
	fixture := newRejectedTokenFixture(t, nil)
	fixture.seedCachedToken(t, rejectedTestStaleToken)

	replacement, err := fixture.source.discardRejectedToken(t.Context(), rejectedTestStaleToken)
	if err != nil || replacement.AccessToken != "" {
		t.Fatalf("discardRejectedToken() = %+v err:%v, want a plain delete", replacement, err)
	}

	if fixture.storage.Exists(fixture.source.cacheKey()) {
		t.Fatal("rejected token is still cached")
	}
}

func TestReplaceRejectedTokenLeavesStaticTokenFilesAlone(t *testing.T) {
	cfg := clientCredentialsConfig(tokenSourceEndpoint)
	cfg.StaticTokenFile = "/nonexistent/token"

	source := &bearerTokenSource{cfg: cfg, now: time.Now}

	if _, err := source.ReplaceRejectedToken(t.Context(), rejectedTestStaleToken); err == nil {
		t.Fatal("ReplaceRejectedToken() replaced a static token")
	}
}
