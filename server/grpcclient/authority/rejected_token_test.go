// Package authority tests outbound authority client helpers.
package authority

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	delay    time.Duration
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

		time.Sleep(e.delay)

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
	clock    *testClock
	logs     *syncBuffer
}

// testClock is a settable clock for the token source.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current test time.
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// Advance moves the test time forward.
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// syncBuffer is a log sink that is safe for concurrent writers.
type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

// Write appends one log record.
func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.Write(p)
}

// countRecords returns how many log records at logLevel contain text.
func (b *syncBuffer) countRecords(logLevel string, text string) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	count := 0

	for line := range strings.SplitSeq(b.buffer.String(), "\n") {
		if strings.Contains(line, `"level":"`+logLevel+`"`) && strings.Contains(line, text) {
			count++
		}
	}

	return count
}

// newRejectedTokenFixture builds the fixture; tokenSource overrides the bearer token source when set, and
// configure adjusts the options of the Redis-backed source before it is constructed.
func newRejectedTokenFixture(
	t *testing.T,
	tokenSource BearerTokenSource,
	configure ...func(*BearerTokenSourceOptions),
) *rejectedTokenFixture {
	t.Helper()

	storage := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = db.Close() })

	fixture := &rejectedTokenFixture{
		storage: storage,
		stub:    &authorityStub{},
		clock:   &testClock{now: time.Now()},
		logs:    &syncBuffer{},
	}
	fixture.endpoint = &tokenEndpointStub{storage: storage}

	options := BearerTokenSourceOptions{
		AuthorityName: tokenSourceAuthorityName,
		Config:        clientCredentialsConfig(tokenSourceEndpoint),
		Redis:         rediscli.NewTestClient(db),
		HTTPClient:    fixture.endpoint.client(),
		Now:           fixture.clock.Now,
	}

	for _, apply := range configure {
		apply(&options)
	}

	fixture.source = newTestBearerTokenSource(options)
	fixture.endpoint.cacheKey = fixture.source.cacheKey()

	if tokenSource == nil {
		tokenSource = fixture.source
	}

	logger := slog.New(slog.NewJSONHandler(fixture.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fixture.manager = startAuthorityStub(t, fixture.stub, tokenSource, logger)

	return fixture
}

// startAuthorityStub serves stub over bufconn and returns a connection manager dialing it.
func startAuthorityStub(t *testing.T, stub *authorityStub, tokenSource BearerTokenSource, logger *slog.Logger) *ConnectionManager {
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
		Logger:        logger,
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

// seedCachedToken stores token in the shared cache with a comfortable lifetime and no fetch time, like a
// record written before the fetch time was recorded.
func (f *rejectedTokenFixture) seedCachedToken(t *testing.T, token string) {
	t.Helper()

	f.seedCachedRecord(t, cachedBearerToken{AccessToken: token, ExpiresAt: f.clock.Now().Add(time.Hour)})
}

// seedCachedRecord stores record in the shared cache.
func (f *rejectedTokenFixture) seedCachedRecord(t *testing.T, record cachedBearerToken) {
	t.Helper()

	if err := f.storage.Set(f.source.cacheKey(), mustEncodeCachedToken(t, record)); err != nil {
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

// authenticateN runs n Authenticate RPCs one after another and returns their status codes.
func (f *rejectedTokenFixture) authenticateN(t *testing.T, n int) []codes.Code {
	t.Helper()

	result := make([]codes.Code, 0, n)

	for range n {
		_, err := f.manager.Client().Authenticate(t.Context(), &authv1.AuthRequest{})
		result = append(result, status.Code(err))
	}

	return result
}

func TestAuthorityPermanentRejectionFetchesOneTokenPerGuardWindow(t *testing.T) {
	fixture := newRejectedTokenFixture(t, nil)
	fixture.seedCachedToken(t, rejectedTestStaleToken)

	for _, code := range fixture.authenticateN(t, 4) {
		if code != codes.Unauthenticated {
			t.Fatalf("Authenticate() code = %s, want the original UNAUTHENTICATED", code)
		}
	}

	if calls := fixture.endpoint.calls.Load(); calls != 1 {
		t.Fatalf("token endpoint calls within the guard window = %d, want 1", calls)
	}

	// The first RPC retries once; the following ones present the rejected fresh token once and stop.
	if got := len(fixture.stub.presented()); got != 5 {
		t.Fatalf("authority calls = %d, want 2 for the first RPC and 1 for each following RPC", got)
	}

	if got := fixture.cachedAccessToken(t); got != "fresh-token-1" {
		t.Fatalf("cached token = %q, want the guarded fresh-token-1 to stay cached", got)
	}

	if warnings := fixture.logs.countRecords("WARN", "no replacement token"); warnings != 1 {
		t.Fatalf("guard warnings = %d, want exactly one per guard window", warnings)
	}

	fixture.clock.Advance(fixture.source.replacementGuard() + time.Second)
	fixture.authenticateN(t, 2)

	if calls := fixture.endpoint.calls.Load(); calls != 2 {
		t.Fatalf("token endpoint calls after the guard window = %d, want 2", calls)
	}
}

func TestReplaceRejectedTokenDefersRecentlyFetchedToken(t *testing.T) {
	fixture := newRejectedTokenFixture(t, nil)
	fixture.seedCachedRecord(t, cachedBearerToken{
		AccessToken: rejectedTestStaleToken,
		ExpiresAt:   fixture.clock.Now().Add(time.Hour),
		IssuedAt:    fixture.clock.Now().Add(-time.Second),
	})

	if _, err := fixture.source.ReplaceRejectedToken(t.Context(), rejectedTestStaleToken); !errors.Is(err, errReplacementRecentlyRejected) {
		t.Fatalf("ReplaceRejectedToken() error = %v, want errReplacementRecentlyRejected", err)
	}

	if got := fixture.cachedAccessToken(t); got != rejectedTestStaleToken {
		t.Fatalf("cached token = %q, want the guarded token to stay cached", got)
	}

	if calls := fixture.endpoint.calls.Load(); calls != 0 {
		t.Fatalf("token endpoint calls = %d, want none inside the guard window", calls)
	}
}

func TestReplaceRejectedTokenUsesReplicaTokenInsideGuardWindow(t *testing.T) {
	fixture := newRejectedTokenFixture(t, nil)
	fixture.seedCachedRecord(t, cachedBearerToken{
		AccessToken: rejectedTestReplicaToken,
		ExpiresAt:   fixture.clock.Now().Add(time.Hour),
		IssuedAt:    fixture.clock.Now(),
	})

	token, err := fixture.source.ReplaceRejectedToken(t.Context(), rejectedTestStaleToken)
	if err != nil || token != rejectedTestReplicaToken {
		t.Fatalf("ReplaceRejectedToken() = %q err:%v, want the replica token", token, err)
	}

	if calls := fixture.endpoint.calls.Load(); calls != 0 {
		t.Fatalf("token endpoint calls = %d, want none", calls)
	}
}

func TestAuthorityConcurrentRejectionsShareOneReplacementToken(t *testing.T) {
	const parallelRPCs = 8

	fixture := newRejectedTokenFixture(t, nil)
	fixture.seedCachedToken(t, rejectedTestStaleToken)
	fixture.stub.accepted = "fresh-token-1"
	fixture.endpoint.delay = 200 * time.Millisecond

	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		fails atomic.Int32
	)

	start.Add(1)

	for range parallelRPCs {
		done.Go(func() {
			start.Wait()

			if _, err := fixture.manager.Client().Authenticate(t.Context(), &authv1.AuthRequest{}); err != nil {
				fails.Add(1)
			}
		})
	}

	start.Done()
	done.Wait()

	if failed := fails.Load(); failed != 0 {
		t.Fatalf("%d of %d concurrent RPCs failed, want all to use the replacement token", failed, parallelRPCs)
	}

	if calls := fixture.endpoint.calls.Load(); calls != 1 {
		t.Fatalf("token endpoint calls = %d, want 1", calls)
	}

	for _, presented := range fixture.stub.presented() {
		if presented != "Bearer "+rejectedTestStaleToken && presented != "Bearer fresh-token-1" {
			t.Fatalf("authority saw token %q, want only the stale token and fresh-token-1", presented)
		}
	}
}

func TestAuthorityStaticTokenFileIsNeitherRetriedNorFetched(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(rejectedTestStaleToken+"\n"), 0o600); err != nil {
		t.Fatalf("write static token: %v", err)
	}

	artifacts := mustCaptureAuthorityArtifacts(t, tokenPath)

	fixture := newRejectedTokenFixture(t, nil, func(options *BearerTokenSourceOptions) {
		options.Config.StaticTokenFile = tokenPath
		options.Artifacts = artifacts
		options.StaticTokenFiles = true
	})

	for _, code := range fixture.authenticateN(t, 3) {
		if code != codes.Unauthenticated {
			t.Fatalf("Authenticate() code = %s, want UNAUTHENTICATED", code)
		}
	}

	if got := len(fixture.stub.presented()); got != 3 {
		t.Fatalf("authority calls = %d, want no retry for a static token file", got)
	}

	if calls := fixture.endpoint.calls.Load(); calls != 0 {
		t.Fatalf("token endpoint calls = %d, want none for a static token file", calls)
	}

	if warnings := fixture.logs.countRecords("WARN", "caller token"); warnings != 0 {
		t.Fatalf("static token rejections logged %d warnings, want debug level only", warnings)
	}
}
