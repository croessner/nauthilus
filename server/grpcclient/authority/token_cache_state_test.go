// Package authority tests outbound authority client helpers.
package authority

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/redis/go-redis/v9"
)

const tokenCacheStateEncryptionSecret = "token-cache-state-encryption-secret"

// tokenCacheStateFixture shares one miniredis between two edge replicas of the same authority client.
type tokenCacheStateFixture struct {
	storage *miniredis.Miniredis
	client  rediscli.Client
	clock   *testClock
}

// newTokenCacheStateFixture creates the shared Redis with an encrypting security manager.
func newTokenCacheStateFixture(t *testing.T) *tokenCacheStateFixture {
	t.Helper()

	storage := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = db.Close() })

	manager := rediscli.NewSecurityManager(secret.New(tokenCacheStateEncryptionSecret))

	return &tokenCacheStateFixture{
		storage: storage,
		client:  rediscli.NewTestClientWithSecurity(db, manager),
		clock:   &testClock{now: time.Now()},
	}
}

// replica returns one edge replica that fetches tokens through transport.
func (f *tokenCacheStateFixture) replica(transport roundTripFunc) *bearerTokenSource {
	return newTestBearerTokenSource(BearerTokenSourceOptions{
		AuthorityName: tokenSourceAuthorityName,
		Config:        clientCredentialsConfig(tokenSourceEndpoint),
		Redis:         f.client,
		HTTPClient:    &http.Client{Transport: transport},
		Now:           f.clock.Now,
	})
}

// TestBearerTokenCacheDoesNotStorePlaintextToken proves that the shared edge cache keeps the caller bearer
// token unreadable without the Redis encryption secret while replicas still share it.
func TestBearerTokenCacheDoesNotStorePlaintextToken(t *testing.T) {
	fixture := newTokenCacheStateFixture(t)
	issuer := fixture.replica(func(*http.Request) (*http.Response, error) {
		return jsonResponse(`{"access_token":"` + tokenSourceFreshToken + `","token_type":"Bearer","expires_in":3600}`), nil
	})

	if _, err := issuer.Token(context.Background()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	raw, err := fixture.storage.Get(issuer.cacheKey())
	if err != nil {
		t.Fatalf("read cached token: %v", err)
	}

	if strings.Contains(raw, tokenSourceFreshToken) {
		t.Fatalf("shared token cache stores the bearer token in plaintext: %q", raw)
	}

	reader := fixture.replica(func(*http.Request) (*http.Response, error) {
		t.Fatal("second replica fetched a token instead of using the shared cache")

		return nil, nil
	})

	token, err := reader.Token(context.Background())
	if err != nil || token != tokenSourceFreshToken {
		t.Fatalf("second replica Token() = %q, %v; want the shared token", token, err)
	}
}

// TestBearerTokenRefreshKeepsLockOfAnotherReplica proves that a replica whose refresh outlived the lock TTL
// does not delete the refresh lock another replica acquired in the meantime.
func TestBearerTokenRefreshKeepsLockOfAnotherReplica(t *testing.T) {
	fixture := newTokenCacheStateFixture(t)
	successor := fixture.replica(func(*http.Request) (*http.Response, error) {
		t.Fatal("successor replica must not fetch in this test")

		return nil, nil
	})

	var successorLocked bool

	slow := fixture.replica(func(*http.Request) (*http.Response, error) {
		// The fetch outlives the refresh lock, and another replica takes the lock over.
		fixture.storage.FastForward(successor.cfg.GetTokenCache().GetRefreshLockTTL() + time.Second)

		_, locked, err := successor.acquireRefreshLock(context.Background())
		if err != nil {
			t.Errorf("successor acquire lock: %v", err)
		}

		successorLocked = locked

		return jsonResponse(`{"access_token":"` + tokenSourceFreshToken + `","token_type":"Bearer","expires_in":3600}`), nil
	})

	if _, err := slow.Token(context.Background()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if !successorLocked {
		t.Fatal("successor replica could not take over the expired refresh lock")
	}

	if !fixture.storage.Exists(slow.lockKey()) {
		t.Fatal("slow replica deleted the refresh lock held by another replica")
	}
}
