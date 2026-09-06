package grpcauthority

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// authorityCodeBudgetTestDeps supplies isolated script storage for code verification.
func authorityCodeBudgetTestDeps(t *testing.T) core.AuthDeps {
	t.Helper()
	storage := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = client.Close() })

	return core.AuthDeps{Cfg: &config.FileSettings{Server: &config.ServerSection{}}, Redis: rediscli.NewTestClient(client)}
}

// TestAuthorityCodeBudgetUsesResolvedIdentity shares reservations with browser factor identities.
func TestAuthorityCodeBudgetUsesResolvedIdentity(t *testing.T) {
	deps := authorityCodeBudgetTestDeps(t)
	input := authorityMFATestInput("authority-code-budget", "budget@example.test")
	seedAuthorityMFATestUser(t, deps, input.Backend.Name, input.Username, "", nil)
	service := NewBackendManagerIdentityService(BackendManagerIdentityServiceDeps{AuthDeps: deps})
	auth := core.NewAuthStateFromContextWithDeps(nil, deps).(*core.AuthState)
	auth.SetUsername(input.Username)
	auth.SetNoAuth(true)

	manager := core.NewTestBackendManager(input.Backend.Name, deps)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatal(err)
	}

	applyPassDBResult(auth, result)

	identity := auth.GetUniqueUserID()
	if identity == "" {
		t.Fatal("fixture must resolve a stable identity")
	}

	for range 10 {
		if err := core.ConsumeMFAAttempt(t.Context(), deps, identity); err != nil {
			t.Fatal(err)
		}
	}

	for _, verify := range []func(context.Context, AuthorityIdentityInput) (*AuthorityIdentityResult, error){service.VerifyTOTP, service.UseRecoveryCode} {
		if _, err := verify(t.Context(), input); !errors.Is(err, core.ErrMFAAttemptLimit) {
			t.Fatalf("exhausted identity must stop verification, got %v", err)
		}
	}
}

// resolvedBudgetBackend supplies a stable identifier distinct from the account spelling.
type resolvedBudgetBackend struct {
	core.BackendManager
}

// PassDB returns identity attributes without verifying a code.
func (*resolvedBudgetBackend) PassDB(*core.AuthState) (*core.PassDBResult, error) {
	return &core.PassDBResult{
		UniqueUserIDField: "stable_id",
		Attributes:        map[string][]any{"stable_id": {"identity-budget-42"}},
	}, nil
}

// TestAuthorityBudgetPrefersStableIdentifier prevents account spelling from selecting another budget.
func TestAuthorityBudgetPrefersStableIdentifier(t *testing.T) {
	deps := authorityCodeBudgetTestDeps(t)
	auth := core.NewAuthStateFromContextWithDeps(nil, deps).(*core.AuthState)
	auth.SetAccount("different-account-spelling")

	service := &backendManagerIdentityService{authDeps: deps}
	for range 10 {
		if err := core.ConsumeMFAAttempt(t.Context(), deps, "identity-budget-42"); err != nil {
			t.Fatal(err)
		}
	}

	if err := service.consumeMFAAttempt(t.Context(), auth, &resolvedBudgetBackend{}); !errors.Is(err, core.ErrMFAAttemptLimit) {
		t.Fatalf("resolved identity budget must be authoritative, got %v", err)
	}
}
