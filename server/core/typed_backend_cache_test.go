package core

import (
	"fmt"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
)

func TestTypedLDAPProviderPreservesPositiveCache(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Backends = []*config.Backend{mustBackendPlanConfig(t, "cache"), mustBackendPlanConfig(t, "ldap"), mustBackendPlanConfig(t, "plugin(example.identity)")}
	auth, _, _ := newCurrentBehaviorAuthState(t, cfg)

	plan, err := auth.buildAuthnTypedBackendExecutionPlan(policy.AuthnProviderLDAPBackend)
	if err != nil {
		t.Fatal(err)
	}

	if len(plan.passDBs) != 2 || plan.passDBs[0].backend != definitions.BackendCache || plan.passDBs[1].backend != definitions.BackendLDAP {
		t.Fatal("typed LDAP provider omits configured positive cache")
	}

	if !plan.positivePasswordCacheEnabled(definitions.BackendLDAP) {
		t.Fatal("typed LDAP provider disables final positive cache writes")
	}
}

func TestTypedPasswordCacheRejectsForeignEvidence(t *testing.T) {
	cases := []struct {
		name          string
		family        definitions.Backend
		instance      string
		wrongPassword bool
		want          bool
	}{
		{"matching", definitions.BackendLDAP, definitions.DefaultBackendName, false, true},
		{"wrong_password", definitions.BackendLDAP, definitions.DefaultBackendName, true, false},
		{"foreign_family", definitions.BackendLua, definitions.DefaultBackendName, false, false},
		{"foreign_instance", definitions.BackendLDAP, "other", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newCurrentBehaviorConfig(t)
			cfg.Server.Backends = []*config.Backend{mustBackendPlanConfig(t, "cache"), mustBackendPlanConfig(t, "ldap")}
			auth, _, mock := newCurrentBehaviorAuthState(t, cfg)

			plan, err := auth.buildAuthnTypedBackendExecutionPlan(policy.AuthnProviderLDAPBackend)
			if err != nil {
				t.Fatal(err)
			}

			digest := preparedCredentialDigest(auth)
			if tc.wrongPassword {
				digest = strings.Repeat("0", 64)
			}

			mock.Regexp().ExpectHGet(".*", ".*").SetVal(auth.Request.Username)
			mock.ExpectHGetAll(auth.positivePasswordCacheKey("__default__", auth.Request.Username)).SetVal(map[string]string{"backend": fmt.Sprint(int(tc.family)), "backend_name": tc.instance, "password": digest, "account_field": "uid", "attributes": `{"uid":["alice"]}`})

			result, err := plan.passDBs[0].fn(auth)
			if err != nil {
				t.Fatal(err)
			}
			defer PutPassDBResultToPool(result)

			if result.Authenticated != tc.want {
				t.Fatalf("authenticated=%v want=%v", result.Authenticated, tc.want)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTypedBackendCacheHitSettlesHostCredential(t *testing.T) {
	cases := []struct {
		selector, provider string
		family             definitions.Backend
	}{
		{"ldap", policy.AuthnProviderLDAPBackend, definitions.BackendLDAP},
		{"lua", policy.AuthnProviderLuaBackend, definitions.BackendLua},
	}
	for _, tc := range cases {
		t.Run(tc.selector, func(t *testing.T) {
			h := newAuthnFSMGuardHarness(t, policy.OperationAuthenticate, pluginCachePipelineVerifier{}, testLuaSubject{})
			auth := h.execution.auth
			h.cfg.Server.Backends = []*config.Backend{mustBackendPlanConfig(t, "cache"), mustBackendPlanConfig(t, tc.selector)}
			auth.Runtime.MonitoringFlags = []definitions.Monitoring{definitions.MonInMemory}
			db, mock := redismock.NewClientMock()
			auth.deps.Redis = rediscli.NewTestClient(db)

			mock.MatchExpectationsInOrder(false)

			for range 3 {
				mock.Regexp().ExpectHGet(".*", ".*").SetVal(auth.Request.Username)
			}

			mock.ExpectHGetAll(auth.positivePasswordCacheKey("__default__", auth.Request.Username)).SetVal(map[string]string{"backend": fmt.Sprint(int(tc.family)), "backend_name": definitions.DefaultBackendName, "password": preparedCredentialDigest(auth), "account_field": "uid", "attributes": `{"uid":["alice"]}`})

			if _, err := h.execution.prepareTypedBackendProvider(tc.provider); err != nil {
				t.Fatal(err)
			}

			h.completeSubject()

			result := h.finalize(t, policy.StageAuthDecision, policy.DecisionPermit, policy.FSMEventMarkerAuthPermit)
			if result.auth.Decision != AuthDecisionOK {
				t.Fatal("LDAP cache hit did not settle host credential")
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTypedProviderRejectsForeignLocalCache(t *testing.T) {
	f := newBackendAuthenticationOwnershipFixture(t)
	auth, ctx := newRequestOwnedContractAuth(t, f.source.Cfg().(*config.FileSettings), f.source.Request.Username, "credential", "typed-cache")
	auth.deps.BackendAuthenticationCache = f.cache
	execution := &authnCandidateExecution{auth: auth, ginCtx: ctx}

	plan := backendExecutionPlan{passDBs: []*PassDBMap{{backend: definitions.BackendLua, name: definitions.DefaultBackendName}}}
	if execution.prepareCachedBackendResult(plan) {
		t.Fatal("typed Lua provider accepted LDAP in-memory evidence")
	}

	if auth.Runtime.Authenticated || auth.GetAccount() != "" {
		t.Fatal("foreign cache modified request before rejection")
	}
}
