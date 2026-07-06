package core

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/localcache"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

const backendPlanAccountField = "uid"

func TestAuthenticateUserLoadsBruteForceHistoriesWithoutCacheBackend(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	auth.AccountCache().Set(cfg, auth.Request.Username, auth.Request.Protocol.Get(), "", auth.Request.Username)

	bruteForce := &recordingBruteForceService{}

	restore := replaceBackendPlanTestServices(
		t,
		backendPlanPasswordVerifier{},
		nil,
		bruteForce,
		testLuaSubject{},
		currentBehaviorPostAction{},
	)
	defer restore()

	result := auth.authenticateUser(
		ctx,
		backendExecutionPlan{
			positions: map[definitions.Backend]int{definitions.BackendLDAP: 0},
			passDBs:   []*PassDBMap{{backend: definitions.BackendLDAP}},
		},
	)
	if result != definitions.AuthResultOK {
		t.Fatalf("authenticateUser() = %v, want %v", result, definitions.AuthResultOK)
	}

	if bruteForce.loadHistoriesCalls != 1 {
		t.Fatalf("brute-force history loads = %d, want 1", bruteForce.loadHistoriesCalls)
	}

	if bruteForce.accountName != auth.Request.Username {
		t.Fatalf("brute-force account name = %q, want %q", bruteForce.accountName, auth.Request.Username)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestAuthenticateUserSubjectFailDoesNotWritePositiveAuthCaches(t *testing.T) {
	auth, ctx, mock, cacheService := newBackendPlanCacheOrderingAuth(t, "subject-fail@example.test")
	cacheKey := auth.generateLocalCacheKey()

	restore := replaceBackendPlanTestServices(
		t,
		backendPlanPasswordVerifier{},
		cacheService,
		nil,
		backendPlanSubject{result: definitions.AuthResultFail},
		currentBehaviorPostAction{},
	)
	defer restore()

	result := auth.authenticateUser(ctx, backendPlanPositiveCacheBeforeLDAP())
	if result != definitions.AuthResultFail {
		t.Fatalf("authenticateUser() = %v, want %v", result, definitions.AuthResultFail)
	}

	if cacheService.successCalls != 0 {
		t.Fatalf("positive cache success calls = %d, want 0", cacheService.successCalls)
	}

	if cacheService.failureCalls != 1 {
		t.Fatalf("positive cache failure calls = %d, want 1", cacheService.failureCalls)
	}

	if _, found := localcache.LocalCache.Get(cacheKey); found {
		t.Fatal("local auth cache was populated for final AuthResultFail")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestAuthenticateUserSubjectOKWritesPositiveAuthCaches(t *testing.T) {
	auth, ctx, mock, cacheService := newBackendPlanCacheOrderingAuth(t, "subject-ok@example.test")
	cacheKey := auth.generateLocalCacheKey()

	restore := replaceBackendPlanTestServices(
		t,
		backendPlanPasswordVerifier{},
		cacheService,
		nil,
		backendPlanSubject{result: definitions.AuthResultOK},
		currentBehaviorPostAction{},
	)
	defer restore()

	result := auth.authenticateUser(ctx, backendPlanPositiveCacheBeforeLDAP())
	if result != definitions.AuthResultOK {
		t.Fatalf("authenticateUser() = %v, want %v", result, definitions.AuthResultOK)
	}

	if cacheService.successCalls != 1 {
		t.Fatalf("positive cache success calls = %d, want 1", cacheService.successCalls)
	}

	if cacheService.failureCalls != 0 {
		t.Fatalf("positive cache failure calls = %d, want 0", cacheService.failureCalls)
	}

	value, found := localcache.LocalCache.Get(cacheKey)
	if !found {
		t.Fatal("local auth cache was not populated for final AuthResultOK")
	}

	passDBResult, ok := value.(*PassDBResult)
	if !ok {
		t.Fatalf("local auth cache value type = %T, want *PassDBResult", value)
	}

	if !passDBResult.Authenticated {
		t.Fatal("local auth cache PassDBResult.Authenticated = false, want true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestBackendExecutionPlanPositivePasswordCache(t *testing.T) {
	for _, tt := range backendExecutionPlanPositivePasswordCacheCases() {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.plan.positivePasswordCacheEnabled(tt.usedBackend); got != tt.wantEnabled {
				t.Fatalf("positivePasswordCacheEnabled(%v) = %v, want %v", tt.usedBackend, got, tt.wantEnabled)
			}
		})
	}
}

type backendExecutionPlanPositivePasswordCacheCase struct {
	name        string
	plan        backendExecutionPlan
	usedBackend definitions.Backend
	wantEnabled bool
}

func backendExecutionPlanPositivePasswordCacheCases() []backendExecutionPlanPositivePasswordCacheCase {
	testCases := backendExecutionPlanPositivePasswordCacheEnabledCases()

	return append(testCases, backendExecutionPlanPositivePasswordCacheDisabledCases()...)
}

// backendExecutionPlanPositivePasswordCacheEnabledCases returns positive cache cases.
func backendExecutionPlanPositivePasswordCacheEnabledCases() []backendExecutionPlanPositivePasswordCacheCase {
	return []backendExecutionPlanPositivePasswordCacheCase{
		{
			name: "enabled when cache precedes non-remote backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendCache: 0,
					definitions.BackendLDAP:  1,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendLDAP,
			wantEnabled: true,
		},
	}
}

// backendExecutionPlanPositivePasswordCacheDisabledCases returns negative cache cases.
func backendExecutionPlanPositivePasswordCacheDisabledCases() []backendExecutionPlanPositivePasswordCacheCase {
	return []backendExecutionPlanPositivePasswordCacheCase{
		{
			name: "disabled without configured cache backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendLDAP: 0,
					definitions.BackendLua:  1,
				},
			},
			usedBackend: definitions.BackendLua,
		},
		{
			name: "disabled when cache follows used backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendLDAP:  0,
					definitions.BackendCache: 1,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendLDAP,
		},
		{
			name: "disabled for remote backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendCache:  0,
					definitions.BackendRemote: 1,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendRemote,
		},
		{
			name: "disabled for plugin backend",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendCache:  0,
					definitions.BackendPlugin: 1,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendPlugin,
		},
		{
			name: "disabled for backend missing from plan",
			plan: backendExecutionPlan{
				positions: map[definitions.Backend]int{
					definitions.BackendCache: 0,
				},
				hasPositivePasswordCache: true,
			},
			usedBackend: definitions.BackendLDAP,
		},
	}
}

func newBackendPlanCacheOrderingAuth(
	t *testing.T,
	username string,
) (*AuthState, *gin.Context, redismock.ClientMock, *recordingCacheService) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Username = username
	auth.AccountCache().Set(cfg, auth.Request.Username, auth.Request.Protocol.Get(), "", auth.Request.Username)

	cacheKey := auth.generateLocalCacheKey()
	localcache.LocalCache.Delete(cacheKey)
	t.Cleanup(func() {
		localcache.LocalCache.Delete(cacheKey)
	})

	return auth, ctx, mock, &recordingCacheService{}
}

func backendPlanPositiveCacheBeforeLDAP() backendExecutionPlan {
	return backendExecutionPlan{
		positions: map[definitions.Backend]int{
			definitions.BackendCache: 0,
			definitions.BackendLDAP:  1,
		},
		hasPositivePasswordCache: true,
		passDBs: []*PassDBMap{
			{backend: definitions.BackendLDAP},
		},
	}
}

type recordingBruteForceService struct {
	loadHistoriesCalls int
	accountName        string
}

func (s *recordingBruteForceService) WaitDelay(_, _ uint) int {
	return 0
}

func (s *recordingBruteForceService) LoadHistories(_ *gin.Context, _ *AuthState, accountName string) {
	s.loadHistoriesCalls++
	s.accountName = accountName
}

type backendPlanPasswordVerifier struct{}

func (backendPlanPasswordVerifier) Verify(ctx *gin.Context, auth *AuthState, passDBs []*PassDBMap) (*PassDBResult, error) {
	if len(passDBs) == 0 {
		return nil, errors.ErrNoPassDBResult
	}

	result := GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = true
	result.AccountField = backendPlanAccountField
	result.Account = auth.Request.Username
	result.Backend = passDBs[0].backend
	result.Attributes = map[string][]any{
		backendPlanAccountField: {auth.Request.Username},
	}

	if err := ProcessPassDBResult(ctx, result, auth, passDBs[0]); err != nil {
		PutPassDBResultToPool(result)

		return nil, err
	}

	return result, nil
}

type recordingCacheService struct {
	successCalls int
	failureCalls int
	accountName  string
}

func (s *recordingCacheService) OnSuccess(_ *AuthState, accountName string) error {
	s.successCalls++
	s.accountName = accountName

	return nil
}

func (s *recordingCacheService) OnFailure(_ *AuthState, accountName string) {
	s.failureCalls++
	s.accountName = accountName
}

func (s *recordingCacheService) Purge(_ *AuthState, _ string) {}

type backendPlanSubject struct {
	result definitions.AuthResult
}

func (s backendPlanSubject) Analyze(_ *gin.Context, view *StateView, result *PassDBResult) definitions.AuthResult {
	if result != nil && result.Authenticated && s.result == definitions.AuthResultOK {
		view.Auth().Runtime.Authorized = true
	}

	return s.result
}

func replaceBackendPlanTestServices(
	t *testing.T,
	verifier PasswordVerifier,
	cacheService CacheService,
	bruteForceService BruteForceService,
	luaSubject LuaSubject,
	postAction PostAction,
) func() {
	t.Helper()

	previousVerifier := getPasswordVerifier()
	previousCacheService := getCacheService()
	previousBruteForceService := getBruteForceService()
	previousLuaSubject := getLuaSubject()
	previousPostAction := getPostAction()

	RegisterPasswordVerifier(verifier)
	RegisterCacheService(cacheService)
	RegisterBruteForceService(bruteForceService)
	RegisterLuaSubject(luaSubject)
	RegisterPostAction(postAction)

	return func() {
		RegisterPasswordVerifier(previousVerifier)
		RegisterCacheService(previousCacheService)
		RegisterBruteForceService(previousBruteForceService)
		RegisterLuaSubject(previousLuaSubject)
		RegisterPostAction(previousPostAction)
	}
}
