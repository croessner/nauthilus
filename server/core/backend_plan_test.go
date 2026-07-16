package core

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
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

func TestAuthenticateUserStoresBackendAuthenticationBeforeSubjectAuthority(t *testing.T) {
	testCases := []struct {
		name             string
		username         string
		subjectResult    definitions.AuthResult
		wantSuccessCalls int
		wantFailureCalls int
	}{
		{name: "subject permit", username: "subject-ok@example.test", subjectResult: definitions.AuthResultOK, wantSuccessCalls: 1},
		{name: "subject deny", username: "subject-fail@example.test", subjectResult: definitions.AuthResultFail, wantFailureCalls: 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			auth, ctx, mock, cacheService := newBackendPlanCacheOrderingAuth(t, testCase.username)

			restore := replaceBackendPlanTestServices(
				t,
				backendPlanPasswordVerifier{},
				cacheService,
				nil,
				backendPlanSubject{result: testCase.subjectResult},
				currentBehaviorPostAction{},
			)
			defer restore()

			result := auth.authenticateUser(ctx, backendPlanPositiveCacheBeforeLDAP())
			if result != testCase.subjectResult {
				t.Fatalf("authenticateUser() = %v, want %v", result, testCase.subjectResult)
			}

			if cacheService.successCalls != testCase.wantSuccessCalls || cacheService.failureCalls != testCase.wantFailureCalls {
				t.Fatalf("positive password cache calls = success:%d failure:%d, want success:%d failure:%d", cacheService.successCalls, cacheService.failureCalls, testCase.wantSuccessCalls, testCase.wantFailureCalls)
			}

			if _, found := auth.backendAuthenticationCache().load(mustBuildBackendAuthenticationCacheKey(t, auth)); !found {
				t.Fatal("positive backend authentication was not stored before subject authority")
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("redis expectations: %v", err)
			}
		})
	}
}

func TestHandleLocalCacheRerunsPluginSubjectBridge(t *testing.T) {
	auth, ctx, mock, _ := newBackendPlanCacheOrderingAuth(t, "local-cache-subject@example.test")
	auth.Request.Service = definitions.ServNginx
	auth.SetStatusCodes(auth.Request.Service)
	enableBackendHealthChecksForCacheTest(t, auth)

	bridge := &recordingPluginSubjectBridge{
		address: "10.0.0.7",
		port:    993,
	}

	restore := replaceBackendPlanTestServices(
		t,
		backendPlanPasswordVerifier{},
		nil,
		nil,
		backendPlanSubject{result: definitions.AuthResultOK},
		currentBehaviorPostAction{},
	)
	defer restore()

	restoreBridge := replacePluginSubjectBridgeForTest(t, bridge)
	defer restoreBridge()

	cached := backendPlanAuthenticatedCacheResult(auth)
	updateAuthentication(ctx, auth, cached, nil)
	auth.Runtime.Authenticated = true
	auth.Runtime.Authorized = true
	auth.Runtime.AuthFSMTerminalState = string(authFSMStateAuthOK)
	auth.Runtime.UsedBackendIP = bridge.address
	auth.Runtime.UsedBackendPort = bridge.port

	if !auth.backendAuthenticationCache().StoreForRequest(ctx, auth, cached, auth.Cfg().GetServer().GetLocalCacheAuthTTL(), auth.Request.Username) {
		t.Fatal("failed to seed positive backend authentication cache")
	}

	PutPassDBResultToPool(cached)

	if found := auth.GetFromLocalCache(ctx); !found {
		t.Fatal("GetFromLocalCache() = false, want true")
	}

	result := auth.handleLocalCache(ctx)
	if result != definitions.AuthResultOK {
		t.Fatalf("handleLocalCache() = %v, want %v", result, definitions.AuthResultOK)
	}

	if bridge.calls != 1 {
		t.Fatalf("plugin subject bridge calls = %d, want 1", bridge.calls)
	}

	auth.AuthOK(ctx)
	assertNginxBackendHeaders(t, ctx, bridge.address, "993")

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

	auth.deps.BackendAuthenticationCache = NewPositiveBackendAuthenticationCache(time.Now)

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

// assertNginxBackendHeaders verifies backend health response headers for Nginx auth.
func assertNginxBackendHeaders(t *testing.T, ctx *gin.Context, address string, port string) {
	t.Helper()

	if got := ctx.Writer.Header().Get("Auth-Server"); got != address {
		t.Fatalf("Auth-Server = %q, want %q", got, address)
	}

	if got := ctx.Writer.Header().Get("Auth-Port"); got != port {
		t.Fatalf("Auth-Port = %q, want %q", got, port)
	}
}

type recordingPluginSubjectBridge struct {
	address string
	port    int
	calls   int
}

// Analyze records native subject bridge execution and simulates backend selection.
func (b *recordingPluginSubjectBridge) Analyze(_ *gin.Context, view *StateView, result *PassDBResult, current definitions.AuthResult) (definitions.AuthResult, bool) {
	b.calls++
	view.Auth().Runtime.UsedBackendIP = b.address
	view.Auth().Runtime.UsedBackendPort = b.port

	result.BackendRef = RemoteBackendRef{
		Type:        definitions.BackendPluginName,
		Name:        "mailde_auth",
		Protocol:    definitions.ProtoIMAP,
		Authority:   b.address,
		OpaqueToken: "mailde_auth:" + b.address,
	}

	return current, true
}

// backendPlanAuthenticatedCacheResult returns a cached positive PassDB result.
func backendPlanAuthenticatedCacheResult(auth *AuthState) *PassDBResult {
	return &PassDBResult{
		UserFound:     true,
		Authenticated: true,
		AccountField:  backendPlanAccountField,
		Account:       auth.Request.Username,
		Backend:       definitions.BackendLDAP,
		Attributes: map[string][]any{
			backendPlanAccountField: {auth.Request.Username},
		},
	}
}

// enableBackendHealthChecksForCacheTest activates Nginx backend-health response headers.
func enableBackendHealthChecksForCacheTest(t *testing.T, auth *AuthState) {
	t.Helper()

	feat := &config.RuntimeModule{}
	if err := feat.Set(definitions.ServiceBackendHealthChecks); err != nil {
		t.Fatalf("RuntimeModule.Set(%q) failed: %v", definitions.ServiceBackendHealthChecks, err)
	}

	cfg, ok := auth.Cfg().(*config.FileSettings)
	if !ok {
		t.Fatalf("auth config type = %T, want *config.FileSettings", auth.Cfg())
	}

	cfg.Server.RuntimeModules = []*config.RuntimeModule{feat}

	previousServers := ListBackendServers()

	BackendServers.Update([]*config.BackendServer{{Host: "127.0.0.1", Port: 993, Protocol: definitions.ProtoIMAP}})
	t.Cleanup(func() {
		BackendServers.Update(previousServers)
	})
}

// replacePluginSubjectBridgeForTest installs a native subject bridge for one test.
func replacePluginSubjectBridgeForTest(t *testing.T, bridge PluginSubjectSourceBridge) func() {
	t.Helper()

	previousBridge := getPluginSubjectSourceBridge()

	RegisterPluginSubjectSourceBridge(bridge)

	return func() {
		RegisterPluginSubjectSourceBridge(previousBridge)
	}
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
