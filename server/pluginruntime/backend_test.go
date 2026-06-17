// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	servererrors "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/pluginloader"
	"github.com/croessner/nauthilus/server/pluginregistry"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/gin-gonic/gin"
)

const (
	backendTestAccount      = "alice"
	backendTestAccountAttr  = "account"
	backendTestGUID         = "backend-test"
	backendTestMail         = "alice@example.test"
	backendTestMailAttr     = "mail"
	backendTestModuleName   = "customer"
	backendTestName         = "passdb"
	backendTestQualified    = backendTestModuleName + "." + backendTestName
	backendTestPassword     = "s3cret"
	backendTestProviderAttr = "plugin.customer.passdb.account_provider"
	backendTestRiskAttr     = "plugin.customer.passdb.risk"
	backendTestStatusKey    = "auth.ok"
	backendTestStatusText   = "Plugin authenticated"
	backendTestUIDAttr      = "uid"
)

func TestBackendManagerPassDBMapsAuthenticatedResult(t *testing.T) {
	backend := &fakePluginBackend{
		verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
			return pluginapi.BackendResult{
				Status: &pluginapi.StatusMessage{
					Code:        pluginCallResultOK,
					MessageKey:  backendTestStatusKey,
					DefaultText: backendTestStatusText,
				},
				Attributes: map[string][]string{
					backendTestMailAttr: {backendTestMail},
				},
				Facts: []pluginapi.PolicyFact{
					{Attribute: backendTestRiskAttr, Value: float64(0.1)},
				},
				Account: backendTestAccount,
				BackendServer: &pluginapi.BackendServerRef{
					Name:     "sql-a",
					Protocol: "mysql",
					Address:  "127.0.0.1",
					Port:     "3306",
				},
				Authenticated: true,
				UserFound:     true,
			}, nil
		},
	}
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	assertAuthenticatedPassDBResult(t, result, auth)
}

func TestBackendManagerAccountDBPropagatesListAccountFactsToPolicy(t *testing.T) {
	activateAccountProviderPluginSnapshot(t, backendTestProviderAttr)

	backend := &fakePluginBackend{
		list: func(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
			return pluginapi.AccountListResult{
				Accounts: []string{backendTestAccount},
				Facts: []pluginapi.PolicyFact{
					{Attribute: backendTestProviderAttr, Value: true},
				},
			}, nil
		},
	}

	runner := newBackendTestRunner(t, []backendTestModule{
		{name: backendTestModuleName, backend: backend},
	})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	restoreDefaultRunner := replaceDefaultRunnerForTest(runner)
	defer restoreDefaultRunner()

	auth := newBackendTestAuth(t)
	auth.Request.ListAccounts = true
	auth.Cfg().GetServer().Backends = []*config.Backend{mustBackendSelector(t, "plugin("+backendTestQualified+")")}

	accounts := auth.ListUserAccounts()
	if len(accounts) != 1 || accounts[0] != backendTestAccount {
		t.Fatalf("ListUserAccounts() = %#v, want plugin account", accounts)
	}

	report := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()

	attribute, ok := report.Attributes[backendTestProviderAttr]
	if !ok {
		t.Fatalf("missing account-provider plugin fact %q", backendTestProviderAttr)
	}

	if attribute.Value != true {
		t.Fatalf("plugin fact value = %#v, want true", attribute.Value)
	}
}

// assertAuthenticatedPassDBResult verifies the backend result mapping from plugin output.
func assertAuthenticatedPassDBResult(t *testing.T, result *core.PassDBResult, auth *core.AuthState) {
	t.Helper()

	assertBackendResultFlags(t, result)
	assertBackendResultAttributes(t, result)
	assertBackendStatusAndRef(t, result, auth)
	assertBackendFacts(t, result)
}

// assertBackendResultFlags verifies the basic authentication result flags.
func assertBackendResultFlags(t *testing.T, result *core.PassDBResult) {
	t.Helper()

	if !result.Authenticated || !result.UserFound {
		t.Fatalf("result auth flags = authenticated:%t user_found:%t, want both true", result.Authenticated, result.UserFound)
	}

	if result.Backend != definitions.BackendPlugin || result.BackendName != backendTestQualified {
		t.Fatalf("backend = %s/%q, want plugin/%s", result.Backend, result.BackendName, backendTestQualified)
	}
}

// assertBackendResultAttributes verifies attributes mapped from the plugin result.
func assertBackendResultAttributes(t *testing.T, result *core.PassDBResult) {
	t.Helper()

	if got := firstStringAttribute(result.Attributes[backendTestMailAttr]); got != backendTestMail {
		t.Fatalf("mail attribute = %q, want %s", got, backendTestMail)
	}

	if got := firstStringAttribute(result.Attributes[backendTestAccountAttr]); got != backendTestAccount {
		t.Fatalf("account attribute = %q, want %s", got, backendTestAccount)
	}
}

// assertBackendStatusAndRef verifies status text and backend server mapping.
func assertBackendStatusAndRef(t *testing.T, result *core.PassDBResult, auth *core.AuthState) {
	t.Helper()

	if auth.Runtime.StatusMessage != backendTestStatusText || auth.Runtime.StatusMessageI18NKey != backendTestStatusKey {
		t.Fatalf("status = %q/%q, want plugin status", auth.Runtime.StatusMessage, auth.Runtime.StatusMessageI18NKey)
	}

	if result.BackendRef.Type != definitions.BackendPluginName || result.BackendRef.OpaqueToken != "127.0.0.1:3306" {
		t.Fatalf("backend ref = %#v, want plugin server reference", result.BackendRef)
	}
}

// assertBackendFacts verifies plugin policy facts were retained.
func assertBackendFacts(t *testing.T, result *core.PassDBResult) {
	t.Helper()

	facts, ok := result.AdditionalAttributes[core.PassDBAdditionalAttributePluginFacts].([]pluginapi.PolicyFact)
	if !ok || len(facts) != 1 || facts[0].Attribute != backendTestRiskAttr {
		t.Fatalf("policy facts = %#v, want plugin fact", result.AdditionalAttributes)
	}
}

func TestBackendManagerPassDBPasswordMismatchMapsFailedAuth(t *testing.T) {
	manager := newBackendTestManager(t, backendTestModuleName, passwordPluginBackend(backendTestPassword), true)
	auth := newBackendTestAuth(t)
	auth.SetPassword(secret.New("wrong"))

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if result.Authenticated || !result.UserFound {
		t.Fatalf("result auth flags = authenticated:%t user_found:%t, want failed found user", result.Authenticated, result.UserFound)
	}
}

func TestBackendManagerPassDBTemporaryErrorMapsToTempFailure(t *testing.T) {
	backend := &fakePluginBackend{
		verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
			return pluginapi.BackendResult{}, stderrors.New("database timeout with " + backendTestPassword)
		},
	}
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	_, err := manager.PassDB(auth)
	if !stderrors.Is(err, servererrors.ErrBackendTemporaryFailure) {
		t.Fatalf("PassDB() error = %v, want ErrBackendTemporaryFailure", err)
	}

	if strings.Contains(err.Error(), backendTestPassword) {
		t.Fatalf("temporary error leaked password: %v", err)
	}
}

func TestBackendManagerPassDBPanicMapsToSecretSafeTempFailure(t *testing.T) {
	backend := &fakePluginBackend{
		verify: func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
			panic("panic with " + backendTestPassword)
		},
	}
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	_, err := manager.PassDB(auth)
	if !stderrors.Is(err, servererrors.ErrBackendTemporaryFailure) {
		t.Fatalf("PassDB() error = %v, want ErrBackendTemporaryFailure", err)
	}

	if strings.Contains(err.Error(), backendTestPassword) {
		t.Fatalf("panic error leaked password: %v", err)
	}
}

func TestBackendManagerCredentialsRequireCapability(t *testing.T) {
	backend := passwordPluginBackend(backendTestPassword)
	manager := newBackendTestManager(t, backendTestModuleName, backend, false)
	auth := newBackendTestAuth(t)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if result.Authenticated {
		t.Fatal("PassDB() authenticated without credentials capability")
	}

	if !backend.sawCredentialRequest {
		t.Fatal("backend did not attempt credential access")
	}
}

func TestBackendManagerCredentialsAllowedByCapability(t *testing.T) {
	backend := passwordPluginBackend(backendTestPassword)
	manager := newBackendTestManager(t, backendTestModuleName, backend, true)
	auth := newBackendTestAuth(t)

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatalf("PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(result)

	if !result.Authenticated || !backend.sawCredentialRequest {
		t.Fatalf("authenticated = %t credential_requested = %t, want true/true", result.Authenticated, backend.sawCredentialRequest)
	}
}

func TestBackendManagerSameArtifactConfiguredTwiceUsesIndependentPluginResources(t *testing.T) {
	first := &sqlStylePlugin{backendName: backendTestName}
	second := &sqlStylePlugin{backendName: backendTestName}

	runner := newBackendTestRunner(t, []backendTestModule{
		{name: "customer_a", plugin: first, backend: first.backend()},
		{name: "customer_b", plugin: second, backend: second.backend()},
	})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	firstResult, err := (&BackendManager{runner: runner, qualifiedName: "customer_a." + backendTestName}).PassDB(newBackendTestAuth(t))
	if err != nil {
		t.Fatalf("first PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(firstResult)

	secondResult, err := (&BackendManager{runner: runner, qualifiedName: "customer_b." + backendTestName}).PassDB(newBackendTestAuth(t))
	if err != nil {
		t.Fatalf("second PassDB() error = %v", err)
	}
	defer core.PutPassDBResultToPool(secondResult)

	firstPool := firstStringAttribute(firstResult.Attributes["pool_id"])

	secondPool := firstStringAttribute(secondResult.Attributes["pool_id"])
	if firstPool == "" || secondPool == "" || firstPool == secondPool {
		t.Fatalf("pool ids = %q/%q, want independent plugin-owned resources", firstPool, secondPool)
	}
}

func newBackendTestManager(t *testing.T, moduleName string, backend *fakePluginBackend, requireCredentials bool) *BackendManager {
	t.Helper()

	plugin := &backendTestPlugin{
		backend:            backend,
		requireCredentials: requireCredentials,
	}

	runner := newBackendTestRunner(t, []backendTestModule{
		{name: moduleName, plugin: plugin, backend: backend, allowCredentials: requireCredentials},
	})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	return &BackendManager{runner: runner, qualifiedName: moduleName + "." + backend.Name()}
}

func newBackendTestRunner(t *testing.T, modules []backendTestModule) *Runner {
	t.Helper()

	registry := pluginregistry.NewRegistry()
	instances := make([]pluginloader.ModuleInstance, 0, len(modules))

	for _, item := range modules {
		module := config.PluginModule{
			Name: item.name,
			Type: config.PluginModuleTypeGo,
			Path: "/plugins/fake-sql.so",
		}
		if item.allowCredentials {
			module.AllowCapabilities = []pluginapi.Capability{pluginapi.CapabilityCredentials}
		}

		registrar := registry.NewRegistrar(module)
		if item.plugin != nil {
			if err := item.plugin.Register(registrar); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
		} else if err := registrar.RegisterBackend(item.backend); err != nil {
			t.Fatalf("RegisterBackend() error = %v", err)
		}

		if err := registrar.Commit(); err != nil {
			t.Fatalf("Commit() error = %v", err)
		}

		instances = append(instances, pluginloader.ModuleInstance{
			Plugin:       item.plugin,
			Module:       module,
			ModuleName:   module.Name,
			Status:       pluginloader.ModuleStatusRegistered,
			Capabilities: registrar.Capabilities(),
			ArtifactPath: module.Path,
		})
	}

	return NewRunnerFromInstances(registry, instances)
}

func newBackendTestAuth(t *testing.T) *core.AuthState {
	t.Helper()

	initBackendTestPools()

	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "https://nauthilus.test/auth", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	auth := core.NewAuthStateFromContextWithDeps(ctx, core.AuthDeps{Cfg: cfg}).(*core.AuthState)
	auth.Runtime.Context = lualib.NewContext()
	auth.Runtime.GUID = backendTestGUID
	auth.Request.Username = backendTestAccount
	auth.Request.Password = secret.New(backendTestPassword)
	auth.Request.Protocol = config.NewProtocol(definitions.ProtoHTTP)

	return auth
}

func passwordPluginBackend(wantPassword string) *fakePluginBackend {
	backend := &fakePluginBackend{}
	backend.verify = func(ctx context.Context, request pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
		backend.sawCredentialRequest = true

		credential, ok := request.Credentials.Password(ctx)
		if !ok {
			return pluginapi.BackendResult{
				Account:   request.Username,
				UserFound: true,
			}, nil
		}

		matches := false

		if err := credential.WithBytes(func(value []byte) error {
			matches = string(value) == wantPassword

			return nil
		}); err != nil {
			return pluginapi.BackendResult{}, err
		}

		return pluginapi.BackendResult{
			Attributes:    map[string][]string{backendTestUIDAttr: {request.Username}},
			Account:       request.Username,
			UserFound:     true,
			Authenticated: matches,
		}, nil
	}

	return backend
}

func firstStringAttribute(values []any) string {
	if len(values) == 0 {
		return ""
	}

	value, _ := values[0].(string)

	return value
}

type backendTestModule struct {
	plugin           pluginapi.Plugin
	backend          pluginapi.Backend
	name             string
	allowCredentials bool
}

type backendTestPlugin struct {
	backend            pluginapi.Backend
	requireCredentials bool
}

func (p *backendTestPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       backendTestGUID,
		Version:    testRuntimePluginVersion,
		APIVersion: pluginapi.APIVersion,
	}
}

func (p *backendTestPlugin) Register(registrar pluginapi.Registrar) error {
	if p.requireCredentials {
		if err := registrar.RequireCapability(pluginapi.CapabilityCredentials); err != nil {
			return err
		}
	}

	return registrar.RegisterBackend(p.backend)
}

type fakePluginBackend struct {
	verify               func(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error)
	list                 func(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error)
	sawCredentialRequest bool
}

func (b *fakePluginBackend) Name() string {
	return backendTestName
}

func (b *fakePluginBackend) VerifyPassword(ctx context.Context, request pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	if b.verify == nil {
		return pluginapi.BackendResult{}, nil
	}

	return b.verify(ctx, request)
}

func (b *fakePluginBackend) ListAccounts(ctx context.Context, request pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	if b.list == nil {
		return pluginapi.AccountListResult{}, nil
	}

	return b.list(ctx, request)
}

type sqlStylePlugin struct {
	pool        *fakeSQLPool
	backendName string
}

func (p *sqlStylePlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       "sql-style",
		Version:    testRuntimePluginVersion,
		APIVersion: pluginapi.APIVersion,
	}
}

func (p *sqlStylePlugin) Register(registrar pluginapi.Registrar) error {
	return registrar.RegisterBackend(p.backend())
}

func (p *sqlStylePlugin) Start(context.Context, pluginapi.Host) error {
	p.pool = &fakeSQLPool{id: int(sqlStylePoolCounter.Add(1))}

	return nil
}

func (p *sqlStylePlugin) Stop(context.Context) error {
	if p.pool != nil {
		p.pool.closed = true
	}

	return nil
}

func (p *sqlStylePlugin) backend() pluginapi.Backend {
	return &sqlStyleBackend{plugin: p, name: p.backendName}
}

type sqlStyleBackend struct {
	plugin *sqlStylePlugin
	name   string
}

func (b *sqlStyleBackend) Name() string {
	return b.name
}

func (b *sqlStyleBackend) VerifyPassword(context.Context, pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	if b.plugin.pool == nil || b.plugin.pool.closed {
		return pluginapi.BackendResult{}, fmt.Errorf("pool unavailable")
	}

	poolID := strconv.Itoa(b.plugin.pool.id)

	return pluginapi.BackendResult{
		Attributes:    map[string][]string{"pool_id": {poolID}},
		Account:       backendTestAccount,
		UserFound:     true,
		Authenticated: true,
	}, nil
}

func (b *sqlStyleBackend) ListAccounts(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	return pluginapi.AccountListResult{Accounts: []string{backendTestAccount}}, nil
}

type fakeSQLPool struct {
	id     int
	closed bool
}

var sqlStylePoolCounter atomic.Int64

var backendTestPoolInit sync.Once

func initBackendTestPools() {
	backendTestPoolInit.Do(core.InitPassDBResultPool)
}

// activateAccountProviderPluginSnapshot publishes a minimal snapshot for plugin account-provider facts.
func activateAccountProviderPluginSnapshot(t *testing.T, attribute string) {
	t.Helper()

	snapshot := &policyruntime.Snapshot{
		Generation:    1,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		AttributeRegistry: map[string]policyregistry.AttributeDefinition{
			attribute: {
				ID:         attribute,
				Stage:      policy.StageAccountProvider,
				Operations: []policy.Operation{policy.OperationListAccounts},
				Category:   policyregistry.AttributeCategoryEnvironment,
				Type:       policyregistry.AttributeTypeBool,
				Source:     policyregistry.SourcePlugin,
			},
		},
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationListAccounts: {
				policy.StageAccountProvider: {
					Stage: policy.StageAccountProvider,
					Checks: []policyruntime.CompiledCheck{
						{
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
							Name:       "account_provider",
							Type:       policy.CheckTypeAccountProvider,
							ConfigRef:  "auth.backends",
							Stage:      policy.StageAccountProvider,
							Operations: []policy.Operation{policy.OperationListAccounts},
						},
					},
				},
			},
		},
	}
	if err := policyruntime.DefaultStore().Activate(snapshot); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	t.Cleanup(func() {
		if err := policyruntime.DefaultStore().Activate(&policyruntime.Snapshot{}); err != nil {
			t.Fatalf("restore policy snapshot: %v", err)
		}
	})
}

// mustBackendSelector parses a backend selector and fails the test on invalid syntax.
func mustBackendSelector(t *testing.T, selector string) *config.Backend {
	t.Helper()

	backend := &config.Backend{}
	if err := backend.Set(selector); err != nil {
		t.Fatalf("backend selector %q error = %v", selector, err)
	}

	return backend
}

// replaceDefaultRunnerForTest swaps the process-wide plugin runner for one test.
func replaceDefaultRunnerForTest(runner *Runner) func() {
	previous, ok := DefaultRunner()

	SetDefaultRunner(runner)

	return func() {
		if ok {
			SetDefaultRunner(previous)

			return
		}

		SetDefaultRunner(NewRunnerFromInstances(pluginregistry.NewRegistry(), nil))
	}
}
