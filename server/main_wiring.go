// Copyright (C) 2024 Christian Rößner
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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	stdlog "log"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/app/bootfx"
	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/app/envfx"
	"github.com/croessner/nauthilus/v3/server/app/logfx"
	"github.com/croessner/nauthilus/v3/server/app/loopsfx"
	"github.com/croessner/nauthilus/v3/server/app/policyfx"
	"github.com/croessner/nauthilus/v3/server/app/redifx"
	"github.com/croessner/nauthilus/v3/server/app/reloadfx"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/backend/ldappool"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/language"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/redislib"
	"github.com/croessner/nauthilus/v3/server/monitoring"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/privilege"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"

	"go.uber.org/fx"
)

const runtimePluginPolicyConfigKey = "policy"

type configDeps struct {
	fx.Out

	Provider configfx.Provider
	Reloader configfx.Reloader
}

type policyHTTPTransportBaseline struct {
	trustedProxies []string
	cipherSuites   []string
	cert           string
	key            string
	caFile         string
	minTLSVersion  string
	enabled        bool
	skipVerify     bool
}

type policyGRPCTransportBaseline struct {
	address           string
	cert              string
	key               string
	clientCA          string
	minTLSVersion     string
	listenerEnabled   bool
	tlsEnabled        bool
	requireClientCert bool
}

type policyTransportBaseline struct {
	http policyHTTPTransportBaseline
	grpc policyGRPCTransportBaseline
}

type policyTokenAuthorityBaseline struct {
	oidc     config.OIDCConfig
	redis    config.Redis
	timeouts config.Timeouts
}

type policyAccessTokenAuthority struct {
	bootstrap    config.File
	environment  config.Environment
	logger       *slog.Logger
	redisClient  redifx.Client
	accountCache *accountcache.Manager
	channel      backend.Channel
	validator    callerauth.AccessTokenValidator
	validatorErr error
	once         sync.Once
	baseline     policyTokenAuthorityBaseline
}

// newPolicyGenerationStore constructs the sole process-wide generation authority for Fx.
func newPolicyGenerationStore() *policyruntime.GenerationStore {
	return policyruntime.NewGenerationStore()
}

// newConfigDeps constructs config dependencies for fx.
//
// It depends on the bootstrap token to keep the candidate unpublished until generation commit.
func newConfigDeps(bootstrap *bootstrapped, generations *policyruntime.GenerationStore) (configDeps, error) {
	if bootstrap == nil || bootstrap.file == nil {
		return configDeps{}, fmt.Errorf("prepared configuration is nil")
	}

	if generations == nil {
		return configDeps{}, fmt.Errorf("policy generation store is nil")
	}

	if err := config.BindActiveFileSource(func() config.File {
		active := generations.Active()
		if active == nil {
			return bootstrap.file
		}

		return active.Config()
	}); err != nil {
		return configDeps{}, fmt.Errorf("bind active generation config projection: %w", err)
	}

	r := configfx.NewProviderWithCandidate(bootstrap.file, generations)

	return configDeps{Provider: r, Reloader: r}, nil
}

// newLogger provides the process logger for fx.
//
// It depends on the bootstrap token to ensure logging has been initialized.
func newLogger(_ *bootstrapped) *slog.Logger {
	return logfx.NewLogger()
}

// newDbgModuleMapping returns the current DbgModuleMapping and registers its lifecycle with the provided fx.Lifecycle.
func newDbgModuleMapping(lc fx.Lifecycle) *definitions.DbgModuleMapping {
	mapping := definitions.GetDbgModuleMapping()

	lc.Append(fx.Hook{
		OnStop: func(context.Context) error {
			definitions.SetDbgModuleMapping(nil)

			return nil
		},
	})

	return mapping
}

// newRedisClient provides the Redis facade for fx.
//
// It depends on the bootstrap token to ensure configuration/logging has been initialized.
type redisDeps struct {
	fx.Out

	Client    redifx.Client
	Rebuilder redifx.Rebuilder
}

// newRedisDeps provides a swap-capable Redis facade (Client) and its rebuild controller.
//
// Restart orchestration rebuilds Redis exclusively through the injected Rebuilder.
func newRedisDeps(lc fx.Lifecycle, _ *bootstrapped, cfgProvider configfx.Provider, logger *slog.Logger) (redisDeps, error) {
	snap := cfgProvider.Current()

	client, err := rediscli.NewClientWithDeps(snap.File, logger)
	if err != nil {
		return redisDeps{}, err
	}
	managed := redifx.NewManagedClient(client)

	// Ensure the current underlying client is closed on process stop.
	lc.Append(fx.Hook{OnStop: func(context.Context) error {
		managed.Close()

		return nil
	}})

	return redisDeps{Client: managed, Rebuilder: managed}, nil
}

// policyFactoryModule registers candidate-scoped production authentication and transport factories.
func policyFactoryModule() fx.Option {
	return fx.Options(
		fx.Provide(newPolicyAccessTokenValidatorFactory),
		fx.Provide(newPolicyBasicThrottlerFactory),
		fx.Provide(newPolicyTransportCapabilitiesFactory),
	)
}

// newPolicyAccessTokenValidatorFactory builds one real candidate-owned IDP claims adapter.
func newPolicyAccessTokenValidatorFactory(
	bootstrap *bootstrapped,
	environment config.Environment,
	logger *slog.Logger,
	redisClient redifx.Client,
	accountCache *accountcache.Manager,
	channel backend.Channel,
) (policyfx.AccessTokenValidatorFactory, error) {
	if bootstrap == nil || bootstrap.file == nil {
		return nil, fmt.Errorf("policy access-token bootstrap config is nil")
	}

	baseline, err := capturePolicyTokenAuthorityBaseline(bootstrap.file)
	if err != nil {
		return nil, err
	}

	authority := &policyAccessTokenAuthority{
		bootstrap: bootstrap.file, environment: environment, logger: logger,
		redisClient: redisClient, accountCache: accountCache, channel: channel,
		baseline: baseline,
	}

	return authority.validate, nil
}

// validate returns the one boot-bound real validator after rejecting token-authority drift.
func (a *policyAccessTokenAuthority) validate(
	ctx context.Context,
	candidate config.File,
) (callerauth.AccessTokenValidator, error) {
	if a == nil || ctx == nil || candidate == nil {
		return nil, fmt.Errorf("policy access-token validator dependencies are incomplete")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	candidateBaseline, err := capturePolicyTokenAuthorityBaseline(candidate)
	if err != nil {
		return nil, err
	}

	if !a.baseline.equal(candidateBaseline) {
		return nil, fmt.Errorf("%w: live OIDC token authority changed", pluginruntime.ErrRestartRequired)
	}

	a.once.Do(a.initialize)

	return a.validator, a.validatorErr
}

// initialize constructs the sole Policy claims adapter from the live boot IDP authority.
func (a *policyAccessTokenAuthority) initialize() {
	if a.bootstrap == nil || a.environment == nil || a.logger == nil || a.redisClient == nil ||
		a.accountCache == nil || a.channel == nil {
		a.validatorErr = fmt.Errorf("policy access-token validator dependencies are incomplete")

		return
	}

	oidc := a.bootstrap.GetIDP().OIDC
	if !oidc.Enabled {
		a.validatorErr = fmt.Errorf("policy Bearer authentication requires the live OIDC issuer")

		return
	}

	liveIDP := idp.NewNauthilusIDP(&handlerdeps.Deps{
		Cfg:          a.bootstrap,
		Env:          a.environment,
		Logger:       a.logger,
		Redis:        a.redisClient,
		AccountCache: a.accountCache,
		Channel:      a.channel,
	})
	a.validator, a.validatorErr = callerauth.NewClaimsAccessTokenValidator(liveIDP, oidc.Issuer)
}

// capturePolicyTokenAuthorityBaseline captures immutable boot token state without serializing secrets.
func capturePolicyTokenAuthorityBaseline(candidate config.File) (policyTokenAuthorityBaseline, error) {
	if candidate == nil {
		return policyTokenAuthorityBaseline{}, fmt.Errorf("policy token authority config is nil")
	}

	return policyTokenAuthorityBaseline{
		oidc:     candidate.GetIDP().OIDC,
		redis:    *candidate.GetServer().GetRedis(),
		timeouts: *candidate.GetServer().GetTimeouts(),
	}, nil
}

// equal compares secret-bearing token state in memory without rendering or logging it.
func (b policyTokenAuthorityBaseline) equal(candidate policyTokenAuthorityBaseline) bool {
	return reflect.DeepEqual(b, candidate)
}

// newPolicyBasicThrottlerFactory binds Policy-Basic state to the explicit swap-capable Redis facade.
func newPolicyBasicThrottlerFactory(redisClient redifx.Client) policyfx.BasicThrottlerFactory {
	return func(ctx context.Context, candidate config.File) (callerauth.BasicThrottler, error) {
		if ctx == nil || candidate == nil {
			return nil, fmt.Errorf("policy-Basic candidate dependencies are incomplete")
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		return callerauth.NewDefaultRedisBasicThrottler(redisClient)
	}
}

// newPolicyTransportCapabilitiesFactory freezes the listener/evidence baseline used by live transports.
func newPolicyTransportCapabilitiesFactory(
	bootstrap *bootstrapped,
) (policyfx.TransportCapabilitiesFactory, error) {
	if bootstrap == nil || bootstrap.file == nil {
		return nil, fmt.Errorf("policy transport bootstrap config is nil")
	}

	baseline, err := capturePolicyTransportBaseline(bootstrap.file)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, candidate config.File) (callerauth.TransportCapabilities, error) {
		if ctx == nil || candidate == nil {
			return callerauth.TransportCapabilities{}, fmt.Errorf("policy transport candidate is incomplete")
		}

		if err := ctx.Err(); err != nil {
			return callerauth.TransportCapabilities{}, err
		}

		candidateBaseline, err := capturePolicyTransportBaseline(candidate)
		if err != nil {
			return callerauth.TransportCapabilities{}, err
		}

		if !baseline.equal(candidateBaseline) {
			return callerauth.TransportCapabilities{}, fmt.Errorf(
				"%w: live Policy transport listener or trust evidence changed",
				pluginruntime.ErrRestartRequired,
			)
		}

		return baseline.capabilities(candidate.GetPolicy())
	}, nil
}

// capturePolicyTransportBaseline detaches every listener-owned protection setting.
func capturePolicyTransportBaseline(candidate config.File) (policyTransportBaseline, error) {
	if candidate == nil {
		return policyTransportBaseline{}, fmt.Errorf("policy transport config is nil")
	}

	grpcProvider, ok := candidate.(config.RuntimeGRPCAuthServerProvider)
	if !ok {
		return policyTransportBaseline{}, fmt.Errorf("policy transport config has no gRPC listener authority")
	}

	server := candidate.GetServer()
	httpTLS := server.GetTLS()
	grpcServer := grpcProvider.GetRuntimeGRPCAuthServer()
	grpcTLS := grpcServer.GetTLS()

	return policyTransportBaseline{
		http: policyHTTPTransportBaseline{
			trustedProxies: append([]string(nil), server.GetTrustedProxies()...),
			cipherSuites:   append([]string(nil), httpTLS.GetCipherSuites()...),
			cert:           httpTLS.GetCert(),
			key:            httpTLS.GetKey(),
			caFile:         httpTLS.GetCAFile(),
			minTLSVersion:  httpTLS.GetMinTLSVersion(),
			enabled:        httpTLS.IsEnabled(),
			skipVerify:     httpTLS.GetSkipVerify(),
		},
		grpc: policyGRPCTransportBaseline{
			address:           grpcServer.GetAddress(),
			cert:              grpcTLS.GetCert(),
			key:               grpcTLS.GetKey(),
			clientCA:          grpcTLS.GetClientCA(),
			minTLSVersion:     grpcTLS.GetMinTLSVersion(),
			listenerEnabled:   grpcServer.IsEnabled(),
			tlsEnabled:        grpcTLS.IsEnabled(),
			requireClientCert: grpcTLS.RequiresClientCert(),
		},
	}, nil
}

// equal reports whether a candidate still matches every boot-instantiated transport setting.
func (b policyTransportBaseline) equal(candidate policyTransportBaseline) bool {
	return b.http.cert == candidate.http.cert &&
		b.http.key == candidate.http.key &&
		b.http.caFile == candidate.http.caFile &&
		b.http.minTLSVersion == candidate.http.minTLSVersion &&
		b.http.enabled == candidate.http.enabled &&
		b.http.skipVerify == candidate.http.skipVerify &&
		slices.Equal(b.http.trustedProxies, candidate.http.trustedProxies) &&
		slices.Equal(b.http.cipherSuites, candidate.http.cipherSuites) &&
		b.grpc == candidate.grpc
}

// capabilities validates enabled Policy routes against the frozen live transport baseline.
func (b policyTransportBaseline) capabilities(
	policyConfig policyconfig.PolicyConfig,
) (callerauth.TransportCapabilities, error) {
	httpEnabled := policyConfig.API.Enabled && policyConfig.API.HTTP.Enabled
	grpcEnabled := policyConfig.API.Enabled && policyConfig.API.GRPC.Enabled
	httpProtected := b.http.enabled || len(b.http.trustedProxies) > 0
	grpcProtected := b.grpc.listenerEnabled && b.grpc.tlsEnabled

	if err := validatePolicyHTTPTransport(httpEnabled, httpProtected); err != nil {
		return callerauth.TransportCapabilities{}, err
	}

	if err := validatePolicyGRPCTransport(
		grpcEnabled,
		grpcProtected,
		policyConfig.API.GRPC.RequireMTLS,
		b.grpc.requireClientCert,
	); err != nil {
		return callerauth.TransportCapabilities{}, err
	}

	return callerauth.TransportCapabilities{
		HTTPProtected:                 httpEnabled && httpProtected,
		GRPCProtected:                 grpcEnabled && grpcProtected,
		GRPCVerifiedClientCertificate: grpcEnabled && grpcProtected && b.grpc.clientCA != "",
	}, nil
}

// validatePolicyHTTPTransport rejects enabled HTTP routes without live protection.
func validatePolicyHTTPTransport(enabled bool, protected bool) error {
	if enabled && !protected {
		return fmt.Errorf("enabled Policy HTTP API has no live protected transport")
	}

	return nil
}

// validatePolicyGRPCTransport rejects enabled gRPC routes without their configured TLS guarantees.
func validatePolicyGRPCTransport(enabled bool, protected bool, requireMTLS bool, requireClientCert bool) error {
	if enabled && !protected {
		return fmt.Errorf("enabled Policy gRPC API has no live TLS listener")
	}

	if enabled && requireMTLS && !requireClientCert {
		return fmt.Errorf("policy gRPC mTLS requires the live listener to require client certificates")
	}

	return nil
}

// newPluginState loads and validates native modules from the unpublished boot candidate.
func newPluginState(_ *bootstrapped, cfgProvider configfx.Provider, logger *slog.Logger) (*pluginloader.State, error) {
	if cfgProvider == nil {
		return nil, fmt.Errorf("prepared configuration is nil")
	}

	snapshot := cfgProvider.Current()
	if snapshot.File == nil {
		return nil, fmt.Errorf("prepared configuration is nil")
	}

	return bootfx.SetupGoPlugins(snapshot.File, logger)
}

// newRouteArtifacts parses every inbound listener and HTTP-served file before the initial generation commit.
func newRouteArtifacts(_ *bootstrapped, cfgProvider configfx.Provider) (*core.RouteArtifacts, error) {
	if cfgProvider == nil || cfgProvider.Current().File == nil {
		return nil, fmt.Errorf("prepared route configuration is unavailable")
	}

	configured := cfgProvider.Current().File

	snapshot, err := config.ArtifactSnapshotFor(configured)
	if err != nil {
		return nil, fmt.Errorf("resolve sealed route artifacts: %w", err)
	}

	artifacts, err := core.PrepareRouteArtifacts(configured, snapshot)
	if err != nil {
		return nil, fmt.Errorf("prepare route artifacts: %w", err)
	}

	return artifacts, nil
}

// newContextStoreForRuntime constructs the runtime context store.
//
// The store is the legacy coordination struct that still carries context tuples and
// injected dependencies for partially migrated code paths.
func newContextStoreForRuntime(
	_ *bootstrapped,
	cfgProvider configfx.Provider,
	env envfx.Environment,
	logger *slog.Logger,
	redisClient redifx.Client,
	channel backend.Channel,
	accountCache *accountcache.Manager,
	langManager language.Manager,
	bruteForceTolerate tolerate.Tolerate,
	policyStore *policyruntime.GenerationStore,
	policyDecision *decisionservice.DecisionService,
	routeArtifacts *core.RouteArtifacts,
) *contextStore {
	store := &contextStore{
		cfgProvider:        cfgProvider,
		env:                env,
		logger:             logger,
		redisClient:        redisClient,
		channel:            channel,
		accountCache:       accountCache,
		langManager:        langManager,
		bruteForceTolerate: bruteForceTolerate,
		policyStore:        policyStore,
		policyDecision:     policyDecision,
		routeArtifacts:     routeArtifacts,
	}

	return store
}

func newAccountCache(cfgProvider configfx.Provider) *accountcache.Manager {
	return accountcache.NewManager(cfgProvider.Current().File)
}

func newBackendChannel(cfgProvider configfx.Provider) backend.Channel {
	return backend.NewChannel(cfgProvider.Current().File)
}

// newBruteForceTolerate constructs the single boot-lifetime tolerance owner without publishing a package global.
func newBruteForceTolerate(
	_ *bootstrapped,
	cfgProvider configfx.Provider,
	logger *slog.Logger,
	redisClient redifx.Client,
) (tolerate.Tolerate, error) {
	if cfgProvider == nil || cfgProvider.Current().File == nil {
		return nil, fmt.Errorf("brute-force tolerate configuration is unavailable")
	}

	cfg := cfgProvider.Current().File

	return tolerate.NewTolerateWithDeps(
		cfg,
		logger,
		redisClient,
		cfg.GetBruteForce().GetToleratePercent(),
	), nil
}

type runtimeLifecycleParams struct {
	fx.In

	Ctx           context.Context
	Cancel        context.CancelFunc
	Store         *contextStore
	StatsSvc      *loopsfx.StatsService
	MonitoringSvc *loopsfx.BackendMonitoringService
	ConnMgrSvc    *loopsfx.ConnMgrService
	BFSyncSvc     *loopsfx.BruteForceSyncService
	Env           config.Environment
	Channel       backend.Channel
	LangManager   language.Manager
	PluginState   *pluginloader.State
	PolicyStartup *policyfx.StartupCatalog
	PolicyApply   reloadfx.GenerationCoordinator
}

// registerRuntimeLifecycle wires the legacy startup/shutdown sequence into fx.Lifecycle.
//
// Startup preserves the existing initialization order. Shutdown cancels the root context,
// stops long-running services, performs time-bounded waits, and shuts down process-wide
// resources.
func registerRuntimeLifecycle(lc fx.Lifecycle, p runtimeLifecycleParams) {
	params := p

	var pluginRunner *pluginruntime.Runner

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			var err error

			pluginRunner, err = startRuntimeLifecycle(&params)

			return err
		},
		OnStop: func(stopCtx context.Context) error {
			return stopRuntimeLifecycle(stopCtx, &params, pluginRunner)
		},
	})
}

// startRuntimeLifecycle runs the legacy startup sequence inside the fx lifecycle.
func startRuntimeLifecycle(p *runtimeLifecycleParams) (_ *pluginruntime.Runner, err error) {
	snap := p.Store.cfgProvider.Current()
	startRuntimeTelemetryAndConfig(p, snap.File)

	if err := configureRuntimeDefaults(p, snap.File); err != nil {
		return nil, err
	}

	if err := setupRuntimeWorkersAndRedis(p, snap.File); err != nil {
		return nil, err
	}

	pluginRunner, err := startRuntimePluginRunner(p, snap.File, p.PluginState)
	if err != nil {
		return nil, err
	}

	p.Store.pluginRunner = pluginRunner

	defer func() {
		if err == nil {
			return
		}

		stopCtx, cancel := context.WithTimeout(context.Background(), definitions.FxStopTimeout)
		defer cancel()

		cleanupErr := stopRuntimePluginRunner(stopCtx, pluginRunner)
		p.Store.pluginRunner = nil
		err = errors.Join(err, cleanupErr)
	}()

	if err = prepareInitialPolicyGeneration(
		p.Ctx,
		snap,
		p.Store.logger,
		p.Store.redisClient,
		p.Store.bruteForceTolerate,
		localization.NewManagerCatalog(p.LangManager),
		p.PolicyStartup,
		p.PolicyApply,
	); err != nil {
		return nil, err
	}

	core.LoadStatsFromRedis(p.Ctx, snap.File, p.Store.logger, p.Store.redisClient)

	if err := startHTTPAndDropPrivileges(p, snap.File); err != nil {
		return nil, err
	}

	if err := startRuntimeLoopServices(p); err != nil {
		return nil, err
	}

	return pluginRunner, nil
}

// prepareInitialPolicyGeneration captures successful startup overlays before the first atomic commit.
func prepareInitialPolicyGeneration(
	ctx context.Context,
	snapshot configfx.Snapshot,
	logger *slog.Logger,
	redis rediscli.Client,
	tolerance tolerate.Tolerate,
	system localization.Catalog,
	startup *policyfx.StartupCatalog,
	coordinator reloadfx.GenerationCoordinator,
) error {
	if snapshot.File == nil || snapshot.Version == 0 {
		return fmt.Errorf("policy generation boot candidate is incomplete")
	}

	if startup == nil || coordinator == nil {
		return fmt.Errorf("policy generation startup dependencies are incomplete")
	}

	preparation, err := bootfx.PrepareLuaInitCatalogs(
		ctx,
		snapshot.File,
		logger,
		redis,
		tolerance,
		system,
	)
	if err != nil {
		return fmt.Errorf("prepare startup Lua localization: %w", err)
	}

	if err = startup.Capture(snapshot.File, preparation); err != nil {
		return fmt.Errorf("capture startup Lua localization: %w", err)
	}

	if err = coordinator.Apply(ctx, snapshot); err != nil {
		return fmt.Errorf("commit initial policy runtime generation: %w", err)
	}

	return nil
}

// startRuntimeTelemetryAndConfig runs early config-dependent process initialization.
func startRuntimeTelemetryAndConfig(p *runtimeLifecycleParams, cfg config.File) {
	// Initialize OpenTelemetry tracing early (no-op if disabled)
	monitoring.GetTelemetry().Start(p.Ctx, version)

	bootfx.InitializeInstanceInfo(cfg, version)
	bootfx.DebugLoadableConfig(cfg, p.Store.logger)
}

// configureRuntimeDefaults wires legacy package-level defaults for runtime code.
func configureRuntimeDefaults(p *runtimeLifecycleParams, cfg config.File) error {
	if err := bootfx.SetupLuaScripts(cfg, p.Store.logger); err != nil {
		return fmt.Errorf("setup Lua scripts: %w", err)
	}

	bootfx.EnableBlockProfile(cfg)

	if p.Store.bruteForceTolerate == nil {
		return fmt.Errorf("brute-force tolerate owner is unavailable")
	}

	go p.Store.bruteForceTolerate.StartHouseKeeping(p.Ctx)

	if err := configureRuntimeI18N(p, cfg); err != nil {
		return err
	}

	core.InitPassDBResultPool()

	if cfg == nil {
		return fmt.Errorf("config snapshot file is nil")
	}

	setRuntimePackageDefaults(p, cfg)
	priorityqueue.InitQueues(p.Store.logger)

	return nil
}

// configureRuntimeI18N initializes the Lua i18n runtime from the active config.
func configureRuntimeI18N(p *runtimeLifecycleParams, cfg config.File) error {
	if err := lualib.ConfigureDefaultI18NRuntime(
		localization.NewManagerCatalog(p.LangManager),
		cfg.GetServer().Frontend.GetDefaultLanguage(),
		p.Store.logger,
	); err != nil {
		return fmt.Errorf("configure Lua i18n runtime: %w", err)
	}

	return nil
}

// setRuntimePackageDefaults publishes injected dependencies to legacy package defaults.
func setRuntimePackageDefaults(p *runtimeLifecycleParams, cfg config.File) {
	// Provide core defaults for legacy call sites that are not fully constructor-injected yet.
	core.SetDefaultLogger(p.Store.logger)
	core.SetDefaultAccountCache(p.Store.accountCache)
	core.SetDefaultChannel(p.Channel)
	core.SetDefaultEnvironment(p.Env)

	// Provide util defaults for legacy call sites.
	util.SetDefaultLogger(p.Store.logger)
	util.SetDefaultEnvironment(p.Env)

	// Provide ldappool defaults.
	ldappool.SetDefaultEnvironment(p.Env)

}

// setupRuntimeWorkersAndRedis starts workers and initializes Redis-backed defaults.
func setupRuntimeWorkersAndRedis(p *runtimeLifecycleParams, cfg config.File) error {
	setupWorkers(p.Ctx, p.Store, cfg, p.Store.logger, p.Store.redisClient, p.Channel)

	if err := setupRedis(p.Ctx, p.Ctx, cfg, p.Store.logger, p.Store.redisClient); err != nil {
		return err
	}

	setRuntimeRedisDefaults(p)

	return nil
}

// setRuntimeRedisDefaults publishes the injected Redis client to the remaining runtime owners.
func setRuntimeRedisDefaults(p *runtimeLifecycleParams) {
	// Ensure bruteforce tolerations use the injected Redis client.
	tolerate.SetDefaultClient(p.Store.redisClient)

	// Ensure Lua redislib has a configured default client before any Lua code runs.
	redislib.SetDefaultClient(p.Store.redisClient)
}

// startRuntimePluginRunner starts the native plugin runtime with the production host.
func startRuntimePluginRunner(p *runtimeLifecycleParams, cfg config.File, pluginState *pluginloader.State) (*pluginruntime.Runner, error) {
	pluginRunner := pluginruntime.NewRunner(
		pluginState,
		pluginruntime.WithHost(newRuntimePluginHost(
			p.Ctx,
			p.Store.logger,
			cfg,
			p.Store.redisClient,
			priorityqueue.LDAPQueue,
		)),
		pluginruntime.WithObserver(pluginruntime.NewOperationalObserver(
			p.Store.logger,
			pluginruntime.WithOperationalObserverDebugConfig(cfg, pluginState.Registry()),
		)),
		pluginruntime.WithPluginConfig(cfg.GetPlugins()),
	)
	if err := pluginRunner.Start(p.Ctx); err != nil {
		return nil, err
	}

	return pluginRunner, nil
}

// startHTTPAndDropPrivileges starts HTTP entry points before privilege drop.
func startHTTPAndDropPrivileges(p *runtimeLifecycleParams, cfg config.File) error {
	if err := startHTTPServer(p.Ctx, p.Store); err != nil {
		return err
	}

	// Drop privileges after all file-based initialization and socket binding.
	srv := cfg.GetServer()

	if err := privilege.DropPrivileges(srv.GetRunAsUser(), srv.GetRunAsGroup(), srv.GetChroot()); err != nil {
		return fmt.Errorf("privilege drop failed: %w", err)
	}

	return nil
}

// startRuntimeLoopServices starts runtime loop services after HTTP is serving.
func startRuntimeLoopServices(p *runtimeLifecycleParams) error {
	if err := p.ConnMgrSvc.Start(p.Ctx); err != nil {
		return err
	}

	if err := p.MonitoringSvc.Start(p.Ctx); err != nil {
		return err
	}

	if err := p.StatsSvc.Start(p.Ctx); err != nil {
		return err
	}

	if err := p.BFSyncSvc.Start(p.Ctx); err != nil {
		return err
	}

	return nil
}

// stopRuntimeLifecycle runs the legacy shutdown sequence inside the fx lifecycle.
func stopRuntimeLifecycle(stopCtx context.Context, p *runtimeLifecycleParams, pluginRunner *pluginruntime.Runner) error {
	snap := p.Store.cfgProvider.Current()

	p.Cancel()
	stopRuntimeLoopServices(stopCtx, p)
	waitForRuntimeShutdown(stopCtx, p)
	ownerErr := stopGenerationOwnedRuntime(
		stopCtx,
		p.Store.policyStore.Shutdown,
		func(ctx context.Context) error {
			err := stopRuntimePluginRunner(ctx, pluginRunner)
			p.Store.pluginRunner = nil

			return err
		},
		lualib.StopGlobalCache,
	)
	saveRuntimeStats(stopCtx, p, snap.File)
	shutdownRuntimeTelemetry(stopCtx)

	return ownerErr
}

// stopGenerationOwnedRuntime preserves process-lifetime owners when generation drain is incomplete.
func stopGenerationOwnedRuntime(
	ctx context.Context,
	shutdownGenerations func(context.Context) error,
	stopPlugins func(context.Context) error,
	stopLua func(),
) error {
	generationErr := shutdownGenerations(ctx)
	if generationDrainIncomplete(generationErr) {
		return generationErr
	}

	pluginErr := stopPlugins(ctx)

	stopLua()

	return errors.Join(generationErr, pluginErr)
}

// generationDrainIncomplete recognizes only caller-wait interruption reported by the generation owner.
func generationDrainIncomplete(err error) bool {
	var incomplete interface {
		GenerationDrainIncomplete() bool
	}

	return errors.As(err, &incomplete) && incomplete.GenerationDrainIncomplete()
}

// stopRuntimePluginRunner stops process-lifetime native objects after generations drain.
func stopRuntimePluginRunner(stopCtx context.Context, pluginRunner *pluginruntime.Runner) error {
	if pluginRunner == nil {
		return nil
	}

	if err := pluginRunner.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop native plugin runtime. Error: %v", err)

		return err
	}

	return nil
}

// stopRuntimeLoopServices stops runtime loop services best-effort.
func stopRuntimeLoopServices(stopCtx context.Context, p *runtimeLifecycleParams) {
	if err := p.StatsSvc.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop stats service. Error: %v", err)
	}

	if err := p.MonitoringSvc.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop backend monitoring service. Error: %v", err)
	}

	if err := p.ConnMgrSvc.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop connection manager service. Error: %v", err)
	}

	if err := p.BFSyncSvc.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop brute-force sync service. Error: %v", err)
	}
}

// waitForRuntimeShutdown waits for workers without consuming the full stop budget.
func waitForRuntimeShutdown(stopCtx context.Context, p *runtimeLifecycleParams) {
	// Best-effort: do not spend the entire fx stop budget on shutdown waits.
	waitCtx, waitCancel := context.WithTimeout(stopCtx, definitions.FxShutdownWaitTimeout)
	waitForShutdown(waitCtx, p.Store)
	waitCancel()
}

// saveRuntimeStats persists stats without blocking process termination indefinitely.
func saveRuntimeStats(stopCtx context.Context, p *runtimeLifecycleParams, cfg config.File) {
	// Best-effort: do not let stats persistence block process termination.
	statsCtx, statsCancel := context.WithTimeout(stopCtx, definitions.FxShutdownStatsFlushTimeout)
	core.SaveStatsToRedis(statsCtx, cfg, p.Store.logger, p.Store.redisClient)
	statsCancel()
}

// shutdownRuntimeTelemetry shuts down telemetry within the remaining stop budget.
func shutdownRuntimeTelemetry(stopCtx context.Context) {
	// Best-effort: telemetry shutdown should respect the remaining stop budget.
	telemetryCtx, telemetryCancel := context.WithTimeout(stopCtx, definitions.FxShutdownTelemetryTimeout)
	monitoring.GetTelemetry().Shutdown(telemetryCtx)
	telemetryCancel()
}

// newRuntimePluginHost builds the production host facade after process services are initialized.
func newRuntimePluginHost(
	ctx context.Context,
	logger *slog.Logger,
	cfg config.File,
	redisClient rediscli.Client,
	ldapQueue pluginruntime.LDAPQueue,
) *pluginruntime.Host {
	redisPrefix := ""
	if cfg != nil {
		redisPrefix = cfg.GetServer().GetRedis().GetPrefix()
	}

	options := []pluginruntime.HostOption{
		pluginruntime.WithServiceContext(ctx),
		pluginruntime.WithLogger(logger),
		pluginruntime.WithConfig(runtimePluginConfigView(cfg)),
		pluginruntime.WithDebugConfig(cfg),
		pluginruntime.WithHTTPClient(&http.Client{Transport: util.NewHTTPClientTransport(cfg)}),
		pluginruntime.WithConnectionTargets(pluginruntime.NewConnectionTargetFacadeForConfig(cfg)),
		pluginruntime.WithRedisPrefix(redisPrefix),
		pluginruntime.WithHelpers(pluginruntime.NewDeterministicHelperFacade(pluginruntime.HelperOptionsFromConfig(cfg))),
	}

	if redisClient != nil {
		options = append(options, pluginruntime.WithRedisClient(redisClient))
	}

	if ldapQueue != nil {
		options = append(options, pluginruntime.WithLDAP(pluginruntime.NewLDAPFacade(
			pluginruntime.NewLDAPQueueExecutor(ldapQueue),
			pluginruntime.NewLDAPConfigEndpointResolver(func() config.File { return cfg }),
		)))
	}

	return pluginruntime.NewHost(options...)
}

// runtimePluginConfigView converts the loaded config snapshot into a read-only plugin API view.
func runtimePluginConfigView(cfg config.File) pluginapi.ConfigView {
	values, err := runtimePluginConfigMap(cfg)
	if err != nil {
		return pluginregistry.NewConfigView(nil)
	}

	return pluginregistry.NewConfigView(values)
}

// runtimePluginConfigMap materializes non-policy process settings without exposing raw Viper state.
func runtimePluginConfigMap(cfg config.File) (map[string]any, error) {
	if cfg == nil {
		return nil, nil
	}

	raw, err := cfg.GetConfigFileAsJSON()
	if err != nil {
		return nil, err
	}

	values := make(map[string]any)
	if len(raw) == 0 {
		return values, nil
	}

	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}

	delete(values, runtimePluginPolicyConfigKey)

	return values, nil
}
