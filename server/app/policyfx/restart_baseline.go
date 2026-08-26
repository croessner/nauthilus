// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"

	"go.uber.org/fx"
)

const (
	restartClassStorage         = "Redis, account cache, and timeouts"
	restartClassBackendOrder    = "backend order"
	restartClassLDAP            = "LDAP workers, queues, pools, and resources"
	restartClassLua             = "Lua workers, queues, pools, scripts, and HTTP client"
	restartClassBruteForce      = "brute-force toleration and concurrency"
	restartClassRoutes          = "HTTP, backchannel, and IdP route graph"
	restartClassAuthRequest     = "auth request and master-user mapping"
	restartClassBackground      = "auth controls, services, and background loops"
	restartClassRemoteAuthority = "remote authority clients"
	restartClassAuthLuaHooks    = "auth Lua hooks"
	restartClassTransport       = "HTTP and gRPC listener and router graph"
	restartClassPlugins         = "native plugin startup"
	restartClassPluginVisible   = "native plugin host configuration"
)

var secretValueType = reflect.TypeFor[secret.Value]()

// RestartBaselineValidator rejects drift in process-owned policy-critical dependencies.
type RestartBaselineValidator interface {
	Validate(config.File) error
	Close()
}

type restartBaseline struct {
	artifacts *config.ArtifactSnapshot
	classes   []restartClassFingerprint
	closeOnce sync.Once
}

type restartClassFingerprint struct {
	name   string
	digest [sha256.Size]byte
}

type restartClassInput struct {
	value     any
	artifacts []string
	name      string
}

type restartClassArtifactPaths struct {
	luaModules []string
	frontend   []string
	plugins    []string
}

type restartArtifactFingerprint struct {
	digest [sha256.Size]byte
	path   string
}

type restartBackendReference struct {
	typeName string
	name     string
}

type restartStorageCarrier struct {
	redis         config.Redis
	timeouts      restartProcessTimeouts
	localCacheTTL time.Duration
}

type restartProcessTimeouts struct {
	redisRead  time.Duration
	redisWrite time.Duration
	ldapSearch time.Duration
	ldapBind   time.Duration
	ldapModify time.Duration
	luaBackend time.Duration
	luaScript  time.Duration
}

type restartLuaCarrier struct {
	optional         map[string]restartLuaConfigCarrier
	configuration    restartLuaConfigCarrier
	httpClient       config.HTTPClient
	search           []config.LuaSearchProtocol
	scriptTimeout    time.Duration
	configurationSet bool
	optionalSet      bool
}

type restartLuaConfigCarrier struct {
	packagePath            string
	backendScriptPath      string
	cacheFlushScriptPath   string
	numberOfWorkers        int
	backendNumberOfWorkers int
	queueLength            int
	actionNumberOfWorkers  int
	environmentVMPoolSize  int
	subjectVMPoolSize      int
	hookVMPoolSize         int
	luaIPv6CIDR            uint
	luaIPv4CIDR            uint
}

type restartBruteForceCarrier struct {
	configuration *config.BruteForceSection
	maxConcurrent int32
}

type restartRouteCarrier struct {
	identity          *config.IDPSection
	frontend          restartFrontendCarrier
	disabledEndpoints config.Endpoint
	backchannelBasic  config.BasicAuth
	backchannelOIDC   config.OIDCAuth
}

type restartFrontendCarrier struct {
	securityHeaders       config.FrontendSecurityHeaders
	encryptionSecret      secret.Value
	htmlStaticContentPath string
	totpIssuer            string
	totpSkew              uint
	enabled               bool
}

type restartRemoteAuthorityCarrier struct {
	clients  map[string]*config.NauthilusAuthorityClientSection
	backends map[string]*config.RemoteBackendSection
}

type restartTransportCarrier struct {
	grpc                *config.RuntimeGRPCAuthServerSection
	trustedProxies      []string
	middlewares         config.Middlewares
	httpTLS             config.TLS
	insights            config.Insights
	cors                config.CORS
	compression         config.Compression
	keepAlive           config.KeepAlive
	securityTxt         config.SecurityTxt
	openAPIValidation   config.OpenAPIValidation
	prometheusTimer     config.PrometheusTimer
	metricsEndpointAuth config.MetricsEndpointAuth
	address             string
	runAsUser           string
	runAsGroup          string
	chroot              string
	rateLimitPerSecond  float64
	rateLimitBurst      int
	http3               bool
	haProxyV2           bool
}

type restartAuthRequestCarrier struct {
	headers    config.DefaultHTTPRequestHeader
	masterUser config.MasterUser
}

type restartBackgroundCarrier struct {
	runtimeModules      []*config.RuntimeModule
	controls            []*config.Control
	services            []*config.Service
	bruteForceProtocols []*config.Protocol
	monitoring          *config.BackendServerMonitoring
	dns                 config.DNS
}

type restartPluginVisibleCarrier struct {
	runtime       *config.RuntimeSection
	storage       *config.StorageSection
	auth          *config.AuthSection
	identity      *config.IdentitySection
	plugins       *config.PluginsSection
	other         map[string]any
	observability restartPluginObservabilityCarrier
	present       bool
}

type restartPluginObservabilityCarrier struct {
	profiles config.ObservabilityProfiles
	tracing  config.Tracing
	metrics  config.ObservabilityMetrics
	present  bool
}

type authorityClientProvider interface {
	GetNauthilusAuthorityClients() map[string]*config.NauthilusAuthorityClientSection
}

// NewRestartBaseline freezes every process-owned config class from the boot snapshot.
func NewRestartBaseline(configured config.File) (RestartBaselineValidator, error) {
	artifacts, err := config.EnsureArtifactSnapshot(configured)
	if err != nil {
		return nil, fmt.Errorf("capture production restart artifacts: %w", err)
	}

	if err = artifacts.ValidateLive(); err != nil {
		artifacts.Release()

		return nil, fmt.Errorf("validate production restart artifacts: %w", err)
	}

	classes, err := fingerprintRestartClasses(configured, artifacts)
	if err != nil {
		artifacts.Release()

		return nil, fmt.Errorf("capture production restart baseline: %w", err)
	}

	if err = artifacts.Retain(); err != nil {
		artifacts.Release()

		return nil, fmt.Errorf("retain production restart artifacts: %w", err)
	}

	return &restartBaseline{artifacts: artifacts, classes: classes}, nil
}

// provideRestartBaseline captures the immutable bootstrap snapshot before Fx starts runtime resources.
func provideRestartBaseline(
	lifecycle fx.Lifecycle,
	provider configfx.Provider,
) (RestartBaselineValidator, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: restart baseline config provider is required", policyruntime.ErrInvalidGeneration)
	}

	snapshot := provider.Current()
	if snapshot.File == nil || snapshot.Version == 0 {
		return nil, fmt.Errorf("%w: restart baseline boot snapshot is incomplete", policyruntime.ErrInvalidGeneration)
	}

	baseline, err := NewRestartBaseline(snapshot.File)
	if err != nil {
		return nil, err
	}

	lifecycle.Append(fx.Hook{OnStop: func(context.Context) error {
		baseline.Close()

		return nil
	}})

	return baseline, nil
}

// Validate compares a candidate only with the detached boot fingerprints.
func (b *restartBaseline) Validate(candidate config.File) error {
	if b == nil || b.artifacts == nil || candidate == nil || len(b.classes) == 0 {
		return fmt.Errorf("%w: restart baseline validation dependencies are incomplete", policyruntime.ErrInvalidGeneration)
	}

	artifacts, err := config.EnsureArtifactSnapshot(candidate)
	if err != nil {
		return fmt.Errorf("%w: seal restart-bound candidate: %v", pluginruntime.ErrRestartRequired, err)
	}

	if err = artifacts.ValidateLive(); err != nil {
		return fmt.Errorf("%w: candidate artifact drift: %w", pluginruntime.ErrRestartRequired, err)
	}

	classes, err := fingerprintRestartClasses(candidate, artifacts)
	if err != nil {
		return fmt.Errorf("%w: inspect restart-bound candidate: %v", pluginruntime.ErrRestartRequired, err)
	}

	if len(classes) != len(b.classes) {
		return fmt.Errorf("%w: process-owned configuration classes changed", pluginruntime.ErrRestartRequired)
	}

	for index := range b.classes {
		if b.classes[index] != classes[index] {
			return fmt.Errorf(
				"%w: %s configuration changed",
				pluginruntime.ErrRestartRequired,
				b.classes[index].name,
			)
		}
	}

	return nil
}

// Close releases the process-lifecycle reference after all live artifact owners stop.
func (b *restartBaseline) Close() {
	if b == nil {
		return
	}

	b.closeOnce.Do(func() {
		b.artifacts.Release()
	})
}

// fingerprintRestartClasses snapshots deterministic config and artifact digests by responsibility.
func fingerprintRestartClasses(
	configured config.File,
	artifacts *config.ArtifactSnapshot,
) ([]restartClassFingerprint, error) {
	if configured == nil || artifacts == nil {
		return nil, fmt.Errorf("%w: restart baseline config is nil", policyruntime.ErrInvalidGeneration)
	}

	inputs, err := restartClassInputs(configured, artifacts)
	if err != nil {
		return nil, err
	}

	result := make([]restartClassFingerprint, 0, len(inputs))
	for _, input := range inputs {
		fingerprints, err := fingerprintRestartArtifacts(artifacts, input.artifacts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", input.name, err)
		}

		digest, err := fingerprintRestartValue(struct {
			Value     any
			Artifacts []restartArtifactFingerprint
		}{Value: input.value, Artifacts: fingerprints})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", input.name, err)
		}

		result = append(result, restartClassFingerprint{name: input.name, digest: digest})
	}

	return result, nil
}

// restartClassInputs projects only process-owned fields; Policy and logging remain reloadable.
func restartClassInputs(
	configured config.File,
	artifacts *config.ArtifactSnapshot,
) ([]restartClassInput, error) {
	paths, err := collectRestartClassArtifactPaths(configured, artifacts)
	if err != nil {
		return nil, err
	}

	server := configured.GetServer()
	lua := configured.GetLua()
	ldap := configured.GetLDAP()
	identity := configured.GetIDP()
	manifest := config.ProductionArtifactManifestFor(configured)

	return projectRestartClassInputs(configured, server, lua, ldap, identity, manifest, paths), nil
}

// collectRestartClassArtifactPaths resolves the manifest collections required by restart classes.
func collectRestartClassArtifactPaths(
	configured config.File,
	artifacts *config.ArtifactSnapshot,
) (restartClassArtifactPaths, error) {
	manifest := config.ProductionArtifactManifestFor(configured)

	luaModules, err := restartLuaModuleArtifactPaths(artifacts, manifest.LuaPackagePatterns)
	if err != nil {
		return restartClassArtifactPaths{}, err
	}

	frontendArtifacts, err := restartManifestCollectionPaths(
		artifacts,
		manifest.FrontendGlobs,
		manifest.FrontendTrees,
	)
	if err != nil {
		return restartClassArtifactPaths{}, err
	}

	pluginArtifacts, err := restartPluginManifestPaths(artifacts, manifest)
	if err != nil {
		return restartClassArtifactPaths{}, err
	}

	return restartClassArtifactPaths{
		luaModules: luaModules,
		frontend:   frontendArtifacts,
		plugins:    pluginArtifacts,
	}, nil
}

// projectRestartClassInputs maps process-owned config and resolved artifacts into deterministic classes.
func projectRestartClassInputs(
	configured config.File,
	server *config.ServerSection,
	lua *config.LuaSection,
	ldap *config.LDAPSection,
	identity *config.IDPSection,
	manifest config.ProductionArtifactManifest,
	paths restartClassArtifactPaths,
) []restartClassInput {
	return []restartClassInput{
		{
			name: restartClassStorage,
			value: restartStorageCarrier{
				redis: *server.GetRedis(), timeouts: restartTimeouts(server.GetTimeouts()),
				localCacheTTL: server.GetLocalCacheAuthTTL(),
			},
			artifacts: append([]string(nil), manifest.RedisTLS...),
		},
		{name: restartClassBackendOrder, value: restartBackendOrder(server.GetBackends())},
		{name: restartClassLDAP, value: ldap, artifacts: append([]string(nil), manifest.LDAP...)},
		{
			name: restartClassLua, value: restartLuaConfig(server, lua),
			artifacts: append(append(append([]string(nil), manifest.Lua...), manifest.HTTPClientTLS...), paths.luaModules...),
		},
		{
			name: restartClassBruteForce,
			value: restartBruteForceCarrier{
				configuration: configured.GetBruteForce(), maxConcurrent: server.GetMaxConcurrentRequests(),
			},
		},
		{
			name: restartClassRoutes, value: restartRoutes(server, identity),
			artifacts: append(append([]string(nil), manifest.Identity...), paths.frontend...),
		},
		{
			name: restartClassAuthRequest,
			value: restartAuthRequestCarrier{
				headers: *server.GetDefaultHTTPRequestHeader(), masterUser: *server.GetMasterUser(),
			},
		},
		{name: restartClassBackground, value: restartBackground(configured, server)},
		{
			name:      restartClassRemoteAuthority,
			value:     restartRemoteAuthority(configured),
			artifacts: append([]string(nil), manifest.RemoteAuthority...),
		},
		{name: restartClassAuthLuaHooks, value: lua.GetHooks(), artifacts: append([]string(nil), manifest.Hooks...)},
		{
			name: restartClassTransport, value: restartTransport(configured, server),
			artifacts: append([]string(nil), manifest.Transport...),
		},
		{
			name: restartClassPlugins, value: configured.GetPlugins(),
			artifacts: paths.plugins,
		},
		{name: restartClassPluginVisible, value: restartPluginVisibleConfig(configured)},
	}
}

// restartTimeouts projects only timeouts consumed by process-owned auth dependencies.
func restartTimeouts(timeouts *config.Timeouts) restartProcessTimeouts {
	if timeouts == nil {
		timeouts = &config.Timeouts{}
	}

	return restartProcessTimeouts{
		redisRead: timeouts.GetRedisRead(), redisWrite: timeouts.GetRedisWrite(),
		ldapSearch: timeouts.GetLDAPSearch(), ldapBind: timeouts.GetLDAPBind(),
		ldapModify: timeouts.GetLDAPModify(), luaBackend: timeouts.GetLuaBackend(),
		luaScript: timeouts.GetLuaScript(),
	}
}

// restartBackendOrder detaches effective backend type and instance order.
func restartBackendOrder(backends []*config.Backend) []restartBackendReference {
	if backends == nil {
		return nil
	}

	result := make([]restartBackendReference, 0, len(backends))
	for _, backend := range backends {
		if backend == nil {
			result = append(result, restartBackendReference{})
			continue
		}

		result = append(result, restartBackendReference{
			typeName: backend.Get().String(), name: backend.GetName(),
		})
	}

	return result
}

// restartLuaConfig removes startup init-script fields owned by StartupCatalog.
func restartLuaConfig(server *config.ServerSection, lua *config.LuaSection) restartLuaCarrier {
	if lua == nil {
		lua = &config.LuaSection{}
	}

	var optional map[string]restartLuaConfigCarrier
	if lua.OptionalLuaBackends != nil {
		optional = make(map[string]restartLuaConfigCarrier, len(lua.OptionalLuaBackends))
	}

	for name, value := range lua.OptionalLuaBackends {
		optional[name] = restartLuaConfiguration(value)
	}

	return restartLuaCarrier{
		optional: optional, configuration: restartLuaConfiguration(lua.Config),
		httpClient:       *server.GetHTTPClient(),
		search:           slices.Clone(lua.Search),
		scriptTimeout:    server.GetLuaScriptTimeout(),
		configurationSet: lua.Config != nil,
		optionalSet:      lua.OptionalLuaBackends != nil,
	}
}

// restartLuaConfiguration projects process VM inputs while excluding init scripts.
func restartLuaConfiguration(input *config.LuaConf) restartLuaConfigCarrier {
	if input == nil {
		return restartLuaConfigCarrier{}
	}

	return restartLuaConfigCarrier{
		packagePath: input.PackagePath, backendScriptPath: input.BackendScriptPath,
		cacheFlushScriptPath: input.CacheFlushScriptPath,
		numberOfWorkers:      input.NumberOfWorkers, backendNumberOfWorkers: input.BackendNumberOfWorkers,
		queueLength: input.QueueLength, actionNumberOfWorkers: input.ActionNumberOfWorkers,
		environmentVMPoolSize: input.EnvironmentVMPoolSize, subjectVMPoolSize: input.SubjectVMPoolSize,
		hookVMPoolSize: input.HookVMPoolSize, luaIPv6CIDR: input.LuaIPv6CIDR, luaIPv4CIDR: input.LuaIPv4CIDR,
	}
}

// restartRoutes excludes system-localization fields owned by StartupCatalog.
func restartRoutes(server *config.ServerSection, identity *config.IDPSection) restartRouteCarrier {
	frontend := server.GetFrontend()

	return restartRouteCarrier{
		identity: identity,
		frontend: restartFrontendCarrier{
			securityHeaders: frontend.SecurityHeaders, encryptionSecret: frontend.EncryptionSecret,
			htmlStaticContentPath: frontend.HTMLStaticContentPath,
			totpIssuer:            frontend.TotpIssuer, totpSkew: frontend.TotpSkew, enabled: frontend.Enabled,
		},
		disabledEndpoints: *server.GetDisabledEndpoints(),
		backchannelBasic:  *server.GetBasicAuth(),
		backchannelOIDC:   *server.GetOIDCAuth(),
	}
}

// restartRemoteAuthority captures outbound clients and their backend references together.
func restartRemoteAuthority(configured config.File) restartRemoteAuthorityCarrier {
	result := restartRemoteAuthorityCarrier{}
	if provider, ok := configured.(authorityClientProvider); ok {
		result.clients = provider.GetNauthilusAuthorityClients()
	}

	if settings, ok := configured.(*config.FileSettings); ok && settings.Auth != nil {
		result.backends = settings.Auth.Backends.Remote
	}

	return result
}

// restartBackground projects boot-started controls, services, and monitoring loops.
func restartBackground(configured config.File, server *config.ServerSection) restartBackgroundCarrier {
	return restartBackgroundCarrier{
		runtimeModules: slices.Clone(server.GetRuntimeModules()),
		controls:       slices.Clone(server.Controls), services: slices.Clone(server.Services),
		bruteForceProtocols: slices.Clone(server.GetBruteForceProtocols()),
		monitoring:          configured.GetBackendServerMonitoring(), dns: *server.GetDNS(),
	}
}

// restartTransport projects listener, router, process, and observability inputs fixed at boot.
func restartTransport(configured config.File, server *config.ServerSection) restartTransportCarrier {
	result := restartTransportCarrier{
		trustedProxies: slices.Clone(server.GetTrustedProxies()), middlewares: *server.GetMiddlewares(),
		httpTLS: *server.GetTLS(), insights: *server.GetInsights(), cors: *server.GetCORS(),
		compression: *server.GetCompression(), keepAlive: *server.GetKeepAlive(),
		securityTxt: *server.GetSecurityTxt(), openAPIValidation: *server.GetOpenAPIValidation(),
		prometheusTimer: *server.GetPrometheusTimer(), metricsEndpointAuth: *server.GetMetricsEndpointAuth(),
		address: server.Address, runAsUser: server.RunAsUser, runAsGroup: server.RunAsGroup,
		chroot: server.Chroot, rateLimitPerSecond: server.RateLimitPerSecond,
		rateLimitBurst: server.RateLimitBurst, http3: server.HTTP3, haProxyV2: server.HAproxyV2,
	}
	if provider, ok := configured.(config.RuntimeGRPCAuthServerProvider); ok {
		result.grpc = provider.GetRuntimeGRPCAuthServer()
	}

	return result
}

// restartPluginVisibleConfig detaches the full boot Host.Config view except separately-owned mutable fields.
func restartPluginVisibleConfig(configured config.File) restartPluginVisibleCarrier {
	settings, ok := configured.(*config.FileSettings)
	if !ok || settings == nil {
		return restartPluginVisibleCarrier{}
	}

	return restartPluginVisibleCarrier{
		runtime: settings.Runtime, storage: settings.Storage,
		auth: restartPluginAuthConfig(settings.Auth), identity: restartPluginIdentityConfig(settings.Identity),
		plugins: settings.Plugins, other: settings.Other,
		observability: restartPluginObservabilityConfig(settings.Observability), present: true,
	}
}

// restartPluginObservabilityConfig excludes logging, whose runtime owner supports live changes.
func restartPluginObservabilityConfig(input *config.ObservabilitySection) restartPluginObservabilityCarrier {
	if input == nil {
		return restartPluginObservabilityCarrier{}
	}

	return restartPluginObservabilityCarrier{
		profiles: input.Profiles, tracing: input.Tracing, metrics: input.Metrics, present: true,
	}
}

// restartPluginAuthConfig excludes startup Lua paths owned by StartupCatalog.
func restartPluginAuthConfig(input *config.AuthSection) *config.AuthSection {
	if input == nil {
		return nil
	}

	result := *input
	result.Backends.Lua.Backend.Default = restartPluginLuaConfig(result.Backends.Lua.Backend.Default)
	result.Backends.Lua.Backend.NamedBackends = restartPluginLuaConfigs(
		result.Backends.Lua.Backend.NamedBackends,
	)

	return &result
}

// restartPluginLuaConfigs clones named Lua inputs while removing startup script fields.
func restartPluginLuaConfigs(input map[string]*config.LuaConf) map[string]*config.LuaConf {
	if input == nil {
		return nil
	}

	result := make(map[string]*config.LuaConf, len(input))
	for name, configured := range input {
		result[name] = restartPluginLuaConfig(configured)
	}

	return result
}

// restartPluginLuaConfig removes startup scripts from one detached Lua configuration.
func restartPluginLuaConfig(input *config.LuaConf) *config.LuaConf {
	if input == nil {
		return nil
	}

	result := *input
	result.InitScriptPath = ""
	result.InitScriptPaths = nil

	return &result
}

// restartPluginIdentityConfig excludes system localization fields owned by StartupCatalog.
func restartPluginIdentityConfig(input *config.IdentitySection) *config.IdentitySection {
	if input == nil {
		return nil
	}

	result := *input
	result.Frontend.Assets.LanguageResources = ""
	result.Frontend.Localization = config.IdentityFrontendLocalization{}

	return &result
}

// restartLuaModuleArtifactPaths projects bounded package-pattern membership without retaining byte clones.
func restartLuaModuleArtifactPaths(
	artifacts *config.ArtifactSnapshot,
	patterns []string,
) ([]string, error) {
	paths := make([]string, 0)

	for _, pattern := range patterns {
		files, err := artifacts.FilesForLuaPackagePattern(pattern)
		if err != nil {
			return nil, err
		}

		paths = appendRestartArtifactFilePaths(paths, files)
	}

	return paths, nil
}

// restartManifestCollectionPaths projects captured glob and tree memberships without retaining bytes.
func restartManifestCollectionPaths(
	artifacts *config.ArtifactSnapshot,
	globs []string,
	trees []string,
) ([]string, error) {
	paths := make([]string, 0)

	for _, pattern := range globs {
		files, err := artifacts.FilesMatching(pattern)
		if err != nil {
			return nil, err
		}

		paths = appendRestartArtifactFilePaths(paths, files)
	}

	for _, root := range trees {
		files, err := artifacts.FilesUnder(root)
		if err != nil {
			return nil, err
		}

		paths = appendRestartArtifactFilePaths(paths, files)
	}

	return paths, nil
}

// appendRestartArtifactFilePaths records path identity and clears detached file content immediately.
func appendRestartArtifactFilePaths(paths []string, files []config.ArtifactFile) []string {
	for index := range files {
		paths = append(paths, files[index].Path)
		clear(files[index].Content)
	}

	return paths
}

// restartPluginManifestPaths includes captured optional inputs while preserving expected absence.
func restartPluginManifestPaths(
	artifacts *config.ArtifactSnapshot,
	manifest config.ProductionArtifactManifest,
) ([]string, error) {
	paths := append([]string(nil), manifest.Plugins...)
	for _, path := range manifest.OptionalPlugins {
		if path == "" {
			continue
		}

		_, err := artifacts.Fingerprint(path)
		switch {
		case err == nil:
			paths = append(paths, path)
		case errors.Is(err, config.ErrArtifactNotCaptured):
			continue
		default:
			return nil, err
		}
	}

	return paths, nil
}

// fingerprintRestartArtifacts owns sorted path and byte digests without retaining content.
func fingerprintRestartArtifacts(
	artifacts *config.ArtifactSnapshot,
	paths []string,
) ([]restartArtifactFingerprint, error) {
	unique := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path != "" {
			unique[path] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(unique))
	for path := range unique {
		ordered = append(ordered, path)
	}

	sort.Strings(ordered)

	result := make([]restartArtifactFingerprint, 0, len(ordered))
	for _, path := range ordered {
		fingerprint, err := artifacts.Fingerprint(path)
		if err != nil {
			return nil, err
		}

		result = append(result, restartArtifactFingerprint{path: fingerprint.Path, digest: fingerprint.Digest})
	}

	return result, nil
}

// fingerprintRestartValue hashes deterministic type-aware structure without serializing secrets.
func fingerprintRestartValue(value any) ([sha256.Size]byte, error) {
	hasher := sha256.New()
	if err := writeRestartValue(hasher, reflect.ValueOf(value)); err != nil {
		return [sha256.Size]byte{}, err
	}

	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))

	return result, nil
}

// writeRestartValue writes one canonical reflect value into the class digest.
func writeRestartValue(hasher hash.Hash, value reflect.Value) error {
	if !value.IsValid() {
		writeRestartString(hasher, "invalid")

		return nil
	}

	writeRestartString(hasher, value.Type().String())

	handled, err := writeRestartSpecialValue(hasher, value)
	if handled || err != nil {
		return err
	}

	return writeRestartValueKind(hasher, value)
}

// writeRestartSpecialValue handles secrets and nullable wrappers before kind dispatch.
func writeRestartSpecialValue(hasher hash.Hash, value reflect.Value) (bool, error) {
	if value.Type() == secretValueType && value.CanInterface() {
		var digest [sha256.Size]byte

		value.Interface().(secret.Value).WithBytes(func(content []byte) {
			digest = sha256.Sum256(content)
		})
		hasher.Write(digest[:])

		return true, nil
	}

	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			writeRestartUint64(hasher, 0)

			return true, nil
		}

		writeRestartUint64(hasher, 1)

		return true, writeRestartValue(hasher, value.Elem())
	}

	return false, nil
}

// writeRestartValueKind writes one non-nullable canonical value by reflection kind.
func writeRestartValueKind(hasher hash.Hash, value reflect.Value) error {
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			writeRestartUint64(hasher, 1)
		} else {
			writeRestartUint64(hasher, 0)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		writeRestartUint64(hasher, uint64(value.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		writeRestartUint64(hasher, value.Uint())
	case reflect.Float32, reflect.Float64:
		writeRestartUint64(hasher, math.Float64bits(value.Convert(reflect.TypeFor[float64]()).Float()))
	case reflect.String:
		writeRestartString(hasher, value.String())
	case reflect.Slice:
		return writeRestartSlice(hasher, value)
	case reflect.Array:
		return writeRestartArray(hasher, value)
	case reflect.Map:
		return writeRestartMap(hasher, value)
	case reflect.Struct:
		return writeRestartStruct(hasher, value)
	default:
		return fmt.Errorf("unsupported restart baseline value kind %s", value.Kind())
	}

	return nil
}

// writeRestartSlice distinguishes absence from an explicitly empty ordered value.
func writeRestartSlice(hasher hash.Hash, value reflect.Value) error {
	if value.IsNil() {
		writeRestartUint64(hasher, 0)

		return nil
	}

	writeRestartUint64(hasher, 1)

	return writeRestartArray(hasher, value)
}

// writeRestartArray writes one ordered sequence into the canonical digest.
func writeRestartArray(hasher hash.Hash, value reflect.Value) error {
	writeRestartUint64(hasher, uint64(value.Len()))

	for index := 0; index < value.Len(); index++ {
		if err := writeRestartValue(hasher, value.Index(index)); err != nil {
			return err
		}
	}

	return nil
}

// writeRestartMap writes one deterministically ordered map while retaining nil presence.
func writeRestartMap(hasher hash.Hash, value reflect.Value) error {
	if value.IsNil() {
		writeRestartUint64(hasher, 0)

		return nil
	}

	writeRestartUint64(hasher, 1)

	keys := value.MapKeys()
	sort.Slice(keys, func(left int, right int) bool {
		return restartMapKey(keys[left]) < restartMapKey(keys[right])
	})
	writeRestartUint64(hasher, uint64(len(keys)))

	for _, key := range keys {
		if err := writeRestartValue(hasher, key); err != nil {
			return err
		}

		if err := writeRestartValue(hasher, value.MapIndex(key)); err != nil {
			return err
		}
	}

	return nil
}

// writeRestartStruct writes named fields so layout changes cannot alias the digest.
func writeRestartStruct(hasher hash.Hash, value reflect.Value) error {
	writeRestartUint64(hasher, uint64(value.NumField()))

	for index := 0; index < value.NumField(); index++ {
		writeRestartString(hasher, value.Type().Field(index).Name)

		if err := writeRestartValue(hasher, value.Field(index)); err != nil {
			return err
		}
	}

	return nil
}

// restartMapKey returns a stable scalar representation for config map ordering.
func restartMapKey(value reflect.Value) string {
	if value.Kind() == reflect.String {
		return value.String()
	}

	return fmt.Sprint(value)
}

// writeRestartString writes a length-prefixed scalar into the running digest.
func writeRestartString(hasher hash.Hash, value string) {
	writeRestartUint64(hasher, uint64(len(value)))
	_, _ = hasher.Write([]byte(value))
}

// writeRestartUint64 writes one canonical unsigned scalar into the running digest.
func writeRestartUint64(hasher hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = hasher.Write(encoded[:])
}

var _ RestartBaselineValidator = (*restartBaseline)(nil)
