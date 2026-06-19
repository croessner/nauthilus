# Go Plugin API Working Draft

This document is the working implementation contract for adding native Go extensions to the same conceptual extension
points that Nauthilus currently exposes to Lua. The initial v1 host path is implemented, while explicitly marked limits
remain part of the supportability contract until they are closed.

## Purpose

Nauthilus already supports Lua-based extension points for startup initialization, pre-auth environment sources,
post-backend subject sources, backends, actions selected by policy obligations, and HTTP/custom hooks. Native Go
extensions would cover the same use cases while also allowing compiled integrations to keep long-lived state, start
background workers, use goroutines, and implement customer-specific backends without routing through Lua.

Good examples for native extensions:

- GeoIP or ASN enrichment backed by local databases, periodic refresh jobs, or vendor SDKs.
- Customer-specific identity backends with MFA and WebAuthn support.
- High-throughput policy attribute sources that need native concurrency or typed libraries.
- Operational workers started during initialization, such as cache warmers or external metadata synchronizers.

## Current Extension Model

The current Lua model provides the main shape for Go plugins:

- `server/app/bootfx/boot.go` precompiles Lua environment sources, subject sources, init scripts, and hooks through
  `SetupLuaScripts`.
- `server/lua-plugins.d/README.md` describes the operator-visible categories: `init`, `environment`, `subject`,
  `backend`, `actions`, `hooks`, `policy`, and `share`.
- `server/config/schema_v2.go` materializes Lua environment and subject sources from
  `auth.policy.attribute_sources.lua.*`, and Lua actions from `auth.policy.obligation_targets.lua.actions`.
- `server/lualib/environment/environment.go` and `server/lualib/subject/subject.go` already execute sources through a
  dependency plan with per-level parallelism.
- `server/lualib/context.go` provides a request-local, thread-safe Lua context with snapshot, diff, and merge support.
- `server/core/types.go` already has a `BackendManager` interface plus a factory registry, but the current contract
  exposes `*core.AuthState`, which is too internal for a stable plugin API.
- `server/lualib/luamod/manager.go` shows the current service surface exposed to Lua: context, CBOR, Redis, psnet, DNS,
  OpenTelemetry, brute force, i18n, HTTP request/response, and LDAP.
- `server/policy/collection/collection.go` and `server/policy/observability/metrics.go` provide request-local policy
  facts and policy metrics, which should remain the authority for decisions.

The important design point: Lua is not merely a scripting feature. It is already intertwined with policy scheduling,
request-local facts, runtime context, backend selection, Redis, LDAP, Prometheus, and OpenTelemetry. Go plugins should
therefore use the same concepts through a typed host API instead of importing internal packages directly.

## Go Plugin Runtime Constraints

The Go standard-library `plugin` package is powerful but operationally sharp:

- A Go plugin is a `main` package built with `go build -buildmode=plugin`.
- A loaded plugin is initialized once and cannot be closed or unloaded.
- Plugin `init` functions run when the plugin is first opened; the plugin `main` function does not run.
- The host and plugin must be built with the same Go toolchain, build tags, relevant flags, and exact common dependency
  sources, or runtime crashes are likely.
- The race detector does not reliably cover plugin code.
- Plugins are supported only on Linux, FreeBSD, and macOS.
- Plugins run inside the Nauthilus process and must be treated as trusted code.

Decision: native Go plugins are loaded only as `.so` files through the standard-library `plugin` package. Nauthilus does
not define a statically linked plugin deployment model or an interpreted Go plugin path.

## Design Goals

- Provide the same conceptual extension points for Lua and Go.
- Keep policy as the decision authority. Plugins emit facts, backend results, obligation results, and status details;
  policy decides.
- Do not export `*core.AuthState`, `*gin.Context`, raw Viper state, Redis internals, LDAP queues, raw Prometheus
  registerers, or raw OpenTelemetry providers as the public contract.
- Make request APIs context-first, cancelable, and deadline-aware.
- Support background workers through an explicit lifecycle, not through package `init` side effects.
- Keep host services capability-based and narrow: Redis, LDAP, metrics, tracing, logging, config, HTTP metadata, and
  controlled goroutine supervision. Policy attributes are declared through the registrar, and request-time policy facts
  are returned through extension result values.
- Keep Lua and Go implementations behind shared internal extension interfaces where possible.
- Make reload behavior explicit. Loaded Go plugins cannot be unloaded, so removal or binary replacement should normally
  require restart.

## Non-Goals

- Sandboxing untrusted code.
- A stable ABI across arbitrary Go versions or dependency graphs.
- Letting plugin code mutate arbitrary Nauthilus internals.
- Making Go plugins a replacement for remote authority backends when process isolation is required.
- Defining a remote plugin protocol, such as a gRPC companion-process contract, in the initial public API.

## Proposed Package Boundary

Create a small API package that plugin authors import from the repository root:

```go
package pluginapi

const APIVersion = "nauthilus.plugin.v1"
```

Decision: the public package should live under `pluginapi/v1`, for example
`github.com/croessner/nauthilus/v3/pluginapi/v1`. Keeping the API outside `server/*` makes the extension boundary explicit
and avoids making plugin authors depend on server internals.

The package should depend only on stable standard-library types and carefully selected external types. Internal Nauthilus
types should be copied into API-level value objects instead of exported directly.

Recommended `.so` export symbol:

```go
// In a plugin main package.
func NauthilusPlugin() (pluginapi.Plugin, error) {
    return NewPlugin(), nil
}
```

The host loads the factory symbol, calls it once per configured module instance, checks `Metadata().APIVersion`, and then
calls `Register` with the instance-scoped registrar.

The factory intentionally receives no context, config, or host services. Instance-specific configuration is available
through the registrar during `Register`; runtime services are available only through `Start`.

A single `.so` plugin may register multiple extension points. The plugin is the deployment unit, while registered
components such as init tasks, environment sources, backends, obligation targets, and hooks remain individually named and
observable.

The same `.so` path may be configured more than once under different module names and configs. `plugin.Open` may reuse
the already-loaded code for a path, but the factory function gives each configured module instance a separate plugin
object and instance-scoped lifecycle.

The configured plugin module name is the instance namespace for registered components. It is distinct from
`Metadata().Name`, which identifies the plugin product or package. Components may expose short local names, but the host
should build fully qualified names such as `geoip.environment`, `geoip.reload_worker`, or `customer.backend` for logs,
metrics, lifecycle status, policy registration, and collision checks.

The host should validate module and component names strictly instead of normalizing them:

- Module instance names: `[a-z0-9][a-z0-9_]{0,62}`
- Component local names: `[a-z0-9][a-z0-9_]{0,62}`
- Fully qualified component names: `<module_name>.<component_name>`

Names such as `GeoIP`, `geo-ip`, `geoip.public`, `_geoip`, and `äuth` should be rejected with clear configuration or
registration errors. Rejecting invalid names is preferable to automatic normalization because normalization can create
surprising collisions.

Core entry contracts:

```go
type Metadata struct {
    Name         string
    Version      string
    APIVersion   string
    Description  string
    DocsURL      string
    Features     []Feature
    Capabilities []Capability
    Build        BuildInfo
}

type BuildInfo struct {
    GoVersion string
    GitCommit string
    BuildTime string
    BuildTags []string
}

type Plugin interface {
    Metadata() Metadata
    Register(Registrar) error
}

type RuntimePlugin interface {
    Start(context.Context, Host) error
    Stop(context.Context) error
}

type ReloadablePlugin interface {
    Reconfigure(context.Context, ConfigView) error
}

type ConfigView interface {
    Get(path string) (any, bool)
    GetPath(path []string) (any, bool)
    Sub(path string) ConfigView
    SubPath(path []string) ConfigView
    Decode(target any) error
    IsZero() bool
}

type ArgsView interface {
    Get(path string) (any, bool)
    GetPath(path []string) (any, bool)
    Sub(path string) ArgsView
    SubPath(path []string) ArgsView
    Decode(target any) error
    IsZero() bool
}

type Registrar interface {
    Config() ConfigView
    RequireCapability(Capability) error
    RegisterInitTask(InitTask) error
    RegisterEnvironmentSource(EnvironmentSource) error
    RegisterSubjectSource(SubjectSource) error
    RegisterBackend(Backend) error
    RegisterObligationTarget(ObligationTarget) error
    RegisterPostActionTarget(PostActionTarget) error
    RegisterHook(Hook) error
    RegisterPolicyAttribute(AttributeDefinition) error
}

type Capability string
type Feature string

const CapabilityCredentials Capability = "credentials"
```

The loader must reject plugins whose `Metadata().APIVersion` does not exactly match the supported public API major
contract, such as `nauthilus.plugin.v1`. `Features` allow plugins to declare optional behavior inside that major
contract without weakening the version check. `Metadata.Capabilities` declares what the plugin build can use, while
`Registrar.RequireCapability` declares what the current module instance actually needs after reading config. `Build`
makes plugin diagnostics visible before registration; hard compatibility should still be based on `APIVersion` and Go
plugin load success.

`Register` should be side-effect-light. It declares extension points, capabilities, and policy attributes. It may inspect
the plugin-owned configuration block through the registrar, but long-lived workers start only through `Start`, after host
services are ready.

## Plugin Configuration

Native plugin configuration should keep Nauthilus responsible for loading and provenance, while the plugin owns the
meaning of its parameters.

The plugin configuration should live at the root-level `plugins` section because a plugin module can contribute process
startup behavior, background workers, hooks, auth backends, policy attribute sources, and obligation targets.

Example shape:

```yaml
plugins:
  verification_policy: when_present
  allowed_dirs:
    - /usr/lib/nauthilus/plugins
  trust:
    signers:
      - id: nauthilus-plugin-build-key-2026
        format: minisign
        public_key_file: /usr/share/nauthilus/plugin-keys/build-2026.pub
  modules:
    - name: geoip
      type: go
      path: /usr/lib/nauthilus/plugins/geoip.so
      checksum: sha256:...
      signature: minisign:/usr/lib/nauthilus/plugins/geoip.so.minisig
      signer: nauthilus-plugin-build-key-2026
      optional: false
      stop_timeout: 10s
      allow_capabilities:
        - credentials
      config:
        database_path: /var/lib/GeoIP/GeoLite2-City.mmdb
        database_format: mmdb
        asn_lookup:
          enabled: true
          refresh_interval: 720h
          timeout: 30s
          source_urls:
            - https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log
            - https://publicdata.caida.org/datasets/routing/routeviews6-prefix2as/pfx2as-creation.log
        refresh_interval: 1h
        lookup_timeout: 50ms
        asn_registry:
          enabled: true
          refresh_interval: 720h
```

Nauthilus should validate the loader fields such as name, type, path, checksum, signature, signer, API version,
optionality, and allowed capabilities. `type` is optional and defaults to `go`; unknown values are unsupported. The
nested `config` block is intentionally opaque to the host and should be passed to the plugin as a scoped `ConfigView`
that preserves the structured values from YAML, JSON, TOML, or another supported config format.

Plugin artifact paths must be absolute. This includes module `path`, detached signature file paths, and signer
`public_key_file` paths. Relative paths should be rejected during configuration validation.

`allow_capabilities` is optional. When present, `Registrar.RequireCapability` may only request capabilities listed for
that module instance. If absent, the host default policy decides whether requested capabilities are allowed. Sensitive
capabilities such as `credentials` should be default-deny and require explicit allowance. Ordinary host facades such as
logging, metrics, and tracing do not need capability gates by default.

The plugin is responsible for interpreting, validating, defaulting, and documenting its own `config` keys. This avoids a
false shared schema across unrelated plugin types such as GeoIP sources, customer-specific backends, and background
workers.

`ConfigView` should be read-only and format-neutral. Plugins can read individual values, select subtrees, or decode the
plugin-owned `config` block into their own structs without exposing raw Viper state or tying plugins to YAML, JSON, TOML,
or another source format. Dot-path helpers are available for common cases, while segment-based helpers avoid ambiguity
when a config key itself contains a dot. `Decode` should be strict by default: unknown fields are errors, and plugin
defaults remain the plugin's responsibility. The API should not add a permissive decode helper; plugins that need
flexible config can read values explicitly through `Get` or `GetPath`.

Policy arguments for `ObligationTarget` and `PostActionTarget` should use an `ArgsView` with the same read-only,
format-neutral, strict-decode behavior as `ConfigView`.

## Host Services

Plugins should receive a single `Host` facade instead of importing internal packages:

```go
type Host interface {
    ServiceContext() context.Context
    Logger(scope string) Logger
    Tracer(scope string) Tracer
    Metrics(scope string) Metrics
    HTTP(scope string) HTTPClient
    ConnectionTargets(scope string) ConnectionTargets
    BackendServers() BackendServers
    Redis() Redis
    Cache(scope string) (Cache, error)
    Helpers() DeterministicHelpers
    LDAP() LDAP
    Config() ConfigView
    Go(ctx context.Context, name string, fn func(context.Context) error)
}
```

Service notes:

- `Logger` should be a small facade rather than raw `*slog.Logger`. The host should automatically attach module,
  component scope, plugin metadata, request IDs when present, and stable operational labels.
- `Redis` should expose broad, host-owned `go-redis` handles through dependency injection. Plugins can use Redis
  commands directly without Nauthilus reimplementing the Lua Redis module in Go. Nauthilus should not expose internal
  Redis singletons or mutable Redis security internals as the plugin contract. Host-owned key helpers and the named script
  registry cover behavior that must remain consistent with Nauthilus prefixing, Redis Cluster slots, and script recovery.
- `Cache` should expose only process-local module cache semantics: TTL values, delete/exists, list push/pop-all, and clear.
  Cache contents are isolated by validated module scope and are not durable.
- `DeterministicHelpers` should hold shared non-secret helper logic used when porting Lua scripts, such as account hash
  tags, scoped IPs, and routable IP checks.
- `LDAP` should expose queued, request-aware `Search` and `Modify` methods that package LDAP operations, submit them to
  the existing worker queues, and wait for results. Plugins should not receive raw LDAP queues, pools, or
  `LDAPRequest` internals.
- `Metrics` should register namespaced counters, gauges, histograms, and summaries without panicking on duplicate
  registration. Raw Prometheus registerers are not part of the public v1 API.
- `Tracer` should attach spans to the active request context through a Nauthilus-owned facade. Raw OpenTelemetry
  providers are not part of the public v1 API.
- `HTTP` exposes host-managed outbound HTTP calls with context deadlines, trace-header injection, bounded plugin metrics,
  response body limits, and redacted operational logs. Plugins pass API-level request and response values, not raw
  `*http.Request` or `*http.Response` objects.
- `ConnectionTargets` registers named `host:port` targets with local/remote direction for generic connection
  observability. It validates names, addresses, bounded labels, and duplicate registration before delegating to the host
  connection monitor.
- `BackendServers` exposes value-only backend candidates from the host monitoring list. Plugins receive defensive
  copies, not raw `*config.BackendServer` pointers or live monitor objects. Candidate selection still returns through
  `SubjectResult.SelectedBackend`.
- Policy data is not exposed through the process-scoped host. Plugins declare attributes through
  `Registrar.RegisterPolicyAttribute` during registration and return request-time facts through extension result values.
- `Go` should start supervised goroutines with panic recovery, logging, tracing, and shutdown coordination.

```go
type Logger interface {
    Debug(context.Context, string, ...LogField)
    Info(context.Context, string, ...LogField)
    Warn(context.Context, string, ...LogField)
    Error(context.Context, string, ...LogField)
}
```

```go
type Metrics interface {
    Counter(MetricDefinition) (Counter, error)
    Gauge(MetricDefinition) (Gauge, error)
    Histogram(MetricDefinition) (Histogram, error)
}

type MetricDefinition struct {
    Name    string
    Help    string
    Labels  []string
    Buckets []float64
}

type Counter interface {
    Add(context.Context, float64, ...LabelValue)
}

type Gauge interface {
    Set(context.Context, float64, ...LabelValue)
    Add(context.Context, float64, ...LabelValue)
}

type Histogram interface {
    Observe(context.Context, float64, ...LabelValue)
}

type LabelValue struct {
    Name  string
    Value string
}

type Tracer interface {
    Start(context.Context, string, ...TraceAttribute) (context.Context, Span)
}

type Span interface {
    AddEvent(string, ...TraceAttribute)
    SetAttributes(...TraceAttribute)
    RecordError(error)
    End()
}

type TraceAttribute struct {
    Key   string
    Value any
}
```

The host should also emit automatic plugin metrics such as call count, error count, panic count, and duration by module,
component, extension point, and result. Plugin-defined metrics are additional and must remain namespaced, duplicate-safe,
and low-cardinality. Label names must be declared in `MetricDefinition.Labels`; runtime observations may only provide
declared labels. The host should reject unknown labels and guard against empty or excessively long label values.

The host should also create automatic spans for host-invoked plugin methods. Plugin-created spans must be child spans of
the context passed into the plugin and should use low-cardinality attributes.

Redis should be broad enough to avoid mirroring Lua helpers:

```go
type Redis interface {
    Read() redis.Cmdable
    Write() redis.Cmdable
    ReadPipeline() redis.Pipeliner
    WritePipeline() redis.Pipeliner
    Keys() RedisKeyBuilder
    Scripts() RedisScriptRegistry
}

type RedisKeyBuilder interface {
    Key(string) string
    Keys(...string) []string
    SameSlot([]string, string) []string
}

type RedisScriptRegistry interface {
    Upload(context.Context, string, string) (string, error)
    Run(context.Context, string, []string, ...any) (any, error)
}

type Cache interface {
    Set(context.Context, string, any, time.Duration)
    Get(context.Context, string) (any, bool)
    Delete(context.Context, string) bool
    Exists(context.Context, string) bool
    Push(context.Context, string, any) int
    PopAll(context.Context, string) []any
    Clear(context.Context)
}

type DeterministicHelpers interface {
    AccountTag(string) string
    ScopedIP(string, string) string
    IsRoutableIP(string) bool
}
```

Plugins must use the host-provided request, startup, worker, or derived contexts for Redis calls. Redis connection
timeouts remain centrally configured by Nauthilus; plugins should not create unbounded background contexts for Redis
operations. Redis keys that need the configured Nauthilus prefix or Redis Cluster hash-tag behavior should be built
through `Redis.Keys()`. Named scripts should be uploaded through `Redis.Scripts().Upload` and run by deterministic name.
The host stores script source/SHA metadata and retries once after `NOSCRIPT`.

Named Redis pools are intentionally plugin-owned in v1. If a plugin needs an additional Redis deployment, it should
construct that client from module-owned config, redact connection details in logs and errors, and close or replace it in
`Stop` and `Reconfigure`.

Process-local cache state should use `Host.Cache(scope)` when init-time and request-time native components of one module
need a shared in-process buffer. Scope validation prevents accidental cross-module sharing; cross-module cache sharing
requires an explicit future API.

Deterministic helpers are also available as dependency-light public helpers for code that does not have a live `Host`
facade. Runtime `Host.Helpers()` applies Nauthilus config and Lua-compatible environment defaults.

LDAP should stay queue-backed but not queue-exposing:

```go
type LDAP interface {
    Search(context.Context, LDAPSearchRequest) (LDAPSearchResult, error)
    Modify(context.Context, LDAPModifyRequest) error
}

type LDAPSearchRequest struct {
    PoolName   string
    BaseDN     string
    Filter     string
    Scope      LDAPScope
    Attributes []string
}

type LDAPSearchResult struct {
    Attributes map[string][]string
    Entries    []LDAPEntry
}

type LDAPModifyRequest struct {
    PoolName   string
    DN         string
    Operation  LDAPModifyOperation
    Attributes map[string][]string
}

type LDAPEntry struct {
    DN         string
    Attributes map[string][]string
}

type LDAPScope string
type LDAPModifyOperation string

const (
    LDAPScopeBase LDAPScope = "base"
    LDAPScopeOne  LDAPScope = "one"
    LDAPScopeSub  LDAPScope = "sub"

    LDAPModifyAdd     LDAPModifyOperation = "add"
    LDAPModifyDelete  LDAPModifyOperation = "delete"
    LDAPModifyReplace LDAPModifyOperation = "replace"
)
```

The host adapter can build internal LDAP requests, enqueue them to the configured pool, wait on the reply channel, and
apply Nauthilus timeouts, retries, logging, and tracing.

The public LDAP API should not expose bind/auth operations, raw queues, pools, or go-ldap request structs. The host
should validate `LDAPScope` and `LDAPModifyOperation` values.

## Request And Runtime Model

Plugins should see immutable request snapshots plus narrow mutation sinks.

```go
type RequestSnapshot struct {
    Headers           map[string][]string
    IDP               IDPInfo
    Session           string
    ExternalSessionID string
    HealthCheck       bool
    Service           string
    Protocol          string
    Method            string
    Username          string
    Account           string
    AccountField      string
    UniqueUserID      string
    DisplayName       string
    ClientIP          string
    ClientPort        string
    ClientNet         string
    ClientHost        string
    ClientID          string
    UserAgent         string
    LocalIP           string
    LocalPort         string
    OIDCCID           string
    SAMLEntityID      string
    AuthLoginAttempt  uint
    TLS               TLSInfo
    Diagnostics       RequestDiagnostics
    Runtime           RuntimeFlags
}

type IDPInfo struct {
    RequestedScopes         []string
    UserGroups              []string
    AllowedClientScopes     []string
    AllowedClientGrantTypes []string
    GrantType               string
    ClientID                string
    ClientName              string
    RedirectURI             string
    MFAMethod               string
    MFACompleted            bool
}

type RequestDiagnostics struct {
    StatusMessage     string
    BruteForceName    string
    EnvironmentName   string
    LatencyMillis     int64
    BruteForceCounter uint
    HTTPStatus        int
}

type TLSInfo struct {
    Legacy         TLSLegacyInfo
    ServerName     string
    CipherSuite    string
    PeerCommonName string
    PeerIssuer     string
    Version        string
    VerifiedChains int
    Enabled        bool
    Mutual         bool
}

type RuntimeFlags struct {
    Debug                    bool
    LocalRequest             bool
    NoAuth                   bool
    UserFound                bool
    Authenticated            bool
    Authorized               bool
    Repeating                bool
    RWP                      bool
    EnvironmentRejected      bool
    EnvironmentStageExpected bool
    SubjectStageExpected     bool
}

type RuntimeContext interface {
    Get(string) (any, bool)
    Snapshot() map[string]any
}

type RuntimeDelta struct {
    Set    map[string]any
    Delete []string
}
```

`Headers` should be an immutable copy of request headers after host redaction, using canonical MIME header keys as in
Go's `net/http` package. Sensitive headers such as authorization, cookies, and configured secret-bearing headers should
be removed or masked before the snapshot reaches plugins.

`RequestSnapshot` should not carry HTTP request bodies. Bodies are available only to HTTP hooks through `HookRequest`,
after the host has enforced the hook's body limit.

Current implementation note: the Lua surface audit in `server/docs/go_plugin_developer_api.md` is the source of truth for
Lua-to-native parity. The runtime adapter now populates the safe request snapshot parity set: transport metadata,
identity fields, IDP/MFA policy inputs, explicit outcome flags, bounded diagnostics, `auth_login_attempt`, redacted
headers, and lossless safe legacy TLS metadata under `TLS.Legacy`. Backend candidates are exposed through a value-only
host facade, backend-result account-field mutation is handled through explicit result values, and policy-selected
effect requests receive validated Lua/native plugin facts from the active decision context. Response header mutations are
supported through request-time subject and obligation result values. Redis key-prefix helpers remain separate follow-up
work.

Runtime context values should be limited to JSON/CBOR-compatible data: nil, bool, numbers, strings, lists, and maps with
string keys. Plugin-specific Go objects should stay in plugin instance state, not in the shared runtime context. The host
should validate `RuntimeDelta.Set` values before merging.

Passwords and other secrets should not be part of the general snapshot. Plugins that need request credentials must
declare that capability during `Register` and request credentials explicitly through a request-scoped provider:

```go
type CredentialProvider interface {
    Password(context.Context) (Secret, bool)
}

type Secret interface {
    WithBytes(func([]byte) error) error
    IsZero() bool
}
```

The provider is intentionally not a global `Host` service. Secret access is request-bound, auditable through capability
declaration, and unavailable to plugins that did not declare the credential capability.

The v1 credential provider should expose only request passwords. Additional secret kinds, such as bearer tokens, client
secrets, or API keys, should be added later only with explicit capabilities and concrete use cases.

`Secret` intentionally exposes only closure-based byte access. The host should implement `WithBytes` so the secret
handling call tree runs inside `runtime/secret.Do` when the runtime experiment is enabled. Plugins must not retain the
provided byte slice after the callback returns. If a plugin must convert to string for a downstream API, that conversion
should happen inside the callback and is the plugin maintainer's responsibility.

Backend requests follow the same rule: `BackendAuthRequest` should expose a `CredentialProvider`, not a direct password
or `Secret` field. Backend plugins must request credentials explicitly after declaring and receiving the credentials
capability.

For parallel environment and subject sources, use the Lua merge pattern:

- Each source receives an isolated read-only runtime context view.
- The source returns a `RuntimeDelta`.
- The host merges deltas in deterministic plan order after each dependency level completes.

This avoids data races while preserving the current ability for one extension point to pass values to later extension
points. If multiple sources in the same dependency level set the same runtime key, the host should apply deterministic
last-writer-wins semantics using descriptor order and emit debug logging for overwritten keys.

## Result Value Objects

Plugin results should use API-level value objects instead of exporting internal Nauthilus status, logging, policy, or
backend structs. The host maps these values into internal runtime, policy, logging, metrics, and response types.

```go
type StatusMessage struct {
    Code        string
    MessageKey  string
    DefaultText string
    Temporary   bool
}

type LogField struct {
    Key   string
    Value any
}

type PolicyFact struct {
    Attribute string
    Value     any
}

type AttributePatch struct {
    Set    map[string][]string
    Delete []string
}

type ResponseHeaderMutation struct {
    Set    map[string][]string
    Delete []string
}

type ResponseMutation struct {
    Headers      ResponseHeaderMutation
    StatusHeader bool
}

type BackendResult struct {
    Authenticated bool
    UserFound     bool
    Account       string
    AccountField  string
    Attributes    map[string][]string
    BackendServer *BackendServerRef
    Status        *StatusMessage
    Facts         []PolicyFact
}
```

`StatusMessage` is a protocol-neutral signal. Plugins should provide a stable code, an optional message key, fallback
text, and whether the condition is temporary. The host maps that signal to Dovecot, HTTP, JSON, logs, metrics, and i18n
behavior.

Backend attributes should stay `map[string][]string` to match existing LDAP and Lua backend result semantics. Typed or
non-string policy data belongs in `PolicyFact` values instead of backend attributes.

`PolicyFact.Value` should use the same JSON/CBOR-compatible value set as runtime context values. This keeps policy facts
serializable, reportable, and safe to bridge between Lua and Go extension paths.

## Extension Point Interfaces

The extension point names should be domain-specific and neutral. Lua and Go can be implementations of the same internal
concept.

Environment and subject sources should use the same dependency scheduler semantics that Lua uses today. In v1, Lua and
Go sources are planned and executed as separate source sets; mixed Lua/Go dependency graphs are not supported.

```go
type SourceDescriptor struct {
    Name        string
    Requires    []string
    After       []string
    Timeout     time.Duration
    Priority    int
    AbortPolicy AbortPolicy
}
```

Each scheduler can then execute independent sources in the same dependency level concurrently and merge source outputs in
deterministic descriptor order after each level completes. Go plugin sources return `RuntimeDelta` values; Lua sources
continue to publish request-context deltas through the existing Lua request context.

Dependency names in `Requires` and `After` are resolved relative to the registering module first. A local component name
such as `asn` can refer to `geoip.asn` when declared by the `geoip` module. Dependencies outside the module must use
fully qualified plugin component names. Dependencies on Lua sources are unsupported in v1; use runtime context values to
consume Lua output from later Go source execution instead of declaring a cross-family dependency.

### Init

```go
type InitTask interface {
    Name() string
    Start(context.Context, InitContext) error
    Stop(context.Context) error
}
```

`InitTask` is for resource setup and optional workers. It must not make policy decisions for individual auth requests.
Decision: `InitTask` is a first-class registrable runtime unit. Plugins register named init tasks during `Register`, and
the host starts and stops those tasks after service-backed runtime facilities are available. This gives each worker or
setup task its own name, logging scope, metrics, tracing, startup error, and shutdown behavior without adding a second
config-only lifecycle hook.

### Environment Source

```go
type EnvironmentSource interface {
    Descriptor() SourceDescriptor
    Evaluate(context.Context, EnvironmentRequest) (EnvironmentResult, error)
}

type EnvironmentResult struct {
    Triggered    bool
    Abort        bool
    Status       *StatusMessage
    Logs         []LogField
    Facts        []PolicyFact
    RuntimeDelta RuntimeDelta
}
```

This maps to the current pre-auth Lua environment source behavior: collect request/environment facts, optionally trigger a
pre-auth rejection candidate, optionally abort later environment sources, and emit policy facts.

### Subject Source

```go
type SubjectSource interface {
    Descriptor() SourceDescriptor
    Evaluate(context.Context, SubjectRequest) (SubjectResult, error)
}

type SubjectResult struct {
    Rejected          bool
    Status            *StatusMessage
    Logs              []LogField
    Facts             []PolicyFact
    BackendAttributes AttributePatch
    BackendResultPatch *BackendResultPatch
    Response          ResponseMutation
    RuntimeDelta      RuntimeDelta
    SelectedBackend   *BackendServerRef
}

type BackendResultPatch struct {
    Account         string
    AccountField    string
    Authenticated   *bool
    UserFound       *bool
    Attributes      AttributePatch
    SelectedBackend *BackendServerRef
}
```

This maps to Lua subject sources, including backend-result enrichment, attribute removal, backend server selection, and
policy facts. `BackendResultPatch` is explicit and value-only; it supports account, account field,
user-found/authenticated flags, selected backend, and string attributes without exposing mutable internal backend-result
pointers or full replacement semantics.
`Response` supports controlled HTTP response header set/delete operations while the response is still mutable. It does
not expose response bodies, cookies, streaming, raw `http.ResponseWriter`, or Gin contexts.

### Backend

```go
type Backend interface {
    Name() string
    VerifyPassword(context.Context, BackendAuthRequest) (BackendResult, error)
    ListAccounts(context.Context, AccountListRequest) (AccountListResult, error)
}
```

Backends should be capability-oriented. The core interface covers password verification and account listing, while MFA
and account security features are discovered through optional interfaces:

```go
type TOTPBackend interface {
    BeginTOTP(context.Context, TOTPBeginRequest) (TOTPBeginResult, error)
    FinishTOTP(context.Context, TOTPFinishRequest) (TOTPFinishResult, error)
    VerifyTOTP(context.Context, TOTPVerifyRequest) (TOTPVerifyResult, error)
    DeleteTOTP(context.Context, TOTPDeleteRequest) error
}

type RecoveryCodeBackend interface {
    GenerateRecoveryCodes(context.Context, RecoveryCodeGenerateRequest) (RecoveryCodeGenerateResult, error)
    UseRecoveryCode(context.Context, RecoveryCodeUseRequest) (RecoveryCodeUseResult, error)
    DeleteRecoveryCodes(context.Context, RecoveryCodeDeleteRequest) error
}

type WebAuthnBackend interface {
    ListWebAuthnCredentials(context.Context, WebAuthnListRequest) (WebAuthnListResult, error)
    SaveWebAuthnCredential(context.Context, WebAuthnSaveRequest) error
    UpdateWebAuthnCredential(context.Context, WebAuthnUpdateRequest) error
    DeleteWebAuthnCredential(context.Context, WebAuthnDeleteRequest) error
}

type PublicMFAStateBackend interface {
    PublicMFAState(context.Context, PublicMFAStateRequest) (PublicMFAStateResult, error)
}
```

This mirrors the current `core.BackendManager` capabilities while avoiding `*core.AuthState` in the public API. Backends
that do not implement an optional interface simply do not advertise that capability and should not need stub methods.
Lua backend request fields such as `totp_secret`, `totp_recovery_codes`, `webauthn_credential`, and
`webauthn_old_credential` stay out of `RequestSnapshot`; native ports use the typed TOTP, recovery-code, WebAuthn, and
public MFA request structs instead.

#### Backend Order Integration

The existing `auth.backends.order` setting remains the operational place where PassDB backends are selected and ordered.
Native plugin backends should plug into that list through an explicit selector:

```yaml
auth:
  backends:
    order:
      - cache
      - plugin(customer_auth.passdb)
      - ldap(ff)

plugins:
  allowed_dirs:
    - /usr/lib/nauthilus/plugins
  modules:
    - name: customer_auth
      type: go
      path: /usr/lib/nauthilus/plugins/customer_auth.so
      config:
        datasource: customer-main
```

The value inside `plugin(...)` is the fully qualified backend component name, composed from the configured module name
and the backend name returned by the plugin:

```go
func (p *Plugin) Register(r pluginapi.Registrar) error {
    return r.RegisterBackend(&PassDB{name: "passdb"})
}

func (b *PassDB) Name() string {
    return b.name
}
```

With the module name `customer_auth`, this backend is referenced as `plugin(customer_auth.passdb)`.

There should be no separate `auth.backends.plugin` configuration subtree in v1. Plugin-owned backend configuration stays
under the module's opaque `plugins.modules[].config` block. The backend order only selects an already registered
backend. This keeps plugin configuration responsibility with the plugin author while preserving the existing backend
ordering model.

The host should reject unqualified plugin backend selectors such as `plugin(passdb)` because `auth.backends.order` has no
module-local context. It should also reject `plugin` without parentheses because there is no global default plugin
backend. If the same `.so` is configured more than once with different module names, each instance becomes addressable
through its own fully qualified backend name, for example `plugin(customer_a.passdb)` and `plugin(customer_b.passdb)`.

Validation should be split into two steps:

- syntax validation during config loading accepts the new `plugin(<module>.<backend>)` selector shape;
- reference validation runs after plugin `Register` has completed and fails startup if an ordered plugin backend was not
  registered by any loaded module.

A module marked `optional: true` can only be skipped when no required host configuration references one of its
components. An `auth.backends.order` entry for `plugin(<module>.<backend>)` makes that backend required, so a missing or
failed module must still fail startup instead of silently removing a PassDB from the configured order.

#### Long-Lived Backend Resources

Backend plugins may own long-lived resources. A SQL PassDB plugin, for example, should open a `database/sql` pool once
during module startup and reuse it for all request-time backend calls. The host must not require the plugin to open and
close external database connections per request.

```yaml
auth:
  backends:
    order:
      - cache
      - plugin(customer_sql.passdb)

plugins:
  modules:
    - name: customer_sql
      path: /usr/lib/nauthilus/plugins/customer_sql_passdb.so
      allow_capabilities:
        - credentials
      config:
        driver: mysql
        dsn_file: /etc/nauthilus/secrets/customer-sql.dsn
        max_open_connections: 50
        max_idle_connections: 10
        connection_max_lifetime: 10m
```

The recommended ownership model is:

- `Register` decodes and validates cheap configuration and registers the backend component;
- `Start` opens the SQL pool, applies pool limits, and pings the database before request-time execution is enabled;
- request-time methods such as `VerifyPassword` use `QueryContext`, `ExecContext`, or prepared statements with the
  request context passed by Nauthilus;
- `Stop` closes the pool during shutdown.

```go
type Plugin struct {
    cfg     SQLConfig
    db      *sql.DB
    backend *PassDB
}

func (p *Plugin) Register(r pluginapi.Registrar) error {
    if err := r.Config().Decode(&p.cfg); err != nil {
        return err
    }

    if err := r.RequireCapability(pluginapi.CapabilityCredentials); err != nil {
        return err
    }

    p.backend = &PassDB{plugin: p}

    return r.RegisterBackend(p.backend)
}

func (p *Plugin) Start(ctx context.Context, host pluginapi.Host) error {
    dsn, err := os.ReadFile(p.cfg.DSNFile)
    if err != nil {
        return err
    }

    db, err := sql.Open(p.cfg.Driver, strings.TrimSpace(string(dsn)))
    if err != nil {
        return err
    }

    db.SetMaxOpenConns(p.cfg.MaxOpenConnections)
    db.SetMaxIdleConns(p.cfg.MaxIdleConnections)
    db.SetConnMaxLifetime(p.cfg.ConnectionMaxLifetime)

    if err := db.PingContext(ctx); err != nil {
        _ = db.Close()

        return err
    }

    p.db = db

    return nil
}

func (p *Plugin) Stop(context.Context) error {
    if p.db == nil {
        return nil
    }

    return p.db.Close()
}
```

`*sql.DB` is already a concurrency-safe connection pool. The backend can share it across concurrent authentication
requests and across multiple components registered by the same plugin module. Separate configured module instances get
separate plugin instances and therefore separate pools by default. Plugins should avoid package-level global pools unless
they intentionally want to break instance isolation.

An `InitTask` is not required just to hold the SQL pool. Use `Start` and `Stop` for mandatory resources that request-time
backends depend on. Register an `InitTask` only for additional named startup or background work, such as schema checks,
warmup queries, cache refresh loops, or periodic health synchronization. Such tasks may use the plugin-owned pool after
`Start` has initialized it, and request-time backend execution should not begin until required init tasks have completed
successfully.

If a SQL backend supports `Reconfigure`, it should open and validate a replacement pool first, then atomically swap it
into the backend and close the previous pool. If replacement validation fails, the plugin should keep using the previous
pool and return the reconfiguration error so the host can report the failed reload.

Long-lived database credentials are plugin configuration secrets, not request credentials. The request-scoped
`CredentialProvider` is for user passwords and similar per-request secrets. For SQL DSNs, plugins should prefer secret
file references, environment integration, or another plugin-owned secret source over inline passwords in Nauthilus config,
and they should avoid logging DSNs.

#### Shared Resources Across Components

A plugin module is not limited to one extension point. The `.so` is the deployment unit, the configured module is the
runtime instance, and registered components are the host-visible roles provided by that instance. A customer SQL plugin
can therefore register a PassDB backend, a post-backend subject source, and an optional init task while sharing one
module-owned SQL pool internally.

This is the intended model for post-backend filters, now described as `SubjectSource` in the plugin API. Subject sources
run after backend execution, receive the backend result through their request value, and may enrich, remove, or derive
subject attributes. If the source belongs to the same plugin module as the backend, it can use the same plugin-owned
resources.

```go
type Plugin struct {
    cfg     SQLConfig
    db      *sql.DB
    passdb  *PassDB
    subject *SQLSubjectSource
}

func (p *Plugin) Register(r pluginapi.Registrar) error {
    if err := r.Config().Decode(&p.cfg); err != nil {
        return err
    }

    if err := r.RequireCapability(pluginapi.CapabilityCredentials); err != nil {
        return err
    }

    p.passdb = &PassDB{plugin: p}
    p.subject = &SQLSubjectSource{plugin: p}

    if err := r.RegisterBackend(p.passdb); err != nil {
        return err
    }

    return r.RegisterSubjectSource(p.subject)
}

type PassDB struct {
    plugin *Plugin
}

func (b *PassDB) VerifyPassword(ctx context.Context, req pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
    row := b.plugin.db.QueryRowContext(ctx, "...", req.Username)

    return mapSQLPasswordRow(row)
}

type SQLSubjectSource struct {
    plugin *Plugin
}

func (s *SQLSubjectSource) Evaluate(ctx context.Context, req pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
    rows, err := s.plugin.db.QueryContext(ctx, "...", req.BackendResult.Account)
    if err != nil {
        return pluginapi.SubjectResult{}, err
    }
    defer rows.Close()

    return mapSQLSubjectRows(rows)
}
```

The host should treat the registered backend and subject source as separate observable components with separate names,
metrics, traces, timeouts, and errors. Internally, they can still be small wrappers around the same plugin instance. This
keeps component behavior visible to Nauthilus while letting the plugin author manage shared resources with normal Go
composition.

Shared resources stay inside the configured plugin module. Other plugin modules should not be able to reach a module's
private SQL pool unless the plugin author explicitly uses package-level globals or an external service. This preserves
instance isolation: configuring the same `.so` twice under different module names creates two module instances and, by
default, two independent pools.

Because backend and subject source calls may run concurrently, any shared mutable plugin state must be concurrency-safe.
`*sql.DB` is safe to share; mutable caches, prepared statement registries, or reloadable configuration pointers need
appropriate locking or atomic replacement.

### Obligation Targets

Current Lua "actions" are now selected through policy obligations. The Go plugin API should use the newer terminology
directly and expose this extension point as `ObligationTarget`.

```go
type ObligationTarget interface {
    Name() string
    Execute(context.Context, ObligationRequest) (ObligationResult, error)
}
```

Obligation targets should mirror the current synchronous Lua action dispatch semantics. They are selected by the winning
policy decision and execute synchronously as request-time enforcement after the policy decision, before the request
handling path is considered complete. They should honor the request context and deadline.
`ObligationRequest` carries policy arguments as `ArgsView`; built-in Lua compatibility effects include stable `action`
and `feature` values such as `brute_force`. `ObligationRequest.Facts` carries the current validated Lua and native
plugin policy facts from the active decision context. `ObligationResult.Facts` may emit additional `auth_decision`
facts, and the runtime validates them against the active registry before recording them. These facts are recorded after
policy has selected the effect and do not let the plugin replace the policy decision.
`ObligationResult.Response` uses the same `ResponseMutation` value object as subject sources for timely header set/delete
operations. The host filters forbidden and configured secret-bearing headers, applies duplicate canonical names
deterministically, and ignores mutations when the request is not HTTP-backed or the response has already been written.
`Response.StatusHeader` may expose the selected plugin status message as `Auth-Status`; direct `Auth-Status` header
mutation is host-owned and filtered.

Asynchronous post-action enqueueing is a separate concept. The existing Lua post-action path schedules detached worker
execution, but that should not make `ObligationTarget` itself an async/sync choice in v1.

The existing Lua-facing `actions` terminology remains unchanged for compatibility, but it should not be carried into the
public Go plugin API.

### Post-Action Targets

```go
type PostActionTarget interface {
    Name() string
    Enqueue(context.Context, PostActionRequest) (PostActionEnqueueResult, error)
}
```

Post-action targets mirror the existing Lua post-action enqueue path. They are selected by policy as post-decision
effects, receive a host-built request snapshot, and enqueue detached worker execution with host-owned deadlines,
observability, panic recovery, and shutdown coordination. Post-action enqueueing is distinct from synchronous
`ObligationTarget` execution. `PostActionRequest` carries policy arguments as `ArgsView` and receives the same
decision-context facts as obligation requests. Post-action enqueue results are enqueue diagnostics only; v1 does not let
detached post-actions emit more policy facts into the selected request outcome or mutate an already-selected client
response.

### Hooks

```go
type Hook interface {
    Descriptor() HookDescriptor
    Serve(context.Context, HookRequest) (HookResponse, error)
}

type HookRequest struct {
    Snapshot RequestSnapshot
    Path     string
    Method   string
    Headers  map[string][]string
    Query    map[string][]string
    Body     []byte
}

type HookResponse struct {
    StatusCode int
    Headers    map[string][]string
    Body       []byte
}

type HookDescriptor struct {
    Name    string
    Method  string
    Path    string
    Alias   string
    Scope   HookScope
    Auth    HookAuth
    Timeout time.Duration
    MaxBodyBytes int64
}

type HookScope string
type HookAuth string

const (
    HookScopePublic   HookScope = "public"
    HookScopeInternal HookScope = "internal"
    HookScopeAdmin    HookScope = "admin"

    HookAuthNone    HookAuth = "none"
    HookAuthToken   HookAuth = "token"
    HookAuthSession HookAuth = "session"
    HookAuthAdmin   HookAuth = "admin"
)
```

Hooks are HTTP-facing and should stay separate from auth-pipeline sources. They need explicit method, path, alias, scope,
request body, response, timeout, body limit, and authorization semantics. `HookRequest.Body` is a byte slice because the
host has already enforced the hook body limit before invoking the plugin. Go plugin hooks should not receive
`*gin.Context`; the host should translate the HTTP request and response through API-level `HookRequest` and
`HookResponse` value objects. The host should enforce the declared `HookAuth`, `HookScope`, and `MaxBodyBytes` before
calling `Serve`. If `MaxBodyBytes` is zero, the host should apply the global default.
The host should filter hook response headers before writing them to the client, rejecting hop-by-hop headers and
configured denied headers such as transport or security headers owned by Nauthilus. Native hooks should return standard
library `net/http` status constants in `HookResponse.StatusCode`. Lua response helpers such as `string`, `html`, and
header setters map to returning `HookResponse{StatusCode, Headers, Body}`. For HEAD requests, the host writes status and
allowed headers but deliberately does not write `HookResponse.Body`, so HEAD behavior is deterministic even when plugin
code accidentally returns body bytes.

## Policy Integration

Plugins should register policy attributes before policy snapshots compile:

```go
type Registrar interface {
    RegisterPolicyAttribute(AttributeDefinition) error
}
```

Plugin attribute declarations should be made through `Registrar.RegisterPolicyAttribute` during registration so policy
snapshots can compile a complete registry before request handling begins. Request-time policy facts should be returned
through extension result `Facts` fields such as `EnvironmentResult.Facts`, `SubjectResult.Facts`,
`BackendResult.Facts`, `AccountListResult.Facts`, or `ObligationResult.Facts`.

Native plugin attribute names should use the `plugin.<extension>.<module_or_feature>.<fact>` convention. The helper
`pluginapi.PluginPolicyAttributeID(extension, moduleOrFeature, fact)` builds validated names such as
`plugin.environment.geoip.matched`. Lua migration attributes that already use `lua.plugin.*` may remain registered, but
new native examples should prefer `plugin.*`.

The process-scoped lifecycle host does not expose a policy facade in v1. The current Lua policy registry has a useful
safety rule: runtime emission of unknown attributes fails instead of silently creating unplanned facts. Go plugin result
facts should follow the same rule.

Decision: native Go plugins must register their policy attributes during `Register`, before policy snapshot compilation.
Returning an unknown result fact is an error and should be reported through plugin logs, metrics, and the current
extension-point result where applicable.

Policy facts are not public output by themselves. Plugins that intentionally expose a selected value in public logs
should return `LogField` values directly or build them with `pluginapi.PublicPolicyFactLogField(namespace, key, value)`,
which uses stable `policy_fact_<namespace>_<key>` keys. Request-time status text is explicit through `StatusMessage`;
post-action status describes enqueue behavior and does not mutate an already-sent response.

Check type naming should keep Lua and native plugins semantically distinct:

- Existing Lua check types stay unchanged: `lua.environment` and `lua.subject`.
- Native plugins use add-on-oriented check types such as `plugin.environment`, `plugin.subject`, and `plugin.backend`.

Rationale: Lua is already a normal Nauthilus integration surface and is likely to remain sufficient for most
deployments. Native Go plugins are more specific operational add-ons with stronger build and trust assumptions, so their
policy names should make that distinction visible.

## Lifecycle And Startup Order

Native plugins need more lifecycle precision than Lua scripts because they may start workers.

Decision: use two clear lifecycle checkpoints:

- `Register(Registrar)` declares metadata, extension points, policy attributes, and any config-dependent descriptors.
- `Start(context.Context, Host)` runs only after host services such as logging, tracing, metrics, Redis, LDAP access, and
  worker supervision are available.

Recommended lifecycle checkpoints:

- Load plugin metadata after configuration is available and logging is configured.
- Register policy attributes and extension descriptors before policy snapshot compilation.
- Start telemetry before plugin `Start` so plugin initialization can be traced.
- Call plugin `Start` before starting registered `InitTask` instances or enabling request-time extension execution. This
  lets a module initialize shared resources, such as SQL pools, that its init tasks and backend components can use.
- Start plugin init tasks only after the managed service dependencies they may use are configured and plugin `Start`
  succeeded.
- Start request-time extension execution only after workers, queues, policy snapshots, and host services are ready.
- Stop plugins during shutdown before closing host-owned clients. Shutdown should use a global plugin stop timeout with
  an optional per-module `stop_timeout` override.

Go plugin module set and binary replacement should be restart-only. Config-only changes can call `Reconfigure` on SIGHUP
if the plugin implements `ReloadablePlugin`. Adding modules, removing modules, replacing `.so` files, or changing loader
and artifact fields requires an operator process restart.

Loader and artifact fields are not reloadable. Changes to `name`, `type`, `path`, `checksum`, `signature`, `signer`, API
version, symbol name, verification policy, trust anchors, or allowed directories require a process restart. SIGUSR1
should not attempt to replace or unload Go plugin code because loaded Go plugins remain resident until process exit.

## Concurrency Rules

Plugins can use goroutines, but the API must define ownership:

- Request-time calls receive a context with deadline and cancellation.
- Plugins must return before the request deadline unless they explicitly schedule detached work through `Host.Go`.
- Host-managed goroutines are preferred because they get panic recovery and shutdown coordination.
- Long-running or service-related plugin workers should be started through `Host.Go`. Plugins may use short-lived
  internal goroutines for local implementation details, but workers that outlive a single method call need host
  supervision, shutdown coordination, logging, metrics, tracing, and panic recovery.
- Runtime context mutation should use deltas when sources run in parallel.
- Backend implementations may be called concurrently and must be thread-safe.
- Init workers must stop when the service context is canceled.

## Error And Panic Boundaries

Every host-invoked plugin method should run behind a panic boundary. The host should recover panics, convert them into
technical errors, log plugin metadata and the extension point, increment plugin error metrics, and mark the active trace
span as failed.

Startup-time failures in `Register`, `Start`, or init task startup follow the plugin `optional` setting. Runtime failures
from request-time extension points should map to the existing Nauthilus error semantics. In the auth pipeline, plugin
panics and unexpected technical errors should become temporary failures where comparable Lua or backend errors already
do so.

## Security And Operations

Go plugins are trusted in-process code. They can read process memory, access secrets passed to them, start goroutines,
panic the process if unmanaged, and call the filesystem or network.

Operational controls to consider:

- Configure an allowlisted plugin directory.
- Verify SHA-256 hashes or detached minisign/signify-style signatures for `.so` files when configured or required by
  local policy.
- Load plugins before privilege drop only if the plugin path is outside the final runtime root; otherwise prefer a
  plugin directory inside the runtime root.
- Record plugin name, version, API version, path, build Go version, checksum, signer, and verification status in logs
  and metrics.
- Recover panics around every host-invoked plugin method and convert them to technical errors.
- Treat plugin load failures as startup errors unless explicitly configured as optional.

## Plugin Artifact Verification

Nauthilus should support optional `.so` artifact verification before any plugin code is opened. Verification belongs to
the loader contract and should run before `plugin.Open`, symbol lookup, plugin metadata inspection, or `Register`.

Supported verification inputs:

- `checksum`: an optional SHA-256 digest that pins the configured plugin to one exact file.
- `signature`: an optional detached signature over the plugin artifact. The current config model accepts
  minisign/signify-style Ed25519 signatures expressed with a format prefix such as
  `minisign:/path/to/plugin.minisig`.
- `signer`: an optional key identifier or trust anchor name used to select the verification key.

Trusted signer keys should be configured globally under `plugins.trust.signers`. Plugin modules reference the expected
trust anchor through `signer`, keeping key material centralized and avoiding repeated public keys in every module entry.
Each signer should provide exactly one public key source: inline `public_key` or `public_key_file`.

Recommended loader order:

- Resolve and canonicalize the configured plugin path.
- Check that the path is inside an allowlisted plugin directory.
- Read the artifact and verify the configured checksum when present.
- Resolve the configured `signer` against `plugins.trust.signers`.
- Verify configured detached signatures against the selected trusted signer public key before `plugin.Open`.
- Apply the local verification policy.
- Open the plugin, resolve the `NauthilusPlugin` factory, create an instance for the configured module, validate
  metadata, then call `Register`.

Distribution-provided native plugins can be signed in CI and shipped with detached signatures plus trusted public keys.
Operators can enforce checksum provenance, signature provenance, or accept unsigned local plugins depending on local
policy.

Recommended verification policy modes:

- `off`: do not verify plugin artifacts. This is useful for local development and test environments.
- `when_present`: verify configured checksums and signatures when present.
- `checksum_required`: require a valid SHA-256 checksum for every configured `.so` plugin.
- `signature_required`: require a valid detached signature and trusted signer for every configured `.so` plugin.

The recommended default is `when_present`, so packaged plugins with checksums can be verified automatically while
operators can harden production deployments with `checksum_required` or `signature_required`.

## Plugin Load Failure Behavior

Plugin load failures should be controlled per plugin entry through `optional`.

- `optional: false` is the default. Any load, verification, symbol, API-version, registration, or startup failure aborts
  Nauthilus startup.
- `optional: true` converts those failures into visible operational errors while allowing Nauthilus to start without the
  affected plugin.

Optional plugins should still emit clear logs and metrics that include the plugin name, path, failure step, and error.
This makes non-critical enrichment plugins practical without weakening critical plugins such as customer-specific
backends.

## Plugin Reload Behavior

Native Go plugins may support config-only reloads through `ReloadablePlugin`.

```go
type ReloadablePlugin interface {
    Reconfigure(context.Context, ConfigView) error
}
```

Only the plugin-owned `config` block is eligible for live reconfiguration. Loader and artifact fields require restart
because Go plugin code cannot be unloaded or replaced after `plugin.Open`.

If `Reconfigure` fails, the host should keep the previous working plugin configuration and report the reload failure
through logs and metrics. Plugins that do not implement `ReloadablePlugin` continue running with their existing
configuration until process restart.

## Observability Contract

Native plugins should report metrics and traces through host-provided facades only. The public API should not expose raw
Prometheus or OpenTelemetry objects in v1.

The metrics facade should:

- Prefix or namespace metric names by plugin scope.
- Convert duplicate registration into an explicit error instead of panicking.
- Attach stable labels such as plugin name, plugin version, extension point, and result where appropriate.
- Keep high-cardinality request data out of default metric labels.

The tracing facade should:

- Start child spans from the request context passed to the plugin.
- Attach low-cardinality plugin metadata to spans.
- Let the host own tracer provider setup, exporters, sampling, and shutdown.

## Recommended Architecture

Add one internal extension registry and make both Lua and native Go plugin adapters feed it.

```text
config
  -> extension registry
       -> Lua adapter descriptors
       -> .so Go plugin descriptors
  -> policy compiler
  -> request pipeline
       -> environment sources
       -> backend managers
       -> subject sources
       -> obligation targets
```

This keeps registration, policy fact declaration, observability, and result aggregation under one host-owned extension
model. In v1, Lua and Go source sets still execute through separate adapters and graphs while sharing scheduler semantics
and deterministic merge rules inside each source family.

## Process Model

Native Go plugins should stay close to Nauthilus as trusted in-process extensions. The public API should model extension
points as local Go interfaces backed by host facades, not as a remote procedure protocol.

A gRPC companion-process model is intentionally outside the v1 scope. It would create a second extension architecture
with protobuf contracts, transport security, health checks, reconnect semantics, deployment lifecycle, and versioning
rules. Those concerns are useful when isolation is required, but they are not the goal for native Nauthilus add-ons.

## Decisions

- The public API package lives under `pluginapi/v1` at the repository root.
- Existing `lua.*` policy check types stay unchanged. Native Go plugins use `plugin.*` check types to mark them as
  specific native add-ons rather than the normal Lua integration path.
- Native Go plugins use a two-checkpoint lifecycle: `Register` for declarations and `Start` for service-backed runtime
  work.
- Nauthilus owns only loader-level configuration such as name, type, path, checksum, signature, signer, and
  optionality. Each plugin receives an opaque structured `config` block and is responsible for validating, defaulting,
  and documenting its own parameters.
- Native Go plugins use Nauthilus-owned metrics and tracing facades in v1. Raw Prometheus and OpenTelemetry objects stay
  outside the public plugin API.
- `InitTask` is a first-class registrable runtime unit for named setup or worker behavior. The host owns task startup,
  shutdown, logging scope, observability, and error reporting after service-backed runtime facilities are available.
- The initial public plugin API is an in-process Go interface contract. Nauthilus does not define a gRPC or other remote
  companion-process plugin protocol for v1.
- Native Go plugins use the newer `ObligationTarget` terminology. Existing Lua `actions` naming stays unchanged and is
  not refactored as part of this spec.
- Go `ObligationTarget` execution mirrors synchronous Lua action dispatch: selected by policy and executed synchronously
  as request-time enforcement after the policy decision. Async post-action enqueueing is a separate concept.
- Go post-action enqueueing uses a separate `PostActionTarget` extension point that mirrors the existing Lua post-action
  path and runs detached work under host supervision.
- Native Go plugins are loaded only from `.so` files. Statically linked plugin deployment and interpreted Go plugin
  loading are not part of the current or planned plugin model.
- The `.so` loader supports artifact verification with SHA-256 checksums and minisign/signify-style detached Ed25519
  signatures before `plugin.Open`.
- Signature values use a format prefix such as `minisign:/path/to/plugin.minisig`.
- Trusted public keys are configured centrally under `plugins.trust.signers`; module-level `signer` values reference
  those trust anchors. Each signer uses exactly one key source: inline `public_key` or `public_key_file`.
- `.so` paths must resolve inside one of the configured `plugins.allowed_dirs` entries before verification or
  `plugin.Open` runs.
- Plugin artifact paths are absolute only. Module `path`, detached signature file paths, and signer `public_key_file`
  paths reject relative values during validation.
- Verification strictness is controlled by a global plugin verification policy, with plugin modules supplying the actual
  checksum, signature, and signer metadata.
- Plugin load failures are startup-fatal by default. Operators can mark individual non-critical plugins with
  `optional: true` to continue startup while surfacing the failure through logs and metrics.
- Plugin shutdown uses a global stop-timeout default with an optional per-module `stop_timeout` override.
- Native Go plugins support config-only reloads only when they implement `ReloadablePlugin`. Module additions/removals,
  binary replacement, verification metadata changes, loader field changes, trust changes, allowed directory changes, and
  verification policy changes require process restart.
- SIGHUP can apply plugin-owned config-only changes through `Reconfigure`; Go plugin module additions/removals, `.so`
  replacement, loader field changes, verification changes, trust changes, and allowed directory changes require operator
  process restart. SIGUSR1 must not attempt restartless Go plugin code replacement.
- Redis access uses broad, host-owned `go-redis` handles exposed through dependency injection, with host-owned key helpers
  and named script registry behavior for prefixing, Redis Cluster hash-slot safety, and `NOSCRIPT` recovery. LDAP access
  uses Nauthilus-owned queued `Search` and `Modify` calls that wait for results without exposing raw queue or pool
  internals.
- Plugins must use host-provided or derived contexts for Redis calls. Redis connection timeout configuration remains
  centralized in Nauthilus.
- Named Redis pools are plugin-owned for now; the host does not expose Lua-style pool registration or lookup.
- `Host.Cache(scope)` exposes process-local, scope-isolated cache semantics for TTL values and list batching.
- `Host.Helpers()` exposes deterministic account tag, scoped-IP, and routable-IP helpers; dependency-light equivalents
  live under `pluginapi/v1/helpers`.
- `Host.HTTP(scope)` is the native replacement for Lua-style outbound HTTP helpers when host-managed tracing, bounded
  metrics, timeouts, response body limits, and redacted logs are required.
- `Host.ConnectionTargets(scope)` is the native replacement for psnet target registration. It is observability-only and
  does not provide raw socket management.
- LDAP plugin access is limited to API-level queued `Search` and `Modify` requests. Bind/auth operations, raw queues,
  pools, and go-ldap request structs stay outside the public plugin API.
- LDAP scopes and modify operations use v1 constants; the host rejects unknown values.
- Request snapshots never contain passwords or other secrets. Plugins can access credentials only through an explicit,
  capability-gated, request-scoped `CredentialProvider`.
- `Secret` exposes closure-based byte access only. The host should use `runtime/secret.Do` for the secret handling call
  tree when available; plugins must not retain the provided byte slice after the callback.
- Backend plugins use the same credential access model as other extension points: `BackendAuthRequest` carries a
  `CredentialProvider`, not a direct password or `Secret` field.
- The v1 `CredentialProvider` exposes only `Password(ctx)`. Additional secret kinds require future explicit
  capabilities and concrete use cases.
- `RequestSnapshot` may include an immutable copy of request headers after host redaction of authorization, cookies, and
  configured secret-bearing headers. Header names use canonical MIME header keys as in Go's `net/http` package.
- `RequestSnapshot` does not include HTTP request bodies. Request bodies are available only through `HookRequest` after
  host-side body limit enforcement.
- `HookRequest.Body` is `[]byte` in v1. Streaming is out of scope because the host enforces body limits before invoking
  plugin hooks.
- The host filters `HookResponse.Headers` before writing the HTTP response, rejecting hop-by-hop headers, auth/cookie
  headers, configured secret-bearing headers, and denied headers that Nauthilus owns. HEAD responses write status and
  allowed headers but not `HookResponse.Body`.
- Subject sources and synchronous obligations may return `ResponseMutation` values for allowed response header set/delete
  operations while the HTTP response is still mutable. Asynchronous post-actions have no response mutation surface.
- Environment and subject sources do not mutate the shared runtime context directly. They receive a read-only runtime
  view and return `RuntimeDelta` values that the host merges deterministically.
- Runtime context values are limited to JSON/CBOR-compatible data. The host validates `RuntimeDelta` values before
  merging, and plugin-specific Go objects remain in plugin instance state.
- Runtime delta conflicts use deterministic last-writer-wins semantics in descriptor order, with debug logging for
  overwritten keys.
- Native backend plugins use a small core `Backend` interface plus optional capability interfaces for TOTP, recovery
  codes, WebAuthn, and public MFA state.
- Native backend plugins are selected through the existing `auth.backends.order` list with
  `plugin(<module>.<backend>)`. Plugin-owned backend configuration stays under `plugins.modules[].config`; there is no
  separate `auth.backends.plugin` subtree in v1.
- Backend plugins may own long-lived resources such as `database/sql` pools. Mandatory resources should be initialized
  in plugin `Start`, reused by request-time backend methods, and closed in `Stop`; `InitTask` is reserved for additional
  named startup or worker behavior.
- A single configured plugin module may register a backend, subject source, init task, and other components that share
  module-owned resources such as a SQL pool. The host observes each component separately, while internal resource sharing
  remains private to that module instance.
- Backend plugin attributes use `map[string][]string`, matching existing LDAP and Lua backend result semantics. Typed
  policy data belongs in `PolicyFact` values.
- A single `.so` plugin may register multiple extension points. Each registered component must still have its own stable
  name, logging scope, metrics scope, and lifecycle status.
- Go environment and subject sources use the same dependency scheduler semantics as Lua sources, but Lua and Go source
  graphs are separate in v1; cross-family `Requires` and `After` dependencies are unsupported.
- Source descriptor dependencies resolve local names inside the registering plugin module and require fully qualified
  names for dependencies on other plugin modules.
- Native Go plugins must register policy attributes before policy snapshots compile. Runtime emission of unknown
  attributes is an error.
- `PolicyFact.Value` uses JSON/CBOR-compatible values, matching the runtime context value discipline.
- Native Go plugins may provide HTTP hooks, but hooks are separate from auth-pipeline sources and use API-level request
  and response values instead of `*gin.Context`.
- Plugin hooks declare `HookAuth` and `HookScope`; the host authorizes requests before invoking the plugin hook.
- Plugin hooks may declare `MaxBodyBytes`; the host enforces the body limit before invoking the plugin hook and falls
  back to the global default when no hook-specific limit is set.
- Every host-invoked plugin method is called behind a panic boundary. Runtime panics become technical errors and should
  map to temporary failures in auth-pipeline contexts where existing Lua or backend errors do the same.
- Long-running or Nauthilus-related plugin workers must be started through `Host.Go`. Short-lived internal goroutines are
  allowed as implementation details, but they remain the plugin maintainer's responsibility.
- Plugin metadata contains a strict `APIVersion`, feature declarations, possible capability declarations, and optional
  build diagnostics. `Registrar.RequireCapability` records the capabilities actually required by the configured module
  instance.
- Runtime discovery is derived from registered component descriptors. `Metadata.Description` and `Metadata.DocsURL` may
  provide human-facing documentation pointers, but descriptors remain the machine-readable runtime truth.
- Module configuration may set `allow_capabilities`. When present, the registrar rejects capability requests not listed
  for that module instance; when absent, host defaults apply.
- Sensitive capabilities are default-deny when `allow_capabilities` is absent. `credentials` requires explicit allowance;
  ordinary logging, metrics, and tracing facades are available without capability gates.
- `ConfigView` is a read-only, format-neutral view over the plugin-owned `config` block with dot-path helpers, exact
  segment helpers, and strict `Decode`.
- The plugin API does not provide permissive decode. Flexible plugin config should be handled explicitly through
  `ConfigView` lookup methods.
- Policy arguments for `ObligationTarget` and `PostActionTarget` use an `ArgsView` with the same read-only,
  format-neutral, strict-decode behavior as `ConfigView`. Built-in Lua action effects include stable `feature` metadata
  alongside `action`.
- Plugin configuration lives in the root-level `plugins.modules[]` section. Module `type` is optional, defaults to `go`,
  and unsupported type values are rejected.
- The configured module name is the instance namespace for all registered plugin components, while `Metadata().Name`
  identifies the plugin product or package. Module and component names are strictly validated, not normalized, and the
  host rejects fully qualified name collisions.
- The same `.so` path may be configured multiple times with different module names and configs. The exported
  `NauthilusPlugin` symbol is a factory function so each module receives a distinct plugin instance and lifecycle.
- The `NauthilusPlugin` factory receives no arguments. It constructs a plugin object only; instance config is available
  during `Register`, and host services are available during `Start`.
- Plugin results use API-level value objects for status messages, log fields, policy facts, backend results, and
  attribute patches. The host maps them to internal Nauthilus types and validates policy facts against the active
  policy registry before recording them.
- Plugin `StatusMessage` values are protocol-neutral status signals with code, optional message key, fallback text, and
  temporary/permanent classification. The host maps them to concrete protocol responses and i18n behavior.
- Plugins log through a Nauthilus `Logger` facade rather than raw `*slog.Logger`; the host attaches module, component,
  plugin metadata, request, and operational context.
- The host emits automatic plugin call/error/panic/duration metrics and exposes a namespaced duplicate-safe `Metrics`
  facade for plugin-defined counters, gauges, and histograms.
- Plugin metric labels must be declared up front in `MetricDefinition`; runtime observations cannot add unknown labels
  and should be guarded against high-cardinality values.
- The host creates automatic plugin method spans and exposes a small `Tracer` facade for plugin-created child spans
  without exposing raw OpenTelemetry providers.
- Host-managed plugin HTTP calls use `Host.HTTP(scope)` for trace propagation, bounded metrics, context deadlines,
  response body limits, and redacted logs. SMTP/LMTP mail and raw TCP/dialer behavior stay plugin-owned in v1; plugins
  own config validation, lifecycle, TLS/deadline/retry policy, metrics, traces, and redaction for those transports.

## Final v1 Follow-Up State

The current v1 implementation covers the native plugin surfaces needed for production Lua-to-Go ports without importing
`server/*` from plugin code:

- immutable request snapshots with safe transport, identity, IDP/MFA, TLS compatibility, diagnostics, and outcome
  fields populated by auth and hook adapters;
- credential-gated password access plus public `pluginapi/v1/password` helpers shared with the Lua/server password path;
- backend password and account-list adapters, custom account fields, account-list policy facts, and typed TOTP,
  recovery-code, WebAuthn, and public MFA operations;
- host-provided backend candidates plus value-only selected-backend and backend-result patching from subject sources;
- policy-selected obligations and post-actions with populated args/facts, registered fact validation, explicit public log
  conventions, status messages, and synchronous response mutation where the response is still mutable;
- host-managed Redis key/script helpers, module-local process cache, deterministic helper functions, outbound HTTP,
  bounded metrics/tracing, connection-target observability, and supervised workers;
- native hook request/response adapters for GET, HEAD, aliases, query/header/body copies, response filtering, and a
  dynamic textmap-style sample fixture.

Known v1 parity limits are intentional and documented in the developer and operator guides: extra or named Redis pools,
SMTP/LMTP mail, raw TCP/dialer behavior, SQL/Telegram/template libraries, and the Lua GeoIP bridge remain plugin-owned;
full mutable backend-result replacement, cross-family Lua/Go source dependencies, raw request bodies in snapshots,
passwords, cookies, authorization headers, raw WebAuthn credential blobs, raw `*gin.Context`, raw Prometheus
registerers, raw OpenTelemetry providers, and raw backend-server config pointers stay outside the public API.

## Implementation Plan

The implementation should be split into named delivery slices that follow the dependency chain. Each slice should be
small enough for focused review, should leave the tree in a coherent state, and should include reproducer or contract
tests for the behavior it introduces. Go test commands must use the repository-required `GOEXPERIMENT=runtimesecret`
prefix.

### Contract Baseline

Goal: create the public API surface without wiring it into request execution yet.

Deliverables:

- `pluginapi/v1` outside `server/*`, with `Plugin`, `Registrar`, `Host`, `RuntimePlugin`, `ReloadablePlugin`, metadata,
  capabilities, descriptors, result values, and error/status value types.
- Extension interfaces for `EnvironmentSource`, `SubjectSource`, `ObligationTarget`, `PostActionTarget`, `Backend`, and
  the optional backend capability interfaces.
- Request and runtime value objects: `RequestSnapshot`, `RuntimeContext`, `RuntimeDelta`, `PolicyFact`, `ArgsView`,
  `CredentialProvider`, `Secret`, `BackendResult`, and attribute patch types.
- Compile-only sample plugin code that exports `NauthilusPlugin() (pluginapi.Plugin, error)`.

Acceptance checks:

- `pluginapi/v1` has no imports from `server/*`.
- A tiny external-style plugin package can compile against `pluginapi/v1`.
- Name validation, metadata validation, and strict API version semantics are covered by focused tests.

### Config And Artifact Verification

Goal: teach Nauthilus to read plugin loader configuration and verify plugin artifacts before any Go code is opened.

Deliverables:

- Root-level `plugins` config section with `modules`, `allowed_dirs`, `verification_policy`, and `trust.signers`.
- Module fields for `name`, optional `type`, `path`, optional `checksum`, optional `signature`, optional `signer`,
  optional `optional`, optional `allow_capabilities`, optional lifecycle timeouts, and opaque `config`.
- Strict validation for module names, component selector names, absolute paths, allowed directory containment, unsupported
  module types, signer references, and verification policy values.
- SHA-256 and minisign/signify-style detached signature verification before `plugin.Open`.

Acceptance checks:

- Config tests reject relative paths, invalid names, unsupported types, missing signer references, and artifacts outside
  `plugins.allowed_dirs`.
- Verification tests cover checksum success, checksum mismatch, missing required verification, signature metadata
  validation, valid minisign/signify signatures, and invalid signature rejection.
- Plugin-owned `config` remains opaque to Nauthilus and is exposed only through `ConfigView`.

### Loader And Module Instances

Goal: load `.so` artifacts into configured module instances and run registration without enabling request-time execution.

Deliverables:

- A loader that opens the configured `.so`, resolves `NauthilusPlugin`, calls the factory once per configured module
  instance, validates `Metadata().APIVersion`, and invokes `Register`.
- Module instance state that keeps metadata, configured module name, plugin object, descriptors, capability requirements,
  lifecycle status, and registration errors.
- Startup behavior for required versus `optional: true` modules.
- Collision detection for fully qualified component names.

Acceptance checks:

- Loader tests cover missing symbol, wrong symbol type, factory error, unsupported API version, duplicate component name,
  required module failure, and optional module failure.
- If platform support for `-buildmode=plugin` is available in CI, include a tiny real `.so` loader smoke test; otherwise
  keep pure-Go loader validation through fakes and gate the real `.so` smoke test behind an explicit build tag.
- The same `.so` configured under two module names produces two module instances and distinct component namespaces.

### Registry And Lifecycle

Goal: centralize extension registration and lifecycle handling so Lua and native plugins can feed the same runtime model.

Deliverables:

- Internal extension registry that stores init tasks, environment sources, subject sources, backends, obligation targets,
  post-action targets, and hooks with fully qualified names.
- Registrar implementation with capability gating, descriptor validation, policy attribute registration, and component
  collision checks.
- Lifecycle runner for `Start`, registered `InitTask` values, request-time enablement, `Stop`, and config-only
  `Reconfigure`.
- Panic boundaries and automatic call/error/panic/duration observability around every host-invoked plugin method.

Acceptance checks:

- Registry tests cover ordering, dependency resolution, name collisions, capability rejection, and missing required
  components.
- Lifecycle tests prove that plugin `Start` runs before init tasks and before request-time components are invoked.
- Reload tests prove that `Reconfigure` failure keeps the previous working config and that loader/artifact changes
  require process restart.

### Host Facades And Runtime Values

Goal: expose useful host services without leaking internal packages or mutable request state.

Deliverables:

- `Host` implementation with logger, metrics, tracer, Redis, LDAP, config view, worker supervision, and clock/time helper
  surfaces where needed.
- `RequestSnapshot` builder with immutable request metadata and host-side header redaction.
- `RuntimeContext` and `RuntimeDelta` adapters with JSON/CBOR-compatible value validation and deterministic merge
  behavior.
- Request-scoped `CredentialProvider` and `Secret` implementation using closure-based password access.

Acceptance checks:

- Tests prove that request snapshots do not include passwords, request bodies, cookies, authorization headers, or
  configured secret-bearing headers.
- Credential tests prove that password access requires the `credentials` capability and is request-scoped.
- Runtime delta tests cover unsupported values, deterministic merge order, and conflict logging.
- Redis and LDAP facades are covered by fake-backed tests that do not require external services.

### Environment Reference Module

Goal: prove the full loader and lifecycle path with a useful but bounded reference plugin.

Deliverables:

- GeoIP/ASN `.so` example plugin with plugin-owned config, signature/checksum support in example config, MaxMind `.mmdb`
  lookup support, local ASN routing snapshot lookup, optional delegated RIR ASN registry metadata refresh,
  `InitTask` for database loading or refresh scheduling, `EnvironmentSource`, `RuntimeDelta`, `PolicyFact` emission,
  metrics, tracing, and config-only `Reconfigure`.
- Example policy snippets using `plugin.environment` attributes emitted by the reference module.
- Operational docs for building, signing, configuring, and troubleshooting the reference module.

Acceptance checks:

- The plugin can be built as `.so`, loaded from an allowed directory, and rejected when verification policy fails.
- A focused auth-request test or integration smoke test proves that the environment source emits expected facts and
  runtime context values.
- Focused tests cover `.mmdb` config selection with a fake path fixture, local ASN routing snapshot parsing,
  creation-log resolution, and delegated ASN registry parsing/enrichment.
- Reload tests prove that database path or refresh config can be reconfigured without changing the `.so` artifact.

### Backend Integration

Goal: make native plugin backends usable through the existing PassDB order model.

Deliverables:

- `auth.backends.order` parser support for `plugin(<module>.<backend>)`.
- Reference validation after plugin registration that rejects missing ordered plugin backends.
- Adapter from `pluginapi.Backend` and optional backend capability interfaces to the current internal backend manager
  contract.
- Credential provider wiring for backend password verification.
- Backend result mapping into internal `PassDBResult`, attributes, status messages, policy facts, and backend server
  references.

Acceptance checks:

- Config tests cover valid `plugin(customer.passdb)`, invalid `plugin(passdb)`, invalid bare `plugin`, missing module,
  missing backend, and optional module referenced by `auth.backends.order`.
- Backend tests prove that successful, failed, temporary-error, and panic paths map to existing auth semantics.
- Password access tests prove that backend plugins must explicitly request and be allowed the `credentials` capability.

### Subject And Effects

Goal: support post-backend enrichment and policy-selected effects through native plugin components.

Deliverables:

- `SubjectSource` adapter with backend-result input, attribute patch output, policy facts, runtime deltas, and optional
  backend server selection.
- `ObligationTarget` adapter with synchronous request-time execution after policy decision.
- `PostActionTarget` adapter for detached post-action enqueueing under host supervision.
- Policy attribute registration integration for `plugin.subject` and effect arguments through `ArgsView`.

Acceptance checks:

- Subject tests prove enrichment, attribute removal, rejection, runtime delta output, and deterministic merge behavior.
- Obligation tests prove synchronous execution order and temporary-failure mapping.
- Post-action tests prove detached execution, worker supervision, timeout handling, and panic recovery.

### Hook Integration

Goal: expose native HTTP/custom hooks without leaking `gin.Context`.

Deliverables:

- Hook registration, route binding, auth/scope enforcement, `MaxBodyBytes` handling, and `HookRequest`/`HookResponse`
  adapters.
- Host-side response header filtering for hop-by-hop headers and configured host-owned headers.
- Hook metrics, tracing, panic boundaries, and timeout handling.

Acceptance checks:

- Hook tests cover authorization, scope rejection, body limit enforcement, denied response headers, success responses,
  plugin errors, and panics.
- No hook API exposes raw `*gin.Context` or mutable internal request objects.

### Operational Hardening

Goal: make the plugin system supportable for operators and maintainers.

Deliverables:

- Runtime discovery output through `pluginloader.State.Discovery()`, derived from registered descriptors and metadata.
- Structured logs and metrics for module load, verification, registration, lifecycle, reload, request calls, errors, and
  panics.
- Clear startup and reload error messages that include module and component names.
- Build and operations documentation for `.so` plugins, API version compatibility, checksums, signature metadata,
  trusted signers, capabilities, credentials, discovery, observability, and reload/restart behavior.
- Example configs for required plugins, optional plugins, signed distribution plugins, local development, and
  backend-order plugin use.

Acceptance checks:

- Operator-facing docs explain which changes require process restart and which config-only changes can use SIGHUP.
- Metrics and logs include enough labels to identify module and component without introducing high-cardinality request
  labels.
- Host-created plugin traces use only low-cardinality module, component, extension point, method, and result attributes.
- The normal project guardrails pass before any implementation branch is considered complete.

### Suggested Delivery Order

Recommended order:

- Contract Baseline
- Config And Artifact Verification
- Loader And Module Instances
- Registry And Lifecycle
- Host Facades And Runtime Values
- Environment Reference Module
- Backend Integration
- Subject And Effects
- Hook Integration
- Operational Hardening

The first externally useful result should be the GeoIP/ASN reference module because it proves loader, verification,
config, lifecycle, worker behavior, policy facts, runtime deltas, metrics, tracing, and reload without requiring password
or MFA semantics. Backend and subject integration should follow once the loader, registry, lifecycle, and host facades
are stable.
