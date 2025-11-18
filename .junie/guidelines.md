Nauthilus development guidelines (project-specific)

This document captures practical, project-specific details to build, configure, test, and extend Nauthilus efficiently. It assumes familiarity with Go, Make, Docker, Redis, OIDC, and typical testing patterns.

1. Build and configuration

- Toolchain and modules
  - Go version: the module sets go 1.25 (see go.mod). Use a recent Go 1.25 toolchain.
  - Vendor mode: the Makefile builds with -mod=vendor. Keep vendor/ in sync (go mod vendor) when updating deps.
- Makefile targets (preferred workflow)
  - make build: builds server binary to nauthilus/bin/nauthilus with trimpath and ldflags that set main.version and main.buildTime.
  - make test: runs unit tests in short mode across all packages (excludes vendor).
  - make race: runs tests with -race in short mode.
  - make msan: runs tests with -msan in short mode (requires platform support).
  - make install|uninstall: manages /usr/local/sbin/nauthilus and systemd unit.
- Direct build (without Make)
  - go build -mod=vendor -trimpath -v -ldflags "-X main.buildTime=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -X main.version=$(git describe --tags --abbrev=0)-$(git rev-parse --short HEAD)" -o nauthilus/bin/nauthilus ./server
- Runtime configuration
  - Server entrypoint: ./server is a main package (server/main.go).
  - Client entrypoint: ./client is a main package (client/main.go).
  - Flags (parsed in server.go):
    - -version: print version and exit.
    - -config <path>: path to the configuration file. If set, server validates file existence.
    - -config-format <yaml|json|toml|...>: viper config type, default yaml.
  - The config package exposes config.ConfigFilePath and getters to read the loaded configuration. Viper is used under the hood; you can use YAML (default), JSON, TOML, etc.
  - Insights and profiles: block profiling can be toggled via configuration (see config.GetFile().GetServer().GetInsights()).
  - Redis: client initialization is centralized in server/rediscli; for unit tests we rely on redismock, see Testing section.

2. Testing

- Running tests
  - Repository-wide unit tests (short):
    - make test or go test -short ./...
  - With the race detector:
    - make race or go test -race -short ./...
  - With MSAN (platform-dependent):
    - make msan or go test -msan -short ./...
  - Package-scoped runs (useful while iterating):
    - go test -v ./server/util
    - go test -run <Regex> ./server/lualib/redislib
- External dependencies and isolation
  - Redis is mocked using github.com/go-redis/redismock/v9 in unit tests. Avoid hitting real Redis in unit tests; prefer rediscli.NewTestClient(...) with a redismock client when the code path touches Redis.
  - Lua: Lua-related tests use github.com/yuin/gopher-lua and preload modules via lualib.LoaderModX. Keep tests hermetic by constructing an L state and PreloadModule calls. Example: L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(ctx)).
  - HTTP and Gin: tests use httptest/httptest.ResponseRecorder where applicable. Prefer JSON-iter used in the project if encoding/decoding is under test.
- Golden and table-driven tests
  - The codebase uses table-driven tests extensively and a few golden comparisons (e.g., response JSON). Keep JSON iteration deterministic; when tests fail due to ordering, use maps with stable encoding or compare unmarshaled structures.
- Adding a new test
  - Place _test.go alongside the code under test, using the same package unless you deliberately want black-box tests (package <pkg>_test).
  - Use testify (github.com/stretchr/testify) as imported in go.mod if you prefer its assertions; the repository also uses the standard library testing package widely.
  - For code touching Redis:
    - db, mock := redismock.NewClientMock()
    - rediscli.NewTestClient(db) // inject mock client used by redislib/handlers
    - Define mock.Expect... calls; ensure mock.ExpectationsWereMet() passes (often implicitly verified by test termination; explicitly check if needed).
  - For Lua-facing code:
    - L := lua.NewState(); defer L.Close()
    - L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(ctx)) and similar module preloaders
    - L.DoString(...) or load compiled Lua chunks; read results via L.GetGlobal("var").
  - Keep tests short and environment-agnostic. Place long/integration tests behind build tags or separate make targets if needed.
- Example: minimal test (pattern)
  - Create server/util/example_test.go with:
    - package util
    - import "testing"
    - func TestExample(t *testing.T) { if 2+2 != 4 { t.Fatal("broken math") } }
  - Run it with: go test -run TestExample ./server/util -v

We verified this flow by temporarily adding a trivial test under server/util and running it with go test; the file is removed per task policy after verification.

3. Additional development information

- Language for comments and docs
  - Write all code comments and public Go doc comments in English only. This includes inline // ..., block /* ... */, and doc comments above declarations, as well as Lua -- comments and YAML/TOML # comments. User‑facing messages may be localized; internal comments must remain English.
  - Prefer English for commit messages and PR descriptions as well, to keep the history consistent.
- Code style and layout
  - Standard Go formatting via gofmt/goimports; keep imports grouped and minimal. The repo favors standard testing and explicit error checks.
  - Logging: the server uses a custom log package with levels (server/log and server/log/level), plus slog/jsoniter integrations. Prefer level.Debug/Info/Warn/Error wrappers to keep logs structured. For bridging standard log to slog, server uses a custom writer (see server.go).
  - JSON: json-iterator (ConfigFastest) is used for performance-sensitive JSON encoding/decoding.
  - Vendoring: updates to dependencies must be vendored (go mod tidy && go mod vendor) so Makefile builds are reproducible.
- Profiles and observability
  - Block profiling is toggled via the configuration (insights). When enabled, runtime.SetBlockProfileRate(1) is applied. Ensure pprof endpoints or collection are configured if you need to consume profiles.
  - Prometheus metrics are used; instance info metric is labeled with instance name and version (stats.GetMetrics().GetInstanceInfo()).
- Configuration patterns
  - Viper drives configuration loading. -config and -config-format flags steer source and format. Many features are optional (RBLs, brute force, OAuth2, LDAP). Use config.GetFile().<Feature>() getters rather than accessing raw Viper state.
  - Lua initialization: if configured, init scripts are loaded via hook.RunLuaInit for each path found in the config file.
- Testing tips specific to this repo
  - When adding code that depends on Redis, prefer writing the logic against an interface and redirect rediscli.GetClient() calls to test clients via rediscli.NewTestClient.
  - For Lua bridges, ensure module names match definitions (definitions.LuaModXYZ). Preload all modules you call from Lua in tests; otherwise DoString will fail.
  - Some packages do not have tests (handlers, router); create tests at the boundary with httptest and fake config states.
- CI expectations
  - The repository includes a GitHub Actions workflow for stable builds. Aim for `go test -short ./...` to pass without external services.

4. Quick commands reference

- Build: make build
- Test (short): make test or go test -short ./...
- Test (race): make race
- Per-package: go test -v ./server/lualib/redislib
- Single test: go test -run TestName ./server/util -v

If you modify dependencies or add new modules, run go mod tidy && go mod vendor and ensure make build still succeeds.
