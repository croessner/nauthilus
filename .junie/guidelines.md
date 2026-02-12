Nauthilus development guidelines (project-specific)

This document captures practical, project-specific details to build, configure, test, and extend Nauthilus efficiently. It assumes familiarity with Go, Make, Docker, Redis, OIDC, and typical testing patterns.

1. Build and configuration

- Toolchain and modules
  - Go version: the module sets go 1.25 (see go.mod). Use a recent Go 1.25 toolchain.
  - Vendor mode: the Makefile builds with -mod=vendor. Keep vendor/ in sync (go mod vendor) when updating deps.
- Makefile targets (preferred workflow)
  - make build: builds server binary to nauthilus/bin/nauthilus with trimpath and ldflags that set main.version and main.buildTime.
  - make build-client: builds client binary to nauthilus/bin/nauthilus-client with trimpath.
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
- Linting and whitespace (mandatory)
  - Keep code readable — no “pressed” code. The following whitespace/cuddling rules are mandatory and should be enforced locally (see golangci-lint snippet below):
    - Do not cuddle declarations with control flow: put a blank line between a block of variable/constant declarations and a following if/for/switch/select.
    - After a closing if/for/switch block, insert a blank line before unrelated code. Exception: else/else if belongs directly after the closing brace of the same if.
    - Keep at most one blank line between logical blocks; avoid multiple consecutive empty lines.
    - Example (good):
      
      // local declarations
      v := compute()
      n := len(v)
      
      if n == 0 {
          return nil
      }
      
      doSomething(v)
      
    - Example (bad – declarations cuddled to if, missing blank line after if):
      
      v := compute()
      n := len(v)
      if n == 0 {
          return nil
      }
      doSomething(v)
      
  - Run a linter locally before pushing. Recommended baseline: golangci-lint with wsl (whitespace), funlen (function size), gocyclo (complexity), dupl/goconst (duplication), revive/govet (general quality), errcheck.
  - Optional golangci-lint configuration (add a .golangci.yml at repo root):
    
    linters:
      enable:
        - wsl         # whitespace/cuddling rules
        - funlen      # maximum function length
        - gocyclo     # cyclomatic complexity
        - dupl        # duplicate code blocks
        - goconst     # duplicate literals/consts
        - revive      # general lint rules (successor of golint)
        - govet       # vet checks
        - errcheck    # error handling
    linters-settings:
      wsl:
        allow-assign-and-anything: false
        allow-cuddle-declarations: false   # force a blank line before control flow after declarations
        allow-cuddle-return-with-block: false
        allow-trailing-comment: true
      funlen:
        lines: 60         # soft cap; refactor above this
        statements: 40
      gocyclo:
        min-complexity: 12
      dupl:
        threshold: 75
      goconst:
        min-occurrences: 2
        min-lines: 2
- Code style and layout
  - Standard Go formatting via gofmt/goimports; keep imports grouped and minimal. The repo favors standard testing and explicit error checks.
  - Logging: the server uses a custom log package with levels (server/log and server/log/level), plus slog/jsoniter integrations. Prefer level.Debug/Info/Warn/Error wrappers to keep logs structured. For bridging standard log to slog, server uses a custom writer (see server.go).
  - JSON: json-iterator (ConfigFastest) is used for performance-sensitive JSON encoding/decoding.
  - Vendoring: updates to dependencies must be vendored (go mod tidy && go mod vendor) so Makefile builds are reproducible.
- Design preferences (OO, small and DRY) — MANDATORY
    - The DRY (Don't Repeat Yourself) principle is a **hard requirement** for every change in this project. Duplicated
      logic, repeated code blocks, and copy-paste patterns are not acceptable. Every piece of knowledge or logic must
      have a single, authoritative representation in the codebase.
        - Before writing new code, check whether similar logic already exists. If it does, refactor it into a shared
          helper, method, or package and reuse it.
        - Extract common code into private helpers, utility functions, or shared packages rather than duplicating it
          across call sites.
        - Promote repeated string literals and magic numbers into named constants (use `goconst` linter to detect
          violations).
        - In tests, use table-driven test patterns to consolidate similar test flows instead of duplicating test logic.
        - When duplicated or copy-paste code is discovered during any task (even if unrelated to the current issue), *
          *report it to the user** and ask whether it should be cleaned up as a follow-up. Do not silently ignore DRY
          violations.
    - Prefer an object-oriented, clean architecture style:
        - Use small, focused types with methods. Each type should have a single, clear responsibility.
        - Define narrow interfaces at package boundaries (e.g., storage, Redis, HTTP clients) and inject them where
          needed for testability and loose coupling.
        - Apply composition over inheritance — embed smaller types or use interfaces to compose behavior.
        - Encapsulate implementation details; expose only what is needed through exported methods and interfaces.
        - When a function or method grows beyond its responsibility, split it into smaller, well-named helpers or
          refactor it into a dedicated type with methods.
  - Keep functions short and focused. As a guideline, aim for fewer than ~60 lines and low cyclomatic complexity; split into helpers or methods when a function grows, or when multiple responsibilities appear.
  - Favor early returns to keep indentation shallow; prefer explicit error handling over deeply nested branches.
- Memory and Performance optimization (Structs)
  - Optimize structs for padding by ordering fields from largest to smallest to minimize memory overhead.
  - Keep structs GC PtrData-friendly: group pointer-containing fields (pointers, slices, maps, channels, interfaces)
    together (preferably at the beginning) to reduce the PtrData area that the garbage collector needs to scan.
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

- Build server: make build
- Build client: make build-client
- Test (short): make test or go test -short ./...
- Test (race): make race
- Per-package: go test -v ./server/lualib/redislib
- Single test: go test -run TestName ./server/util -v

If you modify dependencies or add new modules, run go mod tidy && go mod vendor and ensure make build still succeeds.
