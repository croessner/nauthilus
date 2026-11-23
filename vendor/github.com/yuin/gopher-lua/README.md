# gopher-lua-jit

> **Thank you, Yusuke Inuzuka.** This project stands on
> [GopherLua](https://github.com/yuin/gopher-lua), created by Yusuke Inuzuka
> and maintained for many years together with its contributors. The virtual
> machine design, the Go API and most of the Lua 5.1 implementation here are
> their work; everything in this repository is an extension of it.

[![CI](https://github.com/croessner/gopher-lua-jit/actions/workflows/ci.yml/badge.svg)](https://github.com/croessner/gopher-lua-jit/actions/workflows/ci.yml)


A Lua runtime for Go, derived from [GopherLua](https://github.com/yuin/gopher-lua),
with two additions:

- a **Lua 5.5 language profile** (integers, bitwise operators, `goto`, `<const>`/`<close>`,
  `global` declarations, `_ENV`, the Lua 5.5 standard library) next to the original,
  GopherLua compatible Lua 5.1 profile, and
- an optional **native JIT compiler** for hot loops, written in Go and Go assembly,
  for amd64 and arm64 on Linux and macOS. No cgo anywhere.

The Go API of GopherLua is preserved. The module keeps the import path
`github.com/yuin/gopher-lua`, so existing code and libraries built on GopherLua
work by adding a `replace` directive.

> Status: the interpreter and both language profiles are covered by the upstream
> test-suite plus a conformance suite checked against the reference `lua5.5`
> interpreter. The JIT is verified by differential tests against the interpreter
> on linux/amd64, linux/arm64, darwin/amd64 and darwin/arm64 (all four run in
> CI on every push). See [Compatibility](docs/compatibility.md) for the exact
> list of what is and is not implemented.

## Installation

The module keeps GopherLua's import path, so it is used through a `replace`
directive in the `go.mod` of your program:

```bash
go mod edit -replace github.com/yuin/gopher-lua=github.com/croessner/gopher-lua-jit@v0.1.0
go mod tidy
```

which results in

```go
// go.mod
require github.com/yuin/gopher-lua v1.1.2

replace github.com/yuin/gopher-lua => github.com/croessner/gopher-lua-jit <version>
```

or, for a local checkout:

```
replace github.com/yuin/gopher-lua => ../gopher-lua-jit
```

Requirements: Go 1.23 or newer. No C toolchain, no cgo, no dependencies.

## Quick start

```go
import lua "github.com/yuin/gopher-lua"

L := lua.NewState(lua.Options{
    LanguageVersion: lua.Lua55,                       // default: lua.Lua51
    JIT:             lua.JITOptions{Enabled: true},   // default: interpreter only
})
defer L.Close()

if err := L.DoString(`
    local sum <const> = (function()
        local s = 0
        for i = 1, 10000000 do s = s + i % 7 end
        return s
    end)()
    print(sum, math.type(sum), 7 // 2, 1 << 10)
`); err != nil {
    panic(err)
}
fmt.Println(L.JITStats())
```

`lua.NewState()` without options behaves exactly like upstream GopherLua
(Lua 5.1 profile, no JIT).

More: [examples/basic](examples/basic), [examples/jit](examples/jit),
[examples/pool](examples/pool).

## What you get

| | Lua 5.1 profile (default) | Lua 5.5 profile |
|---|---|---|
| GopherLua Go API | unchanged | unchanged, plus `lua.LInteger` |
| Numbers | `float64` only | 64-bit integers and floats |
| Language | Lua 5.1 + `goto` (as upstream) | Lua 5.5 |
| Standard library | as upstream | Lua 5.5 (`utf8`, `string.pack`, `table.move`, …) |
| JIT | optional | optional |

| Platform | Interpreter | JIT | Tested |
|---|---|---|---|
| linux/amd64 | yes | yes | CI |
| linux/arm64 | yes | yes | CI (arm64 hardware) |
| darwin/arm64 | yes | yes | CI (Apple Silicon) |
| darwin/amd64 | yes | yes | CI and the development machine |
| windows/amd64 | yes | falls back to the interpreter | CI (interpreter) |
| everything else | yes | falls back to the interpreter | cross-compiled only |

Speed, on the benchmark kernels in [`benchmarks/`](benchmarks) (details and
methodology in [docs/benchmarks.md](docs/benchmarks.md)):

- the interpreter is on par with upstream GopherLua (it is the same design),
- the JIT speeds up numeric and array loops by one to two orders of magnitude,
- code dominated by function calls, string operations, hash-table field access
  or metamethods is **not** accelerated by the JIT and runs at interpreter speed.

## Documentation

- [docs/architecture.md](docs/architecture.md) – how the runtime and the JIT work
- [docs/jit.md](docs/jit.md) – JIT configuration, diagnostics, safety model, limits
- [docs/compatibility.md](docs/compatibility.md) – GopherLua API compatibility,
  Lua 5.5 conformance report, known deviations and unsupported features
- [docs/migration.md](docs/migration.md) – moving from GopherLua
- [docs/benchmarks.md](docs/benchmarks.md) – methodology and results
- [docs/gopher-lua-README.md](docs/gopher-lua-README.md) – the original GopherLua
  README (API guide; everything in it still applies)

## Building and testing

```bash
make build            # regenerate inlined sources and build
make test             # all tests
make test-race        # with the race detector
make test-linux-amd64 # the suite on linux/amd64 through Docker
make test-linux-arm64 # the suite on linux/arm64 through Docker (short mode)
make bench            # benchmarks of this runtime
make bench-upstream   # the same benchmarks on upstream GopherLua v1.1.2
make bench-external   # the same kernels on lua5.5 / luajit, if installed
make fuzz             # differential fuzzing interpreter vs JIT
```

The command line interpreter lives in `cmd/glua`:

```bash
go run ./cmd/glua -lua 5.5 -jit -jitstats script.lua
```

## License

MIT, like GopherLua. Copyright (c) 2015 Yusuke Inuzuka and contributors of
GopherLua; modifications copyright (c) their respective authors. See
[LICENSE](LICENSE).
