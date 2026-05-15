# OpenAPI Management Bindings

This package contains generated Go model and client bindings for selected
management OpenAPI operations. The source contract is
`server/openapi/openapi.yaml`, and generation is limited by
`server/openapi/oapi-management-bindings.yaml` to OpenAPI export, async, cache,
brute-force, runtime config, and OIDC session administration endpoint tags.

The production-supported boundary for downstream callers is
`server/openapi/client`. Use this generated package for the DTOs and generated
response wrappers that boundary exposes.

The generated files are committed so normal builds do not require generator
access at compile time.

## Generator

This package is generated with:

```sh
github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen v2.7.0
```

The project keeps the generator as a vendored tool dependency. `oapi-codegen`
v2.7.0 warns that OpenAPI 3.1 support is not complete, so generation stays
narrow and is guarded by adapter, smoke, and supported-boundary tests. Gin route
registration, runtime request validation, and special protocol clients stay
hand-owned by Nauthilus.

## Regenerating

From the repository root:

```sh
make generate-openapi-bindings
```

The package-local `go:generate` directive is equivalent:

```sh
go generate ./server/openapi/generated/management
```

Check that committed generated files are in sync:

```sh
make generate-openapi-bindings-check
```

After regenerating, run:

```sh
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/openapi ./server/openapi/client ./server/openapi/generated/management ./server/handler/cache ./server/handler/bruteforce
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
```
