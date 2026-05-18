# OpenAPI IdP Client

This package contains a narrow generated Go client for public IdP OpenAPI
surfaces where generated code adds contract confidence without replacing
protocol-specific test clients. The source contract is `server/openapi/idp.yaml`,
and generation is limited by `server/openapi/oapi-idp-client.yaml` to public
OpenAPI export, OIDC discovery, JWKS, and SAML metadata endpoints.

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

The project keeps the generator as a vendored tool dependency. Token exchange,
browser login, SAML SSO/SLO, and WebAuthn flows stay covered by manually
crafted clients and focused tests because those flows need protocol-realistic
behavior.

## Regenerating

From the repository root:

```sh
make generate-openapi-bindings
```

The package-local `go:generate` directive is equivalent:

```sh
go generate ./server/openapi/generated/idp
```

Check that committed generated files are in sync:

```sh
make generate-openapi-bindings-check
```

After regenerating, run:

```sh
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/openapi ./server/openapi/generated/idp
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
```
