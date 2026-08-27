---
name: nauthilus-api-contracts
description: Use for Nauthilus OpenAPI, generated management or IdP clients, route contract tests, gRPC protobuf generation, HTTP route registration, management API authentication, public discovery API, `server/openapi`, `server/router`, `server/grpcapi`, `server/grpcclient`, and API-boundary client work.
---

# Nauthilus API Contracts

## Expertise Lens

- Work as a contract-first API and protocol-boundary engineer.
- Treat OpenAPI specs, generated bindings, gRPC protobufs, route registration, and supported client wrappers as public compatibility surfaces.
- Optimize for reproducible generation, route-contract truth, explicit authentication, and separation between generated DTOs and protocol-realistic flows.

## Sources To Read

- `AGENTS.md`
- `POLICY.md`
- `server/openapi/client/README.md`
- `server/openapi/openapi.yaml`
- `server/openapi/idp.yaml`
- `server/openapi/oapi-management-bindings.yaml`
- `server/router/`
- `server/grpcapi/`
- `server/grpcclient/`

## Contract Rules

- Keep generated code committed and generated through central Makefile/script workflows.
- Use `make generate-openapi-bindings` and `make generate-openapi-bindings-check`.
- Use `make generate-grpc-proto` for gRPC bindings.
- Keep route contract tests aligned with the actual Gin route registration.
- Keep management API backchannel auth explicit.
- Keep IdP discovery API public surfaces separate from browser login, MFA, OIDC token exchange, SAML SSO/SLO, CBOR auth, header auth, and NGINX `auth_http` flows.
- Do not replace protocol-realistic client/test behavior with generated clients when the generator cannot model the protocol safely.

## Implementation Workflow

1. Identify whether the change is public API, generated client boundary, route registration, or internal handler behavior.
2. Update specs before generated artifacts when the public contract changes.
3. Regenerate through Makefile/script targets.
4. Update route-contract tests for intentional route additions or exclusions.
5. Keep supported client wrappers explicit in `server/openapi/client`.

## Validation

- Run `make generate-openapi-bindings-check` when OpenAPI or generated clients are in scope.
- Run focused route/OpenAPI/client tests with `GOEXPERIMENT=runtimesecret`.
- Run `GOEXPERIMENT=runtimesecret make test` and `git diff --check`.
- Run `make guardrails` before commit or pull request.
