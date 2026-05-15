# OpenAPI Client Boundary

This package is the supported production boundary around selected generated
OpenAPI clients. The generated packages remain the source for request and
response DTOs, while this package keeps authentication and supported operation
selection explicit.

## Supported Surface

Management API:

- `NewManagementClient`
- `ManagementClient.GetOpenAPIYAML`
- `ManagementClient.GetOpenAPIJSON`
- `ManagementClient.ListBruteForceEntries`
- `ManagementClient.ListFilteredBruteForceEntries`
- `ManagementClient.FlushBruteForceRule`
- `ManagementClient.EnqueueBruteForceRuleFlush`
- `ManagementClient.FlushUserCache`
- `ManagementClient.EnqueueUserCacheFlush`
- `ManagementClient.GetAsyncJobStatus`
- `ManagementClient.LoadRuntimeConfig`
- `ManagementClient.ListOIDCSessions`
- `ManagementClient.DeleteOIDCSessions`
- `ManagementClient.DeleteOIDCSession`
- `BearerToken`
- `BasicCredentials`

IdP public discovery API:

- `NewIDPDiscoveryClient`
- `IDPDiscoveryClient.GetPublicOpenAPIJSON`
- `IDPDiscoveryClient.GetPublicOpenAPIYAML`
- `IDPDiscoveryClient.GetOIDCDiscovery`
- `IDPDiscoveryClient.GetOIDCJWKS`
- `IDPDiscoveryClient.GetSAMLMetadata`

The management client boundary requires backchannel authentication. Use
`BearerToken` for `Authorization: Bearer ...` or `BasicCredentials` for
`Authorization: Basic ...`. The request and response values stay generated
types from `server/openapi/generated/management`.

Document-style downloads such as OpenAPI YAML and SAML metadata intentionally
return raw `*http.Response` values from the generated client. JSON management
and discovery workflows return generated response wrappers.

## Intentional Exclusions

The following surfaces remain outside this supported generated-client boundary:

- CBOR authentication
- Header authentication
- NGINX `auth_http` authentication
- OIDC token exchange
- Browser login and MFA flows
- SAML SSO/SLO protocol flows
- WebAuthn

Those flows require protocol-realistic clients and tests. They must not be
replaced by generated clients unless the contract tooling can model the
protocol behavior without weakening coverage.

## Regeneration And Validation

Generated code is committed and regenerated only through the central server
workflow:

```sh
make generate-openapi-bindings
```

Check drift with:

```sh
make generate-openapi-bindings-check
```

Run focused client checks with:

```sh
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/openapi/client ./server/openapi/generated/management ./server/openapi/generated/idp
```

The full server gate is:

```sh
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
```
