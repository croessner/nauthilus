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
- `ManagementClient.ListOIDCSessions`
- `ManagementClient.DeleteOIDCSessions`
- `ManagementClient.DeleteOIDCSession`
- `BearerToken`
- `BasicCredentials`

Policy API:

- `NewPolicyClient`
- `PolicyClient.Evaluate`
- `PolicyBearerToken`
- `PolicyBasicCredentials`

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

The Policy client is a separate boundary. Its `PolicyAuth` type is deliberately
not assignable to `BackchannelAuth`; Policy Bearer tokens and Policy-Basic
credentials are accepted only by `/api/v1/policy/decisions` and must never be
used to imply management/backchannel access.

## Exact Resource Authentication

`BearerToken` is for the management/backchannel resource and requires an access
token whose exact single audience is `nauthilus:backchannel` plus the issuer-owned
non-empty `client_id` emitted for service tokens. A browser access token cannot
qualify by using a colliding client audience. `PolicyBearerToken`
is for the Policy resource and requires all of the following:

- the normalized audience set is exactly `{nauthilus:policy}`;
- `nauthilus:policy_evaluate` is present;
- `nauthilus:policy_diagnostics` is also present when sanitized diagnostics are
  explicitly requested; and
- the token contains one issuer-validated, issuer-owned `client_id` that matches
  an admitted Policy client profile.

Policy authentication never substitutes `sub`, `azp`, or `iss` for a missing
or ambiguous `client_id`. Policy endpoints reject backchannel tokens, and
management/backchannel endpoints reject Policy tokens. The constructors do not
rewrite scopes or infer an audience; they preserve the caller's explicit token
choice.

For Nauthilus-issued client-credentials tokens, scope families are classified
before persistence. A request containing one or both Policy-family scopes
(`nauthilus:policy_evaluate`, `nauthilus:policy_diagnostics`) and no backchannel
scope receives `aud=nauthilus:policy`. A request with no Policy scope, including
an empty request or one containing only existing non-Policy service scopes,
receives `aud=nauthilus:backchannel`. Mixing either Policy scope with a
backchannel scope fails with `invalid_scope` and writes no token, session, or
flow state. If client filtering would remove or replace an explicitly requested
resource family, the request also fails with `invalid_scope` before issuance.
A client that calls both resources must obtain, cache, and rotate
two independent tokens. External issuers must preserve the same exact resource
separation.

`PolicyBasicCredentials` is also distinct from management Basic credentials.
Policy-Basic has no OAuth scope and receives authority only from its exact
enabled Policy client profile over a protected transport. The supported client
boundary reaches the active top-level `policy` generation used by the gRPC
adapter and the internal authentication applications; there is no secondary
Policy catalog or authentication fallback.

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
