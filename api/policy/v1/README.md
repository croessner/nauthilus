# Policy gRPC API v1

This directory owns the public unary Policy gRPC API.

`PolicyDecisionService.Evaluate` is the only RPC. Generated Go bindings are
committed and are produced exclusively through `make generate-grpc-proto`.

## Authentication And Resource Contract

Policy Bearer authentication is resource-specific. The validated token must
have a normalized audience set exactly equal to `{nauthilus:policy}`, include
`nauthilus:policy_evaluate`, and contain one issuer-validated, issuer-owned
`client_id` admitted by the configured Policy client profile. An explicit
request for sanitized diagnostics additionally requires
`nauthilus:policy_diagnostics` and profile permission. Missing or ambiguous
`client_id` is an authentication failure; the service never substitutes `sub`,
`azp`, or `iss` as the service-client identity.

Tokens for `nauthilus:backchannel` are rejected by this service, and Policy
tokens are rejected by existing authentication, identity, management, and MFA
backchannel services. Nauthilus classifies client-credentials scope families
before persistence: Policy-only requests receive the exact single audience
`nauthilus:policy`, backchannel-only requests retain the exact single audience
`nauthilus:backchannel`, and a mixed request fails with `invalid_scope` without
writing token, session, or flow state. Filtering may not remove or replace an
explicitly requested resource family; such a request also fails before
issuance. Backchannel admission requires the issuer-owned non-empty `client_id`
emitted for service tokens, preventing browser-token audience collisions. A
client that needs both resources uses
two independently issued, cached, and rotated tokens. External issuers must
provide the same separation.

Policy-Basic, when enabled for an exact client profile, is a separate
credential family with no OAuth scope and no management-Basic fallback. It is
accepted only over the Policy transport's protected-transport boundary.

Audience and caller identity are authenticated transport properties, not
fields controlled by `DecisionRequest`. The unary adapter supplies admitted
caller and transport facts to the shared Decision Service; the protobuf
contract exposes neither multi-resource token selection nor a bypass around
application-level admission.

The top-level `policy` configuration, caller authenticator, admission catalog,
and runtime generation are published atomically. HTTP and gRPC adapters use the
same active Decision Service and cannot fall back to another policy authority.
