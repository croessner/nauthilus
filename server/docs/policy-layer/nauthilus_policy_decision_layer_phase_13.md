# Nauthilus Policy Decision Layer - Phase 13

## Goal

Phase 13 extends custom policy enforcement to the non-password operations:

- `lookup_identity` for HTTP no-auth, gRPC `LookupIdentity`, and IdP lookup-style backend reads.
- `list_accounts` for HTTP list-accounts and gRPC `ListAccounts`.

The implementation keeps caller authentication and transport authorization outside policy denial semantics. It also keeps the account list itself as response data, not as a policy attribute.

## Implemented Files and Modules

- `server/core/auth.go`
  - Added account-listing policy finalization after account-provider collection.
  - Evaluates configured `auth_decision` policies for `list_accounts`.
  - Applies configured deny/tempfail decisions through the existing policy enforcement boundary.
  - Keeps permit decisions on the existing account-list success renderer.

- `server/core/rest.go`
  - Stops the HTTP list-accounts success renderer when policy enforcement already wrote a response.

- `server/core/auth_application_service.go`
  - Extended `ListAccountsOutcome` with decision, status message, error, and HTTP status metadata.
  - Returns configured list-account denial/tempfail outcomes without turning them into caller-auth errors.

- `server/handler/grpcauth/handler.go`
  - Keeps gRPC `ListAccounts` policy denials as successful RPCs.
  - Renders denial metadata through `auth-status`, `auth-error`, and `x-nauthilus-session` response metadata.

- `server/core/policy_nonpassword_authority_test.go`
  - Added focused non-password policy authority tests for lookup and list-account enforcement.
  - Verifies IdP no-auth lookup uses the `lookup_identity` operation and IdP browser response surface.
  - Verifies account-provider status attributes and that account-list payloads are not exposed as policy attributes.

- `server/handler/grpcauth/server_test.go`
  - Added gRPC ListAccounts response-surface coverage for policy denial metadata.

## Tests and Validation

- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryConfigured(LookupDecision|IDPLookup|ListAccountsDecision)|TestAuthApplicationServiceListAccountsReturnsConfiguredDenialOutcome' ./server/core`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestBufconnAuthServiceListAccounts(Success|PolicyDenialUsesResponseMetadata)' ./server/handler/grpcauth`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/handler/grpcauth`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/...`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails`

## Active Temporary Adapters

- Target FSM markers are still applied through the existing auth-state FSM marker bridge. This is inherited migration scaffolding and remains until the final target FSM cleanup.
- gRPC `ListAccounts` policy denials are rendered through response metadata because the current proto response carries only account data and session. This keeps policy denial distinct from caller-auth or transport errors without changing the protobuf contract in this slice.
- The account-listing HTTP renderer still uses the existing auth response writer for deny/tempfail decisions.

## Planned Adapter Removal

- The FSM marker bridge is removed when the target FSM is the only production FSM path.
- The gRPC ListAccounts metadata bridge should be revisited when the response marker registry and gRPC ListAccounts response profile become the only rendering authority. If the protobuf contract is extended later, policy denial details can move from metadata into the typed response payload.
- The HTTP auth response-writer bridge for account-listing denials is removed when policy response profiles render HTTP list-account decisions directly.

## Open Risks and Deliberately Not Implemented

- No new public config surface was added in this phase.
- No compiler, registry, or snapshot authority changes were combined into this phase.
- No proto contract change was made for gRPC `ListAccounts`; denial metadata is intentionally a migration bridge.
- IdP lookup flows rely on the existing `AuthState.SetNoAuth(true)` path, which maps to `lookup_identity` when the request policy context is created. No IdP-specific response profile change was made in this phase.
- Built-in default behavior was not widened beyond the existing account-list collection and comparison path; custom enforcement is the production change for this phase.
- HTTP account-list denial/tempfail rendering still goes through the current auth response writer, so any remaining writer-level side effects are treated as migration scaffolding until direct response profiles replace it.

## Review-Abgleich

The second pass re-read the Phase 13 requirements, the completion rules, Section 17 account-provider attributes, response markers, parity rows, and the `standard_auth` mapping checklist.

Result:

- HTTP no-auth, gRPC lookup, and IdP no-auth lookup use `lookup_identity`. The added IdP test fixed the review coverage gap for the IdP surface.
- HTTP list-accounts and gRPC ListAccounts use `list_accounts` and evaluate configured auth-decision policies after the account-provider stage.
- `account_provider` records completed/tempfail attributes and a `count` detail only. The account list remains response data and is covered by a negative assertion.
- Caller authentication and transport authorization were not moved into policy denial. Existing gRPC caller-auth and scope checks remain outside the handler policy response path.
- No config, schema, dump/redaction, compiler, registry, snapshot, or atomic reload changes were required for this scope.
- Observability remains on the existing configured-policy evaluation path: policy decisions, response rendering surface, FSM markers, reports, logs, metrics, and OTel spans are emitted by the shared policy evaluation/enforcement helpers.
- No later authority switch was combined into this change. The active adapters are listed above with planned removal points.
