# Browser Session Contract Inventory

The target runtime has one canonical versioned opaque browser envelope. It is
only a reference to a server-side session anchor. It never carries identity,
protocol request data, MFA state, credentials, recovery material, redirect
targets, or ceremony state. Legacy, unrecognized, or malformed envelopes are
removed from the browser. Missing, expired, or inconsistent canonical records
fail closed and are cleaned only within the canonical keyspace. The affected
OIDC, SAML, or MFA operation restarts at its documented safe entry point. There
is no dual-read or dual-write compatibility mode.

## Legacy Key Ownership

`server/sessionstate/inventory.go` is the executable inventory of all 84 current
primary-cookie fields: 78 exported `definitions.SessionKey*` fields and six
package-local self-service step-up fields. Every field has exactly one target
owner: session anchor, OIDC flow, SAML flow, required-MFA enrollment, step-up,
WebAuthn ceremony, TOTP/recovery, consent/logout indexes, protocol session, or
deletion. No legacy field is assigned to the canonical envelope.

The only deletion-only field is the deprecated `lang` value. Language remains
owned by the dedicated language cookie. All other legacy fields move to their
typed server-side owner before the canonical runtime is enabled.

## Legacy Redis Data After Cutover

The hard cutover is intentionally not a Redis data migration. Records written
by the legacy browser-session and IDP-flow implementation are incompatible
legacy state: the canonical runtime neither reads nor adopts them, and their
presence must not change canonical authentication, MFA, OIDC, or SAML behavior.
They may remain until their existing TTLs expire.

Production request paths must not scan, backfill, translate, or delete legacy
Redis namespaces. Operators may optionally use the allowlisted, dry-run-first
tool under `contrib/session-keyspace-retirement` after a verified uniform
rollout. That tool is operational housekeeping only; it is not a cutover
prerequisite, compatibility mechanism, startup action, or request-path fallback.

Review must therefore treat residual legacy Redis records as expected inert
data. A review finding is warranted only if the canonical runtime reads them,
derives decisions from them, writes legacy formats, or makes cleanup necessary
for correctness.

## Executable Browser Boundary

Frontend login, MFA, enrollment, authenticated self-service, OIDC browser
flows, and SAML SSO/SLO use only the canonical v1 envelope and typed Redis
records. Direct `cookie.Manager`, legacy session keys, `ReferenceAdapter`, or
`HybridStore` access from an executable browser handler, middleware, helper,
or composition root is release-blocking. Dormant alternate browser runtimes
must be removed rather than retained as fallback code.

OIDC discovery, token, userinfo, introspection, JWKS, dynamic registration,
and device authorization remain cookie-free server/API routes. The only MFA
machine interface is the scoped `/api/v1/mfa-backchannel/*` API. The former
session-cookie `/api/v1/mfa/*` routes are retired and must not be registered,
documented, or restored as a compatibility path. Route inventory tests,
handler reachability tests, single-use issuance tests, and session-revocation
tests are the executable proof of this boundary.

## Authentication Application Boundary

OIDC authorization-code and device-code journeys, SAML, delayed response, MFA
follow-up lookups, WebAuthn backend lookups, backend affinity, identity
materialization, and claim release use the common `AuthApplicationService`
boundary when they need authentication-domain work. Each adapter selects an
exact host-owned internal caller profile and supplies explicit operation,
protocol or transport, OIDC-client or SAML-SP, correlation, localization,
requested-attribute, and existing backend-affinity facts. The active shared
Decision Service admits those profiles and runs the common authentication
checkpoints from the current atomic generation.

That boundary does not absorb browser state. The envelope, `SessionAnchor`,
OIDC/SAML flow, device verification, delayed-response latch, consent,
enrollment, step-up, assurance, WebAuthn ceremony, and claim-release lifecycle
remain owned by their canonical IdP/session repositories. Generic target input
contains none of those records. Domain handlers validate and transition them,
invoke the application service with the minimum typed facts for the current
operation, and apply the detached outcome afterward. Ceremony verification and
protocol issuance therefore remain domain operations rather than alternate
policy evaluators.

The top-level `policy` configuration, catalog, caller admission, extensions,
and routes are committed as one generation. The browser runtime has no second
policy authority or fallback evaluator.

## Direct Cookie Manager Prohibition Matrix

| Executable boundary | Browser state authority | Direct `cookie.Manager` allowed | Required proof |
| --- | --- | --- | --- |
| Frontend login, MFA, enrollment, and authenticated self-service | Canonical v1 envelope plus typed Redis records | No | Registrar and handler reachability tests; legacy-only browser state rejects before the handler |
| OIDC authorize, consent, device verification, device consent, and logout | Canonical v1 envelope plus typed OIDC/session records | No | Protocol-entry/continuation route tests, issuance single-use tests, and logout revocation tests |
| SAML SSO and SLO | Canonical v1 envelope plus typed SAML/session records | No | Protocol-entry/continuation route tests, assertion single-use tests, and SLO revocation tests |
| OIDC discovery, token, userinfo, introspection, JWKS, dynamic registration, and device authorization | Protocol request and server-side token/device stores; no browser session | No browser manager | Cookie-free route inventory and backchannel regression tests |
| MFA machine backchannel | Scoped API authentication context and provider state; no browser session | No browser manager | Cookie-free route inventory and API regression tests |
| Rejected legacy or malformed browser state | None | No | Canonical middleware purges browser representations and does not invoke the handler |
| Legacy Redis retirement | Operator-invoked fixed-allowlist contrib tool only | Not applicable | Dry-run default, aggregate-only output, explicit apply, and no server import edge |

Any executable browser handler, middleware, helper, or composition root that
reads or writes `cookie.Manager`, `ReferenceAdapter`, `HybridStore`, or a legacy
session key is a release-blocking architecture violation. Dead legacy source
must be removed, not retained as a dormant alternate runtime.

## Executable Route Matrix

| Route family | Checkpoint | Runtime handler family |
| --- | --- | --- |
| Frontend login/MFA/enrollment/self-service | Continuation | Canonical frontend handlers and `CanonicalAuthMiddleware` |
| OIDC authorize and device verification | Protocol entry | Canonical OIDC entry handlers |
| OIDC consent, device consent, and logout | Continuation | Canonical OIDC continuation handlers |
| SAML SSO and inbound SLO request | Protocol entry | Canonical SAML handlers |
| SAML SLO response | Continuation | Canonical SAML handler with message-type checkpoint selection |
| OIDC backchannels and MFA machine backchannel | Cookie-free | Existing non-browser handlers, with no canonical or legacy browser-session middleware |

## Executable Invariant Matrix

| Invariant | Structural proof | Runtime owner and proof |
| --- | --- | --- |
| Bounded envelope size | `TestContractCatalogCoversCanonicalRuntimeInvariants` | Envelope codec size and cookie-property tests |
| Server-side business-state ownership | `TestCanonicalEnvelopeOwnsNoBusinessState` | Typed repository and browser-cookie tests |
| Account/session/flow binding | contract catalog | Repository binding and tamper tests |
| Parallel OIDC and SAML coexistence | contract catalog | Anchor-index and real-browser parallel-flow tests |
| Revision compare-and-swap | typed repository contract | Redis CAS and stale-writer tests |
| Expiry and TTL | typed clock/repository contracts | Record-family expiry tests |
| Unrecognized format purge | contract catalog | Envelope decode, cleanup, and restart tests |
| Safe-checkpoint restart | contract catalog | OIDC, SAML, enrollment, and step-up entrypoint tests |
| Uniform-version rollout | contract catalog | Release guardrail and documented no-mix deployment gate |
| Failure atomicity | transaction contract | Save, Redis, cleanup, and no-response-before-commit tests |

These invariants are active in the production composition root. Frontend,
OIDC, and SAML register only their normal-named canonical route sets; there is
no compatibility runtime or fallback registrar.

## Typed Redis Store Contract

The active server-side store derives Redis keys as
`browser-session:{HMAC(session-handle)}:<owner>:HMAC(record-handle)`. Both
digests use a dedicated secret of at least 32 bytes. Raw session and child
handles never appear in Redis keys. The shared keyed session digest is the
Redis Cluster hash tag, so one anchor and its coordinated child records occupy
one slot while record families remain separately keyed.

| Record family | Hash owner | Lifetime | Atomicity and failure rule |
| --- | --- | --- | --- |
| Session anchor | `session_anchor` | minimum of idle and absolute expiry | revision CAS; bounded idle touch; missing timestamps, TTL, revocation, or tombstone fail closed |
| OIDC flow | `oidc_flow` | interactive TTL capped to live parent | isolated CAS; never loads through SAML repository |
| SAML flow | `saml_flow` | interactive TTL capped to live parent | isolated CAS; never loads through OIDC repository |
| Required-MFA enrollment | `required_mfa_enrollment` | short flow TTL capped to live parent | session and flow binding required |
| Dynamic step-up | `step_up` | freshness/operation TTL capped to live parent | enrollment-independent revision CAS |
| WebAuthn ceremony | `webauthn_ceremony` | short ceremony TTL capped to live parent | typed binding and atomic single-use consume |
| TOTP/recovery operation | `totp_recovery` | short operation TTL capped to live parent | pending material remains server-side |

Every hash carries schema version, owner, revision, payload, explicit expiry,
and Redis PTTL. The anchor also carries creation, idle, absolute, last-touch,
revocation, and tombstone fields. A Lua preflight validates every expected
revision before a multi-record transaction publishes any write. Revocation
writes the anchor tombstone before idempotent child deletion. Loading a child
without a live matching parent purges the orphan and returns a fail-closed
classification.

These stores are the active production browser-state authority behind the
canonical middleware and handlers. The canonical envelope remains only an
authenticated reference; no typed record payload is serialized into it.
