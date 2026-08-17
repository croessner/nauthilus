# Browser Session Contract Inventory

The target runtime has one canonical versioned opaque browser envelope. It is
only a reference to a server-side session anchor. It never carries identity,
protocol request data, MFA state, credentials, recovery material, redirect
targets, or ceremony state. Legacy, unrecognized, malformed, missing, expired,
or inconsistent envelopes and referenced records are purged fail-closed. The
affected OIDC, SAML, or MFA operation restarts at its documented safe entry
point. There is no dual-read or dual-write compatibility mode.

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

## Direct Cookie Manager Call Sites

This is the removal inventory for production code. Each row names all files in
the area that either accepts `cookie.Manager`, retrieves it from Gin context,
or reads, writes, saves, clears, or deletes legacy session keys.

| Area | Current files | Target boundary |
| --- | --- | --- |
| Cookie middleware and response commit | `server/core/cookie/manager.go`, `server/core/cookie/auth_result.go` | Envelope codec plus transaction commit |
| Authentication session and logout cleanup | `server/core/auth.go`, `server/core/common.go`, `server/core/sensitive_output.go` | Session anchor and typed cleanup service |
| Identity and backend affinity | `server/core/idp_mfa.go`, `server/core/remote_backend_session.go`, `server/idp/mfa.go`, `server/idp/nauthilus_idp.go` | Session anchor, enrollment, and step-up repositories |
| WebAuthn registration and login | `server/core/webauthn.go`, `server/core/webauthn_ceremony_store.go` | WebAuthn ceremony repository with single-use consume |
| MFA API and self-service pages | `server/handler/api/v1/mfa.go`, `server/handler/frontend/idp/frontend.go`, `server/handler/frontend/idp/require_mfa.go` | Enrollment, step-up, TOTP, recovery, and ceremony repositories |
| Shared IDP flow adapter and cleanup | `server/idp/flow/reference_adapter.go`, `server/idp/flow/session_context.go`, `server/idp/flow/cleanup.go` | Protocol-flow repositories and session anchor indexes |
| IDP controller and delayed response | `server/handler/frontend/idp/flow_controller_factory.go`, `server/handler/frontend/idp/backend_data.go`, `server/handler/frontend/idp/auth_status_bridge.go` | Transaction commit before response plus protocol-session records |
| OIDC | `server/handler/frontend/idp/oidc.go`, `server/handler/frontend/idp/oidc_authorization_code.go`, `server/handler/frontend/idp/oidc_device_code.go`, `server/handler/frontend/idp/oidc_flow_context.go` | OIDC flow, consent, and protocol-session repositories |
| SAML | `server/handler/frontend/idp/saml.go`, `server/handler/frontend/idp/saml_flow_context.go` | SAML flow and protocol-session repositories |

OIDC cleanup must not delete SAML records or anchor references. SAML cleanup
must not delete OIDC records or anchor references. Logout uses typed index
records to determine the intended protocol-specific and cross-protocol effect.

## Executable Invariant Matrix

| Invariant | Slice A structural test | Future runtime owner and proof |
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

Slice A defines contracts only. It does not write the opaque envelope, switch
production behavior, or introduce a compatibility runtime.

## Typed Redis Store Contract

Slice B adds an unused server-side store package. Redis keys are derived as
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
| WebAuthn ceremony | `webauthn_ceremony` | short ceremony TTL capped to live parent | typed binding; later ceremony slice owns single-use consume |
| TOTP/recovery operation | `totp_recovery` | short operation TTL capped to live parent | pending material remains server-side |

Every hash carries schema version, owner, revision, payload, explicit expiry,
and Redis PTTL. The anchor also carries creation, idle, absolute, last-touch,
revocation, and tombstone fields. A Lua preflight validates every expected
revision before a multi-record transaction publishes any write. Revocation
writes the anchor tombstone before idempotent child deletion. Loading a child
without a live matching parent purges the orphan and returns a fail-closed
classification.

These stores are not connected to cookie middleware or production browser
flows in Slice B.
