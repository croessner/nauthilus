# IDP MFA Flow Developer Notes

This document describes the IDP first-factor, MFA, required-MFA registration,
and WebAuthn continuation paths as implemented by the frontend handlers. It is
intended as a debugging aid for regressions where the browser is sent back to
`/login`, `/login/webauthn`, or `/mfa/*/register` even though an OIDC/SAML flow
should resume.

## Configuration Inputs

The runtime path is not determined by the current URL alone. The IDP client and
session state must be considered together.

| Input | Meaning | Important effects |
| --- | --- | --- |
| `skip_consent` | OIDC client consent can be skipped. | A successful login can resume directly to the OIDC callback path after token/code handling. |
| `delayed_response` | The first-factor password result is hidden until after MFA. | A wrong password still enters MFA if the account/factors can be resolved; the failure is revealed after the second factor. |
| `require_mfa` | List of MFA methods that must be registered for this client. | After successful authentication, the flow may be diverted to `/mfa/<method>/register` before OIDC/SAML resumes. |
| `supported_mfa` | List of MFA methods the client allows during login/registration. | Methods not supported by the client must not be offered or counted as satisfying `require_mfa`. When unset and `require_mfa` is set, the effective login method set is narrowed to `require_mfa`. |
| OIDC flow state | Authorization request, client id, redirect URI, scopes, PKCE, prompt. | Stored in Redis and session cookie; must survive MFA and required-MFA sub-flows. |
| SAML flow state | Request, RelayState, entity id. | Same continuation model as OIDC, but protocol-specific resume target. |
| Device-code flow state | User code/device code and pending verification state. | WebAuthn completion may need to call device-code completion instead of returning a browser redirect. |
| Backend reference | Edge session reference to the authority-side backend result. | Must be preserved for follow-up MFA/backend-data lookups in split edge/authority deployments. |
| MFA factor identity | Account whose second factor is being verified. | Can differ from final subject for formatted Master-User logins. |
| Final subject identity | Account that receives the completed IDP session. | Must be restored after MFA before OIDC/SAML claim materialization. |

The `contrib/identity-proxy-e2e` profile has two relevant OIDC clients:

```yaml
client_id: split-e2e-mfa
skip_consent: true
require_mfa: [totp, webauthn, recovery_codes]
supported_mfa: [totp, webauthn, recovery_codes]

client_id: split-e2e-mfa-delayed
skip_consent: true
delayed_response: true
require_mfa: [totp, webauthn, recovery_codes]
supported_mfa: [totp, webauthn, recovery_codes]
```

## State Owners

```mermaid
flowchart LR
  Browser["Browser session"]
  Edge["Edge frontend handler"]
  Cookie["Encrypted frontend cookie"]
  EdgeRedis["Edge Redis flow store"]
  Authority["Authority backend/gRPC"]

  Browser -->|"OIDC/SAML/MFA HTTP"| Edge
  Edge <-->|"frontend session keys"| Cookie
  Edge <-->|"flow id, step, metadata"| EdgeRedis
  Edge <-->|"auth, identity, MFA state, WebAuthn updates"| Authority

  Cookie -.->|"account, unique_userid, protocol"| Edge
  Cookie -.->|"user backend, backend ref"| Edge
  Cookie -.->|"pending MFA identity/factor"| Edge
  Cookie -.->|"MFA assurance method/time/scope"| Edge
  EdgeRedis -.->|"resume target and parent flow id"| Edge
```

## First-Factor And MFA Selection

```mermaid
sequenceDiagram
  participant Browser
  participant Frontend as FrontendHandler
  participant IDP as NauthilusIDP
  participant Authority
  participant Cookie
  participant FlowStore as Redis Flow Store

  Browser->>Frontend: GET /oidc/authorize or SAML entry
  Frontend->>FlowStore: Store protocol flow state
  Frontend->>Cookie: Store flow id, protocol, client/entity metadata
  Frontend-->>Browser: Redirect /login

  Browser->>Frontend: POST /login username/password
  Frontend->>IDP: Authenticate or delayed-response account lookup
  IDP->>Authority: Resolve account, backend ref, attributes
  Authority-->>IDP: User, backend ref, MFA attributes/state
  IDP-->>Frontend: Auth result and target user

  alt formatted Master-User login
    Frontend->>IDP: Resolve factor account
    IDP->>Authority: Resolve Master-User factor backend ref
    IDP-->>Frontend: Factor user and factor backend ref
  end

  Frontend->>Cookie: Store pending final identity and factor identity
  Frontend->>Cookie: Store backend name/ref and protocol
  Frontend->>Frontend: Compute MFA availability filtered by effective supported methods

  alt no MFA required for login
    Frontend->>Cookie: Store final session
    Frontend->>Frontend: Check require_mfa registration
  else one method available
    Frontend-->>Browser: Redirect /login/totp, /login/webauthn, or /login/recovery
  else multiple methods available
    Frontend-->>Browser: Redirect /login/mfa
  end
```

Important invariant: once MFA availability has been computed from the password
step and authority backend state, the immediate MFA continuation should not make
a contradictory required-MFA decision because the WebAuthn finish request has a
different body shape.

## OIDC Reentry With Existing Sessions

OIDC relying parties may start a new authorization request immediately after a
successful token and userinfo exchange while the browser still has an
authenticated account session. This is a new Authorization-Code request, not a
continuation of the completed one. The handler must therefore persist a fresh
OIDC flow for the current request before consent, MFA assurance, required-MFA
registration, or code issuance is evaluated.

```mermaid
sequenceDiagram
  participant Browser
  participant OIDC as OIDCHandler
  participant Cookie
  participant FlowStore as Redis Flow Store
  participant Frontend as FrontendHandler

  Browser->>OIDC: GET /oidc/authorize with account session and no idp_flow_id
  OIDC->>FlowStore: Store current authorize request metadata
  OIDC->>Cookie: Store flow id, client id, redirect URI, scopes, state, nonce, PKCE
  alt fresh client-scoped MFA assurance
    OIDC-->>Browser: Redirect to client callback with code
  else assurance missing or stale
    OIDC->>Cookie: Seed MFA assurance session
    OIDC-->>Browser: Redirect /login/mfa
    Browser->>Frontend: Complete TOTP/WebAuthn/recovery
    Frontend->>FlowStore: Resolve parent resume target
    Frontend-->>Browser: Redirect /oidc/authorize?...
  end
```

Completing the previous OIDC request may remove temporary flow keys, but it must
not make the next valid `/oidc/authorize` depend on the unauthenticated login
start path. Direct `/login` access without an active IDP flow remains rejected.

## Delayed Response

```mermaid
flowchart TD
  Start["POST /login"] --> Client{"client.delayed_response?"}
  Client -- "false" --> Verify["Verify password"]
  Verify --> Good{"password OK?"}
  Good -- "no" --> LoginError["Render generic login error"]
  Good -- "yes" --> MFA["Proceed to MFA or final session"]

  Client -- "true" --> Resolve["Resolve account and factors without revealing result"]
  Resolve --> Exists{"account/factors resolvable?"}
  Exists -- "no" --> LoginError
  Exists -- "yes" --> Hidden["Store signed auth result in session"]
  Hidden --> MFA
  MFA --> Second["Complete TOTP/WebAuthn/recovery"]
  Second --> Reveal{"stored auth result OK?"}
  Reveal -- "no" --> LoginError
  Reveal -- "yes" --> Final["Store completed IDP session"]
```

`delayed_response` means MFA handlers must validate the stored first-factor
result after the second factor succeeds. It does not mean required-MFA
registration should run against a different identity or backend reference.

## WebAuthn Login Finish

WebAuthn login is special because the browser sends a JSON assertion to
`/login/webauthn/finish`. That request body is consumed by WebAuthn validation.
Internal follow-up lookups must not treat the same JSON body as a Nauthilus auth
request.

```mermaid
sequenceDiagram
  participant Browser
  participant JS as idp_ui.js
  participant Frontend as FrontendHandler
  participant Core as core.CompleteLoginWebAuthn
  participant Authority
  participant Cookie
  participant FlowStore as Redis Flow Store

  Browser->>JS: Click WebAuthn login
  JS->>Frontend: GET /login/webauthn/begin
  Frontend->>Cookie: Store WebAuthn challenge session data
  Frontend-->>JS: PublicKeyCredentialRequestOptions
  JS->>Browser: navigator.credentials.get()
  Browser-->>JS: Signed assertion

  JS->>Frontend: POST /login/webauthn/finish JSON assertion + CSRF header
  Frontend->>Core: CompleteLoginWebAuthn(ctx, deps)
  Core->>Cookie: Load factor identity and challenge data
  Core->>Authority: Load/update credential and sign count
  Authority-->>Core: Credential update persisted
  Core->>Cookie: Store completed MFA session and assurance
  Core-->>Frontend: Success

  Frontend->>Frontend: Compute continuation target
  alt device-code flow
    Frontend->>FlowStore: Complete device-code verification
    Frontend-->>JS: JSON completion result
  else required-MFA registration still missing
    Frontend->>FlowStore: Start require-MFA sub-flow
    Frontend-->>JS: JSON {"redirect":"/mfa/<method>/register"}
    JS->>Browser: location.href = redirect
  else OIDC/SAML can resume
    Frontend->>FlowStore: Resolve parent flow resume target
    Frontend-->>JS: JSON {"redirect":"/oidc/authorize?..."} or SAML target
    JS->>Browser: location.href = redirect
  end
```

Required invariant for this handler:

- The core WebAuthn verifier may consume the request body.
- Any later backend-data, cache-purge, or MFA-availability check must use an
  internal lookup context that does not decode the WebAuthn JSON assertion as a
  structured auth request.
- The completed-MFA session keeps enrollment snapshots for TOTP, WebAuthn, and
  recovery codes so `require_mfa` does not reinterpret a proven factor as
  missing after temporary MFA state is cleaned.
- The handler must not write a second response after an internal lookup already
  aborted the request.
- The continuation redirect must be derived server-side from flow state; the
  browser must only follow a safe relative redirect returned by the server.

## Required-MFA Registration

`require_mfa` is about factor enrollment, not about the current login method
alone. A client can require all of `totp`, `webauthn`, and `recovery_codes`, so
after a successful password or MFA step the flow must prove that every required
method is already registered.

```mermaid
flowchart TD
  Start["After successful first factor or second factor"] --> HasFlow{"IDP flow id exists?"}
  HasFlow -- "no" --> Resume["Resume normal page/session"]
  HasFlow -- "yes" --> Required["Read client require_mfa"]
  Required --> Empty{"require_mfa empty?"}
  Empty -- "yes" --> Clear["Clear required-MFA state"] --> ResumeIDP["Resume OIDC/SAML/device flow"]
  Empty -- "no" --> Identity["Resolve final subject and factor/backend context"]
  Identity --> RequiredPolicy["Evaluate require_mfa registration policy"]
  RequiredPolicy --> CheckTOTP{"TOTP registered?"}
  CheckTOTP -- "no" --> RegisterTOTP["Start require-MFA sub-flow to /mfa/totp/register"]
  CheckTOTP -- "yes" --> CheckWebAuthn{"WebAuthn registered?"}
  CheckWebAuthn -- "no" --> RegisterWebAuthn["Start require-MFA sub-flow to /mfa/webauthn/register"]
  CheckWebAuthn -- "yes" --> CheckRecovery{"Recovery codes registered?"}
  CheckRecovery -- "no" --> RegisterRecovery["Start require-MFA sub-flow to /mfa/recovery/register"]
  CheckRecovery -- "yes" --> Clear --> ResumeIDP
```

Required invariant for split edge/authority deployments:

- The check must use the same final subject, factor identity, backend name, and
  backend reference that were selected during first-factor authentication.
- Explicit `supported_mfa` is the configured allow-list. If it is unset and
  `require_mfa` is set, `require_mfa` becomes the effective allow-list for login
  MFA challenge and method-offer decisions so the UI does not offer a method
  that final client assurance will reject. Required-MFA registration still
  follows `require_mfa` directly.
- A copied/internal lookup context is acceptable only if it preserves the
  encrypted cookie manager and session keys.
- The session enrollment snapshot may satisfy a method only when that method was
  already proven by MFA availability, registration, or a completed challenge; it
  must not be used to invent new factor enrollment state.
- A failed or incomplete lookup must fail closed for security, but it should be
  observable as a lookup failure, not silently downgraded to "factor missing"
  when the factor was proven earlier in the same flow.

## Expected Required-MFA Flow For `split-e2e-mfa`

```mermaid
sequenceDiagram
  participant Browser
  participant Edge
  participant Cookie
  participant Authority
  participant FlowStore

  Browser->>Edge: Initial OIDC login for split-e2e-mfa
  Edge->>Authority: Password OK, user resolved
  Edge->>Authority: TOTP missing, WebAuthn missing, recovery missing
  Edge->>FlowStore: Start require-MFA sub-flow
  Edge-->>Browser: /mfa/totp/register
  Browser->>Edge: Complete TOTP registration
  Edge->>Authority: Save TOTP
  Edge->>Cookie: SessionKeyHaveTOTP=true
  Edge-->>Browser: /mfa/webauthn/register
  Browser->>Edge: Complete WebAuthn registration
  Edge->>Authority: Save WebAuthn credential
  Edge-->>Browser: /mfa/recovery/register
  Browser->>Edge: Generate recovery codes
  Edge->>Authority: Save recovery codes
  Edge->>FlowStore: Required-MFA complete, resume parent flow
  Edge-->>Browser: OIDC callback

  Browser->>Edge: Later login for same client
  Edge->>Authority: Password OK, same backend ref
  Edge->>Cookie: MFA availability includes TOTP, WebAuthn, recovery
  Edge-->>Browser: MFA challenge selection or preferred method
  Browser->>Edge: Complete WebAuthn login
  Edge->>Authority: Persist sign-count update
  Edge->>Cookie: Store completed MFA assurance
  Edge->>FlowStore: Required-MFA check sees all required methods present
  Edge-->>Browser: OIDC callback
```

If the last step redirects to `/mfa/totp/register`, the code has contradicted
state it had already established earlier in the same test profile. The likely
places to audit are:

- loss of `SessionKeyHaveTOTP`, `SessionKeyUserBackend`, or backend-ref session
  keys during MFA cleanup;
- using the WebAuthn JSON finish request as a structured auth request in an
  internal lookup;
- using final subject identity where factor identity is required, or the
  reverse, especially for Master-User logins;
- treating backend-data lookup failure as "factor missing" without logging the
  difference;
- `supported_mfa` filtering that removes a registered method before the
  `require_mfa` comparison.

For the split edge/authority E2E, the currently interesting failing transition
is:

```text
ok recovery-code-generation
ok master-user-mfa-registration
ok oidc-totp-login
ok oidc-delayed-response-totp-login
ok oidc-delayed-response-totp-wrong-password-rejected
WebAuthn finish redirects to /mfa/totp/register/en instead of the OIDC callback
```

That failure means WebAuthn verification itself succeeded, but the continuation
path decided that `totp` is still missing for `split-e2e-mfa`. The next code
audit should therefore focus on how TOTP availability is carried from the
first-factor/MFA-availability decision into the WebAuthn completion
`require_mfa` check, including `delayed_response` and remote backend references.

## Code Map

| Area | Current files |
| --- | --- |
| Route registration and browser handlers | `server/handler/frontend/idp/frontend.go` |
| Required-MFA flow decisions | `server/handler/frontend/idp/require_mfa.go` |
| OIDC/SAML flow state controller | `server/handler/frontend/idp/flow_controller_factory.go` |
| Backend-data/MFA state lookup | `server/handler/frontend/idp/backend_data.go` |
| WebAuthn core validation and sign-count persistence | `server/core/webauthn.go` |
| Completed MFA session storage | `server/core/idp_mfa.go` |
| Remote backend reference session keys | `server/core/remote_backend_session.go` |
| Browser E2E profile | `contrib/identity-proxy-e2e/scripts/browser-e2e.js` |
| Split edge/authority config | `contrib/identity-proxy-e2e/config/edge-a.yml` and `edge-b.yml` |
