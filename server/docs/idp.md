# Identity Provider (IdP): Developer Guide

This document provides a detailed technical overview of the integrated Identity Provider in Nauthilus, covering OIDC,
SAML2, and the modern HTMX-based frontend. It is intended for developers who want to understand the internal signal
flows, component interactions, and the overall design of the IdP.

## 1. High-Level Architecture

The Nauthilus IdP is designed as a modular, lightweight, and built-in Identity Provider. It is
fully integrated into the Nauthilus core, leveraging existing authentication and backend logic.

### Core Philosophy

- **Modular**: Protocol-specific logic (OIDC, SAML2) is separated from core identity management.
- **Backend-Agnostic**: Works with LDAP, Lua, or any future backend through the `BackendManager` interface.
- **Modern UI**: Uses a "no-build" frontend stack (HTMX, Tailwind CSS, DaisyUI) for a responsive and maintainable user
  experience.
- **GitOps-Ready**: Configuration is stored in the main `nauthilus.yaml`, allowing for declarative management of clients
  and service providers.

### Component Map

- **`server/idp/`**: The "Brain" of the IdP. Defines the `IdentityProvider` interface and implements the `NauthilusIdP`
  which orchestrates authentication and token issuance.
- **`server/handler/api/v1/`**: The "JSON Interface".
    - `mfa.go`: Provides a clean JSON API for managing TOTP, Recovery Codes, and WebAuthn credentials.
- **`server/handler/frontend/idp/`**: The "Face" and "Voice".
    - `oidc.go`: Implements the OpenID Connect 1.0 specification (Discovery, Authorize, Token, Introspect, UserInfo,
      JWKS, Logout).
    - `saml.go`: Implements the SAML 2.0 Identity Provider logic (Metadata, SSO).
    - `frontend.go`: Manages the web-based flows (Login, Consent, 2FA Portal).
- **`server/idp/redis_storage.go`**: The "Short-term Memory". Handles volatile state like OIDC codes and session data in
  Redis.
- **`server/core/auth.go`**: The "Engine". Manages the complex multi-step authentication process (Password -> MFA ->
  Success).

## 2. Signal Flow Diagram

The following diagram shows how a request moves through the system:

```mermaid
graph TD
    User([User Browser]) <--> FE[HTMX Frontend server/handler/frontend/idp/frontend.go]
    FE <--> PH[Protocol Handlers server/handler/frontend/idp/oidc, saml.go]
    PH <--> IC[IdP Core server/idp/nauthilus_idp.go]
    IC <--> AS[AuthState server/core/auth.go]
    AS <--> BE[Backends server/backend]
    IC <--> RTS[Redis Token Storage server/idp/redis_storage.go]
    PH <--> RTS
    FE <--> MFA[MFA API server/handler/api/v1/mfa.go]
    MFA <--> MS[MFA Service server/idp/mfa.go]
    MS <--> AS
```

## 3. Detailed Signal Flows

### 3.1 OIDC Authorization Code Flow

This is the primary flow for modern applications. It ensures that user credentials never touch the client application.

**Security Note:** All IdP flow state is stored in an encrypted cookie (`nauthilus_secure_data`) using
ChaCha20-Poly1305.
No flow state (like `return_to`) is passed via URL parameters to prevent Open Redirect vulnerabilities.

```mermaid
sequenceDiagram
    participant B as Browser
    participant H as OIDC Handler
    participant F as Frontend Handler
    participant I as IdP Core
    participant R as Redis
    participant A as AuthState
    Note over B, A: Initial Authorization Request
    B ->> H: GET /idp/oidc/auth?client_id=...&scope=openid...
    H ->> I: FindClient(clientID)
    I -->> H: Client Config
    H ->> H: Validate Redirect URI
    H ->> H: Store OIDC params in encrypted cookie
    H ->> B: 302 Redirect to /login (no query params)
    Note over B, A: Authentication Phase
    B ->> F: GET /login
    F ->> F: Read flow state from cookie
    F -->> B: Render idp_login.html (HTMX)
    B ->> F: POST /login (username, password)
    F ->> F: Read flow state from cookie
    F ->> I: Authenticate(ctx, username, password, ...)
    I ->> A: NewAuthState(ctx, ...)
    A ->> A: Evaluate MFA requirements
    A -->> I: Success or Failure
    Note right of I: Delayed Response logic: always proceed to MFA if enabled and user exists
    I -->> F: User (even if password incorrect, if Delayed Response enabled)
    F ->> F: Create Partial Session (in cookie)
    F ->> B: 302 Redirect to /login/totp (no query params)
    B ->> F: POST /login/totp (code)
    F ->> F: Verify TOTP and check original password result
    F ->> F: Final Session Creation or Error
    F ->> B: 302 Redirect to /oidc/authorize (reconstructed from cookie)
    Note over B, A: Consent & Code Issuance
    B ->> H: GET /idp/oidc/authorize (user now logged in)
    H ->> H: Read consent state
    H ->> B: 302 Redirect to /oidc/consent
    B ->> F: GET /idp/oidc/consent
    F -->> B: Render idp_consent.html
    B ->> F: POST /idp/oidc/consent (Accept)
    F ->> R: StoreSession(code, sessionData, TTL)
    F ->> B: 302 Redirect to client_redirect_uri?code=...
    Note over B, A: Token Exchange
    B ->> H: POST /idp/oidc/token (code, client_secret)
    H ->> R: GetSession(code)
    R -->> H: sessionData
    H ->> I: IssueTokens(ctx, sessionData)
    I ->> I: Sign JWTs (RS256)
    I -->> H: {access_token, id_token, refresh_token, expires_in}
    H ->> R: DeleteSession(code)
    H -->> B: 200 OK (JSON Tokens)
    Note over B, A: Refresh Token Flow
    B ->> H: POST /idp/oidc/token (grant_type=refresh_token, refresh_token=...)
    H ->> R: GetRefreshToken(rt)
    R -->> H: sessionData
    H ->> I: ExchangeRefreshToken(ctx, rt)
    I ->> R: DeleteRefreshToken(rt)
    I ->> I: IssueTokens(ctx, sessionData)
    I ->> R: StoreRefreshToken(new_rt, sessionData)
    I -->> H: {access_token, id_token, refresh_token, expires_in}
    H -->> B: 200 OK (JSON Tokens)
```

### 3.1.1 Cookie-based Flow State (Security Enhancement)

The IdP stores all flow state in the encrypted `nauthilus_secure_data` cookie to prevent Open Redirect attacks.

**Session Keys for IdP Flow:**

| Key                | Description                           |
|--------------------|---------------------------------------|
| `idp_flow_active`  | Boolean indicating an active IdP flow |
| `idp_flow_type`    | Flow type: `oidc` or `saml`           |
| `idp_client_id`    | OIDC client_id                        |
| `idp_redirect_uri` | Validated OIDC redirect_uri           |
| `idp_scope`        | Requested OIDC scopes                 |
| `idp_state`        | OIDC state parameter                  |
| `idp_nonce`        | OIDC nonce parameter                  |
| `idp_original_url` | SAML original request URL             |

**How it works:**

1. `/oidc/authorize` validates all parameters and stores them in the encrypted cookie
2. Redirects to `/login` without any query parameters
3. `/login` reads flow state from cookie and validates it
4. After successful authentication, redirects back to `/oidc/authorize` by reconstructing the URL from cookie
5. `/oidc/authorize` finds user logged in and proceeds with consent/code issuance

### 3.1.2 CSRF Protection

All IdP frontend pages use CSRF protection via `nosurf`. The CSRF token is:

- Generated server-side via `nosurf.Token(ctx.Request)`
- Passed to templates as `{{ .CSRFToken }}`
- Sent as `X-CSRF-Token` header for HTMX and fetch() requests

**Protected endpoints:**

- Login pages (`/login`, `/login/:languageTag`)
- MFA pages (`/login/totp`, `/login/webauthn`, `/login/mfa`, `/login/recovery`)
- Consent pages (`/oidc/consent`, `/oidc/consent/:languageTag`)
- Registration pages (`/mfa/totp/register`, `/mfa/webauthn/register`)
- 2FA Home (`/mfa/register/home`)
- Device management (`/mfa/webauthn/devices`)

**HTMX requests:**

```html
<button hx-delete="/mfa/totp" 
        hx-headers='{"X-CSRF-Token": "{{ .CSRFToken }}"}'>
```

**JavaScript fetch() requests:**

```javascript
const response = await fetch("/mfa/webauthn/register/finish", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": "{{ .CSRFToken }}"
    },
    body: JSON.stringify(data)
});
```

## 4. MFA Management API (/api/v1/mfa)

The IdP provides a JSON API for managing Multi-Factor Authentication. This API is used internally by the HTMX frontend
and can be used by external clients.

### 4.1 TOTP Management

- **`GET /api/v1/mfa/totp/setup`**:
    - Starts the TOTP registration process.
    - Returns JSON: `{"secret": "...", "qr_code_url": "..."}`.
    - Stores the secret in the user's session for verification.
- **`POST /api/v1/mfa/totp/register`**:
    - Finalizes TOTP registration by verifying a code.
    - Request Body: `{"code": "123456"}`.
    - Returns 200 OK on success.
- **`DELETE /api/v1/mfa/totp`**:
    - Deletes the TOTP configuration for the user.
    - Returns 200 OK on success.

### 4.2 Recovery Codes

- **`POST /api/v1/mfa/recovery-codes/generate`**:
    - Generates and returns a new set of 10 recovery codes.
    - Replaces any existing recovery codes in the backend.
    - Returns JSON: `{"codes": ["...", "..."]}`.

### 4.3 WebAuthn Management

- **`GET /api/v1/mfa/webauthn/register/begin`**:
    - Initiates WebAuthn registration.
    - Returns `CredentialCreationOptions` as JSON (standard WebAuthn format).
- **`POST /api/v1/mfa/webauthn/register/finish`**:
    - Finalizes WebAuthn registration.
  - Request Body: Either the raw credential object from `navigator.credentials.create()` or an object containing a
    `name` and `credential` payload (e.g. `{"name": "Office YubiKey", "credential": { ... }}`) to store a
    user-friendly device name.
    - Returns 200 OK on success.
- **`DELETE /api/v1/mfa/webauthn/:credentialID`**:
    - Deletes a specific WebAuthn credential by its ID.
    - Returns 200 OK on success.

### 4.4 WebAuthn Devices Portal

The IdP includes a dedicated view for managing registered WebAuthn devices:

- **`GET /mfa/webauthn/devices`**:
    - Renders an overview of all registered security keys.
  - Displays the device name, device ID, and the "Last Used" timestamp.
  - Allows users to add new devices, rename, or delete specific ones.
- **`DELETE /mfa/webauthn/device/:id`**:
    - Deletes a specific device.
- **`POST /mfa/webauthn/device/:id/name`**:
    - Updates the device name for a specific device.

The "Last Used" timestamp is updated automatically upon every successful WebAuthn login and stored in the persistent
backend (LDAP or Lua).

## 5. Protocol-Specific Flows

RFC 7662 allows clients to query the IdP to determine the active state of an OAuth 2.0 token and to determine
meta-information about this token.

```mermaid
sequenceDiagram
    participant B as Client Application
    participant H as OIDC Handler
    participant I as IdP Core
    B ->> H: POST /idp/oidc/introspect (token, client_id, client_secret)
    H ->> H: Authenticate Client
    H ->> I: ValidateToken(ctx, token)
    I -->> H: Claims (if valid)
    H ->> H: Verify audience / authorization
    H -->> B: 200 OK {active: true, scope: "...", sub: "...", ...}
```

### 3.3 OIDC Logout (Front-channel and Back-channel)

Nauthilus supports both Front-channel and Back-channel logout to ensure that users are logged out from all Relying
Parties (RPs) when they end their session at the IdP.

#### Signal Flow

1. **Logout Initiation**: The user or an RP redirects the browser to `/idp/oidc/logout`.
2. **Validation**: If an `id_token_hint` and `post_logout_redirect_uri` are provided, the IdP validates them against the
   client configuration.
3. **Session Identification**: The IdP uses a session cookie (`oidc_clients`) to track which RPs the user has logged
   into during the current session.
4. **Back-channel Logout**: For all RPs that have a `backchannel_logout_uri` configured, the IdP asynchronously sends a
   POST request with a signed `logout_token` (JWT).
5. **Front-channel Logout**: If any RPs have a `frontchannel_logout_uri`, the IdP renders a page
   (`idp_logout_frames.html`) containing hidden iFrames for each RP. This allows the browser to trigger logout at the
   RPs directly.
6. **Local Logout**: The IdP clears the local user session.
7. **Redirection**: Finally, the user is redirected to the `post_logout_redirect_uri` or back to the login page.

### 3.4 SAML 2.0 SSO Flow (Redirect/POST Binding)

Nauthilus supports the Identity Provider initiated and Service Provider initiated SSO.

```mermaid
sequenceDiagram
    participant B as Browser
    participant H as SAML Handler
    participant F as Frontend Handler
    participant I as IdP Core
    participant A as AuthState
    Note over B, A: Initial SSO Request
    B -> H: GET /idp/saml/sso?SAMLRequest=...
    H -> I: getSAMLIdP(ctx)
    H -> H: Validate SAML Request
    H -> B: 302 Redirect to /login?return_to=...
    Note over B, A: Authentication Phase (Shared with OIDC)
    B -> F: GET /login
    F -> B: Render Login UI
    B -> F: POST /login
    F -> I: Authenticate(...)
    I -> A: Verify Credentials
    Note over B, A: SAML Response Generation
    B -> H: GET /idp/saml/sso (with session)
    H -> I: GetUserByUsername(...)
    H -> H: Create SAML Session & Assertion
    H -> B: 200 OK (SAMLResponse via POST Binding)
```

1. **Metadata**: The SP fetches `/saml/metadata` to obtain the IdP's entity ID and public signing certificate.
2. **SSO Request**: The SP redirects the user to `/saml/sso` with a `SAMLRequest`.
3. **Authentication**: If not already logged in, the user is sent to the `/login` page (shared with OIDC).
4. **SAML Response**: After authentication, the IdP generates a signed XML `SAMLResponse` and sends it back to the SP
   via the browser (usually a POST binding).

### 3.5 SAML 2.0 SLO (Single Logout)

Nauthilus provides a basic SAML Single Logout (SLO) endpoint.

1. **Logout Initiation**: The SP or user redirects the browser to `/idp/saml/slo`.
2. **Local Session Termination**: The IdP clears the local user session cookies.
3. **Redirection**: The user is redirected to a logout confirmation page (`/logged_out`).

Currently, the SAML SLO implementation focuses on local session termination and does not yet support complex
asynchronous SLO propagation to other Service Providers.

## 4. Core Components & Logic

### 4.1 IdP Core (`server/idp/`)

The `NauthilusIdP` struct is the central orchestrator. It holds references to:

- **Dependencies**: For accessing configuration and logging.
- **Key Manager**: Handles OIDC signing keys, supporting both static configuration and automatic rotation.
- **Token Storage**: The Redis interface for session management.

Key Methods:

- `Authenticate`: Wraps the core `AuthState` logic to provide a simplified interface for protocol handlers.
- `IssueTokens`: Generates ID tokens and Access tokens. It performs **Claim Mapping** by taking raw backend attributes
  and transforming them according to the client's configuration (e.g., mapping LDAP groups to the `groups` claim).
- `ValidateToken`: Decodes and verifies the signature of an access token.

### 4.2 Frontend & MFA Self-Service

The `FrontendHandler` uses **HTMX** to provide a single-page-application (SPA) feel while keeping logic on the server.

- **OIDC Authorization Code Flow**: The handler manages the login redirect, session establishment, and code generation.
  It now supports **Delayed Response** by hiding authentication failures until after the MFA step. If `/login` is called
  without a protocol-specific context, it redirects to the MFA portal after successful authentication.
- **Multi-Factor Authentication (MFA)**:
    - **TOTP**: Uses the `otp` package for generation and validation. Secrets are stored in the backend (LDAP or Lua).
      Verification is integrated into the login flow (`/login/totp`).
    - **WebAuthn**: Implements the FIDO2 standard. Registration and authentication flows are handled via
      `/webauthn/register` and `/webauthn/login`.
- **Step-up Authentication**: For security-sensitive actions (like deleting a 2FA method), the handler verifies if the
  user has recently performed a full password authentication (`mfa_stepup` key in Redis).

### 4.3 Redis Storage & Key Schema

All IdP state is transient and stored in Redis.

| Key                                            | Format | TTL | Purpose                                   |
|:-----------------------------------------------|:-------|:----|:------------------------------------------|
| `{prefix}nauthilus:oidc:code:{code}`           | JSON   | 5m  | Stores OIDC session during code exchange. |
| `{prefix}nauthilus:oidc:refresh_token:{token}` | JSON   | var | Stores OIDC session for refresh tokens.   |
| `{prefix}nauthilus:webauthn:session:{id}`      | Binary | 10m | WebAuthn challenge/state.                 |
| `{prefix}nauthilus:mfa:stepup:{session}`       | String | 15m | Step-up auth verification flag.           |

## 5. Observability & Debugging

### Metrics (Prometheus)

- `idp_logins_total`: Track success/failure of logins.
- `idp_tokens_issued_total`: Monitor how many tokens are issued per client.
- `idp_mfa_operations_total`: Track registration and deactivation of TOTP/WebAuthn.

### Tracing (OpenTelemetry)

Spans are created for:

- Protocol requests (OIDC Authorize/Token).
- Backend authentication calls.
- JWT signing operations.

### Debugging

Enable the `idp` debug module in the configuration to see detailed logs of the internal state transitions and protocol
interactions:

```yaml
server:
  debug:
    modules:
      - idp
```

## 6. Implementation Details: Claim Mapping

Nauthilus supports dynamic claim mapping. ID token and access token claims are configured separately per client, using
the same mapping schema:

```yaml
# nauthilus.yaml example
idp:
  oidc:
    clients:
      - client_id: my-app
        id_token_claims:
            mappings:
                -   claim: "email"
                    attribute: "mail"         # Map LDAP 'mail' to OIDC 'email'
                    type: "string"
                -   claim: "groups"
                    attribute: "memberOf"    # Map LDAP 'memberOf' to OIDC 'groups'
                    type: "string_array"
        access_token_claims:
            mappings:
                -   claim: "billing.roles"
                    attribute: "billing_roles"
                    type: "string_array"
```

The mapping logic handles:

- **Direct mapping**: String attributes (e.g., `email`, `name`, `preferred_username`).
- **Arrays**: Multi-valued attributes like `groups`.
- **Custom Claims**: Any claim name can be mapped from a backend attribute.
- **Complex Types**: Booleans (e.g., `email_verified`) and structured objects (e.g., `address`).
- **Default types**: If `type` is omitted, the claim's default type (standard or custom scope) is used when available.

### 6.1 Scope-based Claim Filtering

The IdP automatically filters claims based on the scopes requested by the client. Standard OIDC scopes are supported:

- **`profile`**: Includes `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`,
  `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, and `updated_at`.
- **`email`**: Includes `email` and `email_verified`.
- **`address`**: Includes `address`.
- **`phone`**: Includes `phone_number` and `phone_number_verified`.
- **`groups`**: Includes `groups`.

If a client requests specific scopes, only the claims associated with those scopes (and any requested custom scopes)
will be included in the ID token and access token claim sets. If no specific scopes are requested (legacy behavior),
all configured mappings for the client are included.

### 6.2 Custom Scopes

The IdP supports custom scopes. These are defined globally and can group one or
more custom claims:

```yaml
idp:
  oidc:
    custom_scopes:
      - name: "nauthilus"
        description: "Special access scope"
        claims:
          - name: "custom_claim_1"
            type: "string"
          - name: "custom_claim_2"
            type: "string"
```

To use these, the client must have a mapping for the claim names (in `id_token_claims` and/or `access_token_claims`):

```yaml
idp:
  oidc:
    clients:
      - client_id: "my-client"
        id_token_claims:
            mappings:
                -   claim: "custom_claim_1"
                    attribute: "someBackendAttribute"
                    type: "string"
                -   claim: "custom_claim_2"
                    attribute: "anotherBackendAttribute"
                    type: "string"
```

### 6.3 Token Lifetime Configuration

The lifetime of access tokens and refresh tokens can be configured per client:

```yaml
idp:
  oidc:
    clients:
      - client_id: my-app
        access_token_lifetime: 1h
        refresh_token_lifetime: 30d
```

- **`access_token_lifetime`**: Duration of validity for access tokens and ID tokens (default: 1h).
- **`refresh_token_lifetime`**: Duration of validity for refresh tokens (default: 30d). Refresh tokens are only issued
  if the `offline_access` scope is requested.

### 6.4 SAML Attribute Mapping

Unlike OIDC, which uses a per-client mapping configuration, the SAML 2.0 implementation in Nauthilus currently includes
all attributes retrieved from the user backend directly into the SAML assertion.

The attributes included are determined by the backend configuration (e.g., the `ldap.search.mapping` section). Each
attribute from the backend becomes a `<saml:Attribute>` in the assertion, with the backend attribute name as the
`Name` and the first value as the `AttributeValue`.

```mermaid
sequenceDiagram
    participant B as Backend (LDAP/Lua)
    participant I as IdP Core
    participant S as SAML Handler
    B -->> I: User Attributes {mail: "user@example.com", groups: ["users"]}
    I -->> S: User Object
    S -> S: Iterate over attributes
    S -->> S: Create saml:Attribute (Name="mail", Value="user@example.com")
```

## 7. Backend & LDAP Interaction

The IdP core interacts with user backends (LDAP or Lua) through the `BackendManager` interface. This abstraction ensures
that protocol handlers remain independent of the underlying storage technology.

### 7.1 Authentication Flow

1. **User Lookup**: The system performs an LDAP search using the configured `user_filter` to find the user's
   Distinguished Name (DN) and retrieve basic attributes (e.g., display name, unique ID).
2. **Credential Verification**:
    - **Password**: A second connection attempt (LDAP Bind) is performed using the user's DN and the provided password.
    - **MFA (TOTP)**: If password authentication succeeds and TOTP is enabled, the system retrieves the encrypted shared
      secret from the attribute defined in `totp_secret_field`.
    - **MFA (WebAuthn)**: If the user has WebAuthn credentials registered, the system performs a FIDO2 assertion (
      Login). Nauthilus supports multiple security keys.
3. **Delayed Response**: If enabled, the system will always proceed to the MFA step (TOTP or WebAuthn) even if the
   password was incorrect, to prevent username enumeration and credential validation by attackers.

### 7.2 MFA Storage in LDAP

Nauthilus stores second-factor metadata directly in the user's LDAP entry or in child entries, avoiding the need for a
separate database.

- **TOTP**: The shared secret is stored as a plain string in a single attribute (e.g., `nauthilusTotpSecret`).
- **WebAuthn (FIDO2)**: Nauthilus supports two modes of LDAP storage:
    1. **JSON Mode (Recommended)**: Multiple credentials are stored as serialized JSON strings in a multi-valued
       attribute (e.g., `nauthilusFido2Credential`). This is the most flexible approach and easily supports multiple
       devices per user.
        - During the login ceremony, Nauthilus verifies the signature and checks that the `SignCount` provided by the
          device is greater than the one stored in the backend.
        - After a successful login, Nauthilus automatically updates the `SignCount` in the backend (LDAP or Lua) to
          prevent replay attacks and ensure compliance with the WebAuthn specification.
    2. **Individual Attributes**: Credential details (ID, Public Key, Sign Count, etc.) are mapped to individual LDAP
       attributes.

### 7.3 Dynamic Claim Retrieval

During OIDC token issuance or SAML assertion generation, the IdP performs a "Profile Refresh" by querying the backend
for all attributes requested by the client mapping.

```mermaid
sequenceDiagram
    participant I as IdP Core
    participant B as BackendManager
    participant L as LDAP Server
    I ->> B: GetUserByUsername(username, attributes)
    B ->> L: LDAP Search (Filter: (uid=...))
    L -->> B: LDAP Entry {mail: "...", memberOf: [...]}
    B -->> I: User Object with Attributes
    I ->> I: Apply OIDC/SAML Claim Mapping
    I -->> I: Sign JWT / XML
```

### 7.4 Configuration Example (LDAP)

To enable full IdP support with LDAP, ensure your `nauthilus.yaml` includes the relevant mappings. Below is an example
using the recommended JSON mode for WebAuthn. Optional `*_object_class` settings tell Nauthilus which `objectClass` to
auto-add for MFA/WebAuthn writes. If these settings are omitted, the object classes must already exist on the user
entries.

```yaml
ldap:
  search:
    - protocol: [ "oidc", "saml" ]
      base_dn: "ou=users,dc=example,dc=com"
      filter:
        user: "(uid={{.Username}})"
      mapping:
        account_field: "uid"
        display_name_field: "cn"
        totp_secret_field: "nauthilusTotpSecret"
        totp_object_class: "nauthilusMfaAccount"
        # JSON mode: Use the field that stores all credentials
        webauthn_credential_field: "nauthilusFido2Credential"
        webauthn_object_class: "nauthilusFido2Account"
```

### 7.5 FIDO2 LDAP Schema & LDIF Examples

For a clean integration, Nauthilus provides a dedicated LDAP schema.

#### Adding the Schema (olc / cn=config)

Save the following as `nauthilus.ldif` and import it into your LDAP server:

```ldif
dn: cn=nauthilus,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: nauthilus
olcAttributeTypes: ( 1.3.6.1.4.1.31612.1.5.1.1 NAME 'nauthilusFido2Credential'
  DESC 'Serialized WebAuthn credential (JSON)'
  EQUALITY caseIgnoreMatch
  SUBSTR caseIgnoreSubstringsMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcAttributeTypes: ( 1.3.6.1.4.1.31612.1.5.1.2 NAME 'nauthilusTotpRecoveryCode'
  DESC 'One-time use recovery codes for TOTP'
  EQUALITY caseIgnoreMatch
  SUBSTR caseIgnoreSubstringsMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
olcObjectClasses: ( 1.3.6.1.4.1.31612.1.5.2.1 NAME 'nauthilusFido2Account'
  DESC 'Auxiliary object class for FIDO2 WebAuthn credentials'
  SUP top
  AUXILIARY
  MAY ( nauthilusFido2Credential ) )
olcObjectClasses: ( 1.3.6.1.4.1.31612.1.5.2.2 NAME 'nauthilusMfaAccount'
  DESC 'Auxiliary object class for MFA settings'
  SUP top
  AUXILIARY
  MAY ( nauthilusTotpRecoveryCode ) )
```

#### Multi-Device Support in LDAP

To support multiple FIDO2 devices for a single user, simply add multiple values to the `nauthilusFido2Credential`
attribute. Each value contains a self-contained JSON representation of a device.

**Example user entry with two devices:**

```ldif
dn: uid=jdoe,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: nauthilusFido2Account
uid: jdoe
cn: John Doe
sn: Doe
nauthilusFido2Credential: {"credentialID":"abc...","publicKey":"def...","signCount":123,...}
nauthilusFido2Credential: {"credentialID":"xyz...","publicKey":"ghi...","signCount":456,...}
```

### 7.6 TOTP Backup / Recovery Codes

Nauthilus allows users to generate a set of one-time use recovery codes. These codes can be used instead of a standard
TOTP code during the 2FA phase.

- **Generation**: Users can generate a new set (default 10 codes) in the 2FA settings. Generating new codes invalidates
  all previous ones.
- **Storage**: Codes are stored as plain strings in a multi-valued LDAP attribute (e.g., `nauthilusTotpRecoveryCode`) or
  via the Lua backend.
- **Consumption**: When a recovery code is used, it is immediately and permanently removed from the backend.
- **Validation**: The validation logic (`server/core/totp.go`) checks the user's recovery codes before attempting
  standard TOTP verification.

**Configuration Example (LDAP):**

```yaml
ldap:
  search:
    - protocol: [ "oidc", "saml" ]
      mapping:
        totp_recovery_field: "nauthilusTotpRecoveryCode"
        totp_recovery_object_class: "nauthilusMfaAccount"
```

## 8. Client Credentials Grant (RFC 6749 §4.4)

The Client Credentials Grant allows machine-to-machine (M2M) authentication where the client itself is the resource
owner. Unlike the Authorization Code Grant, **no user interaction** is involved and **only an access token** is returned
(no ID token, no refresh token).

Nauthilus supports two authentication methods for the Client Credentials Grant:

1. **`client_secret`** — The client authenticates using a shared secret (via Basic Auth or POST body).
2. **`private_key_jwt`** (RFC 7523) — The client authenticates using a signed JWT assertion with its private key.

### 8.1 Architecture Overview

```mermaid
sequenceDiagram
    participant C as Client (M2M)
    participant T as Token Endpoint
    participant I as NauthilusIdP

    C ->> T: POST /oidc/token<br/>grant_type=client_credentials<br/>+ authentication
    T ->> T: Authenticate client<br/>(client_secret or private_key_jwt)
    T ->> I: IssueClientCredentialsToken(clientID, scopes)
    I ->> I: Validate grant_type support
    I ->> I: Build access token (JWT or opaque)
    I -->> T: access_token + expires_in
    T -->> C: {"access_token": "...", "token_type": "Bearer", "expires_in": 3600}
```

### 8.2 Signing Abstraction

Token signing uses an OOP abstraction (`server/idp/signing`) that supports multiple algorithms via the `Signer` and
`Verifier` interfaces. Both the Client Credentials Grant and the Authorization Code Grant share this abstraction.

**Supported algorithms:**

| Algorithm | Type    | Status    | Use Case                           |
|-----------|---------|-----------|------------------------------------|
| RS256     | RSA     | Mandatory | Server-side token signing, default |
| EdDSA     | Ed25519 | Optional  | Client assertion verification      |

**Key interfaces:**

```go
// Signer signs JWT tokens.
type Signer interface {
    Sign(claims jwt.MapClaims) (string, error)
    Algorithm() string
    KeyID() string
    PublicKey() crypto.PublicKey
}

// Verifier verifies JWT tokens.
type Verifier interface {
    Verify(tokenString string) (jwt.MapClaims, error)
    Algorithm() string
}
```

The `MultiVerifier` tries multiple verifiers in order, enabling key rotation and multi-algorithm support.

### 8.3 Client Authentication Methods

Client authentication is abstracted via the `ClientAuthenticator` interface (`server/idp/clientauth`):

```go
type ClientAuthenticator interface {
    Authenticate(request *AuthRequest) error
    Method() string
}
```

#### 8.3.1 client_secret_basic / client_secret_post

The client sends its `client_id` and `client_secret` either via HTTP Basic Authentication or as POST form parameters.

```bash
# Basic Auth
curl -X POST https://issuer.example.com/oidc/token \
  -u "my-client:my-secret" \
  -d "grant_type=client_credentials" \
  -d "scope=api.read api.write"

# POST body
curl -X POST https://issuer.example.com/oidc/token \
  -d "grant_type=client_credentials" \
  -d "client_id=my-client" \
  -d "client_secret=my-secret" \
  -d "scope=api.read api.write"
```

#### 8.3.2 private_key_jwt (RFC 7523)

The client signs a JWT assertion with its private key and sends it as `client_assertion`. The server verifies the
assertion using the client's pre-registered public key. This method does **not** use mTLS.

**JWT assertion requirements (per RFC 7523):**

| Claim | Value                                  |
|-------|----------------------------------------|
| `iss` | Must match the `client_id`             |
| `sub` | Must match the `client_id`             |
| `aud` | Must be the token endpoint URL         |
| `exp` | Expiration time (short-lived, e.g. 5m) |
| `jti` | Unique identifier (replay prevention)  |

```bash
curl -X POST https://issuer.example.com/oidc/token \
  -d "grant_type=client_credentials" \
  -d "client_id=my-client" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=eyJhbGciOiJSUzI1NiIs..." \
  -d "scope=api.read"
```

### 8.4 Configuration

#### Client with client_secret authentication

```yaml
oidc:
  clients:
    - client_id: "m2m-service"
      client_secret: "super-secret-value"
      grant_types:
        - client_credentials
      scopes:
        - api.read
        - api.write
      access_token_lifetime: 1h
      token_endpoint_auth_method: client_secret_basic
```

#### Client with private_key_jwt authentication (RS256)

```yaml
oidc:
  clients:
    - client_id: "m2m-service-pki"
      grant_types:
        - client_credentials
      scopes:
        - api.read
      access_token_lifetime: 1h
      token_endpoint_auth_method: private_key_jwt
      client_public_key_algorithm: RS256
      client_public_key: |
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
        -----END PUBLIC KEY-----
```

#### Client with private_key_jwt authentication (EdDSA / Ed25519)

```yaml
oidc:
  clients:
    - client_id: "m2m-service-eddsa"
      grant_types:
        - client_credentials
      scopes:
        - api.read
      access_token_lifetime: 1h
      token_endpoint_auth_method: private_key_jwt
      client_public_key_algorithm: EdDSA
      client_public_key_file: /etc/nauthilus/keys/client-ed25519.pub
```

#### Configuration fields reference

| Field                         | Type       | Default                | Description                                                               |
|-------------------------------|------------|------------------------|---------------------------------------------------------------------------|
| `grant_types`                 | `[]string` | `[authorization_code]` | Allowed grant types for this client                                       |
| `token_endpoint_auth_method`  | `string`   | (any secret method)    | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, or `none` |
| `client_public_key`           | `string`   | —                      | PEM-encoded public key (inline) for `private_key_jwt`                     |
| `client_public_key_file`      | `string`   | —                      | Path to PEM file containing the public key                                |
| `client_public_key_algorithm` | `string`   | `RS256`                | Algorithm for the client's public key (`RS256` or `EdDSA`)                |

### 8.5 Token Response

The Client Credentials Grant returns only an access token (per RFC 6749 §4.4.3):

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

No `id_token` or `refresh_token` is included in the response.

### 8.6 Package Structure

```
server/idp/
├── signing/
│   ├── signer.go           # Signer/Verifier interfaces, RS256 + EdDSA implementations
│   └── signer_test.go      # Unit tests for all signing/verification paths
├── clientauth/
│   ├── authenticator.go    # ClientAuthenticator interface, ClientSecret + PrivateKeyJWT
│   └── authenticator_test.go # Unit tests for all authentication methods
└── nauthilus_idp.go         # IssueClientCredentialsToken method
```
