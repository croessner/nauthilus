# Nauthilus Identity Provider (IdP) - Comprehensive User Manual

This manual describes the configuration, architecture, and usage of the integrated Identity Provider (IdP) in Nauthilus.

---

## 1. Purpose

The integrated IdP of Nauthilus was developed to provide identity services in a streamlined way.

- **All-in-one**: Authentication (LDAP/Lua), 2FA (TOTP/WebAuthn), and protocol provisioning (OIDC/SAML2) in a single
  binary.
- **GitOps-Ready**: The entire configuration (clients, service providers) is done declaratively in `nauthilus.yaml`.
- **Modern User Experience**: A lean, HTMX-based UI ensures smooth flows without unnecessary page reloads.
- **Flexibility**: Seamless integration into existing LDAP structures or fully custom logic via Lua.

---

## 2. Configuration

The Identity Provider configuration is located in the `idp` section of the `nauthilus.yaml` file.

### 2.1 Section `idp`

This is the central configuration for the Identity Provider.

- **Clients**: Are defined directly here.
- **Protocols**: OIDC and SAML2.
- **UI**: Uses the modernized templates (`idp_*.html`).

---

## 3. OIDC Configuration

Enable OIDC in the `idp` section:

```yaml
idp:
  oidc:
    enabled: true
    issuer: "https://auth.example.com"
    # Multiple keys (Key Rotation support):
    signing_keys:
      - id: "key-2025-01"
        key: |
          -----BEGIN RSA PRIVATE KEY-----
          ...
          -----END RSA PRIVATE KEY-----
        active: true
    # Auto Key Rotation (stored encrypted in Redis):
    auto_key_rotation: true
    key_rotation_interval: 24h
    key_max_age: 168h # 7 days
    # Default access token type (jwt or opaque):
    access_token_type: "jwt"
    clients:
      - client_id: "myapp"
        client_secret: "secret"
        # Overwrite access token type for this client:
        access_token_type: "opaque"
        redirect_uris:
          - "https://myapp.example.com/callback"
        scopes: [ "openid", "profile", "email", "groups" ]
        skip_consent: false
        delayed_response: true
        claims:
          name: "displayName"
          email: "mail"
          groups: "memberOf"
```

### OIDC Features:

- **Delayed-Response**: If enabled (`delayed_response: true`), the system will not immediately reveal whether login
  credentials were correct. Instead, it will always proceed to the MFA check (provided the user exists). Only at the end
  of the process is an error displayed if the original credentials were wrong. This makes account enumeration
  significantly harder.
- **Introspection**: Allows applications (clients) to check the validity of an access token directly with the IdP.
- **Discovery**: The configuration is provided at `/.well-known/openid-configuration`.
- **RS256**: Tokens are signed by default with the configured RSA key.
- **JWKS Support**: Public keys are provided for automatic verification by clients.
- **Opaque Access Tokens**: Support for opaque access tokens stored in Redis, providing enhanced security and session
  management capabilities.
- **Dynamic Mapping**: LDAP attributes or Lua results are mapped to OIDC claims at runtime.
- **Logout**: Supports RP-initiated logout as well as Front-channel and Back-channel logout.

### 3.1 Important OIDC Terms for Administrators

To configure Nauthilus optimally, you should be familiar with the following terms:

#### Introspection (Token Validation)

Imagine an application receives a key (access token) from Nauthilus. The application can then ask at the **Introspection
Endpoint** (`/oidc/introspect`): "Is this key still valid and is it allowed to access my resources?".
This is particularly useful for APIs or backend services that want to ensure a token has not expired or been revoked.

#### JWKS (JSON Web Key Set)

Nauthilus publishes its public keys at `/oidc/jwks`. Many modern applications automatically download this list. Using
these public keys, the application can independently verify if a token was truly signed by Nauthilus without having to
ask the server every time. This saves time and reduces the load on the IdP.

#### Opaque Access Tokens (Session Management)

By default, Nauthilus issues JWT (JSON Web Token) access tokens, which are stateless and self-contained. While
convenient, JWTs are hard to revoke before they expire.

Nauthilus now also supports **Opaque Access Tokens**. When enabled:

- Instead of a signed JWT, a high-entropy random string (32 bytes, base64url-encoded) is issued as the access token.
- Tokens use recognizable prefixes for easier identification:
    - `na_at_` for Access Tokens
    - `na_rt_` for Refresh Tokens
- The session data associated with the token is stored securely (encrypted) in Redis.
- Validation requires Nauthilus to look up the token in Redis (Introspection).
- **Session Management**: Admins can list all active sessions for a user and invalidate them immediately by deleting the
  tokens from Redis via the Backchannel API.

This can be configured globally or per client using the `access_token_type: "opaque"` setting.

#### KID (Signing Key ID)

The `id` in `signing_keys` (also called KID) is simply a name for your signing key.

- **Why is this important?** If you ever want to replace your key for security reasons (Key Rotation), you can provide
  the new key with a new ID. Clients will then see both keys in the JWKS (during the transition period) and know exactly
  which one to use for verification based on the ID in the token.
- **Key Rotation in Nauthilus**: Nauthilus supports both static multi-key configuration and automatic key rotation.
    - **Static**: Define multiple keys in `signing_keys`. Only the one marked `active: true` is used for signing, but
      all are published via JWKS.
    - **Automatic**: If `auto_key_rotation` is enabled, Nauthilus generates new RSA keys at the specified
      `key_rotation_interval`. Keys are stored encrypted in Redis and automatically rotated across all Nauthilus
      instances. Old keys remain available in JWKS until they reach `key_max_age`.

### 3.2 OIDC Logout

Nauthilus supports both **Front-channel** and **Back-channel** logout to ensure that users are logged out of all
connected applications when they end their session at the IdP.

#### Configuration

Extend the client definition with logout parameters:

```yaml
idp:
  oidc:
    clients:
      - client_id: "myapp"
        post_logout_redirect_uris:
          - "https://myapp.example.com/logout-callback"
        backchannel_logout_uri: "https://myapp.example.com/backchannel-logout"
        frontchannel_logout_uri: "https://myapp.example.com/frontchannel-logout"
```

> [!NOTE]
> There are no default paths for `backchannel_logout_uri` or `frontchannel_logout_uri`. If these parameters are not
> provided, Nauthilus will not trigger the respective logout mechanism for that client.

#### How it works

1. **Back-channel Logout**: The IdP asynchronously sends a POST request with a signed `logout_token` directly to the
   application. This happens in the background.
2. **Front-channel Logout**: If an application requires front-channel logout, the IdP displays a logout page with hidden
   iFrames. The user's browser calls these iFrames, triggering the logout in the respective application.
3. **State Tracking**: During a session, Nauthilus automatically tracks which clients a user has logged into (
   `oidc_clients` cookie) and only triggers the corresponding mechanisms for these clients upon logout.

---

## 4. SAML2 Configuration

Nauthilus acts as a SAML 2.0 Identity Provider (IdP).

```yaml
idp:
  saml2:
    enabled: true
    entity_id: "https://auth.example.com/saml/metadata"
    # Certificate (PEM or file)
    cert: |
      -----BEGIN CERTIFICATE-----
      ... (IdP Cert) ...
      -----END CERTIFICATE-----
    # OR:
    # cert_file: "/etc/nauthilus/saml.crt"

    # Private Key (PEM or file)
    key: |
      -----BEGIN RSA PRIVATE KEY-----
      ... (IdP Private Key) ...
      -----END RSA PRIVATE KEY-----
    # OR:
    # key_file: "/etc/nauthilus/saml.key"
    signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" # Optional
    default_expire_time: "1h" # Optional
    name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" # Optional
    service_providers:
      - entity_id: "https://sp.example.com/metadata"
        acs_url: "https://sp.example.com/saml/acs"
        slo_url: "https://sp.example.com/saml/slo"
        delayed_response: true
```

The IdP metadata can be retrieved at `https://<domain>/saml/metadata`.

### SAML2 Features:

- **Single Sign-On (SSO)**: Supports Redirect and POST bindings.
- **Single Logout (SLO)**: Enables logout from the IdP via a standardized endpoint.
- **Metadata**: IdP metadata is provided at `/saml/metadata`.
- **Dynamic Attribute Mapping**: User attributes from the backend (LDAP/Lua) are automatically included in the SAML
  assertion.
- **Delayed-Response**: Also available for SAML Service Providers to make account enumeration harder.

### 4.1 SAML Attribute Mapping

Unlike OIDC, which uses per-client mapping configuration, Nauthilus currently automatically includes all attributes
retrieved from the user backend (LDAP or Lua) for the user in SAML assertions.

- **Configuration**: Mapping is primarily done in the backend section (e.g., under `ldap.search.mapping`).
- **Result**: Every attribute found in the backend is included as a SAML attribute in the response.

---

## 5. Generating Keys and Certificates

Nauthilus provides built-in functions to generate suitable keys and certificates for OIDC and SAML2.

### 5.1 OIDC Signing Key

Generates an RSA private key in PEM format (default 4096-bit):

```bash
./nauthilus -gen-oidc-key -key-bits 4096
```

### 5.2 SAML2 Self-Signed Certificate

Generates a self-signed certificate and the matching RSA key:

```bash
./nauthilus -gen-saml-cert "Nauthilus IdP" -key-bits 4096 -cert-years 10
```

The `-gen-saml-cert` parameter specifies the Common Name (CN) for the certificate. `-key-bits` (default 4096) controls
the key length, and `-cert-years` (default 10) the validity period.

---

## 6. Modern UI & Frontend Integration

The new user interface is accessible at `/login` and serves as a central entry point for all protocols. If a user is
already logged in, accessing `/login` without parameters will automatically redirect them to the MFA Portal.

### HTMX Workflow

Nauthilus uses [HTMX](https://htmx.org/) to update parts of the page. If you extend the UI:

- Use `hx-post`, `hx-target`, and `hx-swap` for form interactions.
- Redirects are controlled via the HTTP header `HX-Redirect`.

### Entry Points:

- **Login**: `/login` (Supports `return_to` parameter)
- **MFA Portal**: `/mfa/register/home` (User security hub)

---

## 7. MFA Self-Service (TOTP & WebAuthn)

Users can manage their second factors themselves. This requires the backend (LDAP or Lua) to have write access to the
corresponding fields.

### 7.1 TOTP (Google Authenticator etc.)

- The user scans a QR code.
- The secret is stored in the backend (`nauthilusTotpSecret` in LDAP).

### 7.2 WebAuthn (YubiKey, FaceID, Windows Hello)

- Nauthilus supports FIDO2/WebAuthn.
- Registered credentials are stored as a JSON string in the backend.
- **Security**: After each successful login, the signature counter (`SignCount`) of the credential is updated in the
  backend. This is an important WebAuthn security mechanism to prevent replay attacks with cloned authenticators.

### 7.3 TOTP Recovery Codes (Backup Codes)

- Users can generate a set of 10 recovery codes.
- Each code is valid only once.
- When a code is used, it is immediately removed from the backend.
- Generating new codes invalidates all previous ones.
- These codes serve as emergency access if the primary 2FA device is lost.
- **LDAP Field**: `totp_recovery_field` must be mapped in the LDAP configuration.

---

## 8. Lua Backend Examples

For maximum flexibility, all backend operations can be implemented via Lua.

### 8.1 Password Verification & MFA Check

```lua
function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()
    -- ... DB query ...
    b:authenticated(true)
    b:totp_secret_field("totp_secret_db_column")
    return nauthilus_builtin.BACKEND_RESULT_OK, b
end
```

### 8.2 Loading WebAuthn Credentials

```lua
function nauthilus_backend_get_webauthn_credentials(request)
    -- request.username contains the username
    local credentials = db:query("SELECT webauthn FROM users WHERE...")
    return nauthilus_builtin.BACKEND_RESULT_OK, credentials
end
```

### 8.3 Saving/Deleting WebAuthn/TOTP

Nauthilus calls specific functions when a user changes their MFA:

- `nauthilus_backend_add_totp(request)`: save `request.totp_secret`.
- `nauthilus_backend_delete_totp(request)`: remove TOTP.
- `nauthilus_backend_save_webauthn_credential(request)`: save `request.webauthn_credential` (JSON).
- `nauthilus_backend_delete_webauthn_credential(request)`: remove WebAuthn.
- `nauthilus_backend_add_totp_recovery_codes(request)`: save `request.totp_recovery_codes` (table).
- `nauthilus_backend_delete_totp_recovery_codes(request)`: remove all recovery codes.

---

## 9. Endpoint Reference

### OpenID Connect (OIDC)

| Endpoint                            | Method   | Description                        |
|:------------------------------------|:---------|:-----------------------------------|
| `/.well-known/openid-configuration` | GET      | Discovery Document                 |
| `/oidc/authorize`                   | GET      | Authorization Endpoint             |
| `/oidc/token`                       | POST     | Token Exchange Endpoint            |
| `/oidc/introspect`                  | POST     | Token Introspection Endpoint       |
| `/oidc/userinfo`                    | GET      | User Information (Bearer Auth)     |
| `/oidc/jwks`                        | GET      | Public Keys for Token Verification |
| `/oidc/logout`                      | GET      | Logout Endpoint (RP-initiated)     |
| `/oidc/consent`                     | GET/POST | Obtaining User Consent             |

### SAML 2.0

| Endpoint         | Method   | Description                                |
|:-----------------|:---------|:-------------------------------------------|
| `/saml/metadata` | GET      | IdP Metadata XML                           |
| `/saml/sso`      | GET/POST | SSO Login Endpoint (Redirect/POST Binding) |
| `/saml/slo`      | GET/POST | Single Logout Endpoint                     |

### Frontend & MFA

| Endpoint                 | Method   | Description                        |
|:-------------------------|:---------|:-----------------------------------|
| `/login`                 | GET/POST | Central Login Page                 |
| `/login/totp`            | GET/POST | TOTP Verification during login     |
| `/login/webauthn`        | GET      | WebAuthn Verification during login |
| `/login/mfa`             | GET      | MFA Method Selection page          |
| `/login/recovery`        | GET/POST | Recovery Code login                |
| `/mfa/register/home`     | GET      | MFA Management Overview            |
| `/mfa/totp/register`     | GET/POST | TOTP Registration                  |
| `/mfa/webauthn/register` | GET      | WebAuthn Registration              |
| `/mfa/totp`              | DELETE   | Deactivate TOTP                    |
| `/mfa/webauthn`          | DELETE   | Deactivate WebAuthn                |
| `/mfa/recovery/generate` | POST     | Generate new recovery codes        |

---

## 10. Data Persistence & Security (Redis)

Nauthilus uses Redis for short-term and medium-term data storage. This includes:

- **Authorization Codes**: Short-lived codes for the OIDC flow.
- **Refresh Tokens**: Used to obtain new access tokens without re-authentication.
- **Sessions**: Data about currently active OIDC/SAML sessions.

### 10.1 Security & Encryption

To protect sensitive data in Redis, Nauthilus can encrypt all session-related data before storing it.

- **Algorithm**: ChaCha20-Poly1305 (authenticated encryption).
- **Configuration**: Set a secret in the Redis configuration section:
  ```yaml
  server:
    redis:
      encryption_secret: "a-very-long-and-secure-random-string"
  ```
- **What is encrypted?** All data in the categories mentioned above (Authorization Codes, Refresh Tokens, Session Data).
- **Signing Key**: All OIDC signing keys (static and dynamic) can be published via the JWKS endpoint. Dynamically
  rotated keys are stored encrypted in Redis. Static keys from the configuration are not stored in Redis.

---

## 11. Troubleshooting

### 11.1 Common Issues

- **Redis Prefix**: If data is not found, check the `redis.prefix` in the configuration.
- **Debug Mode**: Enable the `idp` debug module to receive detailed logs:
  ```yaml
  server:
    insights:
      debug: ["idp"]
  ```

---

## 12. User Guide: MFA Registration & Management

This section provides instructions for end-users on how to set up and manage their Multi-Factor Authentication (MFA).

### 12.1 Accessing the MFA Portal

The central hub for managing your security settings is the **MFA Portal**.

- **URL**: `https://<your-domain>/mfa/register/home`
- **Requirement**: You must be logged in with your primary credentials (username and password) to access this page.

### 12.2 Registering TOTP (Authenticator App)

TOTP (Time-based One-Time Password) allows you to use apps like Google Authenticator, Authy, or Microsoft Authenticator.

1. **Open the MFA Portal** and locate the "Authenticator App (TOTP)" section.
2. Click on **Register TOTP**.
3. A QR code will be displayed on the screen.
4. **Scan the QR code** with your mobile authenticator app.
5. The app will start generating 6-digit codes.
6. **Verify the setup**: Enter the current 6-digit code from your app into the input field on the Nauthilus page.
7. Click **Submit**. If the code is correct, TOTP is now active for your account.

### 12.3 Registering WebAuthn (Security Key / Biometrics)

WebAuthn allows you to use physical security keys (like Yubico YubiKey) or biometric methods (like TouchID, FaceID, or
Windows Hello).

1. **Open the MFA Portal** and locate the "Security Key (WebAuthn)" section.
2. Click on **Register WebAuthn**.
3. Follow your browser's instructions:
    - If using a **Security Key**: Insert the key into your USB port and touch the flashing button when prompted.
    - If using **Biometrics**: Follow the prompt to scan your fingerprint or face.
4. Once the browser confirms the interaction, the registration is complete, and WebAuthn is active for your account.

### 12.4 Managing and Deactivating Factors

In the MFA Portal, you can see which factors are currently active:

- **Active Factors**: Show a "Deactivate" button. Clicking this will immediately remove the factor from your account.
- **Inactive Factors**: Show a "Register" button to start the setup process.

### 12.5 Recovery Codes

Recovery codes are emergency codes that allow you to log in if you lose access to your primary MFA device (e.g., you
lost your phone or security key).

- **Generation**: In the MFA Portal, click on **Generate new recovery codes**. This will create a list of 10 one-time
  use codes.
- **Storage**: **Copy and save these codes** in a safe place (e.g., a password manager or a printed document).
- **Usage**: If prompted for a 2FA code during login, you can click on **Recovery Code** on the MFA selection page and
  enter one of your codes.
- **Replacement**: Generating new recovery codes will automatically invalidate all previously generated codes.

### 12.6 MFA Selection & Preferred Method

If you have configured more than one second factor (e.g., both TOTP and a Security Key), Nauthilus will display a *
*selection page** after you enter your password.

- **Choose your factor**: You can decide for each login which method you want to use.
- **Recommendations**: Nauthilus remembers which method you used last and will mark it as "Recommended" for your next
  login.
- **Backup Access**: If your preferred method is unavailable, you can always choose one of your other active factors or
  use a **Recovery Code**.
