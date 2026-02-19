# pam_nauthilus

`pam_nauthilus` is a PAM module that authenticates users through the Nauthilus IdP Device Authorization flow (RFC 8628).
It prompts the user with a verification URL and code and then polls the token endpoint until approval, timeout, or
denial.

## Requirements

- Go toolchain (Go 1.26)
- PAM development headers (`libpam-dev` on Debian/Ubuntu, `pam-devel` on RHEL/Fedora)
- A Nauthilus IdP client configured for Device Code flow and `client_secret_basic` token authentication

## Build

```bash
make build
```

This produces `pam_nauthilus.so` and a C header file `pam_nauthilus.h` in the module directory.

## Install

```bash
sudo make install LIBDIR=/lib/security
```

Some distributions use `/usr/lib/security`. Adjust `LIBDIR` accordingly.

## PAM configuration

Example for `/etc/pam.d/sshd`:

```
auth required pam_nauthilus.so \
    issuer=https://idp.example.com \
    client_id=ssh \
    client_secret=REDACTED \
    scope=openid \
    user_claim=preferred_username \
    timeout=5m \
    request_timeout=10s
```

If you need multiple scopes, provide a URL-encoded space, e.g. `scope=openid%20profile`.

## Nauthilus configuration (idp.oidc only)

Example `nauthilus.yml` snippet for the OIDC IdP section:

```yaml
idp:
    oidc:
        enabled: true
        issuer: "https://idp.example.com"
        signing_keys:
            -   id: "main"
                key_file: "/etc/nauthilus/oidc.key"
                active: true
        device_code_expiry: 10m
        device_code_polling_interval: 5
        device_code_user_code_length: 8
        clients:
            -   name: "SSH"
                client_id: "ssh"
                client_secret: "REDACTED"
                grant_types:
                    - urn:ietf:params:oauth:grant-type:device_code
                token_endpoint_auth_method: "client_secret_basic"
                scopes:
                    - openid
                    - profile
                    - email
```

## Options

- `issuer` (required unless all endpoints are set): Base URL of the Nauthilus IdP, e.g. `https://idp.example.com`.
- `device_endpoint` (optional): Override device endpoint (default: `${issuer}/oidc/device`).
- `token_endpoint` (optional): Override token endpoint (default: `${issuer}/oidc/token`).
- `userinfo_endpoint` (optional): Override userinfo endpoint (default: `${issuer}/oidc/userinfo`).
- `jwks_endpoint` (optional): Override JWKS endpoint (default: `${issuer}/oidc/jwks`).
- `introspection_endpoint` (optional): Override introspection endpoint (default: `${issuer}/oidc/introspect`).
- `client_id` (required): OIDC client id.
- `client_secret` (required): OIDC client secret.
- `scope` (default: `openid`): Space-separated list of scopes (URL-encode spaces if needed).
- `user_claim` (default: `preferred_username`): Claim used to match the PAM username.
- `timeout` (default: `5m`): Overall authentication timeout.
- `request_timeout` (default: `10s`): Timeout for each HTTP request.
- `ca_file` (optional): Additional CA bundle in PEM format.
- `tls_server_name` (optional): Override TLS SNI server name.
- `allow_http` (default: `false`): Allow `http://` endpoints. Use only for local testing.

## Security notes

- HTTPS is enforced by default. Set `allow_http=true` only in trusted local environments.
- The module validates the authenticated user via the `userinfo` endpoint and the configured `user_claim`.
- Access tokens are verified cryptographically via the JWKS endpoint (RS256 signature check).
- Token liveness is confirmed through the introspection endpoint (`active` claim).
- Avoid exposing `client_secret` in world-readable PAM configs; ensure file permissions are restricted.

## Demo Dockerfile

This demo image builds `pam_nauthilus.so` and installs it into `/usr/lib/security` inside the container. The container
keeps running (`sleep infinity`) and an entrypoint renders `/etc/pam.d/login` from environment variables so you can
attach to it and run `/sbin/login` for a realistic PAM prompt.

```bash
docker build -f contrib/pam_nauthilus/Dockerfile.demo -t pam_nauthilus-demo .
```

Run the container with environment variables that map to the PAM module options:

```bash
docker run -d --name test_pam_nauthilus \
  -e PAM_ISSUER=http://host.docker.internal:8080 \
  -e PAM_CLIENT_ID=ssh \
  -e PAM_CLIENT_SECRET=REDACTED \
  -e PAM_SCOPE=openid \
  -e PAM_ALLOW_HTTP=true \
  pam_nauthilus-demo
```

On Linux, add `--add-host=host.docker.internal:host-gateway` or use `--network=host` if you want to reach a local
Nauthilus instance from inside the container.

Then try a real login via PAM:

```bash
docker exec -it test_pam_nauthilus -- /sbin/login
```

Use the user `demo` (created in the image) and make sure your IdP returns a claim matching that username for the
configured `user_claim` (default `preferred_username`).

Supported environment variables are `PAM_ISSUER`, `PAM_DEVICE_ENDPOINT`, `PAM_TOKEN_ENDPOINT`,
`PAM_USERINFO_ENDPOINT`, `PAM_JWKS_ENDPOINT`, `PAM_INTROSPECTION_ENDPOINT`, `PAM_CLIENT_ID`, `PAM_CLIENT_SECRET`,
`PAM_SCOPE`, `PAM_USER_CLAIM`, `PAM_TIMEOUT`, `PAM_REQUEST_TIMEOUT`, `PAM_CA_FILE`, `PAM_TLS_SERVER_NAME`, and
`PAM_ALLOW_HTTP`. If you need a fully custom PAM stack, override the entrypoint and edit `/etc/pam.d/login` manually.

## Testing

```bash
make test
```

Unit tests cover the device-flow logic using `httptest`.
