# SAML2 Test Client

This client is used to test the SAML 2.0 functionality of Nauthilus. It implements a Service Provider (SP).

## Client Configuration

The client is configured via environment variables:

| Variable                     | Description                            | Default Value                          |
|------------------------------|----------------------------------------|----------------------------------------|
| `SAML2_IDP_METADATA_URL`     | URL to the IdP metadata of Nauthilus   | `https://localhost:9443/saml/metadata` |
| `SAML2_SP_ENTITY_ID`         | The entity ID of this test client      | `https://localhost:9095/saml/metadata` |
| `SAML2_SP_URL`               | The base URL of this test client       | `https://localhost:9095`               |
| `SAML2_INSECURE_SKIP_VERIFY` | Skip TLS verification for IdP metadata | `true`                                 |

## Troubleshooting

### TLS and Self-Signed Certificates

Since the client and Nauthilus both use self-signed certificates by default, you may encounter TLS handshake errors in
the browser.
To resolve this:

1. Open `https://localhost:9095` in your browser.
2. If you see a certificate warning, click "Advanced" and "Proceed to localhost (unsafe)".
3. Do the same for the Nauthilus IdP URL: `https://localhost:9443`.
4. Once the browser trusts both ports for the current session, the login flow should work without loops.

The client defaults to `SAML2_INSECURE_SKIP_VERIFY=true` to allow fetching metadata from the IdP even if its certificate
is self-signed.

Example:

```bash
export SAML2_IDP_METADATA_URL=https://localhost:9443/saml/metadata
export SAML2_SP_ENTITY_ID=https://localhost:9095/saml/metadata
export SAML2_SP_URL=https://localhost:9095
./nauthilus/bin/saml2testclient
```

By default, the client listens on `https://localhost:9095`. On the first start, it automatically generates a self-signed
certificate for the SP if no `token.crt`/`token.key` is present. This certificate is also used for the HTTPS server.

## Server Configuration (Nauthilus)

The SAML2 IdP must be enabled and the Service Provider registered in `nauthilus.yaml`. It is highly recommended to use
HTTPS for both IdP and SP to avoid cookie issues related to the "Schemeful Same-Site" policy.

```yaml
idp:
  saml2:
    enabled: true
    entity_id: "https://localhost:9443/saml/metadata"
    cert: "YOUR_IDP_CERTIFICATE_HERE" # Or cert_file
    key: "YOUR_IDP_KEY_HERE"         # Or key_file
    service_providers:
      - entity_id: "https://localhost:9095/saml/metadata"
        acs_url: "https://localhost:9095/saml/acs"
```

## LDAP Backend Example

For users to be able to log in, an authentication backend (e.g., LDAP) must be configured:

```yaml
ldap:
  config:
    server_uri: [ "ldap://localhost:389" ]
    bind_dn: "cn=admin,dc=example,dc=org"
    bind_pw: "admin"
    lookup_pool_size: 1
    auth_pool_size: 1
  search:
    - protocol: [ "saml" ]
      cache_name: "ldap"
      base_dn: "ou=users,dc=example,dc=org"
      filter:
        user: "(uid=%L{user})"
      mapping:
        account_field: "uid"
        mail_field: "mail"
        given_name_field: "givenName"
        surname_field: "sn"
      attribute:
        - "uid"
        - "mail"
        - "cn"
        - "givenName"
        - "sn"
```
