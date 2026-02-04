# OIDC Test Client

This client is used to test the OpenID Connect (OIDC) functionality of Nauthilus. It implements the Authorization Code
Flow.

## Client Configuration

The client is configured via environment variables:

| Variable               | Description                                  | Default Value |
|------------------------|----------------------------------------------|---------------|
| `OPENID_PROVIDER`      | The issuer URL of Nauthilus                  | (required)    |
| `OAUTH2_CLIENT_ID`     | The client ID as configured in Nauthilus     | (required)    |
| `OAUTH2_CLIENT_SECRET` | The client secret as configured in Nauthilus | (required)    |

Example:

```bash
export OPENID_PROVIDER=http://127.0.0.1:8080
export OAUTH2_CLIENT_ID=test-client
export OAUTH2_CLIENT_SECRET=test-secret
./nauthilus/bin/oidctestclient
```

By default, the client listens on `http://127.0.0.1:9094`.

## Server Configuration (Nauthilus)

The OIDC IdP must be enabled and the client registered in `nauthilus.yaml`:

```yaml
idp:
  oidc:
    enabled: true
    issuer: "http://127.0.0.1:8080"
    signing_key: "YOUR_PRIVATE_KEY_HERE" # Or signing_key_file
    clients:
      - client_id: "test-client"
        client_secret: "test-secret"
        redirect_uris:
          - "http://127.0.0.1:9094/oauth2"
        scopes:
          - "openid"
          - "profile"
          - "email"
        claims:
          email: "mail"
          name: "cn"
          given_name: "givenName"
          family_name: "sn"
```

## LDAP Backend Example

For users to be able to log in, an authentication backend (e.g., LDAP) must be configured:

```yaml
ldap:
  config:
    server_uri: ["ldap://localhost:389"]
    bind_dn: "cn=admin,dc=example,dc=org"
    bind_pw: "admin"
    lookup_pool_size: 1
    auth_pool_size: 1
  search:
    - protocol: ["oidc"]
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
