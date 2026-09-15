# OIDC backchannel introspection configuration

`POST /oidc/introspect` authenticates the inspecting client using the configured
`token_endpoint_auth_method`. Static clients can inspect access tokens whose
validated audience includes their own client ID. Other tokens return only
`{"active": false}` unless explicitly authorized below. Missing or malformed
audiences fail closed.

## Client configuration reference

| Key under `idp.oidc.clients[]` | Type | Default | Meaning |
| --- | --- | --- | --- |
| `allow_backchannel_introspection` | boolean | `false` | Permit this static, confidential client to inspect service access tokens issued to other clients with the exact normalized audience set `nauthilus:backchannel`. |

Configuration validation rejects enabling this flag for public clients, unsupported authentication methods, secret authentication without a
secret, or `private_key_jwt` without verification key material. Existing key
validation still applies. The flag grants no token issuance, API access, Policy
audience inspection, or access to other clients' browser/ID tokens. It is an
operator-controlled setting, not a requested scope or token claim. Audience and
`client_id` remain issuer-owned reserved claims.

Vim syntax recognizes the new key.

## Example for `60-identity.yml`

Merge this entry into the existing client list; preserve the caller entries:

```yaml
idp:
  oidc:
    clients:
      - client_id: doppelgaenger-introspection
        client_secret: ${DOPPELGAENGER_INTROSPECTION_SECRET}
        token_endpoint_auth_method: client_secret_basic
        allow_backchannel_introspection: true
        grant_types: [authorization_code]
        redirect_uris: []
        scopes: [openid]
```

Supply the secret through the deployment's existing secret mechanism. The
inspector needs neither a `client_credentials` grant nor backchannel scopes.
Explicit grants and scopes avoid the broader empty-list defaults; without a
redirect URI this entry cannot use the authorization-code browser flow.

`nauthilus-director` and `imappoc-service` continue to obtain their own
`client_credentials` tokens with the required backchannel method scopes. The
sidecar authenticates separately as `doppelgaenger-introspection` and submits the
caller's bearer in the `token` form field. Valid delegated responses include
`active`, `iss`, `aud`, `exp`, `scope`, and the issuing caller's `client_id`, plus
`token_type: Bearer`. Existing validated claims remain available. JWT signature,
expiry, revocation, and authoritative opaque-token storage checks run before
introspection authorization. Unauthorized token inspection returns HTTP 200 with
only `active: false`; failed client authentication retains `invalid_client`.
This follows [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2).

New service tokens include an issuer-owned `client_id`; new opaque service tokens
also persist their issuer and expiration time. Obtain fresh caller tokens after
upgrading: older service tokens lack the identity required for delegated inspection. Redis
TTL and revocation remain authoritative for opaque-token validity.

The sidecar must still check issuer, audience, expiration, and per-method scopes.
This change does not deploy the sidecar or modify Kubernetes manifests.
