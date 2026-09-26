# OIDC backchannel introspection configuration

`POST /oidc/introspect` authenticates the inspecting client using the configured
`token_endpoint_auth_method`. Static clients can inspect access tokens whose
validated audience includes their own client ID. Other tokens return only
`{"active": false}` unless explicitly authorized below. Missing or malformed
audiences fail closed. Dynamic clients cannot call this endpoint.

Two independent authorities exist: `allow_backchannel_introspection` for
Nauthilus service tokens, and `token_introspection` for a protected resource
(for example a mail server) that introspects user access tokens issued to other
clients.

## Client configuration reference

| Key under `identity.oidc.clients[]` | Type | Default | Meaning |
| --- | --- | --- | --- |
| `allow_backchannel_introspection` | boolean | `false` | Permit this static, confidential client to inspect service access tokens issued to other clients with the exact normalized audience set `nauthilus:backchannel`. |
| `token_introspection.resources` | list of strings | `[]` | RFC 8707 resource indicators this client owns. Clients may request them with the `resource` parameter; the issued user access token then carries the resource in `aud` and only this client may introspect it. Each resource has exactly one owner. |
| `token_introspection.clients` | list of strings | `[]` | Static clients whose plain user access tokens (issued without a resource indicator) this client may introspect. The same list decides which static clients may request the resources above. |
| `token_introspection.dynamic_client_profiles` | list of strings | `[]` | Dynamic client registration profiles (currently `mail-client-v1`) treated like `clients` for dynamically registered clients. |

Configuration validation rejects enabling this flag for public clients, dynamic
clients, unsupported authentication methods, secret authentication without a
secret, or `private_key_jwt` without verification key material. Existing key
validation still applies. The flag grants no token issuance, API access, Policy
audience inspection, or access to other clients' browser/ID tokens. It is an
operator-controlled setting, not a requested scope or token claim. Audience and
`client_id` remain issuer-owned reserved claims.

The `token_introspection` block requires the same confidential static client
authentication. Validation also rejects resources that are not absolute URIs,
contain a fragment or whitespace, use the reserved `nauthilus:` scheme, equal a
configured `client_id`, or are already owned by another client; `clients`
entries that are unknown or name the client itself; `dynamic_client_profiles`
entries other than the configured registration profile, or any entry while
dynamic client registration is disabled; and `resources` without at least one
`clients` or `dynamic_client_profiles` entry.

The flag is included in the typed configuration schema, with a zero-value default
of `false`, and in configured dumps. The canonical default dump keeps
`identity.oidc.clients = []`; it does not create an example client. Vim syntax
recognizes the new key.

## Example for `60-identity.yml`

Merge this entry into the existing client list; preserve the caller entries:

```yaml
identity:
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

New opaque service tokens persist and expose their expiration time. Existing
opaque service tokens issued before this change have no stored expiration claim;
obtain fresh caller tokens before enabling a sidecar that requires `exp`. Redis
TTL and revocation remain authoritative for opaque-token validity.

The sidecar must still check issuer, audience, expiration, and per-method scopes.
This change does not deploy the sidecar or modify Kubernetes manifests.

## Resource servers introspecting user access tokens

Every user access token carries the issuer-owned claim `azp`, the client it was
issued to. Without resource indicators `aud` stays the client id string; with
resource indicators it is an array of the client id followed by the resources.
Service tokens keep `client_id` and carry no `azp`.

For a caller with a `token_introspection` block, a user access token is active
when:

- its audience names a resource the caller owns (the allowlist does not apply to
  such tokens; a token for another resource server's resource stays inactive
  even when its issuer is allowlisted), or
- it carries no resource and its issuing client, taken from `azp` (legacy tokens:
  the single-string audience), is listed in `clients`, or is a dynamic client
  whose registration profile is listed in `dynamic_client_profiles`. A dynamic
  issuer that cannot be resolved denies the request.

Service tokens stay inactive for callers that only have `token_introspection`.
The existing rules (own audience, `allow_backchannel_introspection`) are
unchanged, and the response shape is the same apart from `azp` and an array
`aud`.

Resource parameters are validated at `/oidc/authorize` and `/oidc/device`: each
value must be an absolute URI without fragment, registered by a resource
server, and requestable by the client; otherwise the request fails with
`invalid_target`. At `/oidc/token` a `resource` value may only narrow the access
token to a subset of the grant (`authorization_code`, `refresh_token`,
`device_code`); a refresh never widens or shrinks the stored grant, and
`client_credentials` rejects the parameter.

### Example

```yaml
identity:
  oidc:
    clients:
      - name: shardpost-introspection
        client_id: shardpost-introspection
        client_secret: ${SHARDPOST_INTROSPECTION_SECRET}
        token_endpoint_auth_method: client_secret_basic
        grant_types: [authorization_code]
        redirect_uris: []
        scopes: [openid]
        token_introspection:
          resources: ["https://mail.example.org/jmap"]
          clients: ["roundcube-app"]
          dynamic_client_profiles: ["mail-client-v1"]
```

A webmail client obtains a JMAP token with
`/oidc/authorize?...&resource=https%3A%2F%2Fmail.example.org%2Fjmap`; the mail
server introspects it as `shardpost-introspection`. Plain `roundcube-app` tokens
and tokens of `mail-client-v1` dynamic clients are visible to the mail server as
well.
