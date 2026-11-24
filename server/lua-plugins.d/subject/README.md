# Lua Subject Source Plugins for Nauthilus

This directory contains Lua subject source plugins for the Nauthilus authentication system. They run with subject context and can emit subject-derived policy attributes.

## Policy Integration

Configure a compatible custom script below `policy.namespaces.authn.providers.lua_subject_<name>` with `kind: lua_subject`. A provider
instance below the `subject_analysis` checkpoint selects the exact `authn/lua_subject_<name>` identity with `use` and
applies its `after` dependencies. The decision layer records the facts `nauthilus.auth.lua.subject.<name>.rejected` and
`nauthilus.auth.lua.subject.<name>.error`, where `<name>` is the provider key without the `lua_subject_` prefix; a
status message set by the script becomes the public `status_message` detail on the rejected fact. The
`authn/standard_auth` policy set denies a rejected subject and answers an error with a temporary failure. Configured
rules may reference the same fact IDs.

Subject sources may also emit Lua-owned attributes through `nauthilus_policy_facts`. The bundled subject-source attributes are
registered by `../policy/registry.lua` and use IDs below `lua.plugin.*`, for example
`lua.plugin.geoip.rejected` or `lua.plugin.account_protection.active`. The same values remain available as
request-local `policy_facts` for later actions and custom-log correlation.

This subject-source contract is authentication-specific behavior. It is explicitly bound to `authn`, retains its
established callback name and ordering, and never runs for a generic target. Generic Lua fact providers
use the separate `_G["policy.facts.collect"]` contract documented in [`../policy/README.md`](../policy/).

## Bundled callback status

Every subject source in this directory can be configured as a `lua_subject` provider; `test_context_chain.lua` is
test-only. Subject sources run with the complete Lua API, including Redis and cache writes, outbound HTTP, response
headers, and backend server selection through `nauthilus_backend`. The per-file status is in
[`../POLICY_VM_COMPATIBILITY.md`](../POLICY_VM_COMPATIBILITY.md).

## Available Plugins

### account_centric_monitoring.lua
Monitors authentication attempts at the account level to detect potential distributed brute force attacks and suspicious access patterns.

**Features:**
- Tracks IPs that attempt to access specific accounts
- Records failed authentication attempts per account
- Calculates metrics like unique IPs per account and IP-to-failure ratios
- Detects distributed brute force attacks where many IPs target a single account
- Adds suspicious accounts to a monitoring list for enhanced protection

**Behavior:**
The callback uses the following thresholds:
- `threshold_unique_ips`: 10 (alerts if more than 10 unique IPs try to access an account)
- `threshold_ip_to_fail_ratio`: 0.8 (alerts if the ratio of unique IPs to failed attempts is high)

### geoip.lua
Analyzes the geographic origin of authentication requests using IP geolocation to detect suspicious login attempts from unusual locations.

**Features:**
- Determines the country and region of origin for authentication requests
- Maintains a history of locations per user for anomaly detection
- Identifies authentication attempts from high-risk regions
- Supports whitelisting and blacklisting of countries and regions
- Provides detailed logging of geographic access patterns

**Configuration:**
The callback reads the following environment variable:
- `GEOIP_POLICY_URL`: URL endpoint for the geoip_policyd service

The plugin connects to the geoip_policyd service to evaluate geographic access policies and determine if authentication should be allowed based on the client's location.

### Native reputation

Independent reputation assessment and learning are owned by the native reputation
plugin. Select its assessment before the current event and its `learn_outcome`
post-action after Policy selection. The removed Lua writer has no fallback;
its ambient configuration and facts must not remain in deployment configuration.
See [the native reputation contract](../../../../contrib/plugins/reputation/README.md).

### monitoring.lua
Provides comprehensive monitoring of authentication activities, system performance, and security metrics.

**Features:**
- Tracks authentication success and failure rates
- Monitors system performance metrics during authentication
- Detects anomalies in authentication patterns
- Provides real-time visibility into system health
- Supports integration with monitoring systems via metrics export

**Behavior:**
The callback uses the following monitoring values:
- `monitoring_sensitivity`: Adjusts the sensitivity of anomaly detection (low, medium, high)
- `monitoring_metrics_retention`: How long to retain detailed metrics (in days)

The plugin stores metrics in Redis for later analysis and visualization.

### idp_policy.lua

Example policy subject source that demonstrates how to use the IdP-specific request fields to enforce access control in OIDC
flows (Authorization Code Grant, Device Code, Client Credentials).

**Features:**

- Requires MFA for Device Code flows
- Restricts `offline_access` scope to specific user groups
- Limits access to sensitive OIDC clients based on group membership
- Enforces strong MFA (TOTP/WebAuthn) for sensitive scopes like `groups`
- Blocks redirect URIs pointing to internal/staging environments for non-privileged users

**Available IdP request fields:**

- `request.grant_type` — OIDC grant type (e.g. `authorization_code`, `urn:ietf:params:oauth:grant-type:device_code`)
- `request.oidc_cid` — OIDC Client ID
- `request.oidc_client_name` — Human-readable OIDC client name
- `request.redirect_uri` — Requested redirect URI
- `request.mfa_completed` — Whether MFA was successfully completed (boolean)
- `request.mfa_method` — MFA method used: `totp`, `webauthn`, or `recovery`
- `request.requested_scopes` — Table of OIDC scopes requested by the client
- `request.user_groups` — Table of user's group memberships
- `request.allowed_client_scopes` — Table of configured allowed scopes for the OIDC client
- `request.allowed_client_grant_types` — Table of configured allowed grant types for the OIDC client

**Usage:**
Use the top-level Policy example in [`../examples/policy-safe-idp.yml`](../examples/policy-safe-idp.yml), replace its
relative artifact paths with deployment-absolute paths, and customize the captured rules before candidate preparation.
