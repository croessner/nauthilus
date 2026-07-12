# Lua Subject Source Plugins for Nauthilus

This directory contains Lua subject source plugins for the Nauthilus authentication system. They run with subject context and can emit subject-derived policy attributes.

## Policy Integration

Configure these scripts as `lua.subject` checks under `auth.policy.checks`. Use
`config_ref: auth.policy.attribute_sources.lua.subject.<name>` so the policy scheduler can select the configured script and apply its
`after` dependencies. The decision layer records `auth.lua.subject.<name>.rejected` and
`auth.lua.subject.<name>.error`; a status message set by the script becomes the public `status_message` detail on the
rejected attribute.

Subject sources may also emit Lua-owned attributes through `nauthilus_policy_facts`. The bundled subject-source attributes are
registered by `../policy/registry.lua` and use IDs below `lua.plugin.*`, for example
`lua.plugin.geoip.rejected` or `lua.plugin.account_protection.active`. The same values remain available as
request-local `policy_facts` for later actions and custom-log correlation.

## Available Plugins

### account_centric_monitoring.lua
Monitors authentication attempts at the account level to detect potential distributed brute force attacks and suspicious access patterns.

**Features:**
- Tracks IPs that attempt to access specific accounts
- Records failed authentication attempts per account
- Calculates metrics like unique IPs per account and IP-to-failure ratios
- Detects distributed brute force attacks where many IPs target a single account
- Adds suspicious accounts to a monitoring list for enhanced protection

**Usage:**
The plugin runs automatically on each authentication attempt. It uses the following thresholds by default:
- `threshold_unique_ips`: 10 (alerts if more than 10 unique IPs try to access an account)
- `threshold_ip_to_fail_ratio`: 0.8 (alerts if the ratio of unique IPs to failed attempts is high)

You can optionally configure a custom Redis pool using the `CUSTOM_REDIS_POOL_NAME` environment variable.

### geoip.lua
Analyzes the geographic origin of authentication requests using IP geolocation to detect suspicious login attempts from unusual locations.

**Features:**
- Determines the country and region of origin for authentication requests
- Maintains a history of locations per user for anomaly detection
- Identifies authentication attempts from high-risk regions
- Supports whitelisting and blacklisting of countries and regions
- Provides detailed logging of geographic access patterns

**Usage:**
Configure the plugin through environment variables or Nauthilus configuration:
- `GEOIP_POLICY_URL`: URL endpoint for the geoip_policyd service

The plugin connects to the geoip_policyd service to evaluate geographic access policies and determine if authentication should be allowed based on the client's location.

### geoip_reputation.lua
Learns Redis-backed reputation from successful and failed authentication outcomes per client IP, ASN, country, and ASN
country. The plugin emits policy attributes only; it does not reject or tempfail requests by itself.

**Scoring:**
Each entity stores `success` and `failure` counters in Redis. The signed score is calculated as beta-smoothed log-odds,
bounded by `tanh`, and weighted by observation volume:

```text
log_odds = ln((failure + alpha) / (success + alpha))
weight   = 1 - exp(-samples / saturation)
score    = tanh(log_odds / temperature) * weight
```

Positive scores indicate risk, negative scores indicate trust. The emitted `decision` value is a policy hint
(`trusted`, `neutral`, or `suspicious`), not an enforcement result.

**Emitted policy attributes:**
- `lua.plugin.geoip_reputation.score`
- `lua.plugin.geoip_reputation.positive_score`
- `lua.plugin.geoip_reputation.negative_score`
- `lua.plugin.geoip_reputation.ip_score`
- `lua.plugin.geoip_reputation.asn_score`
- `lua.plugin.geoip_reputation.country_score`
- `lua.plugin.geoip_reputation.asn_country_score`
- `lua.plugin.geoip_reputation.samples`
- `lua.plugin.geoip_reputation.decision`
- `lua.plugin.geoip_reputation.preexisting_positive_score`
- `lua.plugin.geoip_reputation.preexisting_samples`
- `lua.plugin.geoip_reputation.preexisting_decision`

The `preexisting_*` attributes are computed before the current authentication
outcome updates Redis. They are intended for policies that must prove risk was
already present, such as shared-egress brute-force enforcement. The original
attributes retain their post-update semantics for compatibility and analytics.

**Configuration:**
- `GEOIP_REPUTATION_ALPHA`: Beta smoothing factor, default `2`.
- `GEOIP_REPUTATION_SATURATION`: Sample count where confidence starts saturating, default `20`.
- `GEOIP_REPUTATION_TEMPERATURE`: Log-odds slope divisor, default `1.5`.
- `GEOIP_REPUTATION_TTL_SEC`: Redis counter TTL, default `2592000`.
- `GEOIP_REPUTATION_SUSPICIOUS_THRESHOLD`: Positive-score hint threshold, default `0.65`.
- `GEOIP_REPUTATION_TRUSTED_THRESHOLD`: Negative-score hint threshold, default `0.65`.

### monitoring.lua
Provides comprehensive monitoring of authentication activities, system performance, and security metrics.

**Features:**
- Tracks authentication success and failure rates
- Monitors system performance metrics during authentication
- Detects anomalies in authentication patterns
- Provides real-time visibility into system health
- Supports integration with monitoring systems via metrics export

**Usage:**
The plugin runs automatically on each authentication attempt. You can configure monitoring thresholds and sensitivity through the Nauthilus configuration file:
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
Copy this file to your active subject-source directory and customize the policy rules (client IDs, group names, thresholds) to
match your environment. The plugin is designed as a starting point — add, remove, or modify rules as needed.
