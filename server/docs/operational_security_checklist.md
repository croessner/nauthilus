# Nauthilus Operational Security Checklist

This checklist is intended for release readiness and recurring security operations in **Production** and **Staging**.

## Usage

- Mark each item as done for both environments.
- Attach evidence (ticket, screenshot, log snippet, config diff, command output).
- Re-run this checklist before each major release and after security-relevant changes.

## 1. Backchannel Access Control

- [ ] **Production**: At least one backchannel auth method is enabled:
    - `auth.backchannel.basic_auth.enabled=true` or `auth.backchannel.oidc_bearer.enabled=true`
- [ ] **Staging**: At least one backchannel auth method is enabled.
- [ ] **Production**: `/api/v1/*` is reachable only from trusted internal networks.
- [ ] Backchannel listeners (`/api/v1/*` including the Policy API, and the gRPC authority listener) are not
      reachable from untrusted networks. A rejected caller is delayed and logged; with the HTTP rate
      middleware enabled, an address that exhausts its failure budget is refused on `/api/v1` until it refills.
- [ ] Backchannel credentials (Basic passwords, Policy-Basic passwords, and OIDC `client_credentials` client
      secrets or keys) are high-entropy.
- [ ] Alerts watch `backchannel_caller_auth_total{outcome=~"rejected|unavailable"}`.
- [ ] `auth.pipeline.max_concurrent_requests` is sized for the backchannel peak. On the caller-authenticated
      backchannel API (`/api/v1/auth/*`, `/api/v1/cache/*`, `/api/v1/bruteforce/*`, the management OpenAPI
      documents, and the other routes behind `auth.backchannel`), the per-client-IP HTTP rate limit
      (`runtime.servers.http.middlewares.rate` with `runtime.servers.http.rate_limit.per_second` and `burst`) is a
      failure budget: requests whose Basic or Bearer caller authentication succeeds never consume it, because a
      few proxy or load balancer addresses carry all backchannel traffic. The shared HTTP/gRPC request budget is
      the process-wide bound for these callers.
- [ ] Every failed caller authentication on these routes (missing or wrong credentials, a token without the
      required scope, missing `auth.backchannel` configuration) and every request to the `auth.basic` endpoint
      consumes one token of the client address. An undecided token validation (`503`) does not. Within the budget
      a failure is answered with `401` or `403` after the rejection delay. Once the address has no token left,
      every request from it, including requests with valid credentials, is answered with `429` (`scope: rate`)
      immediately and without evaluating credentials, until the budget refills at `per_second`. Credential
      guessing is therefore bounded per address to `burst` attempts plus `per_second` attempts per second on
      average; concurrent failures that pass the check together are all charged and delay the refill.
- [ ] Callers that share an address with a misconfigured or hostile client lose backchannel access while that
      client exhausts the budget. Watch `backchannel_caller_auth_total{outcome="rejected"}` and `429` answers
      with `ratelimit_reason=rate` on `/api/v1`, and fix failing callers promptly. Routes without backchannel
      caller authentication, such as the IdP, the frontend, the Policy API, custom hooks, and backchannel routes
      of a developer-mode server without `auth.backchannel`, keep the per-client-IP limit for every request.
- [ ] `/oidc/token` and `/oidc/introspect` have no per-address brake for client-secret guessing; guessing
      there is limited by network exposure and upstream rate limits.
- [ ] With `runtime.servers.http.haproxy_v2` enabled, the listener accepts PROXY headers from every TCP peer
      and logs use the PROXY source, so the listener is reachable only from the PROXY-speaking load balancers.
- [ ] **Staging**: `/api/v1/*` is not publicly exposed.

Evidence:

- [ ] Config snapshot attached
- [ ] Network policy / firewall rule attached

## 2. Metrics Endpoint Access Control

- [ ] **Production**: If `/metrics` is exposed beyond a private scrape network, dedicated metrics Basic Auth is enabled:
    - `observability.metrics.endpoint_auth.basic.enabled=true`
- [ ] **Staging**: `/metrics` exposure is documented and protected when it crosses trust boundaries.
- [ ] Prometheus uses dedicated metrics credentials, not backchannel API credentials.
- [ ] Bearer/OIDC authentication is not used for `/metrics`.

Evidence:

- [ ] Metrics scrape config attached
- [ ] Network policy / firewall rule attached

## 3. OIDC Token Endpoint Hardening

- [ ] **Production**: `identity.oidc.tokens.token_endpoint_allow_get=false`
- [ ] **Staging**: `identity.oidc.tokens.token_endpoint_allow_get=false`
- [ ] Any temporary GET enablement has a documented exception owner and expiration date.

Evidence:

- [ ] Config diff attached
- [ ] Exception ticket (if applicable)

## 4. Configuration Endpoint Exposure

- [ ] **Production**: `runtime.servers.http.disabled_endpoints.configuration=true` unless explicitly required.
- [ ] **Staging**: Configuration endpoint exposure is justified and documented.
- [ ] If enabled, access is restricted and audited.

Evidence:

- [ ] Endpoint accessibility test attached
- [ ] Audit log sample attached

## 5. CSP and Security Headers

- [ ] **Production**: CSP keeps default `form-action 'self' https:` unless `form_action_optional_uris` is intentionally
  used.
- [ ] **Staging**: Any CSP widening (for redirects/dev compatibility) is explicitly documented.
- [ ] Security headers are enabled under `identity.frontend.security_headers`.

Evidence:

- [ ] Response header capture attached
- [ ] Config snippet attached

## 6. Developer Mode Controls

- [ ] **Production**: `NAUTHILUS_DEVELOPER_MODE=false`
- [ ] **Staging**: `NAUTHILUS_DEVELOPER_MODE=false` unless explicitly needed for a short test window.
- [ ] Startup/runtime guardrails prevent accidental non-loopback developer mode usage.

Evidence:

- [ ] Deployment env vars attached
- [ ] Startup log excerpt attached

## 7. Network and Redis Hardening

- [ ] Redis is not publicly reachable.
- [ ] Redis authentication and TLS are configured where applicable.
- [ ] Redis ACLs follow least privilege.
- [ ] `runtime.servers.http.trusted_proxies` is explicitly configured (no broad trust).

Evidence:

- [ ] Redis bind/ACL config attached
- [ ] Proxy trust config attached

## 8. Secrets and Key Management

- [ ] No secrets in repository or plaintext deployment artifacts.
- [ ] OIDC signing keys have a rotation process and owner.
- [ ] Client secrets have rotation and revocation procedures.

Evidence:

- [ ] Secret management policy attached
- [ ] Rotation record attached

## 9. Runtime Hardening

- [ ] Service runs non-root (`run_as_user`, `run_as_group`) where supported.
- [ ] Optional debug endpoints (for example pprof) are disabled in production.
- [ ] Only required endpoints are enabled.

Evidence:

- [ ] Runtime/service config attached
- [ ] Endpoint inventory attached

## 10. Logging, Detection, and Alerting

- [ ] Security-relevant logs are centralized.
- [ ] Alerts exist for:
    - repeated auth failures / brute-force patterns
    - unusual 401/403 spikes
    - token validation and scope-denial anomalies
- [ ] Alert ownership and on-call routing are documented.

Evidence:

- [ ] Alert rule export attached
- [ ] Recent alert test attached

## 11. CI/CD Security Gates

- [ ] `govulncheck` is mandatory for merges to `main`.
- [ ] Dependency update policy is active (scheduled updates, review owner).
- [ ] SBOM generation/verification is part of release flow.

Evidence:

- [ ] CI workflow link attached
- [ ] Last successful run attached

## 12. Backup and Recovery

- [ ] Backup/restore procedures exist for config, keys, and stateful dependencies.
- [ ] Restore drills are executed on a schedule.
- [ ] Security incident rollback procedure is tested.

Evidence:

- [ ] Drill report attached
- [ ] Recovery runbook attached

## 13. Independent Validation

- [ ] External security assessment (pentest/blackbox) is planned or completed.
- [ ] Findings are tracked to closure.
- [ ] High-severity findings are converted into automated regression tests.

Evidence:

- [ ] Assessment report attached
- [ ] Tracking ticket list attached

## Sign-off

- Release/Change ID:
- Environment:
- Reviewer:
- Date:
- Result: `PASS` / `PASS WITH EXCEPTIONS` / `FAIL`
