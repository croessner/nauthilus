# Nauthilus Operational Security Checklist

This checklist is intended for release readiness and recurring security operations in **Production** and **Staging**.

## Usage

- Mark each item as done for both environments.
- Attach evidence (ticket, screenshot, log snippet, config diff, command output).
- Re-run this checklist before each major release and after security-relevant changes.

## 1. Backchannel Access Control

- [ ] **Production**: At least one backchannel auth method is enabled:
    - `server.basic_auth.enabled=true` or `server.oidc_auth.enabled=true`
- [ ] **Staging**: At least one backchannel auth method is enabled.
- [ ] **Production**: `/api/v1/*` is reachable only from trusted internal networks.
- [ ] **Staging**: `/api/v1/*` is not publicly exposed.

Evidence:

- [ ] Config snapshot attached
- [ ] Network policy / firewall rule attached

## 2. OIDC Token Endpoint Hardening

- [ ] **Production**: `idp.oidc.token_endpoint_allow_get=false`
- [ ] **Staging**: `idp.oidc.token_endpoint_allow_get=false`
- [ ] Any temporary GET enablement has a documented exception owner and expiration date.

Evidence:

- [ ] Config diff attached
- [ ] Exception ticket (if applicable)

## 3. Configuration Endpoint Exposure

- [ ] **Production**: `server.disabled_endpoints.configuration=true` unless explicitly required.
- [ ] **Staging**: Configuration endpoint exposure is justified and documented.
- [ ] If enabled, access is restricted and audited.

Evidence:

- [ ] Endpoint accessibility test attached
- [ ] Audit log sample attached

## 4. CSP and Security Headers

- [ ] **Production**: CSP keeps strict default `form-action 'self'`.
- [ ] **Staging**: Any CSP widening (for redirects/dev compatibility) is explicitly documented.
- [ ] Security headers are enabled under `server.frontend.security_headers`.

Evidence:

- [ ] Response header capture attached
- [ ] Config snippet attached

## 5. Developer Mode Controls

- [ ] **Production**: `NAUTHILUS_DEVELOPER_MODE=false`
- [ ] **Staging**: `NAUTHILUS_DEVELOPER_MODE=false` unless explicitly needed for a short test window.
- [ ] Startup/runtime guardrails prevent accidental non-loopback developer mode usage.

Evidence:

- [ ] Deployment env vars attached
- [ ] Startup log excerpt attached

## 6. Network and Redis Hardening

- [ ] Redis is not publicly reachable.
- [ ] Redis authentication and TLS are configured where applicable.
- [ ] Redis ACLs follow least privilege.
- [ ] `server.trusted_proxies` is explicitly configured (no broad trust).

Evidence:

- [ ] Redis bind/ACL config attached
- [ ] Proxy trust config attached

## 7. Secrets and Key Management

- [ ] No secrets in repository or plaintext deployment artifacts.
- [ ] OIDC signing keys have a rotation process and owner.
- [ ] Client secrets have rotation and revocation procedures.

Evidence:

- [ ] Secret management policy attached
- [ ] Rotation record attached

## 8. Runtime Hardening

- [ ] Service runs non-root (`run_as_user`, `run_as_group`) where supported.
- [ ] Optional debug endpoints (for example pprof) are disabled in production.
- [ ] Only required endpoints are enabled.

Evidence:

- [ ] Runtime/service config attached
- [ ] Endpoint inventory attached

## 9. Logging, Detection, and Alerting

- [ ] Security-relevant logs are centralized.
- [ ] Alerts exist for:
    - repeated auth failures / brute-force patterns
    - unusual 401/403 spikes
    - token validation and scope-denial anomalies
- [ ] Alert ownership and on-call routing are documented.

Evidence:

- [ ] Alert rule export attached
- [ ] Recent alert test attached

## 10. CI/CD Security Gates

- [ ] `govulncheck` is mandatory for merges to `main`.
- [ ] Dependency update policy is active (scheduled updates, review owner).
- [ ] SBOM generation/verification is part of release flow.

Evidence:

- [ ] CI workflow link attached
- [ ] Last successful run attached

## 11. Backup and Recovery

- [ ] Backup/restore procedures exist for config, keys, and stateful dependencies.
- [ ] Restore drills are executed on a schedule.
- [ ] Security incident rollback procedure is tested.

Evidence:

- [ ] Drill report attached
- [ ] Recovery runbook attached

## 12. Independent Validation

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
