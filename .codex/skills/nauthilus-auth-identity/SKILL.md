---
name: nauthilus-auth-identity
description: Use for Nauthilus authentication and identity-provider work touching OIDC, OAuth2, SAML, MFA, TOTP, WebAuthn, recovery codes, LDAP-backed identity, browser login and consent flows, token/session/flow state, `private_key_jwt`, introspection, discovery metadata, endpoint-specific client authentication, and security-sensitive auth tests.
---

# Nauthilus Auth Identity

## Expertise Lens

- Work as an identity-protocol and authentication-security specialist for OIDC, OAuth2, SAML 2.0, MFA, WebAuthn, TOTP, LDAP-backed identity, and mail/web authentication integration.
- Treat endpoint audience, token/session state, replay prevention, MFA ceremony state, credential secrecy, and discovery metadata as security-critical.
- When exact protocol behavior matters, verify against primary specs or existing project tests before coding or making claims.

## Sources To Read

- `AGENTS.md`
- `POLICY.md`
- `README.md`
- `IDP.md`
- `server/idp/`
- `server/core/`
- `server/router/`
- `server/handler/frontend/idp/`
- `contrib/oidctestclient/README.md` or `contrib/saml2testclient/README.md` when test clients are in scope

## Auth Rules

- Keep endpoint-specific behavior precise: token endpoint auth, introspection endpoint auth, discovery metadata, and audience checks must not be conflated.
- For `private_key_jwt`, treat client assertion audience and replay protection as endpoint-specific security behavior.
- Prevent token, password, private key, assertion, session, and MFA secret leakage in logs, metrics, errors, docs, and fixtures.
- Keep Redis-backed token, flow, and session state consistent and fail closed on ambiguous state.
- For WebAuthn browser automation, use a CDP VirtualAuthenticator instead of platform authenticators.
- Keep browser-only MFA routes, management API routes, and IdP protocol routes separated according to route contract tests.

## Implementation Workflow

1. Add a focused reproducer test first for auth bugs.
2. Identify the exact endpoint or flow before changing shared auth logic.
3. Keep changes in cohesive domain types rather than spreading conditional logic through handlers.
4. Update OpenAPI, route contracts, discovery metadata, docs, and test clients when public behavior changes.
5. Verify generated artifacts if API surfaces changed.

## Validation

- Run focused tests for touched packages, always with `GOEXPERIMENT=runtimesecret`.
- Run route/OpenAPI tests when routes or API docs move.
- Run WebAuthn/MFA browser automation with virtual authenticators when the workflow requires browser proof.
- Run `GOEXPERIMENT=runtimesecret make test` and `git diff --check`.
- Run `make guardrails` before commit or pull request.
