# Policy Response Message Localization - nauthilus_i18n Lua Module

## Goal

This implementation slice adds the optional `nauthilus_i18n` Lua module for
deployment-owned localization helpers and startup catalog overlays.

It intentionally does not integrate response rendering into HTTP, gRPC, or IdP
UI flows. Final auth responses still use the policy-selected response-message
metadata and the transport renderer work planned for later slices.

## Implemented Model

- `nauthilus_i18n.get_localized({ ... })` accepts exactly one Lua table and
  returns exactly one Lua table with `message`, `language`, `localized`,
  `i18n_key`, and `fallback_used`.
- `get_localized` uses the shared transport-neutral localization resolver and
  preserves fallback behavior when a key is missing. It passes the active Lua
  execution context to the resolver.
- Explicit Lua `language` input drives the selected language for this helper.
  Invalid language values fall through the resolver preference chain.
- `nauthilus_i18n.register_catalog({ ... })` accepts exactly one Lua table with
  `language`, optional `namespace`, and string-to-string `entries`.
- Catalog registration is available only to startup Lua execution. Request-time
  Lua receives the module, but catalog mutation is rejected.
- Deployment overlays are merged on top of the system catalog through the shared
  effective catalog model.
- Deployment overlays may override system keys and earlier deployment entries.
- Failed catalog registration builds do not replace the previously active
  effective catalog.
- The effective request-time catalog remains immutable.

## Wiring

- Lua VM startup preloads `nauthilus_i18n` as a request-time read-only module.
- Standard request-time Lua bindings expose the read-only module.
- Lua init execution rebinds the module in startup mode with a catalog session.
  `register_catalog({ ... })` is allowed only there, and collected overlays are
  activated only after the init script succeeds.
- Server startup configures the default Lua i18n runtime with the existing
  language manager as the system catalog.

## Tests and Validation

Focused tests were added in `server/lualib/i18n_test.go`.

Validated behavior:

- single-table argument validation;
- explicit table return shape;
- fallback text for missing keys;
- selected language reporting;
- invalid language handling through resolver fallback;
- deterministic catalog merge order;
- deployment overlay override of system keys;
- request-time catalog mutation rejection;
- failed catalog registration rollback.

Validation commands:

```text
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/lualib -run 'TestI18N'
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core/localization
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
```

## Deliberately Not Implemented

- No HTTP auth `Accept-Language` or `Content-Language` integration.
- No gRPC auth metadata integration.
- No IdP UI bridge.
- No changes to `server/resources/*.json`.
- No website documentation changes.
- No request-header or request-metadata policy-attribute work.

## Open Points For The Next Slice

- Wire the shared resolver into HTTP and gRPC auth rendering with fake resolver
  tests.
- Define and test the response metadata behavior when fallback text is used
  because no translation exists.
- Keep this Lua module as a companion helper, not as the primary final-auth
  response rendering path.
