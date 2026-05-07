# Policy Response Message Localization - Shared Resolver And Catalog Model

## Goal

This implementation slice adds the transport-neutral localization resolver,
language preference chain, immutable effective catalog model, and atomic catalog
activation primitives for policy-selected i18n response messages.

It intentionally does not integrate response rendering into HTTP, gRPC, IdP UI,
or Lua request-time code. The optional `nauthilus_i18n` Lua module is also not
implemented in this slice.

## Implemented Model

- `server/core/localization` defines a transport-neutral `MessageResolver`
  interface with `StatusMessage`, `LanguagePreference`, and
  `ResolvedStatusMessage` data shapes.
- `Resolver` evaluates language preferences in this order:
  1. explicit UI language;
  2. policy-selected response language;
  3. caller-provided parsed tags;
  4. weighted `Accept-Language` header;
  5. request/default language;
  6. resolver default language.
- `ManagerCatalog` adapts the existing language manager and resource bundle as
  the system catalog without depending on Gin.
- `MapCatalog` provides an immutable fake catalog for unit tests and later
  deployment-owned catalog construction paths.
- `EffectiveCatalog` freezes request-time lookup by copying deployment overlay
  entries and resolving them before the system catalog.
- Deployment overlays are applied in caller-provided order. Later overlays may
  override earlier overlays or system keys.
- `CatalogStore` builds and publishes complete effective catalogs atomically.
  A failed reload leaves the previously active catalog unchanged.

## Tests and Validation

Focused tests were added in `server/core/localization/resolver_test.go`.

Validated behavior:

- explicit language overrides policy and header preferences;
- policy-selected language overrides `Accept-Language`;
- weighted `Accept-Language` values select the preferred supported language;
- invalid or unsupported language preferences fall back to the default language;
- missing i18n keys use fallback text;
- localized and fallback text observe the configured maximum length;
- deployment overlays override system keys deterministically;
- effective catalogs are frozen against later input map mutation;
- failed catalog reload preserves the previous active catalog.

Validation command:

```text
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core/localization
```

## Deliberately Not Implemented

- No HTTP `Accept-Language` or `Content-Language` integration.
- No gRPC metadata integration.
- No IdP UI bridge.
- No request-time localization in existing auth outcomes.
- No `nauthilus_i18n` Lua module.
- No changes to `server/resources/*.json`.

## Open Points For The Next Slice

- Wire the resolver into HTTP and gRPC auth rendering with fake resolver tests.
- Decide the transport behavior for `Content-Language` when fallback text is
  used because a selected i18n key is missing.
- Keep IdP URL and cookie language precedence above policy-selected language
  when the IdP bridge is implemented.
- Reuse `CatalogStore` for startup or reload-owned deployment catalog
  activation when the Lua registration API is introduced.
