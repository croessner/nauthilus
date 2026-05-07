# Change Request: Policy Response Message Localization

## Status

Draft for implementation review.

Date: 2026-05-07

## Goal

Extend the Policy Decision Layer so policy-selected response messages can be
localized consistently across IdP browser flows, HTTP backchannel auth requests,
and gRPC auth requests.

The feature must preserve the existing behavior for plain status messages and
Lua `nauthilus_builtin.status_message_set(...)` fallbacks while adding an
implementation-ready path for stable i18n keys:

```yaml
response_message:
  from: i18n
  i18n_key: auth.policy.account_locked
  fallback: "This account is locked."
```

The policy decision itself remains locale-neutral. Locale negotiation and text
rendering happen only at the response boundary.

## Background

The Policy Decision Layer can already select a response message from built-in
standard-auth facts, literal config, attribute values, and Lua script details.
Lua scripts can call `nauthilus_builtin.status_message_set(...)`; for
`standard_auth` this value is collected as a script result detail and may be
selected as the final response message when the script contributes the winning
deny or reject decision.

This is sufficient for single-language status text, but it is not sufficient for
localized UI and transport responses:

- The selected policy response message is currently a rendered string, not a
  stable localization key.
- IdP browser login error handling currently collapses authentication failures
  to generic localized UI text instead of preserving the policy-selected status
  message.
- HTTP and gRPC backchannel responses do not have a shared transport-neutral
  locale negotiation model.
- Lua `status_message_set(...)` carries free text only. It should remain useful
  as fallback text, but policy decisions should use stable emitted facts for
  machine-readable reason selection.

## Non-Goals

- Do not make locale or language preference influence the selected auth
  decision. Language preference may only influence final response rendering.
- Do not infer i18n keys from free-text status messages.
- Do not rename the field to `message_id`; the public field is `i18n_key`.
- Do not require a protocol-breaking gRPC response shape change for the first
  implementation.
- Do not introduce a separate legacy response pipeline.
- Do not make Lua scripts directly authoritative for final localized messages in
  the first implementation. Lua emits facts; policy maps facts to response
  messages.
- Do not expose arbitrary request headers as policy attributes by default.
- Do not add interpolation arguments for localized response text in the first
  implementation. If this is needed later, it must be a separate design with
  strict allowlists.

## Current Behavior To Preserve

Existing behavior must remain unchanged unless an i18n response message is
explicitly configured:

- `response_message.from: default` keeps the built-in selected message behavior.
- Literal response messages keep returning the configured literal text.
- Attribute or attribute-detail response messages keep returning the selected
  value or detail.
- `fallback` remains the safe final text when the selected source cannot be
  resolved.
- `nauthilus_builtin.status_message_set(...)` remains valid Lua fallback
  behavior.
- Existing HTTP and gRPC response fields or headers that currently expose a
  status message continue to expose a rendered string.

## Target Model

### Configuration

Add an explicit i18n source to policy response messages:

```yaml
response_message:
  from: i18n
  i18n_key: auth.policy.company.account_unpaid
  fallback: "Login failed because open payments exist and the account is locked."
```

Rules:

- `from: i18n` requires `i18n_key`.
- `fallback` is strongly recommended and should be required unless there is an
  existing default message for the rule.
- `text`, `attribute`, and `detail` must not be used with `from: i18n`.
- `i18n_key` must be a stable catalog key. Recommended namespace:
  `auth.policy.<domain>.<reason>`.
- The compiler must reject unknown `from` values with a clear config error.

### Policy Runtime

The compiled policy response message plan must carry both the stable key and the
fallback text:

- `Source`: includes the new value `i18n`.
- `I18NKey`: stable localization key.
- `Fallback`: safe transport-neutral fallback text.
- `MaxLength`: still applies to fallback and rendered localized text.

The policy evaluator selects response message metadata, not a localized final
string. The report-facing selected response message should include enough
metadata to explain the decision without making localization part of policy
evaluation.

Recommended selected-message shape:

```go
type ResponseMessageSelection struct {
    Source       string
    Message      string
    I18NKey      string
    AttributeID  string
    Detail       string
    Truncated    bool
}
```

`Message` remains the safe fallback or selected non-i18n text. `I18NKey` is set
only when the policy selected an i18n response message.

### Authentication Runtime

The auth runtime and outcomes need to preserve both fallback text and i18n key
until the transport renderer has access to the request language.

Recommended minimal model:

```go
type AuthStatusMessage struct {
    Text      string
    I18NKey   string
    Language  string
    Localized bool
}
```

The implementation may embed this as a small struct or use explicit fields on
the existing runtime and outcome structs. The important invariant is:

- Policy authority applies `Text` and `I18NKey`.
- Response rendering resolves `I18NKey` into localized text when possible.
- Existing callers that only know `StatusMessage string` receive the rendered
  text, falling back to `Text`.

### Locale Negotiation

Use standard language negotiation primitives:

- HTTP request header: `Accept-Language`
- gRPC incoming metadata key: `accept-language`
- Optional policy-selected response language from configured policy facts.
- HTTP response header: `Content-Language`
- gRPC response metadata key: `content-language`

There is no standard `Accepted-Locale` header. The standard request header is
`Accept-Language`.

Negotiation rules:

1. IdP browser UI keeps its existing UI language sources:
   URL language tag, language cookie, policy-selected response language, then
   `Accept-Language`.
2. HTTP backchannel auth requests use policy-selected response language, then
   `Accept-Language`.
3. gRPC auth requests use policy-selected response language, then incoming
   metadata `accept-language`.
4. Policy-selected response language is a server-side preference. It may override
   `Accept-Language`, but it must not override an explicit IdP UI language
   selected by URL or cookie.
5. If no language preference is available, use the configured/default language.
6. If the selected key is missing in the selected language, use the configured
   fallback text.
7. If a fallback is used because no translation exists, the response may omit
   `Content-Language` or set it to the selected fallback language. The
   implementation must choose one behavior and test it consistently.

Locale negotiation must be transport-neutral. Do not duplicate language parsing
logic in each handler. Introduce a small shared resolver that can be used from
Gin handlers, raw HTTP auth handlers, and gRPC handlers.

### Localization Resolver

Add a shared resolver around the existing language manager and resource bundle.
The resolver must not depend on Gin.

Recommended responsibilities:

- Parse weighted `Accept-Language` values.
- Match preferred tags against configured supported languages.
- Resolve an `i18n_key` to a localized string.
- Return fallback text when the key is missing.
- Return the selected language tag and whether localization happened.
- Apply the existing response-message length limit after localization.

Example API shape:

```go
type MessageResolver interface {
    ResolveStatusMessage(ctx context.Context, selection AuthStatusMessage, preference LanguagePreference) ResolvedStatusMessage
}

type LanguagePreference struct {
    Explicit string
    Policy   string
    Header   string
    Tags     []string
    Default  string
}

type ResolvedStatusMessage struct {
    Text      string
    Language  string
    Localized bool
    Key       string
}
```

`Explicit` is reserved for IdP URL or cookie language selection. `Policy` is the
policy-selected response language. `Header` is the raw `Accept-Language` value,
and `Tags` can carry already-parsed preferences when a caller has them.

The exact names may differ, but the implementation must keep a single
authoritative resolver for all transports.

### Policy-Selected Response Language

Add an optional response-language selection next to response-message selection.
This is response metadata, not an authentication decision.

Recommended policy shape:

```yaml
then:
  decision: deny
  response_marker: auth.response.fail
  response_language:
    from: literal
    language: de
  response_message:
    from: i18n
    i18n_key: auth.policy.company.account_blocked
    fallback: "Login failed because the account is locked."
```

Alternative attribute-driven shape:

```yaml
then:
  decision: deny
  response_marker: auth.response.fail
  response_language:
    from: attribute
    attribute: lua.company.preferred_language
    fallback: de
  response_message:
    from: i18n
    i18n_key: auth.policy.company.account_blocked
    fallback: "Login failed because the account is locked."
```

Rules:

- `response_language` is optional.
- `from: literal` requires a BCP 47 language tag in `language`.
- `from: attribute` requires an attribute whose value is a BCP 47 language tag.
- The compiler should validate literal tags and reject invalid values.
- Runtime attribute values should be parsed as language tags. Invalid values are
  ignored and fall back to the next language preference source.
- `response_language` applies only when a localized response message is being
  rendered.
- `response_language` must be reported separately from the selected auth
  decision.

### Request Header And Metadata Policy Attributes

Expose non-standard HTTP request headers and gRPC metadata to policy only
through explicit allowlists. This avoids leaking credentials, session
identifiers, proxy internals, and high-cardinality values into policy reports or
logs.

Recommended config shape:

```yaml
auth:
  policy:
    request_headers:
      - header: X-Company-Domain
        attribute: request.header.company_domain
        visibility: public
        normalize:
          trim: true
          case: lower
          max_length: 64

    request_metadata:
      - key: x-company-domain
        attribute: request.metadata.company_domain
        visibility: public
        normalize:
          trim: true
          case: lower
          max_length: 64
```

Runtime behavior:

- Header names are matched case-insensitively.
- gRPC metadata keys are matched in lowercase form.
- Attribute IDs are stable policy IDs and must be unique.
- Values are trimmed and length-limited before entering the policy context.
- Optional case normalization should be explicit; do not lowercase by default if
  deployments need case-sensitive values.
- Multiple header values should be joined only through a documented deterministic
  rule, or rejected for single-value attributes.
- Registered header attributes can be consumed by policy rules like any other
  public request attribute.
- Registered metadata attributes follow the same rules as registered header
  attributes.

Example mapping from a proxy-provided domain header to response language:

```yaml
auth:
  policy:
    request_headers:
      - header: X-Company-Domain
        attribute: request.header.company_domain
        visibility: public
        normalize:
          trim: true
          case: lower
          max_length: 64

    attributes:
      - id: lua.company.account_status
        kind: string
        scope: request
        visibility: public

    rules:
      - name: deny_blocked_account_for_company_de
        stage: auth_decision
        operations:
          - authenticate
        if:
          all:
            - attribute: lua.company.account_status
              is: blocked
            - attribute: request.header.company_domain
              is: companyde
        then:
          decision: deny
          response_marker: auth.response.fail
          response_language:
            from: literal
            language: de
          response_message:
            from: i18n
            i18n_key: auth.policy.company.account_blocked
            fallback: "Login failed because the account is locked."
```

This gives deployments a policy-native way to honor reverse-proxy routing
signals without inventing a custom language header.

### Lua-Selected Response Language

Lua can request a response-language candidate by emitting a registered policy
attribute. This keeps Lua in the existing fact-emitter role and lets policy
remain authoritative for how the emitted value is used.

Example:

```lua
local http_request = require("nauthilus_http_request")
local company_domain_values = http_request.get_http_request_header("X-Company-Domain")
local company_domain = company_domain_values[1]

if company_domain == "CompanyDE" then
    nauthilus_policy.emit_attribute({
        id = "lua.company.preferred_language",
        value = "de",
    })
end
```

Policy mapping:

```yaml
auth:
  policy:
    attributes:
      - id: lua.company.preferred_language
        kind: string
        scope: request
        visibility: public
      - id: lua.company.account_status
        kind: string
        scope: request
        visibility: public

    rules:
      - name: deny_blocked_account_with_lua_language_preference
        stage: auth_decision
        operations:
          - authenticate
        require_checks:
          - lua_subject_company_account
        if:
          attribute: lua.company.account_status
          is: blocked
        then:
          decision: deny
          response_marker: auth.response.fail
          response_language:
            from: attribute
            attribute: lua.company.preferred_language
            fallback: en
          response_message:
            from: i18n
            i18n_key: auth.policy.company.account_blocked
            fallback: "Login failed because the account is locked."
```

This is the recommended first implementation for Lua-driven language selection.
It avoids localizing too early inside Lua while still allowing deployment logic
to override `Accept-Language`.

### Optional Lua Localization Module

A new Lua module can still be useful as a companion feature for Lua-owned debug
messages, custom logs, notices, or deployment-specific fallback strings.

Recommended module name and function:

```lua
nauthilus_i18n.register_catalog({
    language = "de",
    namespace = "company",
    entries = {
        ["auth.policy.company.account_blocked"] = "Login failed because the account is locked.",
        ["auth.policy.company.account_unpaid"] = "Login failed because open payments exist and the account is locked.",
    },
})

local localized = nauthilus_i18n.get_localized({
    i18n_key = "auth.policy.company.account_blocked",
    fallback = "Login failed because the account is locked.",
    language = "de",
})

local message = localized.message
local language = localized.language
local was_localized = localized.localized
```

Function contract:

- Module name: `nauthilus_i18n`.
- Function name: `get_localized`.
- Argument: one Lua table with explicit keys.
- Input key `i18n_key`: required stable localization key.
- Input key `fallback`: required fallback text.
- Input key `language`: optional BCP 47 language tag.
- Return value: one Lua table with explicit keys.
- Return key `message`: rendered message.
- Return key `language`: selected language.
- Return key `localized`: boolean that is `true` when a catalog entry was used.
- Return key `i18n_key`: the requested key.
- Return key `fallback_used`: boolean that is `true` when fallback text was used.
- If input key `language` is omitted, use the request's current language
  preference.
- If the key is missing, return the fallback text and `localized=false`.
- Apply the same maximum length and sanitization rules used for response
  messages.
- Function name: `register_catalog`.
- `register_catalog` argument: one Lua table with explicit keys.
- `register_catalog` input key `language`: required BCP 47 language tag.
- `register_catalog` input key `namespace`: optional deployment namespace for
  logs and diagnostics.
- `register_catalog` input key `entries`: required table mapping i18n keys to
  localized strings.
- `register_catalog` is allowed only during startup/init Lua execution.
- Request-time Lua must not mutate the effective catalog.
- Catalog merge order is system catalog first, then deployment catalog overlays.
- Deployment overlays may override system keys.
- Each override should emit a structured log entry with language, key,
  namespace, and override status.
- After init succeeds, the effective catalog is frozen and shared as immutable
  resolver input.
- On config or Lua reload, build a new effective catalog and activate it
  atomically only after the full reload succeeds. A failed reload must leave the
  previous effective catalog active.

The Lua module should not be the primary bridge for final auth response
localization. Final auth responses should prefer policy-selected
`response_message` plus `response_language`, because that keeps decision reports,
transport behavior, and fallback handling consistent.

The catalog registration API is intended for deployment-owned startup overlays.
It gives deployments a controlled way to add or override language entries
without modifying `server/resources/*.json`.

## Lua Integration Model

Lua `status_message_set(...)` remains a fallback text mechanism. It should not be
the source of the i18n key.

For complex Lua scripts with multiple failure branches, Lua should emit a stable
machine-readable fact, and policy should map that fact to a localized response
message.

Example Lua migration:

```lua
if user_status == "unpaid" then
    nauthilus_builtin.status_message_set("Login failed because open payments exist and the account is locked.")
    nauthilus_policy.emit_attribute({
        id = "lua.company.account_status",
        value = "unpaid",
    })

    login_failed = true
elseif user_status == "blocked" then
    nauthilus_builtin.status_message_set("Login failed because the account is locked.")
    nauthilus_policy.emit_attribute({
        id = "lua.company.account_status",
        value = "blocked",
    })

    login_failed = true
end
```

Example policy mapping:

```yaml
auth:
  policy:
    attributes:
      - id: lua.company.account_status
        kind: string
        scope: request
        visibility: public

    rules:
      - name: deny_unpaid_account
        stage: auth_decision
        operations:
          - authenticate
        require_checks:
          - lua_subject_company_account
        if:
          attribute: lua.company.account_status
          is: unpaid
        then:
          decision: deny
          response_marker: auth.response.fail
          response_message:
            from: i18n
            i18n_key: auth.policy.company.account_unpaid
            fallback: "Login failed because open payments exist and the account is locked."

      - name: deny_blocked_account
        stage: auth_decision
        operations:
          - authenticate
        require_checks:
          - lua_subject_company_account
        if:
          attribute: lua.company.account_status
          is: blocked
        then:
          decision: deny
          response_marker: auth.response.fail
          response_message:
            from: i18n
            i18n_key: auth.policy.company.account_blocked
            fallback: "Login failed because the account is locked."
```

This gives each Lua branch a stable policy fact while preserving the legacy
status text as a fallback for standard-auth and non-localized transports.

## IdP Browser Flow

The IdP flow needs an explicit bridge from authentication outcome to UI error
rendering.

Current failure behavior collapses backend authentication errors to generic UI
text. The implementation must introduce a typed authentication failure or
equivalent outcome object that carries:

- Policy decision result.
- Rendered fallback status message.
- Optional `i18n_key`.
- Optional selected language after localization.
- Any existing failure reason needed for diagnostics.

Required behavior:

- IdP password login renders the policy-selected localized status message when
  the failed auth outcome carries an `i18n_key`.
- IdP password login uses policy-selected response language when no explicit UI
  language was selected by URL or cookie.
- IdP password login falls back to policy fallback text when the key cannot be
  localized.
- IdP password login falls back to the current generic invalid-login text only
  when no policy status message exists.
- Delayed-response login failures use the same rendering path.
- Device-code user-code verification failures use the same rendering path.
- MFA progression must not continue after a policy deny or reject.
- Logs and audit/report entries should include the stable key and fallback text,
  not just the localized rendered UI text.

## HTTP Backchannel Flow

HTTP auth endpoints should localize selected policy response messages when:

- The policy selected `response_message.from: i18n`.
- The request includes a policy-selected response language, `Accept-Language`, or
  a configured default language.
- The key can be resolved in the selected language.

Required behavior:

- Existing status message header/body fields contain the rendered localized
  string.
- Policy-selected response language takes precedence over `Accept-Language`.
- `Content-Language` is emitted when a language was selected for localization.
- If localization fails, the existing fallback string is returned.
- Existing response defaults such as generic password failure stay unchanged
  when policy does not select a status message.

## gRPC Backchannel Flow

gRPC auth endpoints should use incoming metadata:

```text
accept-language: de-DE,de;q=0.9,en;q=0.8
```

Required behavior:

- Existing `StatusMessage` response fields contain the rendered localized
  string.
- Policy-selected response language takes precedence over incoming metadata
  `accept-language`.
- Response metadata includes `content-language` when localization selected a
  language.
- If localization fails, the existing fallback string is returned.
- No initial protobuf schema change is required.

Optional future extension:

- Add an `i18n_key` field to the protobuf response so clients can perform their
  own localization. This is intentionally out of scope for the first
  implementation to avoid a wider protocol change.

## Catalog Handling

Do not add example-only policy response translations to the server repository's
production JSON language resources. The implementation should support resolving
configured `i18n_key` values, but this change request must not add demonstration
keys such as `auth.policy.company.*` to `server/resources/*.json`.

Tests should use fake catalogs or fake language managers for example keys. Real
server resource updates are allowed only for product-owned messages that are
actually shipped by Nauthilus, not for documentation examples.

The public documentation may show example JSON snippets for deployment-owned
translation catalogs. Those examples belong in the `nauthilus-website`
repository under `docs/`, not in the server resource files.

Deployment-owned runtime catalogs can be registered during startup through
`nauthilus_i18n.register_catalog({ ... })`. These catalogs are overlays on top
of the system catalog. They may add new keys and override system keys, but the
effective merged catalog must be immutable during request processing.

## Test Mocking Requirements

The implementation must be fully mockable in the existing test suite. Tests
should exercise the policy and transport boundaries without requiring real
Redis, real backend authentication, or production language bundles unless the
test explicitly validates bundled resource files.

Required test seams:

- Localization resolver:
  - Provide a small interface and a fake resolver for transport and IdP tests.
  - Provide a fake catalog or fake language manager for resolver unit tests.
  - Make missing-key, unsupported-language, fallback, and truncation behavior
    deterministic.
  - Do not add example translations to production JSON resource files for tests.
- Auth outcome bridge:
  - Allow IdP handler tests to inject an auth result or typed auth failure with
    `StatusMessage`, `I18NKey`, and selected response language.
  - Do not require a real passdb, Redis client, or full backend auth chain to
    test UI rendering behavior.
- HTTP request attributes:
  - Use `httptest` requests with explicit headers.
  - Test allowlisted and non-allowlisted headers separately.
  - Test normalization with deterministic input values.
- gRPC metadata attributes:
  - Use in-memory gRPC or handler-level tests with incoming metadata.
  - Mock or fake the auth service layer so metadata localization tests do not
    depend on backend auth.
- Lua policy emissions:
  - Preload Lua modules in hermetic Lua states.
  - Use fake request metadata for `nauthilus_http_request`.
  - Use a test `DecisionContext` and registered attributes to verify emissions.
- Optional `nauthilus_i18n` module:
  - Inject a fake resolver into the module loader.
  - Test the table argument validation, table return shape, fallback behavior,
    selected language, and invalid language handling.
  - Inject a fake startup catalog collector for `register_catalog`.
  - Test catalog merge order with fake system and deployment catalogs.
  - Test that deployment entries can override system keys.
  - Test that request-time Lua cannot mutate the frozen effective catalog.
  - Test that reload failure keeps the previous effective catalog active.
  - Test malformed input tables without needing production resource files.

The test implementation should prefer table-driven tests and shared fixtures so
the same resolver cases can be reused by HTTP, gRPC, IdP, and Lua tests.

## Implementation Plan

### Step 1: Reproducer Tests

Add focused tests first, before implementation:

- Config/schema compiler rejects or cannot compile `response_message.from: i18n`
  today. Keep the test and make it pass with the implementation.
- Policy evaluation preserves `i18n_key` and fallback in the selected response
  message.
- IdP password login currently returns the generic invalid-login UI text when
  policy selected a status message. Keep a test that proves the desired
  policy-selected localized message.
- Policy-selected language preference does not exist today. Keep a test that
  proves `response_language.from: literal` can override `Accept-Language` for
  response rendering without changing the selected auth decision.
- Allowlisted request-header and request-metadata facts do not exist today. Keep
  tests that prove configured `X-Company-Domain` and `x-company-domain` inputs
  become normalized policy attributes and can drive `response_language`.
- Lua-selected language preference is not bridged today. Keep a Lua-focused test
  that emits `lua.company.preferred_language` and proves policy can use it as
  `response_language`.
- Optional `nauthilus_i18n.get_localized(...)` does not exist today. If the
  module is implemented in this slice, keep Lua-focused tests that prove the
  single-table input contract and single-table return contract with a mocked
  resolver.
- Optional `nauthilus_i18n.register_catalog(...)` does not exist today. If the
  module is implemented in this slice, keep startup-Lua tests that prove catalog
  overlays, system-key overrides, frozen request-time behavior, and failed-reload
  rollback with fully mocked catalogs.
- gRPC auth currently ignores `accept-language`. Keep a test that proves a
  localized status message and `content-language` metadata.
- HTTP auth currently ignores `Accept-Language` for policy i18n response
  messages. Keep a test that proves a localized status message and
  `Content-Language`.

### Step 2: Config And Compiler

- Extend the config response-message struct with `i18n_key`.
- Extend validation for `from: i18n`.
- Add `response_language` config as response metadata with literal and attribute
  sources.
- Add allowlisted `auth.policy.request_headers` and
  `auth.policy.request_metadata` config for normalized request attributes.
- Extend compiled response-message plans with `I18NKey`.
- Extend compiled response-language plans with source, literal language,
  attribute ID, fallback, and validation metadata.
- Extend report selection with `I18NKey`.
- Extend reports with selected response-language metadata.
- Update config dump/redaction paths if they expose response-message config.
- Add negative tests for invalid combinations:
  - `from: i18n` without `i18n_key`.
  - `from: i18n` with `attribute`.
  - `from: i18n` with `detail`.
  - `from: i18n` with `text`.
  - `response_language.from: literal` without `language`.
  - `response_language.from: literal` with an invalid BCP 47 tag.
  - `response_language.from: attribute` without `attribute`.
  - `request_headers` or `request_metadata` entries with duplicate attribute IDs.
  - `request_headers` or `request_metadata` entries with unsafe or invalid
    attribute IDs.

### Step 3: Runtime Message Selection

- Update response-message evaluation so `from: i18n` selects the key and
  fallback without localizing it.
- Update response-language evaluation so literal or attribute-derived language
  preferences are selected next to the response message.
- Ignore invalid runtime language tags and continue with the next preference
  source.
- Keep the fallback length-bounded and sanitized through the existing response
  message constraints.
- Apply selected key and fallback in the policy authority boundary.
- Apply selected response-language metadata in the policy authority boundary.
- Preserve current behavior for all existing response-message sources.

### Step 4: Shared Localization Resolver

- Extract or introduce a Gin-independent localization resolver.
- Reuse the existing language manager and resource bundles.
- Add an immutable effective catalog abstraction that merges system catalogs with
  startup-registered deployment overlays.
- Merge order must be deterministic: system catalog first, deployment overlays
  after that.
- Deployment overlays may override system keys.
- Atomic reload must build a complete new effective catalog before activation.
- Failed reload must keep the previous effective catalog active.
- Support weighted `Accept-Language` parsing.
- Support a preference chain that can include explicit UI language,
  policy-selected response language, `Accept-Language`, and default language.
- Return rendered text, selected language, key, and localization status.
- Add unit tests for:
  - German preference resolves German text.
  - English preference resolves English text.
  - Policy-selected language overrides `Accept-Language` for HTTP and gRPC.
  - Explicit IdP URL or cookie language overrides policy-selected language.
  - Unsupported language falls back to default.
  - Missing key uses fallback text.
  - Rendered localized text still observes the maximum response-message length.
- Keep resolver tests backed by fake catalogs or fake language managers so edge
  cases do not depend on production resource files.

### Step 5: HTTP Auth Transport

- Capture `Accept-Language` from incoming HTTP auth requests.
- Capture configured request-header attributes before policy evaluation.
- Resolve the selected policy status message at the response boundary.
- Set `Content-Language` when localization selects a language.
- Keep existing default failure text when no status message was selected.
- Add focused HTTP tests for header/body behavior with a fake resolver.

### Step 6: gRPC Auth Transport

- Capture incoming metadata `accept-language`.
- Capture configured request-header-equivalent metadata only if explicitly added
  to the gRPC request metadata allowlist.
- Resolve the selected policy status message at the response boundary.
- Set response metadata `content-language` when localization selects a language.
- Keep the current protobuf response shape for the initial implementation.
- Add focused gRPC tests for metadata in and out with a fake resolver and mocked
  auth outcome.

### Step 7: IdP Browser Flow

- Introduce a typed authentication failure or outcome bridge that preserves
  policy-selected status message metadata.
- Update IdP password login, delayed-response completion, and device-code user
  verification to use one shared message rendering helper.
- Preserve existing generic invalid-login localization only as fallback.
- Add tests for policy-selected message rendering and fallback behavior with
  mocked auth outcomes and a fake resolver.

### Step 8: Website Documentation

All documentation work in this step belongs in the sibling
`nauthilus-website` repository under `docs/`. Do not add example-only
translations to the server repository's JSON resource files.

- Document the recommended Lua migration pattern in website docs:
  `status_message_set(...)` for fallback text plus
  `nauthilus_policy.emit_attribute(...)` for stable reason facts.
- Document Lua-selected language preference through emitted attributes.
- Add or update policy examples that map emitted Lua reason facts to `i18n_key`.
- Add or update policy examples that map request headers to response language.
- Explain deployment-owned translation JSON with documentation examples in
  `nauthilus-website/docs/`, not by changing `server/resources/*.json`.
- Do not add direct Lua i18n key emission in the first implementation.
- Treat `nauthilus_i18n.get_localized(...)` as an optional companion feature. If
  implemented in this slice, it must share the transport-neutral resolver and
  must not become the primary final-auth response bridge.
- Treat `nauthilus_i18n.register_catalog(...)` as an optional startup-only
  deployment overlay feature. If implemented in this slice, document the table
  API, merge order, system-key override behavior, frozen request-time catalog,
  and atomic reload rollback behavior.

### Step 9: Review And Guardrails

- Run focused package tests while iterating.
- Run repository guardrails before closing the implementation.
- Reconcile the implementation against this CR and the main Policy Decision
  Layer specification.

Required command shape for Go tests:

```sh
GOEXPERIMENT=runtimesecret go test ./...
```

Use a sandbox-local cache when needed:

```sh
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/evaluation ./server/core
```

Final validation should include:

```sh
GOEXPERIMENT=runtimesecret make guardrails
```

## Acceptance Criteria

- `response_message.from: i18n` is accepted by config validation when
  `i18n_key` is present.
- Invalid `from: i18n` combinations fail with clear config errors.
- Policy evaluation records the selected `i18n_key` and fallback without
  resolving language.
- Policy evaluation records selected `response_language` metadata without
  localizing the response message.
- `response_language.from: literal` and `response_language.from: attribute` are
  validated and evaluated.
- Configured request headers are exposed as normalized policy attributes only
  when explicitly allowlisted.
- Configured gRPC metadata keys are exposed as normalized policy attributes only
  when explicitly allowlisted.
- HTTP auth responses honor `Accept-Language` for selected i18n response
  messages.
- HTTP auth responses honor policy-selected response language before
  `Accept-Language`.
- HTTP auth responses emit `Content-Language` when localization selects a
  language.
- gRPC auth responses honor incoming metadata `accept-language`.
- gRPC auth responses honor policy-selected response language before incoming
  metadata `accept-language`.
- gRPC auth responses emit response metadata `content-language` when
  localization selects a language.
- IdP password login renders policy-selected localized status messages.
- Explicit IdP UI language selection by URL or cookie has priority over
  policy-selected response language.
- IdP delayed-response and device-code failures use the same status-message
  rendering path as password login.
- Lua scripts can keep `status_message_set(...)` fallback behavior.
- Lua scripts can emit stable reason attributes that policies map to i18n
  response messages.
- Lua scripts can emit stable language preference attributes that policies map to
  `response_language`.
- The optional `nauthilus_i18n` Lua module, if implemented in this change,
  shares the same resolver and fallback behavior as final response rendering and
  uses a single Lua table argument plus a single Lua table return value.
- The optional `nauthilus_i18n.register_catalog` startup API, if implemented in
  this change, can add deployment keys, override system keys, freeze the
  effective catalog for request-time use, and preserve the previous catalog on
  failed reload.
- HTTP, gRPC, IdP, resolver, request-attribute, Lua-emission, and optional
  `nauthilus_i18n` tests are fully mockable and do not require real backend
  authentication, Redis, or production resource bundles.
- Missing translations fall back to configured fallback text.
- Language preference never changes the selected policy decision.
- Logs and reports include stable key/fallback metadata and do not rely only on
  localized rendered text.
- Existing configurations without `from: i18n` keep their current behavior.

## Security And Privacy Requirements

- Treat `Accept-Language` and gRPC `accept-language` metadata as untrusted input.
- Never use language preference in policy conditions or authentication
  decisions.
- Expose non-standard request headers and gRPC metadata only through explicit
  allowlists.
- Validate and sanitize allowlisted header and metadata values before adding
  them to the policy context.
- Do not log raw non-standard header or metadata values unless the attribute is
  explicitly public and length-limited.
- Validate policy-selected response language values as BCP 47 tags.
- Keep response-message length limits for fallback and localized output.
- Do not expose hidden attribute details through localized messages.
- Do not add dynamic interpolation arguments in the first implementation.
- Do not derive i18n keys from user-controlled Lua text.
- Allow deployment catalog overlays only during startup/init Lua execution.
- Freeze effective catalogs before request processing and reject request-time
  catalog mutation.
- Log system-key overrides by deployment catalogs without logging sensitive
  request data.
- Keep logs low-cardinality where possible by logging `i18n_key` and selected
  language separately from rendered message text.

## Documentation Updates

Update the public documentation in the sibling `nauthilus-website` repository
under `docs/` after implementation:

- Add `response_message.from: i18n`.
- Add `response_language` as response-rendering metadata.
- Add allowlisted request-header and gRPC metadata policy attributes.
- Replace any proposed `message_id` wording with `i18n_key`.
- Document HTTP `Accept-Language` and response `Content-Language`.
- Document gRPC `accept-language` and response `content-language` metadata.
- Document the Lua branch-reason pattern with `nauthilus_policy.emit_attribute`.
- Document Lua-selected response language through emitted policy attributes.
- Document the optional `nauthilus_i18n.get_localized(...)` helper if it is
  implemented in this slice. The helper must use an explicit Lua table API.
- Document the optional `nauthilus_i18n.register_catalog(...)` startup overlay
  helper if it is implemented in this slice. The helper must use an explicit Lua
  table API and must document merge and override semantics.
- Document required mock seams for resolver, transport handlers, IdP auth
  outcomes, request attributes, and Lua modules.
- Document deployment-owned translation JSON with examples in website docs.
- Document fallback semantics and missing-translation behavior.

This CR remains the server-repository implementation artifact. Do not add
documentation-only example translations to `server/resources/*.json`.

## Open Questions For Review

1. Should `fallback` be strictly required for `from: i18n`, or should it be
   optional when a rule already has a safe built-in default?

   Recommendation: require `fallback` for explicit configured i18n response
   messages. It makes backchannel behavior deterministic even without a catalog.

2. Should HTTP auth always localize by default when an i18n key is selected, or
   should this require a server config toggle?

   Recommendation: localize by default when a key is selected. Without
   `Accept-Language`, use the configured default language or fallback text.

3. Should the gRPC protobuf response expose `i18n_key` in addition to localized
   `status_message`?

   Recommendation: not in the first implementation. Use existing
   `status_message` plus `content-language` metadata first.

4. Should `response_language` be a sibling of `response_message`, or should it
   be modeled as generic advice?

   Recommendation: make it an explicit sibling. It is response-rendering
   metadata with strict language-tag validation, and that is clearer than
   overloading generic advice.

5. Should all request headers and gRPC metadata become policy material
   automatically?

   Recommendation: no. Expose only explicitly allowlisted headers and metadata
   keys as normalized policy attributes. This keeps secrets, session
   identifiers, and high-cardinality values out of reports by default.

6. Should Lua-selected language preference be modeled by direct Lua APIs or by
   emitted policy attributes?

   Recommendation: use emitted attributes for the first implementation. Lua can
   derive `de` from deployment-specific request context, but policy remains the
   place that decides whether that value is used as `response_language`.

7. Should the `nauthilus_i18n` Lua module be implemented in this same slice?

   Recommendation: optional. It is useful for Lua-owned logs and notices, but it
   should share the same resolver and should not replace final response
   localization through policy. If implemented, it must accept one explicit Lua
   table and return one explicit Lua table.

8. Should `nauthilus_i18n.register_catalog(...)` load catalogs from files or
   accept tables only?

   Recommendation: start with an explicit Lua table API only. Startup Lua can
   decide how to construct that table. A file-loading helper can be added later
   with path allowlists and separate security review.

9. Should deployment catalogs be allowed to override system keys?

   Recommendation: yes. Overriding system keys is useful for deployment tone and
   product-specific wording. Each override should be logged with language, key,
   namespace, and override status.

10. Should request-time Lua be allowed to register or mutate catalogs?

   Recommendation: no. Catalog registration is startup/init only. The effective
   catalog must be frozen before request processing.

11. Should Lua get a first-class helper such as
   `nauthilus_policy.emit_response_reason(...)`?

   Recommendation: not initially. Use registered public attributes first. Add a
   helper later only if repeated Lua policy facts become too verbose.

12. Should localized response messages support template arguments?

   Recommendation: not initially. Template arguments need a separate security
   review and a strict allowlist.
