# Policy configuration hard cut and manual migration

This guide is the breaking-change and manual migration contract from the
removed `auth.policy` configuration to the production namespace-owned policy
model. It is deliberately field-complete: each old concept has one new owner,
one decode path, one validation path, and one canonical dump path.

Top-level `policy` is the sole production configuration and runtime authority
for authentication, identity-provider, backchannel, Policy HTTP, and Policy
gRPC decisions. Production `FileSettings` owns that top-level field and does
not read `auth.policy`. Old-root and mixed-root inputs are rejected before
candidate preparation.

No runtime, startup, library, supported converter, or offline translator from
`auth.policy` to top-level `policy` exists. Operators must author the new
configuration directly from this guide. The former configuration-converter
surface has been removed and is not replaced. The repository may retain frozen
old inputs and independently authored new inputs as test-only rejection and
parity oracles, but those fixtures are not a decoder, converter, or migration
API.

## Field-complete mapping

The following seventeen rows are the complete B001-C2 mapping. Paths beginning
with `auth.policy` describe removed input. Paths beginning with `policy` are the
sole production representation.

| Mapping family | Removed path | New owner and exact path | Default or identity | Validation contract |
|---|---|---|---|---|
| Mode | `auth.policy.mode` | `policy.targets[].mode` on every activated target with `namespace: authn` | Default `enforce`; copy the old value to every migrated authn target. | Only `enforce` and `observe` are valid authn target modes. |
| Default policy | `auth.policy.default_policy` | `policy.targets[].default_policy` on every activated authn target | The only builtin fallback identity is `authn/standard_auth`. | The unqualified `standard_auth` spelling is rejected. |
| Localization catalogs | `auth.policy.localization.catalogs` | `policy.namespaces.authn.localization.catalogs` | Default empty; the translation namespace remains distinct from `authn`. | Every catalog requires a namespace, language, and entries map. |
| Network condition sets | `auth.policy.sets.networks` | `policy.namespaces.authn.condition_sets.networks` | Default empty; `@network.<name>` references retain their meaning. | Network sets remain namespace-owned operands of the compiled source policy set. |
| String condition sets | `auth.policy.sets.strings` | `policy.namespaces.authn.condition_sets.strings` | Default empty; `@string.<name>` references retain their meaning. | String sets remain namespace-owned operands of the compiled source policy set. |
| Time-window condition sets | `auth.policy.sets.time_windows` | `policy.namespaces.authn.condition_sets.time_windows` | Default empty; `@time_window.<name>` references retain their meaning. | Each configured interval requires non-empty `start` and `end` values. |
| Scheduler guards | `auth.policy.scheduler_guards` | `policy.namespaces.authn.domain_plans.<plan>.scheduler_guards` | Default empty; guards are visible only inside their exact domain plan. | `on_missing_attribute` is omitted or exactly `run`, preserving the legacy compiler contract. |
| Report settings | `auth.policy.report` | `policy.targets[].report` on each activated authn target | Defaults are `enabled: false`, `include_fsm: true`, `include_checks: true`, and `include_attributes: false`. | Authn-only report detail fields are rejected on non-authn targets. |
| Lua environment providers | `auth.policy.attribute_sources.lua.environment` | `policy.namespaces.authn.providers.lua_environment_<old-name>` | The exact provider identity is `authn/lua_environment_<old-name>`. | The provider kind is `lua_environment`; strict production decoding accepts only the canonical `script_path` field, which production validation requires to be non-empty; file/source resolvability belongs to candidate compilation. |
| Lua subject providers | `auth.policy.attribute_sources.lua.subject` | `policy.namespaces.authn.providers.lua_subject_<old-name>` | The exact provider identity is `authn/lua_subject_<old-name>`. | The provider kind is `lua_subject`; strict production decoding accepts only the canonical `script_path` field, which production validation requires to be non-empty; file/source resolvability belongs to candidate compilation. |
| Lua action effects | `auth.policy.obligation_targets.lua.actions` | `policy.namespaces.authn.effects.lua_action_<old-name>` | The exact effect identity is `authn/lua_action_<old-name>`, with mandatory `execution`. | `post` requires `host_post_action`; all other retained Lua action types require `host_sync`. |
| Lua registry scripts | `auth.policy.registry_scripts` | `policy.namespaces.authn.schema_contributions.lua.registry_scripts` | Default empty; scripts contribute bounded authn-owned fact definitions only during candidate compilation. | Every configured registry-script path is non-empty. |
| HTTP header fact sources | `auth.policy.request_headers` | `policy.namespaces.authn.fact_sources.http_headers` | Default empty; source, fact, normalization, visibility, and bounds retain their meaning. | Each entry requires a non-empty header and a canonical fact identity. |
| gRPC metadata fact sources | `auth.policy.request_metadata` | `policy.namespaces.authn.fact_sources.grpc_metadata` | Default empty; source, fact, normalization, visibility, and bounds retain their meaning. | Each entry requires a non-empty metadata key and a canonical fact identity. |
| Backend attribute fact sources | `auth.policy.attribute_exports` | `policy.namespaces.authn.fact_sources.backend_attributes` | Default empty; backend name, fact, type, and sensitivity retain their meaning. | Each entry requires a name, canonical fact identity, exact value kind, and supported sensitivity. |
| Checks | `auth.policy.checks` | `policy.namespaces.authn.domain_plans.<plan>.checkpoints.<checkpoint>.providers[]` | Check `type` plus `config_ref` becomes one deterministic exact `use` identity. | The containing checkpoint owns the removed check stage, and `use` must be exact. |
| Rules | `auth.policy.policies` | `policy.namespaces.authn.policy_sets.configured.rules[]` | Default empty; migrated rules are authored once in private `authn/configured`. | Every imported rule is validated against its exact target action and checkpoint. |

The old Lua provider `name` is appended to the reserved
`lua_environment_` or `lua_subject_` prefix. The old Lua action `name` is
appended to `lua_action_`; its old `type` becomes `action_type`, and
`script_path` remains `script_path`. The retained action types
`brute_force`, `rbl`, `tls_encryption`, `relay_domains`, and `lua` use
`host_sync`; only `post` uses `host_post_action`. Operator configuration does
not add an internal effect-provider binding. Builtin standard-auth effect
descriptors and host bindings remain immutable catalog contributions.

For Lua actions too, strict decoding accepts only the canonical `script_path`
field and production validation requires a non-empty value. Opening the file,
resolving the configured source, and binding its host implementation belong to
candidate compilation. None of these checks translates an old configuration.

Native and plugin provider definitions have no additional legacy storage in the
new model. Configured definitions belong below
`policy.namespaces.<namespace>.providers.<name>`. Loaded descriptors contribute
the real binding and exact output schemas; the matching configured definition
declares the module, target actions, and execution modes. Neither side silently
synthesizes the other. A provider instance references the resulting exact
identity with `use` and never stores a Viper path.

Target timeouts have no removed `auth.policy` source. Generic targets must
provide positive `timeouts.evaluation` and `timeouts.provider_default` values;
authn continues to use its host-owned timeout sources. This is a new generic
target requirement, not a migrated eighteenth row.

## Generic Lua provider configuration

Generic Lua providers likewise have no removed `auth.policy` source and do not
add a mapping row. They use the production namespace-owned `kind: lua` path and
are activated only when their target, schema, provider, and effect bindings all
pass candidate-generation validation. They must not be represented as
`lua_environment`, `lua_subject`, or `lua_action`: those kinds preserve the
existing implicit `authn` behavior only.

```yaml
policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message:
            versions:
              v1:
                facts:
                  - attribute: lua.reputation.risk_score
                    category: environment
                    type: integer
                    allowed_sources: [lua]
      providers:
        risk:
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          targets: [{action: sign-message}]
          produced_facts: [lua.reputation.risk_score]
          executions: [host_sync]
          requires: []
          failure: indeterminate
          timeout: 100ms
          diagnostics: {public_id: reputation}
      effects:
        record-audit:
          kind: obligation
          provider: dkim2/risk
          targets: [{action: sign-message}]
          execution: host_sync
          parameters:
            message:
              type: string
              max_length: 32
              non_empty: true
              required: true
```

`module` is the canonical lowercase Lua authority. The example's authored provider key resolves to the immutable
internal identity `dkim2/lua.reputation.risk`, and the callback returns local `risk_score` for the host-qualified fact
`lua.reputation.risk_score`. Every produced fact must exist with identical category, type, and bounds in every exact
target schema and must allow source `lua`. Explicit targets are used as written; when omitted, target-aware preparation
derives them only from exact plan and effect bindings.

`failure` is mandatory and is exactly `indeterminate` or compiler-safe `continue`. The shared scheduler handles
dependencies and `skipped_dependency`; Lua cannot return an auth-style abort or reorder the plan. Contract violations
such as undeclared facts, source/authority mismatch, wrong type or bounds, or fact collisions always fail closed as
`indeterminate` regardless of `continue`.

Generic scripts register `_G["policy.facts.collect"]` and, when the provider owns selected host effects,
`_G["policy.effects.execute"]`. Only selected `host_sync` and `host_post_action` obligations execute. Advice and
`return_only` effects never call Lua. Post-actions require host-supervisor acceptance before response finalization, and
Lua receives neither the finalization gate nor detached-work authority. The generic contract has no automatic retry,
replay, idempotency, or deduplication fields. The exact Lua tables and strict typed-value encodings are documented in
`server/lua-plugins.d/policy/README.md`.

## Generic native provider configuration

```yaml
policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message:
            versions:
              v1:
                facts:
                  - attribute: plugin.reputation.risk_score
                    category: environment
                    type: integer
                    allowed_sources: [plugin]
      providers:
        risk:
          kind: native
          module: reputation
          targets: [{action: sign-message}]
          produced_facts: [plugin.reputation.risk_score]
          requires: []
          failure: indeterminate
          timeout: 100ms
          diagnostics: {public_id: reputation}
        notifier:
          kind: native
          module: reputation
          targets: [{action: sign-message}]
          executions: [host_sync]
          requires: []
          produced_facts: []
          failure: indeterminate
          timeout: 100ms
      effects:
        record-audit:
          kind: obligation
          provider: dkim2/plugin.reputation.notifier
          targets: [{action: sign-message}]
          execution: host_sync
          parameters:
            channel:
              type: string
              allowed_strings: [security]
              max_length: 16
              non_empty: true
              required: true
      domain_plans:
        default:
          checkpoints:
            final_decision:
              providers:
                - name: risk
                  use: dkim2/plugin.reputation.risk
                  actions: [sign-message]
      policy_sets:
        default:
          rules:
            - name: record-high-risk
              checkpoint: final_decision
              actions: [sign-message]
              require_providers: [risk]
              if:
                attribute: plugin.reputation.risk_score
                gte: 50
              then:
                decision: permit
                obligations:
                  - id: dkim2/record-audit
                    parameters: {channel: security}
  targets:
    - namespace: dkim2
      action: sign-message
      schema: dkim2/sign-message/v1
      domain_plan: dkim2/default
      default_policy: dkim2/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision:
          policy_sets: [dkim2/default]
```

This production example has no removed `auth.policy` source and does not add a
mapping row. `kind: native`, `module: reputation`, and the local key `risk`
derive the exact fact-provider identity `dkim2/plugin.reputation.risk`; they do
not name or load a shared object. The separate local key `notifier` derives the
effect-provider identity `dkim2/plugin.reputation.notifier`, because one
registered native component has one local identity and implements one generic
provider boundary. The schema permits the `plugin` source, while
`plugin.reputation.risk_score` fixes the module-owned fact authority and exact
configured output. Each configured target, output shape, execution class, and
typed effect parameter must match the loaded module's immutable capability
descriptor.

Registering a native descriptor advertises capability but does not activate it. Candidate-generation preparation
resolves only configured provider identities against the already loaded module registry, validates their exact
targets and fact/effect contracts, and freezes the resulting bindings into that generation. An unconfigured
contribution is absent from the prepared catalog; a configured identity that cannot be resolved rejects candidate
generation. A provider cannot activate itself, mutate the catalog, choose an effect, reorder a plan, or schedule
detached work. Existing native environment, subject, and effect extensions retain their separate implicit `authn`
binding and are not converted into generic targets.

The shared scheduler applies configured `failure` and `timeout` values to fact collection. A fact call is context-bound
to the shortest host budget, and a panic, cancellation, timeout, invalid fact type, wrong source or authority,
undeclared output, or collision is classified by the host. `continue` is available only when the compiler proves
continuation safe; contract violations remain `indeterminate`. Dependencies of a failed required provider are skipped
by the shared scheduler. Synchronous effects inherit the Decision evaluation context, while accepted post-actions use
the supervisor plan deadline; effect-only providers are not scheduled as fact collectors.

Only an obligation selected by the compiled decision, such as `dkim2/record-audit` above, can invoke its native
provider. Unselected obligations, advice, and `return_only` effects never call a host provider. `host_sync` execution
finishes before response finalization. `host_post_action` work must be resolved and accepted by the internal effect
supervisor synchronously before finalization, then waits for the response gate; a later failure is observable but
cannot mutate the response.

The host makes at most one effect attempt for each Decision and effect ordinal. It does not automatically retry an
error, timeout, cancellation, panic, or ambiguous dispatch. Ambiguity after an external dispatch is reported as
`outcome_unknown` and is not retried. A provider may voluntarily implement domain-specific idempotency using its own
stable domain data, but that behavior is outside the generic contract. No internal attempt identity is exposed or
usable as a public idempotency key, and configuration adds no retry, replay, deduplication, or idempotency field.

Compatible configuration deactivation is generation-bound: a newly prepared generation omits the provider while an
older leased generation may finish in-flight work with its frozen binding. Native Go modules remain loaded for the
process lifetime. Adding or removing a module, changing its identity or capability set, or removing, replacing, or
changing the configured binary requires a process restart; configuration reload cannot unload or replace a Go
shared object.

## Nested rule, effect, and scheduler mappings

The owner paths above do not change the following nested semantic contract.

| Removed or retained field | New field | Rule |
|---|---|---|
| rule `stage` | `checkpoint` | The exact checkpoint replaces the removed rule stage. |
| rule `operations` | `actions` | Actions are checked against every importing target. |
| `require_checks` | `require_providers` | Provider names resolve inside the same domain plan and compatible checkpoint. |
| rule `name` and `if` | unchanged | The complete condition-tree semantics are retained. |
| decision, reason, markers, response message, and response language | unchanged | Their field names and behavior are retained. |
| `skip_remaining_stage_checks` | `skip_remaining_checkpoint_providers` | Control remains local to the containing checkpoint. |
| effect `id` | exact qualified effect `id` | Obligation and advice identities must resolve in the target effect registry. |
| effect `args` | typed `parameters` | Parameters are schema-validated instead of remaining opaque. |
| check `name` | provider-instance `name` | The scheduler-visible instance name is retained. |
| check `type` plus `config_ref` | exact qualified `use` | No `config_ref` field exists in the new model. |
| check `stage` | removed | The containing checkpoint owns provider placement. |
| check `operations` | provider-instance `actions` | Actions are explicit when one domain plan serves several actions. |
| `run_if`, `after`, `skip_if`, `observe_safe`, and `output` | unchanged | Their scheduling semantics are retained subject to target-aware validation. |
| `run_if.auth_state` | unchanged | Its values remain valid only for authn domain plans. |
| nested localization, time-window, scheduler, normalization, and backend-export fields | unchanged | Field names and validation semantics remain under the new owner path. |

More specifically, localization retains `namespace`, `language`, and `entries`;
time windows retain `timezone`, `days`, and `intervals`; scheduler guards retain
`if` and `on_missing_attribute`; request sources retain their normalization and
bounds; and backend exports retain `name`, `attribute`, `type`, and
`sensitivity`. The full condition tree retains logical, comparison,
set-reference, CIDR, regular-expression, existence, containment, and
time-window operators.

Request-time Policy localization is generation-owned. Its effective catalog is
the immutable combination of the built-in system catalog, the startup Lua
catalogs captured after every init script succeeds, and the catalogs under
top-level `policy.namespaces.*.localization`, in that precedence order. Startup
catalogs are process-lifetime input: changing an init-script path or its content
requires a restart, while a successful config reload replaces only the final
top-level Policy layer. The system catalog is process-lifetime input too: the
configured resource path, configured and effective language order, default
language, and exact selected JSON resource bytes are pinned to the source loaded
by the language manager. Drift in any of those values is restart-bound and
cannot publish a config-only generation over the live system catalog. Startup
registration is never read through a global request-time fallback. Authn Lua
code running inside a Decision session receives that session's captured
resolver, so an in-flight request keeps its old translations across a successful
reload.

Checkpoint ordering is explicit and plan-local. Providers appear under the
checkpoint that replaced their old `stage`; `after` and `skip_if` may refer
only to valid instance names in that same plan and compatible checkpoint. Rules
from the old single list may be activated by several exact target/checkpoint
plans, but remain authored once in `authn/configured`.

## Exact check identities

The new model has no `config_ref` field or alias. These twelve rows are the
complete deterministic `type + config_ref -> use` contract.

| Removed check type | Accepted old form | Exact new `use` | Manual migration rule |
|---|---|---|---|
| `builtin.brute_force` | empty or `auth.controls.brute_force...` | `authn/builtin/brute_force` | Discard any suffix; the builtin binding owns typed brute-force configuration. |
| `builtin.tls_encryption` | empty or `auth.controls.tls_encryption...` | `authn/builtin/tls_encryption` | Discard any suffix. |
| `builtin.relay_domains` | empty or `auth.controls.relay_domains...` | `authn/builtin/relay_domains` | Discard any suffix. |
| `builtin.rbl` | empty or `auth.controls.rbl...` | `authn/builtin/rbl` | Discard any suffix. |
| `lua.environment` | empty or `auth.policy.attribute_sources.lua.environment.<source>` | `authn/lua_environment_<source>` | An empty reference uses the old check name; the migrated provider must exist. |
| `plugin.environment` | exactly `plugins.modules.<module>.environment` | `authn/plugin.<module>.environment` | Empty, non-canonical, or unresolvable references are rejected. |
| `backend.ldap` | empty or `auth.backends.ldap...` | `authn/builtin/ldap_backend` | Discard any suffix; the builtin binding owns typed LDAP configuration. |
| `backend.lua` | empty or `auth.backends.lua.backend...` | `authn/builtin/lua_backend` | Discard any suffix; the builtin binding owns the configured Lua backend. |
| `backend.plugin` | empty or `auth.backends.order...` | `authn/builtin/plugin_backend_order` | Discard any suffix; the builtin binding owns backend order and plugin capabilities. |
| `lua.subject` | empty or `auth.policy.attribute_sources.lua.subject.<source>` | `authn/lua_subject_<source>` | An empty reference uses the old check name; the migrated provider must exist. |
| `plugin.subject` | `plugins.modules.<module>.subject` plus a derivable check-local suffix | `authn/plugin.<module>.subject.<local>` | Empty, non-canonical, non-derivable, or unresolvable references are rejected. |
| `backend.account_provider` | empty or `auth.backends...` | `authn/builtin/account_provider` | Discard any suffix; the builtin binding owns typed backend selection. |

### Plugin environment and subject provider declarations

```yaml
policy:
  namespaces:
    authn:
      providers:
        plugin.acme.environment:
          kind: plugin
          module: acme
          targets: [{action: authenticate}]
          executions: [host_sync]
        plugin.acme.subject.risk:
          kind: plugin
          module: acme
          targets: [{action: authenticate}]
          executions: [host_sync]
```

The `plugin.environment` and `plugin.subject` mapping rows identify configured
authn providers; mapping the old `config_ref` does not create those provider
definitions. Declare each exact `kind: plugin` identity under `authn`, with the
same module embedded in its local name. These legacy authn source bindings are
not generic `kind: native` Decision Fact Providers. Their loaded plugin
descriptors contribute the exact builtin-authn fact schemas, so operators must
not add an authn `schema_contributions.static` override.

The matching plan instances use `authn/plugin.acme.environment` and
`authn/plugin.acme.subject.risk`. Candidate generation rejects a missing
configured definition, missing real descriptor, module mismatch, unsupported
target action, output-schema mismatch, or unavailable binding before commit.

Empty references are therefore valid only in the rows that explicitly say
`empty`. For builtin rows, an accepted canonical old prefix identifies the
mechanism and any suffix is discarded. For Lua environment and subject rows,
an empty reference uses the old check name as the source name; a canonical old
reference supplies `<source>` explicitly. Plugin environment and subject rows
require their canonical module form and, for subjects, a derivable local name.

Unresolvable old references are hard errors. A syntactically accepted old
reference that never identified an existing source, module, subject, provider,
or builtin binding must be corrected during manual migration. It is not copied,
silently ignored, or retained as a no-op. Non-canonical spellings and every
`config_ref` alias are rejected by the production decoder.

### Lua name collision handling

Equal old Lua names remain distinct because the source kind participates in the
new local name. For example, these old entries are allowed to share `name:
shared`:

```yaml
auth:
  policy:
    attribute_sources:
      lua:
        environment:
          - name: shared
            script_path: /etc/nauthilus/lua/environment.lua
        subject:
          - name: shared
            script_path: /etc/nauthilus/lua/subject.lua
```

They are manually authored as two providers with distinct qualified identities:

- `authn/lua_environment_shared`
- `authn/lua_subject_shared`

No last-writer-wins map, unqualified lookup, or shared alias is involved.

## One path authority and redaction

Each exact new path above is derived from the production model's tagged field
authority. It is simultaneously:

- the strict decode path;
- the validation-error path;
- the path returned by the documented field-path authority;
- the canonical dump path.

Unknown fields fail instead of disappearing. In particular, old-root
`auth.policy`, mixed old/new roots, global `policy.policy_sets`, target-inline
sets, rule or check `stage`, check `config_ref`, and unqualified
`standard_auth` are not compatibility aliases.

Provider and effect secrets stay at their documented owner paths and the
canonical projection writes `***REDACTED***` there. It never moves plaintext to an
undocumented store. For example, the provider secret
`policy.namespaces.authn.providers.lua_environment_risk.secrets.token`, the
subject-provider secret
`policy.namespaces.authn.providers.lua_subject_risk.secrets.token`, and the effect secret
`policy.namespaces.authn.effects.lua_action_security.secrets.token` dump as:

```text
policy.namespaces.authn.providers.lua_environment_risk.secrets.token="***REDACTED***"
policy.namespaces.authn.providers.lua_subject_risk.secrets.token="***REDACTED***"
policy.namespaces.authn.effects.lua_action_security.secrets.token="***REDACTED***"
```

The frozen model keeps these owner paths so every format, dump, and schema index
redacts them consistently. The production cutover does not define a typed
provider/effect secret carrier, however, so a candidate with any non-empty map
at one of these paths is rejected before extension preparation. No Lua or native
provider receives an inert or ambient copy of the value.

## Separate Policy and backchannel credentials

Policy and backchannel authentication are separate resource families. A
client-credentials request containing one or both Policy scopes
(`nauthilus:policy_evaluate` and `nauthilus:policy_diagnostics`) and no
backchannel scope receives the exact single audience `nauthilus:policy`. A
request with no Policy scope, including an empty request or one containing only
existing non-Policy service scopes, receives the exact single audience
`nauthilus:backchannel`.

A request that mixes either Policy scope with any backchannel scope fails with
`invalid_scope` before token generation and before any token, session, or flow
state is persisted. If client filtering would remove or replace an explicitly
requested resource family, issuance also fails with `invalid_scope` before
persistence; filtering cannot silently turn a Policy request into a
backchannel token or the reverse.

Policy HTTP and gRPC require a normalized audience set exactly equal to
`{nauthilus:policy}` and the issuer-validated, issuer-owned `client_id` admitted
by the configured Policy client profile. Evaluation requires
`nauthilus:policy_evaluate`; requested sanitized diagnostics additionally
require `nauthilus:policy_diagnostics` and profile permission. Policy endpoints
reject `nauthilus:backchannel` tokens. Authentication, identity, management,
and MFA backchannel endpoints require the exact resource audience
`{nauthilus:backchannel}` plus an issuer-owned, non-empty service `client_id`;
they reject `nauthilus:policy` tokens and browser tokens with a colliding client
audience. A client that uses both resources must obtain, cache, rotate, and
present two independently issued tokens. External issuers must preserve the
same exact resource separation.

Policy-Basic is another Policy-only credential family. It has no OAuth scope,
does not reuse management Basic credentials, and has no management-Basic
fallback. It is accepted only for an exact enabled Policy client profile over
the Policy transport's protected-transport boundary. Management Basic cannot
grant Policy authority, and Policy-Basic cannot grant management or
backchannel authority.

See [`examples/policy_api.yml`](examples/policy_api.yml) for a complete
top-level configuration with enabled HTTP and gRPC transports, global and
per-client admission bounds, an mTLS-bound Policy Bearer profile, dedicated
Policy-Basic credentials, target/schema grants, attribute allowlists, and
diagnostics permission. The example's environment placeholder must resolve to
a non-empty secret during production loading.

## Production loading and migration evidence

Production loading tests decode the independently authored top-level `policy`
fixture through `config.FileSettings`, apply the same defaults and strict field
rules used at startup and reload, and pass the result into candidate-generation
validation. The canonical field-path and dump checks cover the exact new owners
listed above, including secret redaction. They do not expose a reusable
old-to-new mapping function.

The frozen old fixture remains rejection and semantic-parity evidence only.
Tests compare its independently recorded expectations with the new fixture's
target, defaults, report, providers, effects, rules, checkpoint ordering, and
all twelve exact check identities. Production never decodes that old fixture
and has no `auth.policy` decoder, translator, fallback compiler, or migration
API.

## Paired old and new examples

These examples are independently authored operator inputs. The new example is
not generated from the old example at runtime or in a reusable migration
library.

### Old `auth.policy` input

```yaml
auth:
  policy:
    mode: observe
    default_policy: standard_auth
    localization:
      catalogs:
        - namespace: login
          language: en
          entries:
            denied: Access denied
    sets:
      networks:
        trusted: [10.0.0.0/8]
      strings:
        privileged: [admin]
      time_windows:
        office:
          timezone: Europe/Berlin
          days: [Mon, Tue, Wed, Thu, Fri]
          intervals:
            - start: "08:00"
              end: "18:00"
    scheduler_guards:
      known_client:
        if:
          exists: true
          attribute: request.client_id
        on_missing_attribute: run
    report:
      enabled: true
      include_attributes: true
    attribute_sources:
      lua:
        environment:
          - name: risk
            script_path: /etc/nauthilus/lua/risk.lua
        subject:
          - name: profile
            script_path: /etc/nauthilus/lua/profile.lua
    obligation_targets:
      lua:
        actions:
          - name: security
            type: lua
            script_path: /etc/nauthilus/lua/security.lua
    registry_scripts: [/etc/nauthilus/lua/register.lua]
    request_headers:
      - header: X-Forwarded-For
        attribute: request.header.forwarded_for
    request_metadata:
      - key: x-client-id
        attribute: request.metadata.client_id
    attribute_exports:
      - name: department
        attribute: subject.department
        type: string
        sensitivity: internal
    checks:
      - name: rbl
        type: builtin.rbl
        stage: pre_auth
        config_ref: auth.controls.rbl
        operations: [authenticate]
    policies:
      - name: deny_rbl
        stage: pre_auth
        operations: [authenticate]
        require_checks: [rbl]
        if:
          is: true
          attribute: auth.rbl.threshold_reached
        then:
          decision: deny
          reason: rbl
```

### New production `policy` input

```yaml
policy:
  namespaces:
    authn:
      localization:
        catalogs:
          - namespace: login
            language: en
            entries:
              denied: Access denied
      condition_sets:
        networks:
          trusted: [10.0.0.0/8]
        strings:
          privileged: [admin]
        time_windows:
          office:
            timezone: Europe/Berlin
            days: [Mon, Tue, Wed, Thu, Fri]
            intervals:
              - start: "08:00"
                end: "18:00"
      schema_contributions:
        lua:
          registry_scripts: [/etc/nauthilus/lua/register.lua]
      fact_sources:
        http_headers:
          - header: X-Forwarded-For
            attribute: request.header.forwarded_for
            visibility: public
            normalize:
              trim: true
              case: lower
              max_length: 256
        grpc_metadata:
          - key: x-client-id
            attribute: request.metadata.client_id
            visibility: public
            normalize:
              trim: true
              case: lower
              max_length: 256
        backend_attributes:
          - name: department
            attribute: subject.department
            type: string
            sensitivity: internal
      providers:
        lua_environment_risk:
          kind: lua_environment
          script_path: /etc/nauthilus/lua/risk.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
        lua_subject_profile:
          kind: lua_subject
          script_path: /etc/nauthilus/lua/profile.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      effects:
        lua_action_security:
          kind: lua_action
          action_type: lua
          script_path: /etc/nauthilus/lua/security.lua
          execution: host_sync
      domain_plans:
        password:
          scheduler_guards:
            known_client:
              if:
                exists: true
                attribute: input.auth.client_id
              on_missing_attribute: run
          checkpoints:
            pre_auth:
              providers:
                - name: rbl
                  use: authn/builtin/rbl
                  actions: [authenticate]
                  run_if:
                    auth_state: any
                  output: nauthilus.auth.rbl.threshold_reached
      policy_sets:
        configured:
          visibility: private
          rules:
            - name: deny_rbl
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [rbl]
              if:
                is: true
                attribute: nauthilus.auth.rbl.threshold_reached
              then:
                decision: deny
                reason: rbl
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      mode: observe
      default_policy: authn/standard_auth
      domain_plan: authn/password
      plans:
        pre_auth:
          policy_sets: [authn/configured]
      report:
        enabled: true
        include_fsm: true
        include_checks: true
        include_attributes: true
```

Before deploying a new configuration, validate exact provider/effect
resolution, target action and checkpoint compatibility, source fact types,
policy-set imports, credential profiles, route enablement, and secret-safe
canonical output. Production loading and generation compile the new authn plan
directly; production code never reads the old fixture to construct it.

## Hard-cut boundary

The production hard cut has no compatibility window or dual-read phase.
Top-level `policy` is the only accepted root. Production rejects old root,
mixed roots, unqualified `standard_auth`, legacy `stage`, `config_ref`, every
removed alias, and unresolved identities with actionable paths before candidate
preparation.

Startup and reload use the same `prepare -> validate -> commit` boundary.
Candidate generation validates credentials, client profiles, admission limits,
catalog entries, extensions, targets, and route enablement before publication.
Any failure leaves the previous complete generation and its routes active. A
successful commit publishes configuration, credentials, profiles, catalog,
extensions, plans, and HTTP/gRPC route state together; no second compiler,
translator, plan map, evaluator authority, or partially activated generation
remains.
