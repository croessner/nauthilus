# Policy configuration migration

This guide is the manual hard-cut contract from the currently supported
`auth.policy` configuration to the standalone namespace-owned policy model. It
is deliberately field-complete: each old concept has one new owner, one decode
path, one validation path, and one canonical dump path.

The standalone model is preparation for the later atomic production cutover.
Production remains on the pre-cutover `auth.policy` authority until that
cutover is performed. In particular, production `FileSettings` does not yet
contain a top-level `Policy` field and must not read both roots.

No runtime, startup, library, or offline translator from `auth.policy` to standalone policy exists. Operators must author the new configuration directly
from this guide. The repository may use frozen old inputs and independently
authored new inputs as test-only oracles, but those fixtures are not a decoder,
converter, or migration API.

## Field-complete mapping

The following seventeen rows are the complete B001-C2 mapping. Paths beginning
with `auth.policy` describe removed input. Paths beginning with `policy` are the
sole standalone representation.

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
| Lua environment providers | `auth.policy.attribute_sources.lua.environment` | `policy.namespaces.authn.providers.lua_environment_<old-name>` | The exact provider identity is `authn/lua_environment_<old-name>`. | The provider kind is `lua_environment`; strict standalone decoding accepts only the canonical `script_path` field, which standalone validation requires to be non-empty; file/source resolvability belongs to candidate compilation. |
| Lua subject providers | `auth.policy.attribute_sources.lua.subject` | `policy.namespaces.authn.providers.lua_subject_<old-name>` | The exact provider identity is `authn/lua_subject_<old-name>`. | The provider kind is `lua_subject`; strict standalone decoding accepts only the canonical `script_path` field, which standalone validation requires to be non-empty; file/source resolvability belongs to candidate compilation. |
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
field and standalone validation requires a non-empty value. Opening the file,
resolving the configured source, and binding its host implementation belong to
candidate compilation. None of these checks translates an old configuration.

Native and plugin provider definitions have no additional legacy storage in the
new model. Configured definitions belong below
`policy.namespaces.<namespace>.providers.<name>`; builtin and loaded-plugin
bindings contribute their exact identities internally. A provider instance
references that identity with `use` and never stores a Viper path.

Target timeouts have no removed `auth.policy` source. Generic targets must
provide positive `timeouts.evaluation` and `timeouts.provider_default` values;
authn continues to use its host-owned timeout sources. This is a new generic
target requirement, not a migrated eighteenth row.

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
`config_ref` alias are rejected by the standalone decoder.

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

Each exact new path above is derived from the standalone model's tagged field
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

## Executed test-only evidence

`TestPolicyMigrationContractDocumentsEveryMappingFamily` independently decodes
every old fixture into the pre-cutover `config.FileSettings` model through a
test-only strict reader, reads the row's exact legacy semantic leaf, and pairs
that evidence with standalone validation, `FieldPaths`, and canonical dump
evidence. It does not expose a reusable old-to-new mapping function.

`TestPolicyMigrationNormalizedInputParity` compares the independently authored
complete old and new fixtures at the normalized semantic boundary.
`TestPolicyMigrationCompiledPlanParity` compiles both fixtures and compares the
target, defaults, report, providers, effects, rules, and checkpoint ordering.
`TestPolicyMigrationCompiledCheckIdentityParity` supplies compiled evidence for
all twelve removed check identities. These oracles exist only in test files;
production has no `auth.policy`-to-standalone decoder or translator.

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
      - name: risk
        type: lua.environment
        stage: pre_auth
        config_ref: auth.policy.attribute_sources.lua.environment.risk
        operations: [authenticate]
    policies:
      - name: deny_risk
        stage: pre_auth
        operations: [authenticate]
        require_checks: [risk]
        if:
          eq: high
          attribute: auth.lua.environment.risk
        then:
          decision: deny
          reason: risk
```

### New standalone `policy` input

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
                attribute: request.client_id
              on_missing_attribute: run
          checkpoints:
            pre_auth:
              providers:
                - name: risk
                  use: authn/lua_environment_risk
                  actions: [authenticate]
                  run_if:
                    auth_state: any
                  observe_safe: true
                  output: nauthilus.auth.rbl.threshold_reached
      policy_sets:
        configured:
          visibility: private
          rules:
            - name: deny_risk
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [risk]
              if:
                is: true
                attribute: nauthilus.auth.rbl.threshold_reached
              then:
                decision: deny
                reason: risk
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

Before using a new fixture, validate exact provider/effect resolution, target
action and checkpoint compatibility, source fact types, policy-set imports, and
secret-safe canonical output. Test-only parity suites compare the normalized new
compiled authn plan with a frozen old plan oracle; production code never reads
the old fixture to construct the new plan.

## Hard-cut boundary

This guide does not authorize a dual-read phase. The later production cutover
must atomically remove the old root and make the top-level `policy` model the
only authority. Until then, the standalone decoder is isolated and production
continues to expose only its pre-cutover root. The final cutover must reject old
root, mixed root, removed aliases, and unresolved identities with actionable
paths before preparing a runtime generation.

This contract proves compiled scheduling metadata and exact identities only.
Production host dispatch and execution of standalone authn plans remain a later
runtime-cutover responsibility and must not be activated here.
