# Policy Registry Scripts

This directory contains Lua registry scripts for custom policy attributes emitted by bundled plugins.

## registry.lua

Registers the `lua.plugin.*` attributes emitted through `share/nauthilus_policy_facts.lua`.

Configure it under `auth.policy.registry_scripts`:

```yaml
auth:
  policy:
    registry_scripts:
      - "/etc/nauthilus/lua-plugins.d/policy/registry.lua"
```

The registry script is compile-time material. Runtime plugins emit only attributes that were registered in the active
policy snapshot. If an emitting plugin tries to write an unknown attribute, Nauthilus fails that Lua execution instead
of treating the value as a loose fact.
