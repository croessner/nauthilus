# Lua Plugin Test Fixtures

These fixtures exercise selected core scripts from `server/lua-plugins.d` in `--test-lua` mode.

Run all plugin tests locally:

```bash
./scripts/run-lua-plugin-tests.sh
```

Each test consists of:

- a wrapper script (`*_wrapper.lua`) that loads the real plugin and adds small test shims
- a JSON mock file (`*_test.json`) consumed by `--test-mock`

The wrappers are intentionally minimal, keep plugin logic unchanged, and preserve the production callback return
signatures.

Current fixtures also include a cache flush contract example:

- `cache_flush_wrapper.lua` + `cache_flush_test.json` (tests `nauthilus_cache_flush` behavior via `cache_flush` callback
  in test mode)

Redis key layout fixtures run the bundled monitoring, protection, notification, and brute-force hook plugins under
`lib/redis_layout_probe.lua`. The probe fails a fixture when a multi-key script would be rewritten on Redis Cluster,
when a plugin passes the `CUSTOM_REDIS_POOL_NAME` string instead of its connection, or when a plugin touches a
retired key. Wrappers that compose a writer with a reader also check that the reader finds the data under the
documented names (`server/docs/development/redis_keyspace.md`, section 3.15). The same fixtures run in Go through
`TestBundledLuaPluginRedisKeyLayout` in `server/testing/luatest`.
