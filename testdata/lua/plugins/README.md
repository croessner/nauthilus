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
