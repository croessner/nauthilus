# Have I Been Pwned Native Post-Action

This plugin registers the native post-action target `haveibeenpwnd.post_action`.
It ports the Lua `haveibeenpwnd.lua` k-anonymity Redis/cache/HTTP behavior into a
native Go plugin shape.

Builds from the stable and debug Dockerfiles bundle this plugin at
`/usr/local/lib/nauthilus/plugins/haveibeenpwnd.so`. When `REQUIRE_PLUGIN_SIGNATURE=true`, the image build also writes
`/usr/local/lib/nauthilus/plugins/haveibeenpwnd.so.minisig`.

## Configuration

Configure the module under `plugins.modules[].config` and allow the
`credentials` capability:

```yaml
plugins:
  modules:
    - name: haveibeenpwnd
      type: go
      path: /usr/local/lib/nauthilus/plugins/haveibeenpwnd.so
      allow_capabilities:
        - credentials
      config:
        redis_pool: default
        api_base_url: https://api.pwnedpasswords.com/range/
        http_timeout: 10s
        http_max_response_bytes: 1048576
        cache_positive_ttl: 1h
        cache_negative_ttl: 10m
        redis_positive_ttl: 1h
        redis_negative_ttl: 24h
        gate_ttl: 5m
        mail:
          enabled: false
```

`redis_pool` is retained for Lua configuration parity. The current native host
facade exposes the host-provided Redis handles only, so named Redis pool
selection is not available to this plugin yet.

## Compatibility Notes

The implementation keeps the Lua-compatible Redis keys:

- `HAVEIBEENPWND:<md5(account)>`
- `HAVEIBEENPWND:GATE:<md5(account)>:<prefix>`
- `hibp:<account>:<prefix>` for the module-local cache key

Runtime parity is currently bounded by the native post-action API. Native
post-actions receive a request-scoped `CredentialProvider`, but they cannot
apply a runtime delta to the already-selected outcome. As a result, the native
plugin returns safe log fields for leaked-password results, but it cannot set
the Lua `haveibeenpwnd_hash_info` or `rt.action_haveibeenpwnd` runtime markers.

Policy migration:

```yaml
then:
  obligations:
    - id: haveibeenpwnd.post_action
```

Use this native effect ID instead of a Lua action dispatch to `haveibeenpwnd.lua` after the module is configured and the
`credentials` capability is allowed. Adding or removing the module, changing the module name, or replacing the `.so`
artifact requires a process restart. Config-only changes inside `plugins.modules[].config` can be applied by SIGHUP when
validation succeeds.

Observability is host-integrated: the plugin registers the HIBP range API endpoint through
`Host.ConnectionTargets("haveibeenpwnd")`, calls it through `Host.HTTP("haveibeenpwnd")`, and records bounded check/HTTP
metrics and spans. Logs, labels, and spans do not include passwords, account names, raw response bodies, recipients, or
raw transport errors.

SMTP/LMTP notification is not implemented in this slice. `mail.enabled: true` is rejected at config decode time instead
of being silently ignored. Keep the Lua action when mail notification is required. The current Lua mail gate also has a
known compatibility mismatch: `init/init.lua` returns `send_email`, while `actions/haveibeenpwnd.lua` checks
`send_mail`; this native plugin does not fix that Lua-side mismatch.
