# Have I Been Pwned Native Post-Action

This plugin registers the native post-action target `haveibeenpwnd.post_action`.
It ports the Lua `haveibeenpwnd.lua` k-anonymity Redis/cache/HTTP behavior into a
native Go plugin shape.

Builds from the stable and debug Dockerfiles bundle this plugin at
`/usr/local/lib/nauthilus/plugins/haveibeenpwnd.so`. When `REQUIRE_PLUGIN_SIGNATURE=true`, the image build also writes
`/usr/local/lib/nauthilus/plugins/haveibeenpwnd.so.minisig`.

## Configuration

Configure the module under `plugins.modules[].config` and allow the `credentials` capability. When `mail.enabled` is
`true`, the module must also allow the `mail` capability because SMTP/LMTP sends go through the host mail facade.

```yaml
plugins:
  modules:
    - name: haveibeenpwnd
      type: go
      path: /usr/local/lib/nauthilus/plugins/haveibeenpwnd.so
      allow_capabilities:
        - credentials
        # Required when config.mail.enabled is true.
        # - mail
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
          use_lmtp: false
          server: localhost
          port: 25
          helo_name: localhost
          tls: false
          starttls: false
          username: ""
          password: ""
          mail_from: postmaster@example.invalid
          website: https://self-service.example.invalid/
          template_path: ""
          subject_template: "Password leak detected for your account <{{ .Account }}>"
```

`redis_pool` is retained for Lua configuration parity. The current native host
facade exposes the host-provided Redis handles only, so named Redis pool
selection is not available to this plugin yet.

The mail body uses a builtin Lua-compatible text template when `template_path` is empty. A custom `template_path` is
read and parsed during registration and `Reconfigure`, is limited to 64 KiB, and rejects the new config before request
time on read or parse failure. `subject_template` uses the same Go `text/template` data model and falls back to the
default subject when empty.

Template data is intentionally small: `Account`, `HashPrefix`, `Count`, `Website`, and `Timestamp`. Do not include
passwords, full hashes, account names, recipients, or rendered message text in logs, metrics, traces, policy facts, or
status messages.

## Compatibility Notes

The implementation keeps the Lua-compatible Redis keys:

- `HAVEIBEENPWND:<md5(account)>`
- `HAVEIBEENPWND:GATE:<md5(account)>:<prefix>`
- `hibp:<account>:<prefix>` for the module-local cache key

Runtime exchange is plan-local. Native and Lua post-actions run inside one
detached plan in final-obligation order, and this plugin publishes positive
HIBP hits as `plugin.exchange.haveibeenpwnd` through
`PostActionEnqueueResult.RuntimeDelta`. The exchange map contains `hash_info`
and, for positive hits, the bounded `leaked` and `count` fields. Later
post-action steps in the same plan, such as `clickhouse.post_action`, can read
that standard value when policy orders HIBP before ClickHouse. Post-action
deltas do not mutate the already-selected policy decision, client response, or
live request runtime after the plan finishes.

`rt` is historical Lua runtime state and is not the native Go exchange standard. This plugin does not write
`rt.action_haveibeenpwnd`; native consumers should read `plugin.exchange.haveibeenpwnd.hash_info` instead.

Policy migration:

```yaml
then:
  obligations:
    - id: haveibeenpwnd.post_action
```

Use this native effect ID instead of a Lua action dispatch to `haveibeenpwnd.lua` after the module is configured and the
required capabilities are allowed. Adding or removing the module, changing the module name, replacing the `.so` artifact,
or changing `allow_capabilities` requires a process restart. Config-only changes inside `plugins.modules[].config` can be
applied by SIGHUP when validation succeeds; invalid mail templates keep the previous working config. Enabling mail for a
module that was registered with `mail.enabled: false` requires a restart so the module can acquire `CapabilityMail`.

Observability is host-integrated: the plugin registers the HIBP range API endpoint through
`Host.ConnectionTargets("haveibeenpwnd")`, calls HIBP through `Host.HTTP("haveibeenpwnd")`, sends notification mail
through `Host.Mail("haveibeenpwnd")`, and records bounded check/HTTP/mail metrics and spans. Logs, labels, and spans do
not include passwords, account names, raw response bodies, recipients, rendered subjects, rendered bodies, template
paths, or raw transport errors.

Mail is attempted only after a fresh positive HIBP HTTP lookup writes the positive Redis count. The native plugin does
not run the Lua `nauthilus_send_mail_hash` script because `init/init.lua` returns `send_email`, while
`actions/haveibeenpwnd.lua` checks `send_mail`. Instead, it claims duplicate notification ownership directly with
`HSETNX <redis-key> send_mail 1`; duplicate claims skip `Send`. After a successful send, the plugin extends the HIBP
hash expiration to `redis_negative_ttl` to suppress repeated notification noise.
