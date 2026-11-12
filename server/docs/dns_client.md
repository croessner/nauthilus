# DNS Client

All outbound DNS lookups share one long-lived client: RBL checks, the client IP reverse lookup, the Lua
`nauthilus_dns` module, and the connection monitor. The client bounds every lookup by a total budget, retries
lost queries inside that budget, and can reuse UDP sockets instead of opening one per query.

## Configuration

The settings live under `runtime.clients.dns`. Changing them requires a restart.

| Key | Default | Meaning |
| --- | --- | --- |
| `resolver` | system resolvers | Optional `host:port` of the resolver to use |
| `timeout` | `5s` | Total budget of one lookup, including all attempts |
| `attempts` | `3` | Maximum number of queries sent for one lookup; `1` disables retries |
| `retry_interval` | `timeout / attempts` | Delay before an additional attempt is started |
| `pool_size` | `0` (disabled) | Idle UDP sockets kept per resolver |
| `pool_max_uses` | `256` | Queries after which a pooled socket is replaced |
| `resolve_client_ip` | `false` | Resolve the client IP to a host name |

```yaml
runtime:
  clients:
    dns:
      resolver: 192.0.2.53:53
      timeout: 300ms
      attempts: 3
      pool_size: 64
```

## Retries

UDP does not retransmit. A single lost query or response would otherwise always end in a timeout after the full
budget. The client therefore starts an additional attempt after each `retry_interval` while the earlier attempts
keep running. The first definitive answer wins, and "name does not exist" counts as an answer.

Earlier attempts are never abandoned, so a resolver that answers slowly but inside `timeout` still succeeds. With
`timeout: 300ms` and `attempts: 3` the queries leave at 0 ms, 100 ms and 200 ms, and a lookup fails only when all
three stay unanswered until 300 ms. In the normal case exactly one query is sent.

Retries add load precisely when the resolver is slow or lossy: a lookup can send up to `attempts` queries.

## Socket Pool

Without a pool every query opens its own UDP socket. Behind NAT or connection tracking each of them creates a
state entry that outlives the query by 30 seconds or more, which adds up at high request rates.

With `pool_size` greater than zero the client keeps that many idle sockets per resolver and reuses them:

- A socket serves one query at a time. When no idle socket is available, the query opens its own socket instead
  of waiting, so `pool_size` is not a concurrency limit.
- A socket whose query stayed unanswered or failed is closed and not reused, so a late response can never reach
  an unrelated query.
- A socket is replaced after `pool_max_uses` queries, which keeps the source port from staying fixed.
- TCP fallback for truncated responses does not use the pool.

A reasonable `pool_size` is a small multiple of the lookups in flight at once (lookups per second times the
typical answer time).

## Metrics

| Metric | Labels | Meaning |
| --- | --- | --- |
| `dns_lookups_total` | `result`, `attempts` | Finished lookups. `result` is `success`, `not_found`, `timeout` or `error`; `attempts` is the number of queries started |
| `dns_pool_sockets_total` | `source` | Pooled queries by socket source, `reused` or `new` |

`dns_lookups_total{result="success",attempts="2"}` counts lookups that a retry rescued.
`dns_lookups_total{result="timeout"}` counts lookups that failed despite all attempts. A high share of
`source="new"` means the pool is too small or sockets are retired often because queries stay unanswered.
