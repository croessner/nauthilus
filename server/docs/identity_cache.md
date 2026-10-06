# LDAP identity lookup cache

Passwordless identity lookups can use a dedicated positive Redis cache. Enable it explicitly:

```yaml
storage:
  redis:
    identity_cache:
      enabled: true
      ttl: 60s
```

The default is disabled. An omitted or zero TTL uses one minute; explicit nonzero values must be between one second
and 8760 hours. Choose a short TTL appropriate for the freshness required for account attributes and group membership.
Cache hits do not extend the entry lifetime. Enabling this option is sufficient for LDAP identity lookups; it does not
require a `cache` backend in the authentication backend order.

The identity cache stores successful LDAP backend results before per-request policy and plugin processing. It is
independent of the positive password cache (UCP): an identity entry carries no password proof and cannot satisfy a
password authentication request. Native backend plugins and Lua backends do not populate this cache. Protocol, client,
backend, and rendered LDAP lookup context separate otherwise similar identity requests. Entries for the same username
and cache namespace share one slot: a different context replaces that slot and can reduce the hit rate. Policy and authorization still run for
every request, including cache hits.

Eligible identity lookups bypass both reads and writes of the process-local LDAP membership cache. A UCI miss
therefore resolves current LDAP groups before creating a new snapshot; the local membership TTL cannot extend
identity-cache staleness or repopulate stale groups after a flush. Password and browser IdP requests retain their
existing membership-cache behavior.

Identity payloads use the configured Redis encryption and the separate UCI key namespace. Redis failures and unusable
cache entries fall back to LDAP. Identity cache reads use the Redis writer even when replica reads are enabled,
so replica lag cannot bypass generation invalidation. A cache write failure does not turn a successful LDAP lookup into an authentication
failure. No negative identity entries are stored.

## Invalidation

The user-cache flush API (synchronous and asynchronous) and internal cache purge invalidate identity entries as well
as password entries. Identity invalidation deliberately rotates a shared generation for the configured Redis prefix:
**flushing any user makes all identity cache entries under that prefix cold**, including entries served by other
Nauthilus instances. Old payloads expire through their fixed TTL. This conservative behavior prevents an in-flight
lookup, including a lookup through a previously unknown alias, from repopulating valid stale data after a flush.

Keep the generation key persistent; it is not an expiring payload. A lost or unreadable generation must not make
previously invalidated entries usable. After an external LDAP account or group change, flush the affected user or wait
for the identity TTL. A successful flush is required for immediate invalidation; investigate reported Redis errors.
