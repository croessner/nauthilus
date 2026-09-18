# Load-test error classification and logging

Native plugin loggers use the host's configured severity filter. At `warn`, debug
and info messages are suppressed, including for a logger retained across a
logging reload. Warning and error messages remain visible. A high warning count
alone does not demonstrate a plugin severity-filter bypass.

Post-action audit and operational observers can share the same logger. In that
configuration, each transition produces one classified audit log record instead
of an additional identical supervisor record. Separate audit destinations still
receive their own evidence. Trace events and state metrics remain independent of
log deduplication. Queue saturation, deadline expiry and ambiguous outcomes remain
distinct failures; this change does not increase capacity or suppress failures.

Auth-authority and Policy gRPC adapters share decision-service status mapping:

| Failure category | gRPC status |
| --- | --- |
| Caller authentication | `Unauthenticated` |
| Caller or invocation permission | `PermissionDenied` |
| Request-size, fact-count, concurrency or rate limit | `ResourceExhausted` |
| Unavailable runtime generation or missing service dependency | `Unavailable` |
| Disabled decision route | `Unimplemented` |

Only classified limit failures map to `ResourceExhausted`; a generic admission
rejection is not evidence of capacity exhaustion. Wrapped diagnostic details are
excluded from these public statuses. Rejections still stop before backend or
effect execution.

Redis tracing retains operation spans, timing and status while disabling raw
`db.statement` attributes for individual commands and pipelines. Redis keys and
arguments can contain tokens, credentials or account data. This prevents new raw
command capture; it does not remove previously stored telemetry.
