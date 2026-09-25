# Health Endpoints

Nauthilus serves three unauthenticated health routes on the HTTP listener. All of them bypass the concurrency
limiter and the per-IP rate limiter, and Basic credentials sent to them are never counted as backchannel caller
outcomes.

| Route | Answer | Checks | Purpose |
| --- | --- | --- | --- |
| `GET /ping` | `200` with the plain text `pong` | none | Manual reachability test |
| `GET /livez` | `200` with the JSON document `{"status":"up"}` | none | Liveness probe |
| `GET /healthz` | `200` or `503` with a JSON document `{"status":...,"checks":{...}}` | test backend login, Redis, LDAP | Readiness and startup probe |

## Liveness: `/livez`

`/livez` only proves that the process still accepts and answers HTTP requests. It never touches Redis, LDAP, a
backend, or the configuration, and it answers a fixed, preallocated document. It therefore stays fast when the
server is saturated or a dependency is slow.

The document is a subset of the `/healthz` answer: its `status` field is always `up`. Clients that understand the
readiness answer, including the `healthcheck` binary shipped in the container image, accept it unchanged.

## Readiness: `/healthz`

`/healthz` runs a test login against the test backend and checks Redis reads, Redis writes, and LDAP. The overall
`status` is `down` (HTTP `503`) when the test backend login fails and `degraded` (HTTP `200`) when only its MFA
storage checks fail; failed Redis or LDAP checks are reported in `checks` without making the instance unready. Because the checks do real work, the answer can take noticeably longer under
load than a probe timeout of a few seconds allows.

The `ldap_queue` check is the exception that does decide readiness. It turns `down` (HTTP `503`) when an LDAP
lookup or auth pool with a running worker holds queued requests and no worker has taken one for the longer of 30
seconds and `connect_abort_timeout` plus the 30 second connect deadline (40 seconds with the default abort timeout),
and lists the pools as `lookup:<pool>` or `auth:<pool>` in `meta.pools`. Workers that take requests at any rate, including requests that
expired in the queue, count as progress, so a slow but working directory never trips it. The check takes a pod
whose LDAP workers stopped out of routing even while a cached test login still succeeds; liveness is not affected.

## Container healthcheck binary

The image contains `/usr/app/healthcheck`. It requests one URL, expects HTTP `200`, and decodes the JSON `status`
field: `up` and `degraded` succeed, `down`, a missing status, or a body that is not JSON fail. `/ping` is therefore
not a valid target for the binary, because `pong` is not JSON.

```text
/usr/app/healthcheck --url https://127.0.0.1:9443/livez --tls-skip-verify
/usr/app/healthcheck --url https://127.0.0.1:9443/healthz --tls-skip-verify
```

## Kubernetes probes

Use `/livez` for the liveness probe and `/healthz` for the readiness and startup probes. A liveness probe that runs
the readiness checks restarts healthy pods whenever a dependency is slow or the pod is busy, which removes capacity
exactly when it is needed. A slow `/healthz` only takes the pod out of the service endpoints until it recovers.

```yaml
livenessProbe:
  exec:
    command: ["/usr/app/healthcheck", "--url", "https://127.0.0.1:9443/livez", "--tls-skip-verify"]
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
readinessProbe:
  exec:
    command: ["/usr/app/healthcheck", "--url", "https://127.0.0.1:9443/healthz", "--tls-skip-verify"]
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
startupProbe:
  exec:
    command: ["/usr/app/healthcheck", "--url", "https://127.0.0.1:9443/healthz", "--tls-skip-verify"]
  periodSeconds: 5
  timeoutSeconds: 5
  failureThreshold: 30
```

An `httpGet` probe works the same way for `/livez`; Kubernetes only evaluates the status code.
