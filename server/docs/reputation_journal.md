# Durable reputation journal

## Implementation status

This document tracks the Kafka integration while it is being implemented.
The production baseline remains v4.0.0-alpha.28. Only the Kafka namespace has been created; the operator and brokers are not
yet deployed, and no throughput or failure qualification has been completed.

## Acceptance and replay contract

Policy remains the only authority selecting learning. Producers freeze only
independent observations and opaque HMAC identifiers. Credentials, raw account
names and raw IP addresses must never enter Kafka, outbox files or metrics.

An acceptance receipt requires either Kafka acknowledgement with all in-sync
replicas or a synced record on a persistent outbox volume. Process memory and
client-side Kafka buffers are not durable acceptance. An outbox record is
removed only after confirmed Kafka acknowledgement. A failed or ambiguous
send can therefore be repeated.

Redis remains the score and deduplication authority. Kafka consumer offsets
advance only after every subject contribution has been applied or recognized
as an exact duplicate. Partial updates are retried through the existing
same-slot atomic score and seen-set operation. Kafka producer idempotence
alone does not make Redis updates exactly once.

The immutable Redis manifest fixes the contribution and its expiration.
Processing must complete before that expiration. Expired records must be
retained in quarantine with an alert; they must never be silently discarded
or applied after their deduplication window. Extending Kafka retention does
not extend the safe Redis replay window.

## Kubernetes ownership and capacity

Shared Kafka infrastructure belongs in the existing general Kubernetes
repository under a dedicated kafka directory. Nauthilus configuration,
outbox mounts, producer and consumer deployments belong in
nauthilus-tests/kubernetes. Existing unrelated changes and unpublished
commits in either repository must be preserved.

The selected operator version is Strimzi 1.2.0, which lists Kafka 4.3.1 and
Kubernetes 1.36 as supported. Installation must use pinned release artifacts.
The intended production topology has three brokers and three independent
KRaft controllers, internal mutual TLS, explicit topic/user ACLs, replication
factor three, minimum in-sync replicas two and disabled unclean elections.

Read-only preflight on 2026-09-13 found worker memory reservations of 84%,
65% and 86%, despite lower instantaneous usage. Capacity planning must account for guaranteed guest memory, not only the
configured VM maximum, before qualifying this topology with a node failure reserve.
Free Ceph storage does not resolve the worker memory constraint.

## Qualification gates

- Test recovery after a producer process restart and a broker outage.
- Test ambiguous acknowledgement, exact duplicate, conflicting retry,
  partial subject updates, consumer restart and consumer rebalance.
- Prove TLS verification, producer/consumer ACL separation and absence of
  raw identifiers in sample journal records without printing those records.
- Measure sustained throughput, tail latency, Redis memory, hot-subject
  capacity, queue age, outbox occupancy and Kafka consumer lag.
- Test a broker restart and a worker-node failure without losing accepted
  evidence or double-counting scores.
- Run the sustained qualification workload for its actual documented
  duration. A started soak test is not a completed qualification.
- Apply Shadow before Prod, retain paired application/plugin rollback
  artifacts, and drain accepted work before disabling the journal.

## Sources

- [Strimzi supported versions](https://strimzi.io/downloads/)
- [franz-go client](https://github.com/twmb/franz-go)
- [Kafka delivery semantics](https://kafka.apache.org/40/design/design/)
- [Redis Cluster specification](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/)

## Runtime responsibilities

The optional `journal` block accepts exactly one role: `producer` or `consumer`.
A producer still admits the immutable manifest through Redis before publishing.
Redis admission failure therefore prevents a durable journal receipt; Kafka does
not remove that synchronous dependency. `queued` means that Kafka or the
persistent outbox accepted the record, whereas `applied` means Redis subject
updates completed. Authentication success alone is not a journal receipt.

The `reputation-worker` executable is built from the same reputation package with
`reputation_worker` enabled. Start it with `-config /etc/nauthilus/nauthilus.yml`.
It reuses sealed configuration, HMAC keys, Redis prefix and atomic update scripts.
It exposes TLS `/healthz` and authenticated `/metrics` only. It does not start
LDAP, authentication, OIDC or SAML routes. Its deployment must use a distinct
application label so authentication Services cannot select worker pods.

The worker requires the producer's model identity, Redis namespace and opaque
identifier scope/key material. During model changes, retain compatible consumers
until accepted work has drained. A record with an incompatible model, invalid
signature or expired replay window goes to the quarantine topic before its input
offset is committed. Transient Redis failures retain the uncommitted input offset.
An offset outside Kafka retention stops consumption rather than resetting silently.

## Configuration and operational bounds

`journal` requires `brokers`, `role`, `topic`, `quarantine_topic`, `group_id`,
`ca_file`, `certificate_file` and `key_file`. Producer configuration additionally
requires an absolute `outbox_directory`, `outbox_max_bytes` and
`outbox_max_records`. `delivery_timeout` bounds each foreground delivery attempt.
Client certificates are re-read for new TLS handshakes; CA changes require a
restart. Kubernetes Secret rotation must trigger that restart.

The outbox uses a shared persistent filesystem with cross-process advisory locks,
file synchronization and atomic rename. Records are bounded by both count and
bytes. A full or unavailable outbox rejects new durable acceptance after Kafka
failure. Exact retry remains possible at the record limit. Filesystem scans and
recovery are bounded but have not yet been qualified at sustained production load.

Operational overrides preserve the model fingerprint:

- `event_manifest_capacity_per_source`: retained immutable manifests per source.
- `subject_seen_capacity_per_subject`: retained exact replay markers per subject.
- `new_subject_capacity_per_source_hour`: new-subject admission budget.
- `source_admission_capacity`: per-source `requests_per_second` and
  `max_concurrency` above the model's baseline admission policy.

The first three cardinality ceilings are 10,000,000. Host admission ceilings remain
10,000 requests/second and 1,024 concurrent calls per source. These are validation
ceilings, not measured sustainable rates. Expired replay markers are pruned in
batches of at most 512 per invocation to limit Lua execution work.

Exact replay protection still stores one marker per retained event/subject pair,
and Redis retains complete immutable manifests. Estimate memory from measured
bytes per manifest and marker, event rate, subjects per event and retention time.
Kafka partitions do not remove contention on a single popular IP/network subject.
Capacity planning must include NAT traffic and abusive sources, not only account
count. Raising a numeric limit without this measurement is insufficient.

## Validation evidence and remaining gates

Local tests cover signed topic/expiry binding, conflicting retries, outbox reopen,
Kafka acknowledgement before removal, consumer restart without offset commit,
duplicate delivery, partial Redis application and bounded expired-marker pruning.
`make reputation-kafka-check` starts an isolated, single-broker Kafka fixture and
removes only its own Compose resources on exit. That fixture uses loopback
plaintext and replication factor one; it does not qualify production TLS, ACLs,
quorum behavior or node failure recovery.

`make reputation-worker-check` checks the worker build and diagnostic HTTP boundary.
Both targets are part of `make release-guardrails`, alongside normal guardrails,
vulnerability checking and identity E2E. Actual production throughput, TLS/ACL
proof, three-broker failover and the sustained qualification remain deployment
gates. No completed soak test or million-user capacity result is claimed here.

## Deployment status on 2026-09-13

The general Kubernetes repository contains inactive pinned Strimzi manifests,
three broker/controller node pools, topic and user definitions, certificate-sync
manifests and alert rules. The application repository contains inactive producer
and consumer components and a release-checked worker renderer. Neither active
application overlay has enabled the journal.

Authenticated Prometheus scraping needs additional integration: the existing
Prometheus configuration has no authenticated Nauthilus scrape job. Extending
credential synchronization to read the existing application Secret in each
namespace requires operator approval. Kubernetes Secret RBAC cannot restrict a
read to individual data keys, even though the proposed synchronizer copies only
the metrics username/password. That extension has not been persisted or deployed.

The operator delegated pilot sizing on 2026-09-13. Worker VM normal and emergency
balloon floors were increased from 18 to 21 GiB without a VM restart; the host
retains its existing 48 GiB normal reserve. Three separate brokers and three
controllers remain required, with smaller initial resource budgets recorded in
the Kubernetes repository. Production TLS/ACL/failure qualification remains
required. Operator installation and Secret synchronization are awaiting explicit
security-setting approvals after automatic approval review rejected the general
rollout delegation for those permissions. Existing unrelated work in both manifest repositories remains
outside this change. No new release tag or production rollout is recorded for
this integration yet.

Local `make release-guardrails` completed successfully on 2026-09-13, including
normal guardrails, vulnerability analysis, worker checks, Kafka/Redis recovery
and the complete identity Compose E2E gate. The stronger Kafka replay sample
assertions also passed a subsequent focused run and integration-tag lint. The
application repository validation, both producer component renders, worker
renderer tests, eleven Strimzi schema checks and eleven Prometheus rule syntax
checks passed. These results do not replace the pending production gates.
