# Durable reputation journal

## Implementation status

This document tracks the Kafka integration while it is being implemented.
The production baseline remains v4.0.0-alpha.28. The simple single-broker pilot is being deployed. No million-user throughput
or high-availability qualification is claimed.

## Acceptance and replay contract

Policy remains the only authority selecting learning. Producers freeze only
independent observations and opaque HMAC identifiers. Credentials, raw account
names and raw IP addresses must never enter Kafka, outbox files or metrics.

Producers sync every immutable record to the persistent outbox before spending
the caller deadline on Kafka delivery. This preserves acceptance even if the
broker consumes the remaining request budget. Process memory and
client-side Kafka buffers are not durable acceptance. An outbox record is
removed only after confirmed Kafka acknowledgement. A failed or ambiguous
send can therefore be repeated. Recovery never holds the shared admission lock
while waiting for Kafka. Acknowledgement checks the exact immutable record before
removal, so concurrent recovery cannot delete a different record. This design
adds filesystem synchronization to the healthy path; benchmark that cost before
raising the pilot load.

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

Kafka infrastructure belongs in the general Kubernetes repository under `kafka`.
Nauthilus configuration, outbox mounts and consumer deployments belong in
nauthilus-tests/kubernetes. Preserve unrelated work and unpublished commits.

The selected production pilot uses one Apache Kafka 4.3.1 StatefulSet, combining
broker and controller roles, with replication factor one and minimum ISR one.
It requests 512 MiB RAM with a 1 GiB limit and a 384 MiB JVM heap, and uses a
16 GiB retained Ceph PVC. Synchronous log flushing reduces the durability gap
of a single broker at the pilot's low event rate. There is no Strimzi operator,
additional CRD installation or workload permission to read Kubernetes Secrets.
The existing cert-manager CA issuer supplies separate broker and client leaves.

A broker outage pauses consumption; persistent producer outboxes retain newly
accepted work until recovery. A lost Kafka volume is not protected by Kafka
replication. Ceph storage protection and the application outbox do not make this
a highly available Kafka service. Scale up only after measuring actual demand.

The temporary increase of worker balloon floors was rolled back when the
operator selected this smaller deployment. Existing host memory safeguards and
worker budgets remain the sizing baseline. Each environment uses one consumer
with a 128 MiB memory request and a 512 MiB limit.

## Qualification gates

- Test recovery after a producer process restart and a broker outage.
- Test ambiguous acknowledgement, exact duplicate, conflicting retry,
  partial subject updates, consumer restart and consumer rebalance.
- Prove TLS verification, producer/consumer ACL separation and absence of
  raw identifiers in sample journal records without printing those records.
- Measure sustained throughput, tail latency, Redis memory, hot-subject
  capacity, queue age, outbox occupancy and Kafka consumer lag.
- Test broker restart, persistent record recovery and idempotent Redis replay.
  Broker or worker loss is an expected temporary service interruption in this
  single-broker pilot, not an HA failover qualification.
- Record actual test duration and load. Do not claim a completed soak or
  million-user qualification from a small functional pilot.
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
vulnerability checking and identity E2E. Actual production throughput and sustained qualification remain deployment
gates. The deployed single broker has no Kafka replica failover. No completed soak test or million-user capacity result is claimed here.

## Deployment status on 2026-09-13

The single Kafka StatefulSet, retained PVC and broker certificate have been
applied. The broker is Ready. Four environment-specific client certificates
are managed directly in the application namespaces by the existing cert-manager;
no cross-namespace Secret synchronization is needed. Topic/ACL provisioning, verified TLS hostname checking, eight topic-scope checks,
four forbidden-write denials and persistent record readback after a broker restart
passed. Journal activation in Shadow and production remains a separate gate.

The runtime commit passed local release guardrails and all seven CI workflows,
including Kafka integration. Documentation changes do not change that runtime.
The release and live journal activation remain incomplete until paired native
artifacts, consumer readiness and actual learning/replay are verified.
