# Durable reputation journal

## Implementation status

The optional Kafka transport and isolated consumer are implemented. The selected
pilot uses one broker and one consumer per environment. Live release inventories
and activation evidence belong to the Kubernetes manifest repositories. No
million-user throughput or high-availability qualification is claimed.

## Acceptance and replay contract

Policy remains the only authority selecting learning. Producers freeze only
independent observations and opaque HMAC identifiers. Credentials, raw account
names and raw IP addresses must never enter Kafka or metrics.

Producers send the immutable contribution directly to Kafka using the native
franz-go client over mutually authenticated TLS. Acceptance requires all in-sync
replicas to acknowledge the record within `delivery_timeout`. There is no local
outbox, CephFS write, object-store fallback or background producer recovery.
Process memory and client-side Kafka buffers are not durable acceptance.

Authentication learning is a Policy-selected, capture-only obligation. The callback
projects bounded independent backend evidence into a dedicated process-local queue
and returns without Redis admission or Kafka I/O. Full queues, unavailable learning
state, storage failures, and expired jobs never turn the selected authentication
result into Tempfail. Other security obligations retain their existing semantics.
The current decision still consumes only already materialized reputation facts.

Fixed background workers perform Redis admission and direct acknowledged Kafka
production. Source concurrency and requests-per-second limits apply to these
workers, including retries; they no longer reject the synchronous login callback.
Transient unavailable or partial outcomes retry the same event identity, at least
250 ms apart and within the original job age budget. Each delivery attempt has its
own timeout. Permanent validation or quota rejection is terminal and observable.

Queue acceptance is volatile, not a durable receipt. A hard producer crash can lose
pending and active unacknowledged learning. A full queue drops the incoming event;
there is no filesystem outbox or overflow queue. Graceful Stop stops admission and
drains workers before closing the journal, bounded by the host shutdown deadline.
Host cancellation aborts remaining work and counts pending items as shutdown loss.

A lost acknowledgement is ambiguous: Kafka may already hold the record. Worker
retries preserve its event identity and consumer deduplication remains necessary.
A new client authentication request has a new host event identity. No exactly-once
guarantee spans authentication and Kafka. Current authentication policy, including
reputation assessment itself, is not weakened by the asynchronous learning path.

### Authentication queue sizing and telemetry

The optional module-level `auth_learning_queue` block is operational and excluded
from the scoring fingerprint:

```yaml
auth_learning_queue:
  capacity: 1024
  max_age: 30s
  timeout: 5s
```

`capacity` bounds waiting events (1..65536); active events are additionally bounded
by the authentication source's effective `max_concurrency`. `max_age` includes
queue residence, rate waiting, retries, and delivery (positive, at most 5 minutes).
`timeout` bounds each storage attempt and must not exceed `max_age`. Defaults above
apply when fields are omitted. Captured jobs retain only bounded event and subject
evidence plus a span identity, never credentials or an entire request context.
Changing queue capacity or the existing `source_admission_capacity` override does
not reset the reputation model or stored history. These bounds are safeguards,
not evidence of sustainable throughput; size them from measured arrival rates,
worker latency, acceptable learning lag, memory, and backend capacity.

`learning_queue_pending` and `learning_queue_active` expose occupancy. The bounded
`learning_total` results additionally include `buffered`, `queue_full`, `expired`,
`shutdown`, `worker_panic`, and `retried`. `buffered` is only local admission;
`queued` still means a Kafka acknowledgement, and `applied` means subject updates.
Alert on discarded/failed learning and sustained queue pressure independently of
login success. Neither metric labels nor journal records contain raw identities.

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
Nauthilus configuration and consumer deployments belong in
nauthilus-tests/kubernetes. Preserve unrelated work and unpublished commits.

The selected production pilot uses one Apache Kafka 4.3.1 StatefulSet, combining
broker and controller roles, with replication factor one and minimum ISR one.
It requests 512 MiB RAM with a 1 GiB limit and a 384 MiB JVM heap, and uses a
16 GiB retained Ceph PVC. Synchronous log flushing reduces the durability gap
of a single broker at the pilot's low event rate. There is no Strimzi operator,
additional CRD installation or workload permission to read Kubernetes Secrets.
The existing cert-manager CA issuer supplies separate broker and client leaves.

A broker outage pauses consumption and triggers bounded background learning retries.
Authentication continues; learning can expire or be dropped if the queue fills. Previously acknowledged messages remain in Kafka. A lost Kafka
volume is not protected by Kafka replication. Ceph storage protection does not
make this a highly available Kafka service. The current resource-constrained
pilot stays single-broker; a larger deployment needs independent failure domains,
replicated controllers/brokers and measured failover behavior.

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
  capacity, queue age, acknowledgement latency and Kafka consumer lag.
- Test broker restart, acknowledged record recovery and idempotent Redis replay.
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
not remove that dependency from the background delivery worker. `queued` means that Kafka acknowledged the record, whereas `applied` means Redis subject
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
`ca_file`, `certificate_file`, `key_file` and `delivery_timeout`. Delivery budgets
are bounded between 100 ms and 10 s; Kafka buffers are bounded to 1,024 records
and 16 MiB. Source admission separately bounds concurrency and requests per second.
Client certificates are re-read for new TLS handshakes; CA changes require a
restart. Kubernetes Secret rotation must trigger that restart.

Remove the obsolete `outbox_directory`, `outbox_max_bytes` and
`outbox_max_records` keys and their PVC mounts. Before retiring the old producer,
drain its already accepted outbox records and verify consumer progress. Do not
remove a nonempty outbox. Deployment rollback must restore paired binaries and
the previous callback binding, configuration and mounts.

The exact learning binding is now `reputation/learn_outcome/obligation/execute/authn/authenticate`.
The model hash canonicalizes this scheduling-only migration to the previous
binding, preserving scores and accepted contributions. Runtime admission accepts
only the new binding. Signal, attribution and other model changes still change
the fingerprint and require a separately planned model migration.

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

Local tests cover signed topic/expiry binding, conflicting retries, rejected Kafka deadlines,
acknowledged delivery, consumer restart without offset commit,
duplicate delivery, partial Redis application and bounded expired-marker pruning.
`make reputation-kafka-check` starts an isolated, single-broker Kafka fixture and
removes only its own Compose resources on exit. That fixture uses loopback
plaintext and replication factor one; it does not qualify production TLS, ACLs,
quorum behavior or node failure recovery.

`make reputation-worker-check` checks the worker build and diagnostic HTTP boundary.
Both targets are part of `make release-guardrails`, alongside normal guardrails,
vulnerability checking and identity E2E. Actual production throughput and sustained qualification remain deployment
gates. The deployed single broker has no Kafka replica failover. No completed soak test or million-user capacity result is claimed here.

## Deployment evidence ownership

The infrastructure repository records the broker, retained PVC, certificates,
topic ACLs, hostname-verified TLS checks and persistent record readback after a
broker restart. Environment-specific client certificates are issued directly in
the application namespaces; no cross-namespace Secret synchronization is needed.

The application manifest repository records the exact release image and six
paired native artifacts, consumer readiness, actual learning and the controlled
outage/replay evidence. A published image does not itself prove live activation.
Require positive buffered and applied counts, preserved authentication decisions while
Kafka is unavailable, visible bounded retries/loss, and recovered acknowledged delivery
after restoration before declaring an outage test successful.
