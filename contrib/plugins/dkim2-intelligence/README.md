# DKIM2 intelligence

This native fact provider composes an admitted verifier projection with
preexisting generic reputation, current-peer GeoIP/ASN evidence and explicit
operator identity contracts. It has no Redis, HTTP, credential, effect, permit
or deny capability. DKIM2 remains responsible for parsing, cryptographic
verification, reconstruction, Recipe execution, replay handling and sealing.

The component is `dkim2/plugin.dkim2_intelligence.assessment`. Its only outputs
are `plugin.dkim2_intelligence.assessed_chain`, `.smtp_peer` and
`.assessment_complete`. The first collection contains the admitted ordered
chain (1–128 records, 34 declared fields, 262144 aggregate bytes); the second
contains one SMTP peer record (36 declared fields, 8192 aggregate bytes).
Conditional tuple fields are absent when their state does not permit details.
The independent normative fixture is `testdata/record-contract.json`; the
executable field schema is in
`server/docs/examples/policy_dkim2_rspamd_verifier.yml`.

## Input authority and correlation

The generic host must bind the exact configured reputation and geographic
components, declare their output schemas and schedule both before this
component. Reputation additionally depends on GeoIP for the optional typed ASN
extractor. A missing dependency, wrong producer, hidden consumed record field
or incompatible type prevents catalog activation. Names in the Policy
`providers` map are authored aliases; native `component` selects the exact
registered component, so two modules may both export `assessment` without
sharing authority. Omitting `component` preserves the map-name default.

Projection validation and binding recomputation have one implementation in
`internal/dkim2projection`. This checks the already supplied semantic projection;
it does not reconstruct or verify DKIM2 messages. Every signer assessment must
match the corresponding canonical domain, sequence, Message-Instance and
32-byte hop binding, in the same order. The current target must be the final
admitted hop. Missing, duplicated, reordered, oversized or forged correlations
return `invalid_input` with no facts. The provider first builds and validates
both collections, then publishes all three facts atomically.

All reputation tuples retain the exact configured profile, state, band,
override and, when permitted, all six measurement fields. The pure
`internal/reputationview` package owns tuple encoding and validation for both
producer and composer. IP, network and ASN remain separate tuples. A missing
ASN produces an unavailable ASN tuple without inventing a subject or querying
an empty identity. A fresh geographic result cannot conceal an unavailable
reputation lookup. `assessment_complete=true` means structurally complete
correlation, including explicit unavailable states; it is not a trust or
permission result.

## Configuration

Merge the module composition fragment by module and target-binding identity
with the generic reputation configuration. The canonical verifier Policy owns
the provider schedule and all fact schemas in one place. Preserve the reputation model, primary Redis,
opaque-key and source admission settings. Different target namespaces need
different reputation component names. The supplied DKIM2 component is
`assessment`; an authentication component must have another local name when
both are enabled in the same module.

The configuration requires `reputation_provider`, `reputation_fact`,
`geoip_provider` and `decision_profile` (`fast`, `operational` or `baseline`).
These values define the registered input contract and require restart when
changed. `identity_contracts` and `signer_sets` may be reconfigured together as
one immutable snapshot. Unknown configuration keys fail registration.

An identity contract names explicit canonical domains, optional canonical
CIDRs and optional integer ASNs. CIDR match has priority when both kinds are
configured; ASN match retains the weaker, separate `asn` strength. No ISP,
mailbox provider or forwarding service is automatically trusted. Historical
membership in an explicit contract or its referenced signer set yields only `domain_only`.
Only the current target can acquire `matched/cidr` or `matched/asn` from the
actual SMTP peer. Missing domains, mismatches and unavailable required ASN
evidence remain distinct. With no configured contracts there is no inferred
provider allowlist.

GeoIP evidence must describe exactly the current canonical SMTP IP. Fresh or
stale evidence carries a bounded age; unavailable/not-found evidence cannot
carry fabricated location or ASN details. Geographic freshness is determined
by the generic GeoIP provider's opened database snapshot and configured age
limits. The composer does not refresh databases or perform network lookups.

## Privacy and validation

The output excludes raw IP duplication, subject tags, message headers or
values, bodies, keys, selectors, signatures, Recipe payloads and recipe
digests. Hop bindings and ASN organization are provider-private in the
executable schema. The lower-case verifier signature state is copied
unchanged. Closed violation classes describe observed semantic conditions;
Recipe authorization and final action belong to Policy rules.

Run the focused package tests with `GOEXPERIMENT=runtimesecret go test
./contrib/plugins/dkim2-intelligence`. The configured-generation test uses the
actual composer and explicitly identified upstream test doubles to prove
schema, dependency and visibility activation. It does not claim a Redis read,
MMDB lookup or native artifact load. Those boundaries have separate generic
provider integration and native-bundle checks. Build host and plugin from one
coherent source/compiler identity with the repository artifact tooling;
`scripts/check-native-artifact-bundle.sh` includes this module and rejects
stale and unmarked binaries.

## Operational telemetry

The host-scoped `composition_total` counter has one additional `result` label:
`completed`, `unavailable`, `projection_invalid`, `reputation_invalid`,
`correlation_invalid`, `geoip_invalid`, or `composition_invalid`. It follows
the actual enrichment callback and never labels signers, peer addresses, hop
identities, Recipe data or caller input. `completed` means composition passed
its contract checks; the selected Policy still owns the delivery decision.
Exporter failure does not change composition results.
