# Rspamd to Nauthilus DKIM2 policy request contract

## Status

This is the approved version 1 implementation contract. It is intentionally narrower
than everything Rspamd can technically expose. The first implementation must
use the exact target and projection identity below and reject unknown fields.

- Policy API version: `1`
- Target: `dkim2/accept-message-instance`
- Projection: `dkim2.verifier-projection.v1`
- Canonical Policy-Basic username: `rspamd-verifier`
- One unary request per applicable Rspamd scan
- No `subject` object until an independently authenticated policy subject is
  defined
- Diagnostics disabled for the production caller

An applicable scan has a strictly validated projection with complete
verification `PASS`, `scope=chain`, and existing DKIM2
`local_policy_verdict`/`disposition` in `accept|continue`, plus replay class
`first_seen|exploded`. The normal filter enforces verifier
FAIL/PERMERROR/TEMPERROR, non-permittable replay state, reject, tempfail, and
`out_of_band_required` without calling Nauthilus. Required-provider failure is
therefore a failure while assessing an otherwise applicable PASS, never an
encoding of an upstream DKIM2 temporary result.

The complete producer-golden-backed wire request is stored in
`server/docs/policy-layer/dkim2_rspamd_policy_request_v1.example.json`. Its
projection, Recipe, and hop-binding values are copied coherently from the DKIM2
producer golden vector `testdata/reference/verifier-projection-v1-binding.json`;
the Nauthilus plugin keeps a byte-for-byte copy in
`contrib/plugins/dkim2-reputation/testdata`. A cross-artifact test must decode
this tracked request through generic admission and the real native provider
`Collect` path. JSON syntax validation alone is not contract evidence.

## Provenance model

The request has three distinct provenance classes.

1. `resource.dkim2.*` contains verifier-owned facts copied from the strictly
   validated `dkim2d` response. Rspamd transports but does not derive them.
   On the wire, keys nested below `resource.attributes` are local `dkim2.*`
   names; Nauthilus admission adds the `resource.` category prefix.
2. `environment.rspamd.*` contains bounded observations made by Rspamd and the
   MTA integration for the current scan. On the wire, keys nested below
   `environment.attributes` are local `rspamd.*` names; admission adds the
   `environment.` category prefix.
3. `version`, `request_id`, `target`, and the environment identity are transport
   and caller-correlation data.

Nauthilus provider results are not caller inputs. The production v1 native Go
DecisionFactProvider has canonical identity
`dkim2/plugin.dkim2_reputation.assessment` and emits only
`plugin.dkim2_reputation.assessed_chain`. This initial static provider derives
signer reputation, current SMTP-peer reputation, contract matching, Recipe
authorization, and policy violations with host-qualified native-plugin
provenance. It does not implement ASN/Geo enrichment and never authorizes a
terminal OOB case; `terminal_oob_required` makes the assessment unacceptable.
Later native providers may derive ASN/Geo or separately specified OOB trust
from admitted IP/domain facts without changing caller provenance. Generic Lua
is not the production assessor for this contract.

## Nauthilus implementation boundary

The Nauthilus integration is configuration-only: exact target/schema
configuration, caller admission allowlist, policy, and provider binding use the
existing generic Policy surfaces. Nauthilus core gains no DKIM2/Rspamd-specific
validator, handler, target type, request mapper, provider runtime, or policy
branch. The production native Go plugin uses the existing generic
DecisionFactProvider API; it does not introduce another extension point.

The projection binding is an integrity/correlation digest over the canonical
projection. A plain digest is not caller authentication or a cryptographic
signature. Caller authentication authorizes the Rspamd adapter; a future
signed projection would require a separate contract.

## Transport and correlation

| Field | Type | Meaning |
|---|---|---|
| `version` | string enum | Nauthilus Policy wire contract version, fixed to `1`. |
| `request_id` | opaque string | Fresh Rspamd task correlation ID for this scan. It is not the MIME `Message-ID`, queue ID, Redis key, or replay identity. A retry gets a new request ID. |
| `target.namespace` | string enum | Fixed to `dkim2`. |
| `target.action` | string enum | Fixed to `accept-message-instance`. |
| `resource.type` | string enum | Fixed to `dkim2-message-instance`. |
| `environment.service` | string enum | Fixed to `rspamd`. |
| `environment.instance` | canonical service identity | Configured Rspamd/MX instance, admitted for the authenticated caller. It is not taken from message content. |
| `environment.protocol` | string enum | Fixed to `milter` for the production path. |
| `options.include_diagnostics` | boolean | Fixed to `false` for production. |

## Verifier-owned aggregate facts

All of these normalized fact names use the Nauthilus typed-value wrapper shown
in the example. Their wire keys omit the leading `resource.` because they are
already nested below `resource.attributes`.

| Attribute | Type | Meaning |
|---|---|---|
| `resource.dkim2.projection_schema` | string enum | Exact projection identity. |
| `resource.dkim2.draft` | string enum | Exact DKIM2 draft implemented by the verifier. |
| `resource.dkim2.projection_binding_algorithm` | string enum | Fixed to `sha-256` in v1. |
| `resource.dkim2.projection_binding` | 32-byte value | Digest of the complete canonical projection, used for coherence and provider correlation. |
| `resource.dkim2.verification_state` | enum | Immutable verifier state: `PASS`, `FAIL`, `PERMERROR`, or `TEMPERROR`. |
| `resource.dkim2.verification_reason` | closed enum | Verifier-owned primary reason. |
| `resource.dkim2.scope` | enum | `current` or `chain`. |
| `resource.dkim2.historical_content` | enum | `not_evaluated`, `complete`, or `partial`. |
| `resource.dkim2.historical_signatures` | enum | `not_evaluated` or `complete`. |
| `resource.dkim2.custody_structure` | enum | `not_evaluated`, `not_present`, `nd_links_evaluated`, or `terminal_nd_requires_oob`. |
| `resource.dkim2.target_sequence` | positive integer | Selected DKIM2 signature sequence. |
| `resource.dkim2.target_message_instance` | positive integer | Selected Message-Instance number. |
| `resource.dkim2.claimed_hop_count` | bounded positive integer | Number of records claimed in the complete chain. It must match the chain and target coherence rules. |
| `resource.dkim2.authentication_state` | enum | Final DKIM2 authentication state after replay processing. |
| `resource.dkim2.authentication_reason` | closed enum | Final authentication reason, including replay-specific reasons. |
| `resource.dkim2.replay_class` | enum | `not_checked`, `disabled`, `first_seen`, `exploded`, `replayed`, or `indeterminate`. |
| `resource.dkim2.local_policy_mode` | enum | DKIM2 daemon policy mode: `strict`, `permissive`, or `testing`. |
| `resource.dkim2.local_policy_verdict` | enum | Daemon-local `accept`, `continue`, `reject`, or `tempfail`. |
| `resource.dkim2.local_policy_reason` | closed enum | Daemon-local primary policy reason. |
| `resource.dkim2.do_not_modify_state` | closed enum | Daemon evaluation of authenticated `donotmodify`: `not_requested`, `indeterminate`, or `not_evaluated`. |
| `resource.dkim2.do_not_explode_state` | closed enum | Daemon evaluation of authenticated `donotexplode`: `not_requested`, `violated`, `indeterminate`, or `not_evaluated`. |
| `resource.dkim2.dns_testing_effective` | boolean | Whether authenticated DNS testing policy affected the daemon decision. |
| `resource.dkim2.disposition` | enum | Closed disposition already selected by `dkim2d`; Nauthilus cannot widen it. |

The existing `/v1/process` response already supplies most aggregate values.
The projection schema, projection binding, claimed hop count, and complete hop
records require a bounded `dkim2d` response extension.

## Verifier-owned chain records

`resource.dkim2.chain` is one ordered record-list value. Version 1 permits at
most 128 records, matching the verifier's authenticated history ceiling. The
record sequences must be strictly increasing and unique. The generic configured
schema rejects unknown or missing fields, wrong kinds, and static bounds during
admission. The native provider Collect path owns closed vocabularies plus
sequence/count/binding/domain/IP/Recipe semantic coherence and fails closed
without emitting an assessed-chain fact.

Each record contains:

| Field | Type | Meaning |
|---|---|---|
| `sequence` | positive integer | Authenticated DKIM2 hop sequence. |
| `message_instance` | positive integer | Authenticated Message-Instance number at this hop. |
| `hop_binding` | 32-byte value | Canonical digest binding this record to its exact verifier projection. |
| `signer_domain` | canonical DNS domain | Verified signing domain, suitable for Nauthilus domain-reputation lookup. |
| `signature_algorithms` | bounded string list | Closed set of successfully authenticated algorithm families for the hop. |
| `signature_state` | enum | Aggregate authenticated hop signature state, initially `pass` for a retained complete-chain hop. |
| `custody_transition` | enum | Exact v1 vocabulary: `origin`, `ordinary`, `next_domain`, or `terminal_next_domain`. |
| `do_not_modify` | boolean | Authenticated `donotmodify` flag. |
| `do_not_explode` | boolean | Authenticated `donotexplode` flag. |
| `feedback` | boolean | Authenticated `feedback` flag. |
| `feed_here` | boolean | Authenticated `feedhere` flag. |
| `exploded` | boolean | Authenticated `exploded` marker. |
| `recipe_mode` | enum | `unchanged` or `applied`. |
| `recipe_has_header_changes` | boolean | Whether the authenticated Recipe contains one or more header dimensions. |
| `recipe_body_mode` | enum | Exact Draft-06 body member form: `absent`, `steps`, or `unavailable`. `unavailable` represents the irreversible/null-body case. |
| `recipe_digest` | 32-byte value | Digest of the canonical normalized Recipe descriptor, never the Recipe payload. |
| `change_classes` | bounded string list | Ascending lexical-byte-order unique subset of exactly `body.rewrite` and `header.rewrite`. These are verifier-derived, not guessed by Rspamd; `body.append` is not a v1 value. |
| `affected_headers` | bounded string list | Sorted unique lower-case header names only; no values. |
| `history_header_state` | enum | `matched`, `mismatch`, `unavailable`, or `unsupported`. |
| `history_body_state` | enum | `matched`, `mismatch`, `unavailable`, or `unsupported`. |
| `body_availability` | enum | `known` or `unavailable`. |
| `change_count` | bounded nonnegative integer | Number of normalized semantic change classes/events represented by the descriptor. |
| `affected_header_count` | bounded nonnegative integer | Coherence count for the retained affected-header list. |

Selector and key fingerprint are deliberately omitted from v1. DKIM2 permits
multiple signature sets per hop; one scalar selector/fingerprint would either
discard authenticated evidence or introduce ambiguous parallel arrays. Domain
reputation does not need key identity. A concrete key-reputation requirement
must introduce a correctly correlated new projection schema rather than widen
v1 in place.

Exact Recipe JSON is also absent. If a future provider genuinely requires it,
it must use a separately enabled protected field with strict size limits and a
single provider allowlist. It must remain unavailable to expressions,
diagnostics, reports, logs, traces, metrics, and error bodies.

## Native assessed-chain output

The production provider `dkim2/plugin.dkim2_reputation.assessment` emits one
ordered record-list fact, `plugin.dkim2_reputation.assessed_chain`. Its record
schema has exactly ten fields:

- `sequence`;
- `message_instance`;
- `hop_binding`;
- `signer_reputation`;
- `smtp_peer_reputation`;
- `contract_state`;
- `recipe_authorization`;
- `assessment_complete`;
- `acceptable`;
- `violation_classes`.

Count, order, sequence, Message-Instance, and hop-binding coverage correlate the
assessment with every caller chain record. The output does not copy signer
domains, Recipe digests, projection bindings, caller facts, raw provider data,
or arbitrary details. Exact enum vocabularies are fixed by the native plugin
output contract and may not be widened at runtime.

The closed v1 vocabularies are:

- `signer_reputation` and `smtp_peer_reputation`:
  `trusted|neutral|blocked|unknown`;
- `contract_state`: `matched|missing|peer_mismatch`;
- `recipe_authorization`: `permitted|denied|uncontracted`;
- `violation_classes`: an ascending lexical-byte-order, unique subset of
  `authentication_not_pass`, `body_unavailable`, `contract_missing`,
  `contract_peer_mismatch`, `do_not_explode_violated`,
  `do_not_modify_violated`, `history_not_matched`, `recipe_not_authorized`,
  `signer_reputation_blocked`, `signer_reputation_unknown`,
  `smtp_peer_reputation_blocked`, `smtp_peer_reputation_unknown`,
  `terminal_oob_required`, and `upstream_nonpermittable`.

`assessment_complete` and `acceptable` are booleans. Unknown enum or violation
values are invalid provider output and fail closed.

The initial provider never turns `terminal_oob_required` into trusted or
acceptable state. A future OOB authorization mechanism requires its own native
provider contract and policy change.

`smtp_peer_reputation` repeats one request-wide current-peer assessment in each
correlated record so flat record-local predicates remain self-contained. It is
not evidence about the SMTP IP of a historical hop. The provider may enforce
allowed peer CIDRs only for the target/current hop identified by
`target_sequence` and `target_message_instance`; it must never attribute the
current SMTP peer to earlier chain records.

## Rspamd and SMTP environment facts

These normalized fact names are observations, not cryptographic facts. Their
wire keys omit the leading `environment.` because they are already nested below
`environment.attributes`.

| Attribute | Type | Meaning |
|---|---|---|
| `environment.rspamd.scan_action_before_policy` | closed enum | Current metric action immediately before the Nauthilus policy symbol. The exact v1 adapter vocabulary is `no action`, `accept`, `add header`, `rewrite subject`, `greylist`, `soft reject`, `reject`, `quarantine`, and `discard`. It is explicitly not the final Milter action. |
| `environment.rspamd.metric_score` | finite double | Current default metric score. Policy must not confuse this with a final action. |
| `environment.rspamd.reject_threshold` | finite double | Effective reject threshold for this task/settings context. |
| `environment.rspamd.greylist_threshold` | finite double | Effective greylist threshold for this task/settings context. |
| `environment.rspamd.normalized_signals` | bounded closed string list | Adapter-owned semantic mapping of explicitly allowlisted Rspamd symbols. The v1 vocabulary is `dmarc.pass`, `dmarc.fail`, `dmarc.temperror`, `dmarc.permerror`, `spf.pass`, `spf.neutral`, `spf.softfail`, `spf.fail`, `spf.temperror`, `spf.permerror`, `dkim.pass`, `dkim.fail`, `dkim.temperror`, `dkim.permerror`, `arc.pass`, `arc.fail`, `arc.invalid`, `malware.detected`, `phishing.detected`, and `spam.high_confidence`. No options or arbitrary symbol names. |
| `environment.rspamd.smtp_client_ip` | canonical IPv4 or IPv6 string | Mandatory actual remote SMTP peer into the current Rspamd scan, supplied by the MTA through `task:get_from_ip()`. Never use `task:get_client_ip()`, which may identify the MTA-to-Rspamd connection. Missing required input fails admission; malformed or magic substitute semantics fail closed in the native provider Collect path. This is current-hop context, never historical-hop IP evidence. |
| `environment.rspamd.client_class` | closed enum | Locally configured class such as `untrusted`, `trusted`, `local`, or `authenticated`; it does not replace the exact IP. |
| `environment.rspamd.mail_from_class` | closed enum | Privacy-minimized envelope class such as `null`, `local`, or `external`. |
| `environment.rspamd.recipient_classes` | bounded closed string list | Unique privacy-minimized classes such as `local`, `relay`, or `external`. |
| `environment.rspamd.smtp_authenticated` | boolean | Whether the MTA supplied an authenticated SMTP user. The username is not sent. |
| `environment.rspamd.recipient_count` | bounded positive integer | Original SMTP recipient count. |
| `environment.rspamd.message_size` | bounded nonnegative integer | Message size observed by Rspamd. |
| `environment.rspamd.message_fidelity` | enum | Exact representation sent to `dkim2d`, for example `milter_reconstructed_crlf`. |

The SMTP client IP is sensitive request data. It may be used by admitted
Nauthilus providers and policies, but must be redacted or pseudonymized in
normal logs, metrics, traces, reports, diagnostics, and errors. It is never a
Redis retry-cache key component in plaintext.

## Version 1 bounds

Every v1 sorted-unique string list uses ascending lexical byte order. Enum rank,
locale collation, case folding, and producer insertion order are not canonical
ordering rules.

- `resource.dkim2.chain`: at most 128 records;
- `signature_algorithms`: sorted unique subset of `rsa-sha256`, `rsa-sha512`,
  `ed25519-sha256`, and `ed25519-sha512`, at most four values;
- `normalized_signals`: sorted unique schema-owned values, at most 20;
- `affected_headers`: sorted unique lower-case field names, at most 128 values
  of at most 64 bytes each;
- `change_classes`: sorted unique schema-owned values, at most two values of at
  most 64 bytes each;
- canonical domain names: at most 253 bytes;
- request and instance identities: at most 128 bytes;
- recipient classes: sorted unique subset of `external`, `local`, and `relay`,
  at most three values;
- assessed `violation_classes`: sorted unique schema-owned values, at most 14;
- projection and hop bindings and Recipe digests: exactly 32 decoded bytes;
- every value and the complete request remain subject to any stricter generic
  Policy API scalar, list, record, and aggregate bound.

## Deliberately excluded inputs

The v1 request does not contain:

- raw RFC 5322/MIME content, bodies, header values, attachments, or URLs;
- raw envelope sender or recipient addresses, HELO, reverse DNS, authenticated
  username, queue ID, or MIME `Message-ID`;
- all Rspamd symbols, symbol scores, symbol options, arbitrary metadata, or
  arbitrary maps;
- Redis keys, retry-cache state, cache-hit status, replay keys, capabilities,
  credentials, or Nauthilus authentication material;
- DNS public keys, signatures, exact Recipes, reconstructed messages, or
  verifier-internal work accounting;
- caller-supplied reputation, ASN, Geo, trusted-contract, OOB-trust,
  authorization, or violation results.

An excluded field can enter a later schema only with a concrete policy/provider
requirement, exact provenance, bounds, observability rules, and tests. Version
1 remains closed and is not widened silently.

## Decision consumption

Rspamd strictly validates the Nauthilus response. In the initial contract it
consumes `effect` and `status.retryable`; obligations remain empty unless a
separate allowlisted Rspamd obligation contract is specified.

- `permit`: continue without forcing global accept and without widening the
  existing DKIM2/Rspamd result.
- `deny`: permanent reject and consume/delete the retry entry.
- retryable `indeterminate`: soft reject and arm the DKIM2 retry result.
- non-retryable `indeterminate`: permanent reject and consume/delete the retry
  entry.
- unexpected `not_applicable`, malformed or unknown success, unsupported
  effect/obligation, transport timeout, TLS failure, authentication failure, or
  any HTTP failure: technical soft reject and arm/re-arm the retry entry. These
  conditions are operator-correctable and must not cause message loss.

Only a strictly validated success response may select `permit`, `deny`, or
`indeterminate`. Nauthilus reason/detail text, response bodies, provider errors,
and authentication errors are never copied verbatim into SMTP replies, Rspamd
symbols, logs, or metrics. The adapter uses fixed bounded local reason classes.

This response mapping applies only after the normal filter's applicability gate.
Nauthilus permit cannot reopen, relabel, or replace an upstream verifier/local
policy result because non-applicable upstream outcomes never reach the Policy
call.

The late retry-cache finalizer, not the Nauthilus request mapper, observes the
effective action after the Nauthilus symbol and `GREYLIST_SAVE` and then arms,
re-arms, consumes, or deletes the cached `dkim2d` result.

After `permit`, an unrelated final Rspamd soft reject, including greylisting,
arms/re-arms; final accept or an unrelated permanent reject consumes/deletes.
This preserves stricter Rspamd authorities and makes final action, not
intermediate Policy state, authoritative for cache lifecycle.

## Bound implementation decisions

- Version 1 uses signer-domain reputation and intentionally omits selector and
  key fingerprint.
- The actual SMTP client IP is mandatory for every production Milter request.
- The production assessor is the native Go DecisionFactProvider
  `dkim2/plugin.dkim2_reputation.assessment`, which emits only
  `plugin.dkim2_reputation.assessed_chain`; generic Lua is not used for the
  production assessment.
- The DKIM2 producer owns canonical projection and hop-binding construction
  with SHA-256; the Rspamd and Nauthilus consumers validate but never recreate
  verifier facts.
- SMTP IP and domain facts are redacted or pseudonymized in ordinary logs,
  traces, audit, reports, diagnostics, errors, and metrics.
- Outbound signing policy is deferred and is not part of this prompt pack.
