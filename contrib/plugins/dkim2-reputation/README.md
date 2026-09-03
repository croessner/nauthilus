# DKIM2 Reputation Policy Plugin

This native Go plugin is a reference implementation of the Nauthilus generic Policy extension model. It registers one
`DecisionFactProvider` named `dkim2_reputation.assessment` for the exact target
`dkim2/accept-message-instance`. Its canonical provider ID is
`dkim2/plugin.dkim2_reputation.assessment`, and its sole output is the host-qualified record-list fact
`plugin.dkim2_reputation.assessed_chain`.

The plugin does not register an HTTP handler, a DKIM2-specific Nauthilus core type, a legacy environment source, or a
decision callback. Rspamd submits caller-owned `resource.dkim2.*` and `environment.rspamd.*` facts through the existing
generic Policy API. This plugin validates their v1 semantic coherence and contributes assessment facts. Policy remains
the only decision authority.

The complete caller-owned wire schema and response mapping are documented in the
[Rspamd to Nauthilus DKIM2 policy contract](../../../server/docs/policy-layer/dkim2_rspamd_policy_contract.md). This
README covers only the plugin-owned assessment boundary.

## Security boundary

The admitted `environment.rspamd.scan_action_before_policy` fact uses the
exact closed adapter vocabulary `no action`, `accept`, `add header`,
`rewrite subject`, `greylist`, `soft reject`, `reject`, `quarantine`, and
`discard`. It is pre-Policy context and never represents the final Milter
action.

The provider accepts both modes of the closed `dkim2.verifier-projection.v1` contract. A successful `current`
projection contains exactly one origin record, reports content history, signature history, and protection evaluation as
`not_evaluated`, and reports the established absence of next-domain custody as `not_present`. A `chain` projection
carries complete content and signature history plus evaluated custody and protection aggregates. In either
mode, the provider validates the exact closed record shape, canonical domains and SMTP peer address, contiguous
sequence, aggregate counts and target, Recipe coherence, sorted string collections, and producer-compatible projection
and bound-hop SHA-256 frames. Contract violations return the generic `invalid_input` provider class. Raw messages,
header values, addresses, keys, signatures, and Recipe payloads never enter plugin configuration or output.

For complete chains, `custody_structure=not_present` means that no record contains a `next_domain` or
`terminal_next_domain` transition; it does not limit the chain to a single hop. Ordinary transitions may therefore
follow the origin. `nd_links_evaluated` requires at least one non-terminal `next_domain` transition, while
`terminal_nd_requires_oob` requires exactly one terminal transition in the final record. A complete chain without
authenticated protection flags reports `not_requested`; `not_evaluated` protection states are reserved for the
`current` mode.

`environment.rspamd.smtp_client_ip` is the current SMTP peer observed by Rspamd through `task:get_from_ip()`. It is not
historical DKIM2-hop evidence. The provider therefore applies `allowed_client_cidrs` and peer-reputation violations only
to the target/current hop. The same peer classification is repeated in every output record as request-wide context, but
it does not affect a historical record's `acceptable` value.

Unknown signers, unknown peer networks, missing contracts, blocked classifications, unauthorized Recipe changes, and
upstream non-permittable states assess false rather than becoming implicit trust. A terminal `nd=` state always emits
`terminal_oob_required`; this plugin cannot establish out-of-band authority.

## Build and test

```sh
GOEXPERIMENT=runtimesecret go test .
GOEXPERIMENT=runtimesecret go build -buildmode=plugin -o build/dkim2-reputation.so .
```

The build directory is ignored by Git.

## Plugin configuration

All reputation data is explicit and operator-owned. Request-time assessment performs no network or file I/O. A valid
snapshot needs at least one member in each section:

```yaml
plugins:
  modules:
    - name: dkim2_reputation
      type: go
      path: /usr/lib/nauthilus/plugins/dkim2-reputation.so
      checksum: sha256:replace-with-artifact-sha256
      optional: false
      config:
        domains:
          - domain: origin.example
            reputation: neutral
          - domain: relay.example
            reputation: trusted
        client_networks:
          - cidr: 203.0.113.0/24
            reputation: trusted
        contracts:
          - signer_domain: origin.example
            allowed_client_cidrs:
              - 192.0.2.0/24
            permitted_change_classes: []
          - signer_domain: relay.example
            allowed_client_cidrs:
              - 203.0.113.0/24
            permitted_change_classes:
              - body.rewrite
              - header.rewrite
```

Domains must be canonical lower-case DNS names. CIDRs must be canonical network prefixes without host bits or mapped
IPv4-in-IPv6 forms. Overlapping client networks use deterministic longest-prefix classification. Reputation values are
`trusted`, `neutral`, or `blocked`. Unknown inputs remain `unknown`; there is no configurable permissive default.

Contracts are exact signer-domain entries. `permitted_change_classes` is a byte-lexically sorted unique subset of
`body.rewrite` and `header.rewrite`. An unchanged Recipe needs no change-class entry but still needs a signer contract.
For a historical hop, a matching contract validates signer and Recipe facts without evaluating the current peer CIDR.
For the target hop, the exact SMTP peer must also match `allowed_client_cidrs`.

## `assessed_chain` output

Every output record contains exactly:

- `sequence`, `message_instance`, and `hop_binding`, copied from the validated verifier projection;
- `signer_reputation`: `trusted`, `neutral`, `blocked`, or `unknown`;
- `smtp_peer_reputation`: the request-wide current-peer classification using the same vocabulary;
- `contract_state`: `matched`, `missing`, or `peer_mismatch`;
- `recipe_authorization`: `permitted`, `denied`, or `uncontracted`;
- `assessment_complete`: true after complete deterministic assessment;
- `acceptable`: the plugin's fail-closed assessment fact, not a Policy decision;
- `violation_classes`: a sorted unique explanation list.

The closed violation vocabulary is:

- `authentication_not_pass`
- `body_unavailable`
- `contract_missing`
- `contract_peer_mismatch`
- `do_not_explode_violated`
- `do_not_modify_violated`
- `history_not_matched`
- `recipe_not_authorized`
- `signer_reputation_blocked`
- `signer_reputation_unknown`
- `smtp_peer_reputation_blocked`
- `smtp_peer_reputation_unknown`
- `terminal_oob_required`
- `upstream_nonpermittable`

Policy can require complete records, select the target record by the aggregate target identity, and combine these facts
with other configured providers. The plugin never returns `permit`, `deny`, SMTP actions, obligations, or advice.
