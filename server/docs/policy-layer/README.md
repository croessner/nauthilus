# Policy decision layer archives

Most documents in this directory are historical design and implementation
records. They describe configuration roots, migration helpers, runtime
boundaries, and acceptance evidence that have since been superseded by the
production Policy configuration hard cut.

They are not operator documentation and must not be used as a current
configuration reference. The supported production contract is documented in
the [Policy configuration breaking-change guide](../policy_configuration_migration.md),
the [Policy Decision Service operations guide](../policy_operations.md),
the [Policy HTTP client guide](../../openapi/client/README.md), and the
[Policy gRPC guide](../../../api/policy/v1/README.md).

In particular, the former configuration converter and the nested policy root
described by these archives are no longer supported. Migration is manual and
the production server accepts only the top-level `policy` root.

## Current domain contracts

The following files are current versioned integration contracts rather than
historical configuration guidance:

- [DKIM2 Rspamd verifier Policy contract](dkim2_rspamd_policy_contract.md)
- [DKIM2 Rspamd verifier Policy v1 wire example](dkim2_rspamd_policy_request_v1.example.json)
