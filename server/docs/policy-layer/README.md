# Policy decision layer archives

The documents in this directory are historical design and implementation
records. They describe configuration roots, migration helpers, runtime
boundaries, and acceptance evidence that have since been superseded by the
production Policy configuration hard cut.

They are not operator documentation and must not be used as a current
configuration reference. The supported production contract is documented in
the [Policy configuration breaking-change guide](../policy_configuration_migration.md),
the [Policy HTTP client guide](../../openapi/client/README.md), and the
[Policy gRPC guide](../../../api/policy/v1/README.md).

In particular, the former configuration converter and the nested policy root
described by these archives are no longer supported. Migration is manual and
the production server accepts only the top-level `policy` root.
