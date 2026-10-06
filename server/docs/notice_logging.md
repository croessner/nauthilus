# NOTICE field filtering

`observability.log.notice_ignore_fields` removes selected structured field keys
from NOTICE records. An omitted or empty list preserves the existing output.

```yaml
observability:
  log:
    notice_ignore_fields:
      - source
      - ssl_client_subject_dn
      - ssl_client_issuer_dn
      - ldap_lookup
```

Matching is exact and case-sensitive. Keys can belong to built-in request fields,
plugin or Lua `AdditionalLogs`, bound logger attributes, or trace correlation.
Unknown keys are accepted to support custom fields. Matching leaf attributes
inside structured groups are also removed; group names are not field selectors.
All occurrences of a matching key are omitted. Filtering applies to all NOTICE
records, including request processing, authentication results, and identity events.
DEBUG, INFO, WARN, and ERROR records retain their complete fields.

The required keys `time`, `level`, `instance`, `session`, and `msg` cannot appear
in the ignore list. Blank keys are also rejected during configuration validation.
Required fields remain present wherever the corresponding logger or event already
supplies them; the filter does not manufacture session IDs for unrelated events.

JSON, text, and colored text outputs share the same selection. A configuration
reload updates the selection for existing derived loggers as well as new ones.
Filtering reduces encoded output; it does not prevent producers from computing
field values. Removing fields also removes them from downstream log searches,
so retain the identifiers and decision evidence required for operations.
