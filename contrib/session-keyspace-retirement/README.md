# Legacy Session Keyspace Retirement

This operator-only command reports records in the explicitly allowlisted old
`<base-prefix>idp:flow:` namespace. It is not imported by the Nauthilus server
and does not read or print Redis keys or values.

The default is dry-run/report-only:

```shell
GOEXPERIMENT=runtimesecret go run ./contrib/session-keyspace-retirement \
  --redis-address 127.0.0.1:6379 --base-prefix 'nauthilus:'
```

Deletion requires the explicit `--apply` flag. Run it only after the no-mix
full replacement, when old binaries no longer serve traffic. The command never
discovers additional prefixes and never touches the current
`browser-session` keyspace.
