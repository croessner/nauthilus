# Backend Health Checks

Backend health checks are configured under `auth.services.backend_health_checks`. Each target selects its protocol,
endpoint, probe depth, TLS transport, optional PROXY-v2 preface, and authentication mechanism independently.

## TLS Modes

Use `tls_mode` to make the transport contract explicit:

| Mode | Behavior |
| --- | --- |
| `plain` | Keep the connection unencrypted. Credential-bearing checks still fail closed on plaintext. |
| `implicit` | Start TLS immediately after the optional PROXY-v2 preface. |
| `starttls` | Upgrade through the application protocol before authentication. |

`starttls` requires `deep_check: true`. It is supported for SMTP, LMTP when advertised by the server, POP3, IMAP, and
ManageSieve. HTTP targets reject it because HTTP has no corresponding in-band upgrade in this health-check model.

The legacy Boolean `tls` key remains supported. `tls: true` resolves to implicit TLS. An existing ManageSieve target
without `tls_mode` retains its historical STARTTLS behavior. New configurations should use `tls_mode` directly.

Combining `tls: true` with `tls_mode: plain` or `tls_mode: starttls` is invalid. `tls: true` with
`tls_mode: implicit` is accepted for migration compatibility.

## STARTTLS Security

`tls_mode: starttls` is a require-TLS policy, not opportunistic encryption. A missing capability, refused upgrade, TLS
handshake failure, or failed protected capability refresh makes the target unhealthy. Nauthilus discards capabilities
learned before TLS and selects authentication only from the protected capability response.

The protocol upgrade commands are:

- SMTP and LMTP: `STARTTLS` after `EHLO` or `LHLO`;
- POP3: `STLS` after `CAPA`;
- IMAP: tagged `STARTTLS` after `CAPABILITY`;
- ManageSieve: `STARTTLS` after the server greeting.

## PROXY V2 Ordering

When `haproxy_v2: true` is configured, Nauthilus writes the PROXY-v2 header before any TLS or application-protocol
bytes. A STARTTLS target therefore uses this order:

```text
TCP -> PROXY v2 -> greeting -> capabilities -> STARTTLS or STLS
    -> TLS handshake -> protected capabilities -> authentication
```

The target listener must explicitly accept PROXY protocol version 2. Sending the preface to an ordinary protocol
listener makes the probe fail and may be logged as malformed protocol input by the backend.

## Example

```yaml
auth:
  services:
    enabled:
      - backend_health_checks
    backend_health_checks:
      connect_timeout: 5s
      tls_timeout: 5s
      deep_timeout: 10s
      targets:
        - protocol: imap
          host: mail.example.test
          port: 30143
          deep_check: true
          tls_mode: starttls
          tls_skip_verify: false
          haproxy_v2: true
          auth_mechanism: PLAIN
          test_username: monitor
          test_password: ${BACKEND_HEALTH_CHECK_IMAP_TEST_PASSWORD}
```

`tls_skip_verify` controls certificate verification for both implicit TLS and STARTTLS. Keep verification enabled when
the backend certificate identity matches the configured host.
