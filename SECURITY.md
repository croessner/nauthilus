# Security Hardening

This document describes optional security hardening features available in Nauthilus.

## Privilege Drop and Chroot

Nauthilus supports dropping root privileges and optionally chrooting into a restricted filesystem after startup. This
reduces the attack surface by running the server process with minimal permissions.

### Configuration

Add the following optional settings under the `runtime.process` section of your configuration file:

```yaml
runtime:
  process:
    run_as_user: nauthilus
    run_as_group: nauthilus
    chroot: /var/lib/nauthilus
```

| Setting        | Description                                                                                | Required |
|----------------|--------------------------------------------------------------------------------------------|----------|
| `run_as_user`  | Unix username to switch to after startup.                                                  | No       |
| `run_as_group` | Unix group to switch to after startup. Overrides the user's primary group if both are set. | No       |
| `chroot`       | Directory to `chroot(2)` into before dropping privileges.                                  | No       |

All three settings are independent and optional. You can use any combination (e.g., only `run_as_user` without
`chroot`).

### Execution Order

The privilege drop sequence runs **after** configuration loading, TLS setup, Lua initialization, Redis connection, and
HTTP socket binding, but **before** background services start:

1. **User/group lookup** — Resolves `run_as_user` and `run_as_group` to numeric UID/GID via `/etc/passwd` and
   `/etc/group`. Supplementary group memberships are also resolved at this stage. This happens *before* chroot, because
   these files are unavailable afterwards.
2. **Chroot validation** — Checks that essential DNS files exist inside the chroot directory (see below). Aborts with an
   error if any are missing.
3. **`chroot(2)`** — Changes the filesystem root to the configured directory.
4. **`setgroups(2)`** — Sets supplementary groups for the process (all groups the user belongs to). Must happen while
   still root.
5. **`setgid(2)`** — Switches to the target group. Must happen before `setuid` because `setuid` drops root.
6. **`setuid(2)`** — Switches to the target user. After this call, the process has no root privileges.

### Essential Files in Chroot

When `chroot` is configured, the following files **must** exist inside the chroot directory for DNS resolution to work.
If any file is missing, the server refuses to start and logs an error:

- `<chroot>/etc/resolv.conf`
- `<chroot>/etc/nsswitch.conf`
- `<chroot>/etc/hosts`

### Port Binding

After privilege drop, the process can no longer bind to privileged ports (< 1024). This is typically not an issue
because Nauthilus runs behind a reverse proxy (nginx, HAProxy) on a high port (e.g., `:8080`, `:9443`).

If you need to bind to a privileged port (e.g., 443), you have two options:

1. **Use a reverse proxy** (recommended) — Let nginx/HAProxy handle TLS termination on port 443 and forward to Nauthilus
   on a high port.
2. **Grant `CAP_NET_BIND_SERVICE`** — Assign the capability to the binary:
   ```bash
   setcap cap_net_bind_service=+ep /usr/local/sbin/nauthilus
   ```
   This allows binding to privileged ports without root and survives `setuid`.

### SIGUSR1 Restart Considerations

When `SIGUSR1` triggers a full in-process restart, the HTTP server is stopped and re-created. Since the process no
longer has root privileges at this point:

- **Ports ≥ 1024**: Re-binding works without issues.
- **Ports < 1024**: Re-binding fails with `EACCES` unless `CAP_NET_BIND_SERVICE` is set.

### Unix Sockets and Chroot

Unix domain sockets (e.g., for Redis) that are located **outside** the chroot directory become unreachable after
`chroot(2)`. Already-open file descriptors remain valid, but any reconnection attempt (e.g., during `SIGUSR1` restart)
will fail if the socket path is not accessible inside the chroot.

**Recommendation**: When using `chroot`, configure Redis and other services to use TCP connections, or ensure their Unix
sockets are bind-mounted or located inside the chroot directory.

### File Access After Chroot

All files accessed at runtime must be reachable from within the chroot:

- **Configuration file** (`-config` path) — Must be relative to the chroot root.
- **TLS certificates and keys** — Must exist inside the chroot.
- **Lua scripts** — All paths referenced in the configuration must be relative to the chroot.
- **Static frontend assets** — If the frontend is enabled, HTML/CSS/JS files must be inside the chroot.

### Example Setup

```bash
# Create chroot structure
mkdir -p /var/lib/nauthilus/etc
mkdir -p /var/lib/nauthilus/etc/nauthilus
mkdir -p /var/lib/nauthilus/etc/ssl

# Copy essential DNS files
cp /etc/resolv.conf /var/lib/nauthilus/etc/
cp /etc/nsswitch.conf /var/lib/nauthilus/etc/
cp /etc/hosts /var/lib/nauthilus/etc/

# Copy configuration and TLS certificates
cp /etc/nauthilus/config.yaml /var/lib/nauthilus/etc/nauthilus/
cp /etc/ssl/nauthilus.crt /var/lib/nauthilus/etc/ssl/
cp /etc/ssl/nauthilus.key /var/lib/nauthilus/etc/ssl/

# Create the service user
useradd --system --no-create-home --shell /usr/sbin/nologin nauthilus

# Set ownership
chown -R root:nauthilus /var/lib/nauthilus
chmod -R 750 /var/lib/nauthilus

# Start with chroot and privilege drop
nauthilus -config /etc/nauthilus/config.yaml
```

With the configuration:

```yaml
runtime:
  process:
    run_as_user: nauthilus
    run_as_group: nauthilus
    chroot: /var/lib/nauthilus
  listen:
    address: "0.0.0.0:8080"
    tls:
      enabled: true
      cert: /etc/ssl/nauthilus.crt
      key: /etc/ssl/nauthilus.key
```

> **Note**: The `-config` path is read *before* chroot takes effect. TLS certificate paths and all other runtime file
> paths in the configuration must be relative to the chroot root (e.g., `/etc/ssl/nauthilus.crt` resolves to
`/var/lib/nauthilus/etc/ssl/nauthilus.crt` after chroot).
