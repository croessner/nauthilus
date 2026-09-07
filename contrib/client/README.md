# Nauthilus Admin Client

`nauthilus-admin.py` is a dependency-free Python 3 operator client for the
Nauthilus REST backchannel API.

It intentionally keeps secrets out of the repository. Runtime credentials can
come from command-line flags, environment variables, or an env-style file such
as `/etc/nauthilus/admin-client.env` with mode `0600`.

## Configuration

Minimal OIDC client-credentials configuration:

```sh
NAUTHILUS_URL=https://nauthilus.example.invalid
NAUTHILUS_TOKEN_URL=https://nauthilus.example.invalid/oidc/token
NAUTHILUS_CLIENT_ID=...
NAUTHILUS_CLIENT_SECRET=...
NAUTHILUS_CLIENT_AUTH_METHOD=post
NAUTHILUS_SCOPES="nauthilus:authenticate nauthilus:admin nauthilus:security"
```

If the operating host must connect to an internal IP while keeping the public
TLS server name, add a resolve override:

```sh
NAUTHILUS_RESOLVE=nauthilus.example.invalid:443:192.0.2.10
```

## Examples

```sh
./nauthilus-admin.py cache flush alice@example.test
./nauthilus-admin.py cache flush-file users.txt --continue-on-error
./nauthilus-admin.py cache flush-file users.txt --async --wait --live --pending-ok
./nauthilus-admin.py bruteforce list --account alice@example.test --limit 100
./nauthilus-admin.py bruteforce flush --ip 203.0.113.10 --rule rule-a --protocol imap
./nauthilus-admin.py oidc sessions list alice
./nauthilus-admin.py raw GET /api/v1/openapi.json
```

The `raw` subcommand is deliberately included so operators can reach future
backchannel routes before the convenience layer grows first-class subcommands.

## Reputation administration

The existing client also supports the optional native reputation Management
API. These operations require a backchannel bearer token with `nauthilus:admin`;
Basic backchannel credentials and Policy-resource tokens cannot authorize them.
The server derives the audit actor from the authenticated identity.

```sh
./nauthilus-admin.py reputation lookup ip 192.0.2.8
./nauthilus-admin.py reputation lookup account --subject-file /run/private/account.txt
./nauthilus-admin.py reputation override put ip 192.0.2.8 --band blocked --ttl-seconds 3600 --reason incident --origin operator --audit-id ticket-123
./nauthilus-admin.py reputation override delete ip 192.0.2.8 --previous-audit ticket-123 --reason resolved --origin operator --audit-id ticket-124
./nauthilus-admin.py reputation allocation status
./nauthilus-admin.py reputation allocation drain --reason key_rotation --origin operator --audit-id rotation-123
```

Subjects are sent only in JSON bodies. `--subject-file` keeps the subject out of
process arguments and shell history. No command offers enumeration or storage
key access. Override lifetime is mandatory: `--ttl-seconds 0` explicitly means
no expiration. Replacing an existing override requires `--previous-audit`;
`--slot previous` explicitly addresses the previous subject-key generation.

The client does not retry mutations. On a transport error, timeout or uncertain
response, inspect lookup/status before repeating the same change. Drain retry
requires the same authenticated actor and audit fields. The server verifies
primary state before acknowledging success; the receipt is the latest retained
change, not a complete event history. Allocation rotation additionally requires
all 16 shard fences, the maximum retention wait and, after interruption, explicit
server `allocation_maintenance` configuration. See the
[reputation operator guide](../plugins/reputation/README.md#identifier-rotation-and-allocation-drain).

On the managed mailhost, the canonical installation is `/usr/local/sbin/auth-cli`.
`auth-cli-prod` selects the host-local `/etc/nauthilus/admin-client.env` file;
updating the client does not replace that wrapper, credentials or token cache.
The new commands return 404 until the server-side reputation plugin is deployed.

Run the hermetic client contracts with
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s contrib/client -p 'test_*.py'`.
