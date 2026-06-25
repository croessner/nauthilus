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
./nauthilus-admin.py --env-file /etc/nauthilus/admin-client.env config load
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
