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

`bruteforce list` requests a bounded page of 100 entries by default. The IP
and account filters apply to separate result sections: `--ip` alone still
lists affected accounts. An unbounded account listing can exceed a reverse
proxy response-header timeout. Use both filters for an incident, or inspect
`page.has_more` and request `--limit 100 --offset 100` (then subsequent
`next_offset` values) for additional pages. A page is not the complete list.
Affected accounts age out: an account stays listed for at least
`auth.controls.brute_force.affected_accounts.retention` (default 24h) after its
last counted failed or blocked request, and while it still has an IP history.

`--account` names are checked literally by default. With `--via-mapping` the
client asks the server to also check the accounts Nauthilus stored for each
login name (`account_resolution: account_mapping`, at most 100 names). The
JSON response stays on stdout; one line per name goes to stderr, leading with
whether brute-force state was found, followed by the mapping status (`mapped`,
`unmapped`, `ambiguous`, or undecided). A stored mapping only exists for names
that were used for a login and is not re-verified against the backend; an
alias that was never used, or a different spelling, is reported as unmapped
and only the literal name is checked. The client exits with status 1 when a
name stays undecided (HTTP 500 body is still rendered), when the server
ignores the mode (older server: only literal names were checked), or when an
older server with request validation rejects it.

```sh
./nauthilus-admin.py bruteforce list --account alias@example.test --via-mapping
```

Repeated `--resolve` flags replace `NAUTHILUS_RESOLVE`; without CLI overrides,
the process environment takes precedence over the env file. Comma-separated
environment values remain supported.

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
./nauthilus-admin.py reputation override import /run/private/static-import.json
./nauthilus-admin.py reputation allocation status
./nauthilus-admin.py reputation allocation drain --reason key_rotation --origin operator --audit-id rotation-123
```

Subjects are sent only in JSON bodies. `--subject-file` keeps the subject out of
process arguments and shell history. No command offers enumeration or storage
key access. Override lifetime is mandatory: `--ttl-seconds 0` explicitly means
no expiration. Replacing an existing override requires `--previous-audit`;
`--slot previous` explicitly addresses the previous subject-key generation.

`override import` applies the `overrides` of a `reputation-static-import.v1`
artifact written by `scripts/convert-static-reputation.py`. The whole artifact
is validated first (schema, exact entry fields, kind, band, audit fields,
`expires_at`, duplicate subjects); any problem aborts the import with the
offending `overrides[N]` indices and nothing is sent. Each valid entry becomes
one `override put` to the active slot: `ttl_seconds` is computed as
`expires_at - now` immediately before its request, `expires_at: 0` maps to
`ttl_seconds: 0` (non-expiring), and entries whose expiry has already passed are
skipped and reported as `skipped-expired`. The artifact `creator` is ignored
because the server records the authenticated token identity. The import does
not send `previous_audit`, so replacing an existing override still requires an
explicit `override put --previous-audit`. The `ip_override_networks` section
is reputation configuration input and is not applied by the client. Artifacts
written by earlier converter versions may also carry `identity_contracts` and
`policy_rules`; the client accepts and ignores them.

Entries are applied sequentially without retries. Each entry produces a result
line on stderr (`applied`, `skipped-expired`, `failed` with the reason, or
`not-attempted`) and a JSON summary on stdout. The first failure stops the
import unless `--continue-on-error` is given; any failed entry makes the command
exit non-zero.

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

## Support history

The `support` commands are read-only lookups in the recorded authentication
history and brute-force ban history. Each command sends one `POST` with a JSON
body to `/api/v1/support/...`; logins, accounts, addresses and filters never
appear in the URL.

They require a backchannel bearer token with `nauthilus:history_read`.
`nauthilus:history_detail` widens the projection and allows `attempts detail`
without `--login`/`--account`. The server rejects Basic backchannel credentials
and tokens that only carry `nauthilus:admin`; the client refuses Basic-only
credentials before sending anything. With OIDC client credentials, request the
scopes explicitly, for example
`NAUTHILUS_SCOPES="nauthilus:history_read nauthilus:history_detail"`.

```sh
# Attempts of one login during the last two hours
./nauthilus-admin.py support attempts search --login alice@example.test --since 2h
# One attempt; --around is any instant of it, for example started_at from the search
./nauthilus-admin.py support attempts detail --attempt-id fl1.0123456789abcdef0123456789abcdef \
  --around 2026-11-17T08:15:02Z --login alice@example.test
# Bans of one client IP during the last week, all pages
./nauthilus-admin.py support bans search --ip 203.0.113.10 --since 7d --all
./nauthilus-admin.py support bans search --network 203.0.113.0/24 \
  --from 2026-11-01T00:00:00Z --until 2026-11-08T00:00:00Z --audit-reference INC-4711
```

The window is either `--since DURATION` (`30m`, `2h`, `7d`; from now minus the
duration until now) or both `--from` and `--until` as RFC3339 timestamps. It
must not exceed 31 days and `--from` must be earlier than `--until`; the client
checks this locally. `--limit` accepts 1-50 attempts or 1-20 bans per page.
`--cursor` continues from the `next_cursor` of an earlier page with the same
query. `--all` follows `next_cursor` for at most 20 pages and prints one merged
answer: attempts deduplicated by `attempt_id`, bans by `ban_ref`, the other
blocks from the last page (the `history` block stays `partial` if any page was
partial), plus `"pages": n`. If 20 pages are not enough, a stderr warning names
the cursor to continue with. `--audit-reference` (`[A-Za-z0-9._:/-]{1,64}`)
links the lookup to a ticket in the server audit log.

| Exit | Meaning                                                                   |
|------|---------------------------------------------------------------------------|
| 0    | processed and `history.availability` is `available`                       |
| 3    | processed, but history is `partial`; a stderr warning lists `history.conditions` |
| 4    | history unavailable or busy (HTTP 503 or 429)                             |
| 5    | query too broad (HTTP 422); narrow the window or add filters              |
| 1    | any other error: local validation, HTTP 400/401/403/500, transport errors |
| 2    | command-line usage error                                                  |

The JSON `error.code` decides the exit code when the server sends one; the
message text is only displayed. A login failure recorded in the history is data,
never a non-zero exit by itself. An empty search result (or a detail lookup
without an attempt) prints a stderr note with `result_basis` and
`history.conditions`: it does not prove that no login or ban happened, because
history delivery is not guaranteed to be complete.

`attempts search` and `attempts detail` accept `--summary`: instead of JSON they
print a header line (`result_basis`, `availability`, `completion_since`), one
line per attempt with `outcome/outcome_basis`, `final`, `progress`, the four
steps (`primary/second_factor/code_issuance/code_redemption`), the OIDC
`completion` state and `authentication`, finding codes and known gaps, and for
`detail` one line per event with stage, code, the stored decision status
(`answered`, `message`) and the committed `transport` status. A field the answer
does not carry, for example in an answer of an older server, prints as `-`; it
never defaults to a success. Read the OIDC fields as follows: `completion=tokens_issued`
means Nauthilus redeemed the code and issued tokens (its part is complete; a
webmail session is not observed), `redemption_pending` and
`code_expired_redemption_not_observed` mean no redemption was observed (never
proof of an abort), `not_recorded` means the flow predates completion
recording. `answered=200 message="OK"` is the stored host decision status, not
the HTTP status the browser received (`transport`, for example 302).

The JSON output always carries the complete answer. A `jq` view of the same
fields that also copes with older answers:

```sh
./nauthilus-admin.py --output json support attempts search --login alice@example.test --since 2h |
  jq -r '.attempts[] | [.attempt_id, .outcome, .outcome_basis, .progress,
         (.completion.state // "-"), (.completion.authentication // "-"),
         ((.recording.known_gaps // []) | join(",") | if . == "" then "-" else . end)] | @tsv'
./nauthilus-admin.py --output json support attempts detail --attempt-id fl1.0123456789abcdef0123456789abcdef \
  --around 2026-11-17T18:34:56Z --login alice@example.test |
  jq -r '.attempt.events[] | [.sequence, .stage, .code, (.decision.answered_status_code // "-"),
         (.decision.answered_status_message // "-"), (.context.transport_status // "-")] | @tsv'
```

The managed mail stack may run an older or backported copy of this client (see
`/usr/local/sbin/auth-cli` above). The `support` commands exist only in this
owner-repository client. Syncing a deployed copy is a separate, deliberate
step; changing this file does not install or overwrite any live copy.

Run the hermetic client contracts with
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s contrib/client -p 'test_*.py'`.
