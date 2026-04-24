<!--
Copyright (C) 2026 Christian Roessner

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
-->

# Config v1 to v2 Converter

Nauthilus now ships a best-effort migration helper for old monolithic configuration files:

```bash
python3 scripts/convert-config-v1-to-v2.py legacy-nauthilus.yml --output nauthilus-v2.yml
```

## Scope

Current scope:

- single-file legacy YAML input
- single-file config-v2 YAML output
- structural rewrite from legacy roots such as `server`, `ldap`, `lua`, `idp`, `realtime_blackhole_lists`, and `brute_force`
- migration of optional LDAP pools and optional Lua backends
- migration of legacy `server.features` and `lua.features` aliases
- preservation of top-level extension roots such as `x-claim-*`, `x-scope-*`, and similar `x-*` mappings
- support for legacy dotted keys such as `server.oidc_auth.enabled` and `server.keep_alive.enabled`
- preservation of legacy YAML mapping order where the target structure still allows it
- canonical name rewrites such as `backend_server_monitoring -> backend_health_checks`
- report output for warnings, drops, and validation results

Current non-goals:

- include-tree refactoring
- multi-file `conf.d` splitting
- comment preservation
- guaranteed conversion of every historical edge case

## Usage

Basic conversion:

```bash
python3 scripts/convert-config-v1-to-v2.py legacy-nauthilus.yml --output nauthilus-v2.yml
```

Write a migration report:

```bash
python3 scripts/convert-config-v1-to-v2.py \
  legacy-nauthilus.yml \
  --output nauthilus-v2.yml \
  --report migration-report.txt
```

Validate the converted file immediately:

```bash
python3 scripts/convert-config-v1-to-v2.py \
  legacy-nauthilus.yml \
  --output nauthilus-v2.yml \
  --report migration-report.txt \
  --validate
```

Dry-run to stdout:

```bash
python3 scripts/convert-config-v1-to-v2.py legacy-nauthilus.yml --dry-run --stdout
```

## Behavior

The converter is intentionally conservative:

- known legacy paths are rewritten to their current config-v2 locations
- canonical names are enforced where old aliases are no longer accepted
- current config-v2 roots already present in the file are preserved
- top-level `x-*` extension roots are preserved as-is
- best-effort `x-*` anchor/alias reuse is restored in the generated YAML when the converted structure still references the same subtree
- unsupported legacy paths are reported for manual review instead of being silently guessed

Validation uses:

```bash
go run ./server --config <converted-file> --config-check
```

with the required `GOEXPERIMENT=runtimesecret` and `GEXPERIMENT=runtimesecret` environment.

## Notes

- The script currently loads legacy YAML via the vendored Go YAML stack to avoid adding a separate Python YAML dependency.
- The generated YAML is deterministic and intended for review, followed by `--config-check` and usually a manual diff against `nauthilus -n`.
