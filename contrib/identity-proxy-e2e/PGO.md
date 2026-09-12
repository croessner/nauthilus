# PGO candidate generation

The release identity-proxy E2E gate can collect a profile-guided optimization (PGO) candidate while its normal workload is running.

`make release-guardrails` enables the capture for the release E2E phase. Regular `make identity-proxy-e2e` runs do not enable it.

When enabled, the E2E Compose stack exposes the existing Nauthilus pprof handlers only through the localhost-bound E2E HTTP ports. The runner starts CPU profiles for the authority, edge-a, and edge-b instances in parallel with the gRPC, OpenAPI, Redis-isolation, browser, and post-browser checks. The three profiles are merged with `go tool pprof -proto`.

The resulting candidate is written to:

```text
contrib/identity-proxy-e2e/.work/pgo/candidate.pgo
```

The `.work` directory is ignored by Git. A generated candidate is intentionally **not** promoted automatically. Review its coverage and benchmark a build using it before replacing the committed profile used for releases.

To inspect a candidate:

```sh
go tool pprof -top contrib/identity-proxy-e2e/.work/pgo/candidate.pgo
```

To test a build explicitly with the candidate:

```sh
go build -pgo=contrib/identity-proxy-e2e/.work/pgo/candidate.pgo ./server
```

If the candidate proves representative and beneficial, copy it to `server/default.pgo` and commit that profile in a separate reviewed change. Go will then discover it automatically when building the `./server` main package.

The default capture duration is 30 seconds per Nauthilus instance. Override it for an experiment with:

```sh
NAUTHILUS_E2E_PGO_SECONDS=60 make release-guardrails
```

The capture itself can also be requested directly for a smoke run:

```sh
NAUTHILUS_E2E_PGO=1 contrib/identity-proxy-e2e/scripts/run.sh smoke
```
