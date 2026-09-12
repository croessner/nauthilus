# PGO lifecycle

Nauthilus uses Go profile-guided optimization (PGO) as an iterative N -> N+1 build input.

Go automatically enables PGO when a CPU profile named `default.pgo` is present in the main package directory. For Nauthilus that file is:

```text
server/default.pgo
```

Because the normal native and container builds compile the `./server` main package, a committed `server/default.pgo` is automatically consumed by local builds, release builds, development package builds, and Docker builds. No separate runtime feature flag is required.

## Release E2E profile capture

The release identity-proxy E2E gate can collect a PGO candidate while its normal workload is running.

`make release-guardrails` enables the capture for the release E2E phase. Regular `make identity-proxy-e2e` runs do not enable it.

When enabled, the E2E Compose stack exposes the existing Nauthilus pprof handlers only through the localhost-bound E2E HTTP ports. The runner starts equal-duration CPU profiles for the authority, edge-a, and edge-b instances in parallel with the gRPC, OpenAPI, Redis-isolation, browser, and post-browser checks. The three profiles are merged with `go tool pprof -proto`.

The resulting candidate is written to:

```text
contrib/identity-proxy-e2e/.work/pgo/candidate.pgo
```

The `.work` directory is ignored by Git.

To inspect a candidate:

```sh
go tool pprof -top contrib/identity-proxy-e2e/.work/pgo/candidate.pgo
```

To test a build explicitly with the candidate:

```sh
go build -pgo=contrib/identity-proxy-e2e/.work/pgo/candidate.pgo ./server
```

## N -> N+1 lifecycle

The intended lifecycle is:

1. Release N is built with the `server/default.pgo` committed from the previous iteration.
2. The release E2E workload for N captures a new merged CPU profile.
3. That profile becomes the proposed `server/default.pgo` for N+1.
4. Once the profile refresh is merged, every normal Nauthilus server build automatically consumes it.
5. Release N+1 generates the next profile and the cycle repeats.

Go PGO is designed for this iterative model. The profile and the source do not have to be byte-for-byte from the same build; the compiler performs best-effort matching when source has evolved between the profiled release and the next build.

## GitHub Actions refresh

`.github/workflows/pgo-refresh.yaml` closes the release loop automatically.

It runs for `v*` release tags and can also be started with `workflow_dispatch`. The job:

1. installs the identity-proxy browser E2E dependencies;
2. runs the release identity-proxy E2E gate with PGO capture enabled;
3. validates and uploads `candidate.pgo` as a workflow artifact;
4. checks out the current `features` branch;
5. installs the candidate as `server/default.pgo`;
6. proves that the profile is accepted by a PGO-enabled `./server` build;
7. pushes an `automation/pgo-<release>` branch; and
8. attempts to open a pull request against `features`.

The pull-request creation is intentionally reviewable rather than writing directly to the protected `features` branch. If repository policy prevents GitHub Actions from creating pull requests, the refresh branch and uploaded candidate still remain available for review/manual PR creation.

## Bootstrap

The first iteration has no historical profile. That build is therefore an ordinary non-PGO build. Its release E2E run produces the first candidate; once that candidate is committed as `server/default.pgo`, the next build starts the normal iterative lifecycle.

The default capture duration is 30 seconds per Nauthilus instance. Override it for an experiment with:

```sh
NAUTHILUS_E2E_PGO_SECONDS=60 make release-guardrails
```

The capture itself can also be requested directly for a smoke run:

```sh
NAUTHILUS_E2E_PGO=1 contrib/identity-proxy-e2e/scripts/run.sh smoke
```
