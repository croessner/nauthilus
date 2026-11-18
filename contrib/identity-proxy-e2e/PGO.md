# PGO lifecycle

Nauthilus uses Go profile-guided optimization (PGO) as an iterative N -> N+1 build input.

Go automatically enables PGO when a CPU profile named `default.pgo` is present in the main package directory. For Nauthilus that file is:

```text
server/default.pgo
```

Because the normal native and container builds compile the `./server` main package, a committed `server/default.pgo` is automatically consumed by local builds, release builds, development package builds, and Docker builds. No separate runtime feature flag is required.

## Native plugins

PGO applies the profile to every package of the server binary, including the standard library. A native plugin compiled without the same profile carries differently optimized copies of the shared packages, and Go refuses to open it:

```text
plugin was built with a different version of package internal/runtime/maps
```

Every native build therefore takes its `-pgo` flag from one place:

```sh
sh scripts/native-pgo-flag.sh   # prints -pgo=<repo>/server/default.pgo, or -pgo=off without a profile
```

The Dockerfiles, `make native-plugins-build-check`, `contrib/plugins/geoip/Makefile`, and `scripts/check-native-artifact-bundle.sh` pass that flag to the server and to every plugin. The native artifact fingerprint includes `server/default.pgo`, so artifacts built from trees with different profiles have different identities. The bundle check also proves that a plugin built with `-pgo=off` is rejected while a profile is present.

Out-of-tree plugins must be built with the `server/default.pgo` of the Nauthilus revision they are loaded into.

## Release E2E profile capture

The release identity-proxy E2E gate collects a PGO candidate after its functional checks pass.

`make release-guardrails` and `make release-identity-proxy-e2e` enable the capture. Regular `make identity-proxy-e2e` runs do not enable it.

When enabled, the E2E Compose stack exposes the existing Nauthilus pprof handlers only through the localhost-bound E2E HTTP ports. After the gRPC, OpenAPI, Redis-isolation, browser, ClickHouse, post-browser, and plugin-reload checks have passed, the runner starts a dedicated authentication workload (`cmd/smoke --mode pgo-load`):

- edge-a HTTP JSON authentication with a backchannel bearer token: edge handler, auth pipeline, positive cache, and remote backend;
- direct authority gRPC authentication and identity lookups: caller authentication and the authority pipeline.

The workers rotate through a pool of synthetic accounts, so the edge sees positive-cache misses as well as hits, and every request must succeed. The CPU profiles of the authority, edge-a, and edge-b start after a short warm-up and end before the workload does, so every sampled second carries request traffic. The three profiles are merged with `go tool pprof -proto`.

A candidate needs at least `NAUTHILUS_E2E_PGO_MIN_SAMPLES` CPU samples (default 1000, that is 10 seconds of CPU time). The functional checks alone kept the instances almost idle: the candidates of the earlier capture held 1 to 5 samples each, which says nothing about a hot path. Such a candidate is refused.

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
3. That profile is committed to `features` as `server/default.pgo` for N+1.
4. Every normal Nauthilus server and native plugin build on `features` consumes it, and the next release merges it into `main`.
5. Release N+1 generates the next profile and the cycle repeats.

Go PGO is designed for this iterative model. The profile and the source do not have to be byte-for-byte from the same build; the compiler performs best-effort matching when source has evolved between the profiled release and the next build.

## GitHub Actions refresh

`.github/workflows/pgo-refresh.yaml` closes the release loop automatically.

It runs for `v*` release tags and can also be started with `workflow_dispatch`. The job:

1. installs the identity-proxy browser E2E dependencies;
2. runs the release identity-proxy E2E gate with the PGO workload;
3. validates and uploads `candidate.pgo` as a workflow artifact;
4. checks out the current `features` branch and installs the candidate as `server/default.pgo`;
5. proves that a PGO server build succeeds and that `scripts/check-native-artifact-bundle.sh` loads the native plugins under the new profile; and
6. commits the profile as `Build: Refresh the PGO profile from <ref>` and pushes it to `features`, rebasing up to three times when `features` moved meanwhile.

The commit goes to `features` directly. The profile changes optimization decisions only and is validated before the push, while a pull request would need the repository setting that lets GitHub Actions create pull requests, and it would not start the regular workflows. A failed push fails the job.

After a release, pull `features` before continuing local work, because the refresh adds one commit there.

## Bootstrap

Without a committed profile, builds are ordinary non-PGO builds and `scripts/native-pgo-flag.sh` prints `-pgo=off`. The first release E2E run produces the first candidate; once the refresh workflow commits it as `server/default.pgo`, the next build starts the normal iterative lifecycle.

The default capture duration is 30 seconds per Nauthilus instance. Override it, or the sample floor, for an experiment with:

```sh
NAUTHILUS_E2E_PGO_SECONDS=60 make release-guardrails
NAUTHILUS_E2E_PGO_MIN_SAMPLES=5000 make release-identity-proxy-e2e
```

The capture itself can also be requested directly for a smoke run:

```sh
NAUTHILUS_E2E_PGO=1 contrib/identity-proxy-e2e/scripts/run.sh smoke
```
