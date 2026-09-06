# Stable refresh release source

The scheduled refresh must use the selected stable release as the authority for
module identity and Docker base images. Workflow tooling can come from current
main, but its module major and compiler version do not describe an older release.

On 2026-09-06, run 34020370458 selected v3.1.1 while current tooling declared v4.
The semantic-version helper correctly rejected the mismatch, but process
substitution hid its exit status. Empty major/minor tags reached the manifest
merge, which failed with `invalid reference format`. Current tooling also named
Go 1.27.0 while the selected release Dockerfile used Go 1.26.6.

The reusable build now checks the tag against `go.mod` from the release commit.
Both refresh detection and build metadata resolve base digests from that release's
Dockerfile. Command substitutions are checked before publishing step outputs;
registry and release-validation failures cannot become partial metadata.

`python3 scripts/test_release_contracts.py` covers the older release, the actual
workflow metadata shell, a mismatched module major, released compiler selection,
and registry failure. The normal current-module major guard remains strict.
