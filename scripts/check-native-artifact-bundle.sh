#!/bin/sh
set -eu

# Build disposable host and plugin fixtures with exactly the same source and compiler identity.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
export GOEXPERIMENT=runtimesecret
bundle_dir=$(mktemp -d)
trap 'rm -rf "$bundle_dir"' EXIT HUP INT TERM
native_flags=$(go run -mod=vendor ./scripts/native_artifact_fingerprint)
go build -mod=vendor -trimpath -ldflags "$native_flags" -o "$bundle_dir/check" ./server/pluginloader/testdata/nativebundle
set --
for component in sample geoip dkim2-reputation reputation dkim2-intelligence; do
  case "$component" in
    sample) package=./pluginapi/v1/testdata/sampleplugin ;;
    *) package=./contrib/plugins/$component ;;
  esac
  go build -mod=vendor -trimpath -ldflags "$native_flags" -buildmode=plugin -o "$bundle_dir/$component.so" "$package"
  set -- "$@" "$bundle_dir/$component.so"
done
"$bundle_dir/check" "$@"

# Real negative controls must fail before their native factory can be opened.
stale_flags="-X github.com/croessner/nauthilus/v4/pluginapi/v1.nativeArtifactIdentity=nauthilus-native-artifact-v1:0000000000000000000000000000000000000000000000000000000000000000:end-native-artifact"
go build -mod=vendor -trimpath -ldflags "$stale_flags" -buildmode=plugin -o "$bundle_dir/stale.so" ./pluginapi/v1/testdata/sampleplugin
go build -mod=vendor -trimpath -buildmode=plugin -o "$bundle_dir/unmarked.so" ./pluginapi/v1/testdata/sampleplugin
for invalid in stale unmarked; do
  if "$bundle_dir/check" "$bundle_dir/$invalid.so" >/dev/null 2>&1; then
    echo "invalid native artifact passed preflight: $invalid" >&2
    exit 1
  fi
  echo "rejected native artifact: $invalid"
done
