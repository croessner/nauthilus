#!/bin/sh
set -eu

# Print the -pgo flag shared by the server and every native plugin build. The server main package consumes
# server/default.pgo through Go's default -pgo=auto, which applies the profile to all packages of the binary. A plugin
# compiled without that profile carries differently optimized copies of the shared packages, and plugin.Open refuses
# it ("plugin was built with a different version of package ..."). Every native build therefore passes this flag.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
profile="$repo_root/server/default.pgo"

if [ -f "$profile" ]; then
  printf '%s\n' "-pgo=$profile"
else
  printf '%s\n' "-pgo=off"
fi
