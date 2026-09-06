#!/bin/sh
# Validate the repository-owned exact Go toolchain contract.
set -eu
repository=${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
exec python3 "$(dirname -- "$0")/check_go_toolchain_contract.py" "$repository"
