#!/bin/bash
# Runs govulncheck before publishing release-sensitive refs.

set -euo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)
REMOTE_NAME="${1:-origin}"
REMOTE_URL="${2:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

triggered=0
refs=()
target_commits=()
zero_sha="0000000000000000000000000000000000000000"

# ref_requires_govulncheck reports whether a pushed remote ref is release-sensitive.
ref_requires_govulncheck() {
    case "$1" in
        refs/heads/main)
            return 0
            ;;
        refs/tags/v*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# collect_refs records remote refs that need vulnerability analysis before push.
collect_refs() {
    local local_ref local_sha remote_ref remote_sha target_commit

    while read -r local_ref local_sha remote_ref remote_sha; do
        if [ "$local_sha" = "$zero_sha" ]; then
            continue
        fi

        if ref_requires_govulncheck "$remote_ref"; then
            target_commit=$(git rev-parse "${local_sha}^{commit}")
            triggered=1
            refs+=("${remote_ref} -> ${target_commit:0:12}")
            target_commits+=("$target_commit")
        fi
    done
}

# verify_clean_checkout ensures govulncheck analyzes exactly the pushed content.
verify_clean_checkout() {
    cd "$GIT_ROOT"

    if [ -n "$(git status --porcelain)" ]; then
        echo -e "${RED}Push blocked: release-sensitive refs require a clean checkout.${NC}"
        echo -e "${RED}Commit, stash, or remove local changes before pushing main or version tags.${NC}"
        exit 1
    fi
}

# verify_refs_match_head prevents checking one checkout while pushing another commit.
verify_refs_match_head() {
    local head_commit target_commit

    cd "$GIT_ROOT"
    head_commit=$(git rev-parse HEAD)

    for target_commit in "${target_commits[@]}"; do
        if [ "$target_commit" != "$head_commit" ]; then
            echo -e "${RED}Push blocked: release-sensitive ref does not point to current HEAD.${NC}"
            echo -e "${RED}Check out the pushed main or tag commit before pushing so govulncheck analyzes the right code.${NC}"
            exit 1
        fi
    done
}

# run_govulncheck executes the canonical Makefile target from the repository root.
run_govulncheck() {
    cd "$GIT_ROOT"

    echo -e "${YELLOW}Running govulncheck before pushing release-sensitive refs to ${REMOTE_NAME}...${NC}"
    printf '  - %s\n' "${refs[@]}"

    if ! make govulncheck; then
        echo ""
        echo -e "${RED}Push blocked: govulncheck failed for ${REMOTE_NAME} ${REMOTE_URL}.${NC}"
        echo -e "${RED}Fix the vulnerability findings before pushing main or version tags.${NC}"
        exit 1
    fi

    echo -e "${GREEN}Govulncheck passed.${NC}"
}

collect_refs

if [ "$triggered" -eq 0 ]; then
    echo -e "${GREEN}No release-sensitive refs in push; skipping govulncheck.${NC}"
    exit 0
fi

verify_clean_checkout
verify_refs_match_head
run_govulncheck
