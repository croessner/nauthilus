#!/bin/sh
# Install or roll back the standalone administrative client from a reviewed source file.
#
# The script replaces exactly one file. Wrappers, env files, and token caches are never touched.
# Every replacement keeps a timestamped copy next to the target and is guarded by explicit hashes:
#
#   install-admin-client.sh install  --source FILE --target PATH --expect-source SHA256 --expect-current SHA256
#   install-admin-client.sh rollback --target PATH --backup PATH --expect-backup SHA256 --expect-current SHA256
#   install-admin-client.sh check    --target PATH --expect-current SHA256
#
# Options: --owner USER:GROUP (default root:root), --mode MODE (default 0755), --python PATH (default python3),
# --dry-run (verify and print the plan only).
set -eu

owner="root:root"
mode="0755"
python_bin="python3"
dry_run=0
source_file=""
target=""
backup=""
expect_source=""
expect_current=""
expect_backup=""

die() {
    echo "error: $*" >&2
    exit 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

require_hash() {
    # require_hash FILE EXPECTED LABEL
    [ -n "$2" ] || die "missing expected hash for $3"
    actual=$(sha256_of "$1")
    [ "$actual" = "$2" ] || die "$3 hash mismatch: expected $2, found $actual ($1)"
}

postcheck() {
    # postcheck FILE: the client must compile and expose its parser without network access; returns non-zero.
    "$python_bin" -I -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$1" &&
        "$python_bin" -I "$1" --help >/dev/null &&
        "$python_bin" -I "$1" bruteforce list --help >/dev/null
}

replace_atomically() {
    # replace_atomically NEW_CONTENT_FILE: stage next to the target, then rename over it.
    staged="$target.staged-$$"
    trap 'rm -f "$staged"' EXIT
    trap 'rm -f "$staged"; exit 1' INT TERM
    cp "$1" "$staged"
    chown "$owner" "$staged"
    chmod "$mode" "$staged"
    mv -f "$staged" "$target"
    trap - EXIT INT TERM
}

command_name=${1:-}
[ -n "$command_name" ] || die "usage: $0 install|rollback|check [options]"
shift

while [ $# -gt 0 ]; do
    case "$1" in
        --source) source_file=$2; shift 2 ;;
        --target) target=$2; shift 2 ;;
        --backup) backup=$2; shift 2 ;;
        --expect-source) expect_source=$2; shift 2 ;;
        --expect-current) expect_current=$2; shift 2 ;;
        --expect-backup) expect_backup=$2; shift 2 ;;
        --owner) owner=$2; shift 2 ;;
        --mode) mode=$2; shift 2 ;;
        --python) python_bin=$2; shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        *) die "unknown option: $1" ;;
    esac
done

[ -n "$target" ] || die "--target is required"
[ ! -L "$target" ] || die "target $target is a symlink; name the real file"
[ -f "$target" ] || die "target $target does not exist; this script only replaces an existing client"

case "$command_name" in
    check)
        require_hash "$target" "$expect_current" "current target"
        postcheck "$target" || die "post-check failed for $target"
        echo "ok: $target $(sha256_of "$target")"
        ;;
    install)
        [ -n "$source_file" ] && [ -f "$source_file" ] || die "--source must name a readable file"
        require_hash "$source_file" "$expect_source" "source"
        require_hash "$target" "$expect_current" "current target"
        postcheck "$source_file" || die "pre-check failed for $source_file"
        backup_path="$target.previous-$(date -u +%Y%m%dT%H%M%SZ)"
        [ ! -e "$backup_path" ] || die "backup $backup_path already exists"
        echo "plan: backup $target -> $backup_path; install $source_file ($expect_source) as $owner $mode"
        [ "$dry_run" -eq 0 ] || exit 0
        cp -p "$target" "$backup_path"
        require_hash "$backup_path" "$expect_current" "backup"
        echo "rollback: $0 rollback --target $target --backup $backup_path --expect-backup $expect_current --expect-current $expect_source"
        replace_atomically "$source_file"
        if [ "$(sha256_of "$target")" != "$expect_source" ] || ! postcheck "$target"; then
            echo "error: post-install check failed; restoring $backup_path" >&2
            replace_atomically "$backup_path"
            require_hash "$target" "$expect_current" "restored target"
            exit 1
        fi
        echo "installed: $target $expect_source"
        ;;
    rollback)
        [ -n "$backup" ] && [ -f "$backup" ] && [ ! -L "$backup" ] || die "--backup must name the saved previous client"
        require_hash "$backup" "$expect_backup" "backup"
        require_hash "$target" "$expect_current" "current target"
        postcheck "$backup" || die "pre-check failed for $backup"
        echo "plan: restore $backup ($expect_backup) over $target as $owner $mode"
        [ "$dry_run" -eq 0 ] || exit 0
        replace_atomically "$backup"
        require_hash "$target" "$expect_backup" "restored target"
        postcheck "$target" || die "post-check failed for restored $target"
        echo "rolled back: $target $expect_backup (backup kept at $backup)"
        ;;
    *)
        die "unknown command: $command_name"
        ;;
esac
