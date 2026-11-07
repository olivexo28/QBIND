#!/usr/bin/env bash
set -u -o pipefail
output=$1
shift
{
    printf 'UTC_START='
    date -u +%FT%TZ
    printf 'CWD=%s\n' "$PWD"
    printf 'COMMAND='
    printf '%q ' "$@"
    printf '\nREVISION (HEAD, tree, parent):\n'
    git rev-parse HEAD HEAD^{tree} HEAD^
    printf 'WORKTREE_STATUS:\n'
    git status --porcelain=v1
    printf 'SOURCE_DIFF_SHA256:\n'
    git diff -- crates/qbind-node/src/binary_consensus_loop.rs | sha256sum
    printf 'TOOLCHAIN:\n'
    rustc -Vv
    cargo -V
    rustup show active-toolchain
    printf 'RELEVANT_ENVIRONMENT:\n'
    printenv | sort | grep -E '^(CARGO|RUST|RAYON|CC|CXX|LD|LIBCLANG|ROCKSDB|CI|LANG|LC_|PATH|TMPDIR|HOST|TARGET)' || true
    printf 'OUTPUT:\n'
    "$@"
    rc=$?
    printf '\nEXIT_CODE=%s\nUTC_END=' "$rc"
    date -u +%FT%TZ
    exit "$rc"
} 2>&1 | tee "$output"
exit "${PIPESTATUS[0]}"
