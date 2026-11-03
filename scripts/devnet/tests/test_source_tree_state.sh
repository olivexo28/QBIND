#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
HELPER="${REPO_ROOT}/scripts/devnet/lib/source_tree_state.sh"
SCHEMA="${REPO_ROOT}/docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json"
EXAMPLE="${REPO_ROOT}/docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.example.json"
BASELINE="6dd0bc9d4ad5426065460270bf30c2cda6b2ca37"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/qbind-source-tree-test.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0
export HOME="${TEST_ROOT}/home"
mkdir -p "$HOME"

source "$HELPER"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'PASS: %s\n' "$*"
}

new_repo() {
  local name=$1 dir="${TEST_ROOT}/$1"
  mkdir -p "$dir"
  git -c init.defaultBranch=main init -q "$dir"
  git -C "$dir" config user.name "QBIND fixture"
  git -C "$dir" config user.email "fixture@example.invalid"
  git -C "$dir" config core.hooksPath /dev/null
  git -C "$dir" config commit.gpgsign false
  printf 'initial\n' >"${dir}/tracked.txt"
  git -C "$dir" add -- tracked.txt
  git -C "$dir" -c commit.gpgsign=false commit -qm initial
  printf '%s\n' "$dir"
}

assert_state() {
  local expected=$1 root=$2 label=$3 observed
  observed=$(qbind_classify_source_tree_state "$root" 2>"${TEST_ROOT}/diagnostic") ||
    fail "$label: classifier invocation failed"
  [ "$observed" = "$expected" ] ||
    fail "$label: expected $expected, observed $observed"
  printf 'PASS: %-42s expected=%s observed=%s\n' "$label" "$expected" "$observed"
}

commit_fixture() {
  git -C "$1" add -- .
  git -C "$1" -c commit.gpgsign=false commit -qm "fixture update"
}

printf '%s\n' '== Pinned baseline classification slice =='
baseline_slice=$(git show "${BASELINE}:scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh" |
  python3 -c '
import re, sys
s=sys.stdin.read()
match=re.search(r"# Source-tree state: clean unless tracked-source[\s\S]*?(?=\r?\n\r?\n)", s)
if match is None:
    raise SystemExit("baseline classification block not found")
print(match.group(0).replace("\r\n", "\n"))
')
[ -n "$baseline_slice" ] || fail "could not extract pinned baseline source-state slice"
baseline_run() {
  local root=$1
  bash -c 'set -e; REPO_ROOT=$1; eval "$2"; printf "%s\n" "$TREE_STATE"' \
    _ "$root" "$baseline_slice" 2>/dev/null
}
BASE_CLEAN="$(new_repo baseline-clean)"
BASE_DIRTY="$(new_repo baseline-dirty)"
printf 'dirty\n' >>"${BASE_DIRTY}/tracked.txt"
[ "$(baseline_run "$BASE_CLEAN")" = clean ] || fail "baseline clean control changed"
[ "$(baseline_run "$BASE_DIRTY")" = clean ] || fail "baseline dirty slice no longer selects clean"
[ "$(baseline_run "${TEST_ROOT}/not-a-repository")" = clean ] ||
  fail "baseline failed-observation slice no longer selects clean"
pass "pinned source slice selects clean for clean, dirty, and Git-error fixtures"

printf '%s\n' '== Clean, staged, unstaged, and mixed changes =='
repo="$(new_repo basic)"
assert_state clean "$repo" "clean control"
printf 'edit\n' >>"${repo}/tracked.txt"
assert_state dirty "$repo" "unstaged tracked edit"
git -C "$repo" add -- tracked.txt
assert_state dirty "$repo" "staged tracked edit"
printf 'more\n' >>"${repo}/tracked.txt"
assert_state dirty "$repo" "staged plus unstaged same path"
printf 'new\n' >"${repo}/second.txt"
git -C "$repo" add -- second.txt
assert_state dirty "$repo" "staged plus unstaged different paths"

printf '%s\n' '== Add, delete, rename, mode, and type changes =='
repo="$(new_repo structural)"
printf 'added\n' >"${repo}/added.txt"
git -C "$repo" add -- added.txt
assert_state dirty "$repo" "tracked staged addition"
commit_fixture "$repo"
git -C "$repo" rm -q tracked.txt
assert_state dirty "$repo" "tracked staged deletion"
git -C "$repo" mv added.txt renamed.txt
assert_state dirty "$repo" "tracked staged rename"
commit_fixture "$repo"
chmod +x "${repo}/renamed.txt"
assert_state dirty "$repo" "executable mode change with core.filemode=false"
chmod -x "${repo}/renamed.txt"
rm -- "${repo}/renamed.txt"
ln -s tracked.txt "${repo}/renamed.txt"
assert_state dirty "$repo" "tracked regular-file to symlink type change"

printf '%s\n' '== Scope, ignored files, and unusual names =='
repo="$(new_repo scope)"
mkdir -p "${repo}/docs" "${repo}/Audit" "${repo}/.github/workflows" "${repo}/scripts"
for path in docs/readme.txt Audit/register.txt .github/workflows/check.yml scripts/tool.sh Cargo.lock; do
  printf 'base\n' >"${repo}/${path}"
done
commit_fixture "$repo"
printf 'docs only\n' >>"${repo}/docs/readme.txt"
git -C "$repo" add -- docs/readme.txt
assert_state clean "$repo" "root docs/** exclusion (staged)"
printf 'unstaged docs\n' >>"${repo}/docs/readme.txt"
assert_state clean "$repo" "root docs/** exclusion (unstaged)"
for path in Audit/register.txt .github/workflows/check.yml scripts/tool.sh Cargo.lock; do
  printf 'changed\n' >>"${repo}/${path}"
  assert_state dirty "$repo" "included path ${path}"
  commit_fixture "$repo"
done
printf '*.ignored\n' >"${repo}/.gitignore"
git -C "$repo" add -- .gitignore
git -C "$repo" -c commit.gpgsign=false commit -qm ignore
printf 'untracked\n' >"${repo}/untracked.txt"
printf 'ignored\n' >"${repo}/item.ignored"
assert_state clean "$repo" "untracked and ignored exclusions"
unusual=$'line\nbreak-ñ'
printf 'unusual\n' >"${repo}/${unusual}"
git -C "$repo" add -- "$unusual"
assert_state dirty "$repo" "newline, leading-dash, and non-ASCII path"
unusual=$'-leading\nname-ñ'
printf 'unusual\n' >"${repo}/${unusual}"
git -C "$repo" add -- "$unusual"
assert_state dirty "$repo" "leading-dash filename with newline and non-ASCII"
unusual=$'white space\tname'
printf 'unusual\n' >"${repo}/${unusual}"
git -C "$repo" add -- "$unusual"
assert_state dirty "$repo" "space and tab in tracked filename"

printf '%s\n' '== Submodule state =='
subsource="$(new_repo submodule-source)"
subroot="$(new_repo submodule-root)"
git -C "$subroot" -c protocol.file.allow=always submodule add -q "$subsource" module
git -C "$subroot/module" config user.name "QBIND fixture"
git -C "$subroot/module" config user.email "fixture@example.invalid"
git -C "$subroot/module" config core.hooksPath /dev/null
commit_fixture "$subroot"
assert_state clean "$subroot" "initialized clean submodule"
printf 'tracked edit\n' >>"${subroot}/module/tracked.txt"
assert_state dirty "$subroot" "initialized submodule tracked edit"
git -C "$subroot/module" -c commit.gpgsign=false commit -qam "submodule edit"
git -C "$subroot" config submodule.module.ignore all
git -C "$subroot" config diff.ignoreSubmodules all
assert_state dirty "$subroot" "submodule diff-ignore configuration"
git -C "$subroot" config --unset submodule.module.ignore
git -C "$subroot" config --unset diff.ignoreSubmodules
printf 'gitlink update\n' >>"${subroot}/module/tracked.txt"
git -C "$subroot/module" add -- tracked.txt
git -C "$subroot/module" -c commit.gpgsign=false commit -qm "gitlink update"
git -C "$subroot" add -- module
assert_state dirty "$subroot" "tracked staged gitlink change"
commit_fixture "$subroot"
assert_state clean "$subroot" "updated initialized submodule gitlink"
rm -rf -- "${subroot}/module"
assert_state unknown "$subroot" "unavailable initialized submodule"
git -C "$subroot" -c protocol.file.allow=always submodule update --init -q

inner="$(new_repo nested-inner)"
printf '*.ignored\n' >"${inner}/.gitignore"
mkdir -p "${inner}/docs"
printf 'nested docs\n' >"${inner}/docs/nested.txt"
git -C "$inner" add -- .gitignore docs/nested.txt
git -C "$inner" -c commit.gpgsign=false commit -qm "nested tracked docs and ignore fixture"
outer="$(new_repo nested-outer)"
git -C "$outer" -c protocol.file.allow=always submodule add -q "$inner" nested
git -C "$outer/nested" config user.name "QBIND fixture"
git -C "$outer/nested" config user.email "fixture@example.invalid"
git -C "$outer/nested" config core.hooksPath /dev/null
commit_fixture "$outer"
nested_root="$(new_repo nested-root)"
git -C "$nested_root" -c protocol.file.allow=always submodule add -q "$outer" outer
git -C "$nested_root" -c protocol.file.allow=always submodule update --init --recursive -q
git -C "$nested_root/outer" config user.name "QBIND fixture"
git -C "$nested_root/outer" config user.email "fixture@example.invalid"
git -C "$nested_root/outer" config core.hooksPath /dev/null
commit_fixture "$nested_root"
printf 'nested edit\n' >>"${nested_root}/outer/nested/tracked.txt"
assert_state dirty "$nested_root" "nested initialized submodule tracked edit"
git -C "$nested_root/outer/nested" add -- tracked.txt
git -C "$nested_root/outer/nested" -c commit.gpgsign=false commit -qm "nested tracked edit"
git -C "$nested_root/outer" add -- nested
git -C "$nested_root/outer" -c commit.gpgsign=false commit -qm "nested gitlink update"
git -C "$nested_root" add -- outer
git -C "$nested_root" -c commit.gpgsign=false commit -qm "outer gitlink update"
printf 'nested docs edit\n' >>"${nested_root}/outer/nested/docs/nested.txt"
assert_state dirty "$nested_root" "docs/** paths remain included inside submodules"
git -C "$nested_root/outer/nested" add -- docs/nested.txt
git -C "$nested_root/outer/nested" -c commit.gpgsign=false commit -qm "nested docs edit"
git -C "$nested_root/outer" add -- nested
git -C "$nested_root/outer" -c commit.gpgsign=false commit -qm "nested docs gitlink update"
git -C "$nested_root" add -- outer
git -C "$nested_root" -c commit.gpgsign=false commit -qm "outer docs gitlink update"
printf 'untracked\n' >"${nested_root}/outer/untracked-submodule.txt"
printf 'ignored\n' >"${nested_root}/outer/nested/inside.ignored"
assert_state clean "$nested_root" "untracked-only content inside initialized submodule excluded"
rm -rf -- "${nested_root}/outer/nested"
assert_state unknown "$nested_root" "unavailable nested initialized submodule"
git -C "$nested_root" -c protocol.file.allow=always submodule update --init --recursive -q

printf '%s\n' '== Hiding configurations and unsupported index states =='
repo="$(new_repo hiding)"
git -C "$repo" config core.filemode false
git -C "$repo" config diff.external "false"
git -C "$repo" config diff.ignoreSubmodules all
printf '*.txt diff=hidden\n' >"${repo}/.gitattributes"
git -C "$repo" add -- .gitattributes
git -C "$repo" -c commit.gpgsign=false commit -qm "hide text diff"
git -C "$repo" config diff.hidden.textconv "false"
printf 'changed\n' >>"${repo}/tracked.txt"
assert_state dirty "$repo" "external-diff, textconv, and submodule-ignore neutralized"
git -C "$repo" update-index --assume-unchanged tracked.txt
assert_state unknown "$repo" "assume-unchanged index flag"
git -C "$repo" update-index --no-assume-unchanged tracked.txt
git -C "$repo" update-index --skip-worktree tracked.txt
assert_state unknown "$repo" "skip-worktree index flag"
git -C "$repo" update-index --no-skip-worktree tracked.txt
git -C "$repo" config core.sparseCheckout true
assert_state unknown "$repo" "sparse checkout"

repo="$(new_repo conflict)"
git -C "$repo" checkout -qb other
printf 'other\n' >"${repo}/tracked.txt"
commit_fixture "$repo"
git -C "$repo" checkout -q main
printf 'main\n' >"${repo}/tracked.txt"
commit_fixture "$repo"
if git -C "$repo" merge -q other >/dev/null 2>&1; then
  fail "fixture merge unexpectedly had no conflict"
fi
assert_state unknown "$repo" "unresolved index entries"

printf '%s\n' '== Git failures and override isolation =='
repo="$(new_repo errors)"
index_before=$(sha256sum "${repo}/.git/index")
config_before=$(git -C "$repo" config --local --list --null | sha256sum)
GIT_DIR="${TEST_ROOT}/wrong-git-dir" \
GIT_WORK_TREE="${TEST_ROOT}/wrong-worktree" \
GIT_INDEX_FILE="${TEST_ROOT}/wrong-index" \
  assert_state clean "$repo" "ignores inherited Git repository/index overrides"
index_after=$(sha256sum "${repo}/.git/index")
config_after=$(git -C "$repo" config --local --list --null | sha256sum)
[ "$index_before" = "$index_after" ] || fail "classifier modified fixture index"
[ "$config_before" = "$config_after" ] || fail "classifier modified fixture Git config"
pass "classifier leaves fixture index and configuration unchanged"
if output=$(qbind_observe_source_tree_state "${TEST_ROOT}/not-a-repository" 2>"${TEST_ROOT}/diagnostic"); then
  [ "$output" = unknown ] || fail "invalid repository was not unknown"
else
  fail "invalid repository did not return valid unknown"
fi
grep -q '^source_tree_state=unknown:' "${TEST_ROOT}/diagnostic" ||
  fail "unknown classification did not write diagnostics to stderr"
pass "invalid repository emits valid unknown"
unborn="${TEST_ROOT}/unborn"
git -c init.defaultBranch=main init -q "$unborn"
assert_state unknown "$unborn" "unavailable HEAD revision"

real_git="$(type -P git)"
wrapper_bin="${TEST_ROOT}/git-wrapper-bin"
mkdir -p "$wrapper_bin"
printf '#!/bin/sh\nfor arg do [ "$arg" = diff ] && exit 2; done\nexec "%s" "$@"\n' "$real_git" \
  >"${wrapper_bin}/git"
chmod +x "${wrapper_bin}/git"
PATH="${wrapper_bin}:${PATH}" assert_state unknown "$repo" "Git diff exit 2"

missing_git_bin="${TEST_ROOT}/missing-git-bin"
mkdir -p "$missing_git_bin"
for tool in env stat sha256sum mktemp rm wc; do
  ln -s "$(type -P "$tool")" "${missing_git_bin}/${tool}"
done
PATH="$missing_git_bin" assert_state unknown "$repo" "missing Git executable"

printf '%s\n' '== Mixed failures, deterministic instability, and output validation =='
repo="$(new_repo mixed)"
(
  _qbind_source_tree_state_diff() {
    [ "$1" = 1 ] && return 1
    return 2
  }
  assert_state unknown "$repo" "dirty plus failed required observation"
)
(
  _qbind_source_tree_state_observation() {
    if [ "${calls:-0}" -eq 0 ]; then
      calls=1
      return 0
    fi
    return 1
  }
  assert_state unknown "$repo" "repeated observations disagree"
)
(
  original_observation="$(declare -f _qbind_source_tree_state_observation)"
  eval "${original_observation/_qbind_source_tree_state_observation/_qbt_real_observation}"
  calls=0
  _qbind_source_tree_state_observation() {
    local status=0
    _qbt_real_observation "$@" || status=$?
    calls=$((calls + 1))
    if [ "$calls" -eq 1 ]; then
      printf 'post-build mutation\n' >>"${repo}/tracked.txt"
    fi
    return "$status"
  }
  assert_state unknown "$repo" "controlled post-observation worktree mutation"
)
(
  original_observation="$(declare -f _qbind_source_tree_state_observation)"
  eval "${original_observation/_qbind_source_tree_state_observation/_qbt_real_observation}"
  calls=0
  _qbind_source_tree_state_observation() {
    local status=0
    _qbt_real_observation "$@" || status=$?
    calls=$((calls + 1))
    if [ "$calls" -eq 1 ]; then
      printf 'index mutation\n' >>"${repo}/tracked.txt"
      git -C "$repo" add -- tracked.txt
    fi
    return "$status"
  }
  assert_state unknown "$repo" "controlled HEAD/index identity mutation"
)
repo_source="$(new_repo unstable-submodule-source)"
repo="$(new_repo unstable-submodule-root)"
git -C "$repo" -c protocol.file.allow=always submodule add -q "$repo_source" submodule
git -C "$repo/submodule" config user.name "QBIND fixture"
git -C "$repo/submodule" config user.email "fixture@example.invalid"
git -C "$repo/submodule" config core.hooksPath /dev/null
commit_fixture "$repo"
(
  original_observation="$(declare -f _qbind_source_tree_state_observation)"
  eval "${original_observation/_qbind_source_tree_state_observation/_qbt_real_observation}"
  calls=0
  _qbind_source_tree_state_observation() {
    local status=0
    _qbt_real_observation "$@" || status=$?
    calls=$((calls + 1))
    if [ "$calls" -eq 1 ]; then
      printf 'submodule index mutation\n' >>"${repo}/submodule/tracked.txt"
      git -C "${repo}/submodule" add -- tracked.txt
    fi
    return "$status"
  }
  assert_state unknown "$repo" "controlled submodule HEAD/index identity mutation"
)

check_capture() {
  local expected=$1 output=$2 status=$3
  (
    qbind_classify_source_tree_state() {
      printf '%s' "$output"
      return "$status"
    }
    if captured=$(qbind_observe_source_tree_state "$repo" 2>"${TEST_ROOT}/capture-error"); then
      [ "$status" -eq 0 ] || fail "helper failure was accepted"
      [ "$captured" = "$expected" ] || fail "malformed output accepted as $captured"
    else
      [ "$expected" = reject ] || fail "valid enum unexpectedly rejected"
    fi
  )
}
check_capture clean $'clean\n' 0
check_capture dirty $'dirty\n' 0
check_capture unknown $'unknown\n' 0
check_capture reject '' 0
check_capture reject dirty 0
check_capture reject $'clean\nextra\n' 0
check_capture reject $'clean\n\n' 0
check_capture reject $'clean\ndirty\n' 0
check_capture reject $'invalid\n' 0
check_capture reject $'clean\n' 7
pass "actual producer capture boundary accepts only one terminated enum and successful helper"

printf '%s\n' '== Full schema validation and bounded staging compatibility =='
for expected in clean dirty unknown; do
  (
    qbind_classify_source_tree_state() {
      printf '%s\n' "$expected"
    }
    observed=$(qbind_observe_source_tree_state "$repo")
    [ "$observed" = "$expected" ] || fail "capture boundary changed $expected to $observed"
    python3 - "$SCHEMA" "$EXAMPLE" "$observed" "${TEST_ROOT}/synthetic" \
      "${TEST_ROOT}/diagnostic" <<'PY'
import json
import os
import shutil
import sys
import jsonschema

schema_path, example_path, state, outdir, diagnostic_path = sys.argv[1:]
schema = json.load(open(schema_path, encoding="utf-8"))
example = json.load(open(example_path, encoding="utf-8"))
diagnostic = open(diagnostic_path, encoding="utf-8").read().strip()
jsonschema.Draft7Validator.check_schema(schema)
os.makedirs(outdir, exist_ok=True)
manifest = dict(example, source_tree_state=state)
generated = os.path.join(outdir, state + ".json")
staged = os.path.join(outdir, state + ".staged.json")
with open(generated, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh)
jsonschema.validate(manifest, schema)
if state == "unknown":
    assert diagnostic not in json.dumps(manifest)
shutil.copyfile(generated, staged)
staged_doc = json.load(open(staged, encoding="utf-8"))
jsonschema.validate(staged_doc, schema)
assert staged_doc["source_tree_state"] == state
print(f"PASS: schema and caller-compatible staging accept {state}")
PY
  )
done

printf '%s\n' '== Observation-time classification =='
repo="$(new_repo observation-time)"
assert_state clean "$repo" "stable pre-mutation observation"
printf 'after build, before serialization\n' >>"${repo}/tracked.txt"
assert_state dirty "$repo" "post-build/pre-serialization mutation"

printf '%s\n' 'All focused source-tree-state fixture cases passed.'
