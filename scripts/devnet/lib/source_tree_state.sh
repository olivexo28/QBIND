#!/usr/bin/env bash

_qbind_source_tree_state_git() {
  "$QBT_ENV_BIN" -i \
    PATH="${PATH:-/usr/bin:/bin}" \
    LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_SYSTEM=/dev/null \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 \
    "$QBT_GIT_BIN" -C "$QBT_REPO_ROOT" \
      -c core.filemode=true \
      -c diff.ignoreSubmodules=untracked \
      -c diff.external= \
      "$@"
}

_qbind_source_tree_state_identity_for_root() {
  local QBT_REPO_ROOT=$1 exclude_docs=$2 depth=$3 git_root
  local head index_path index_stat index_hash record metadata path mode child_identity
  local entries_file identity_file submodule_hash

  if [ "$depth" -ge 32 ] ||
    ! QBT_REPO_ROOT=$(cd -- "$QBT_REPO_ROOT" 2>/dev/null && pwd -P); then
    return 1
  fi
  if ! git_root=$(_qbind_source_tree_state_git rev-parse --show-toplevel 2>/dev/null) ||
    [ "$git_root" != "$QBT_REPO_ROOT" ]; then
    return 1
  fi
  if ! head=$(_qbind_source_tree_state_git rev-parse --verify 'HEAD^{commit}' 2>/dev/null); then
    return 1
  fi
  if ! index_path=$(_qbind_source_tree_state_git rev-parse --git-path index 2>/dev/null); then
    return 1
  fi
  case "$index_path" in
    /*) ;;
    *) index_path="${QBT_REPO_ROOT}/${index_path}" ;;
  esac
  if ! index_stat=$(stat -Lc '%d:%i:%s:%y:%z' -- "$index_path" 2>/dev/null); then
    return 1
  fi
  if ! index_hash=$(sha256sum -- "$index_path" 2>/dev/null); then
    return 1
  fi
  index_hash=${index_hash%% *}

  if ! entries_file=$(mktemp "${TMPDIR:-/tmp}/qbind-source-tree-entries.XXXXXX"); then
    return 1
  fi
  if ! identity_file=$(mktemp "${TMPDIR:-/tmp}/qbind-source-tree-identities.XXXXXX"); then
    rm -f -- "$entries_file"
    return 1
  fi
  if ! _qbind_source_tree_state_git ls-files --stage -z >"$entries_file" 2>/dev/null; then
    rm -f -- "$entries_file" "$identity_file"
    return 1
  fi
  while IFS= read -r -d '' record; do
    metadata=${record%%$'\t'*}
    path=${record#*$'\t'}
    mode=${metadata%% *}
    [ "$mode" = 160000 ] || continue
    if [ "$exclude_docs" = 1 ]; then
      case "$path" in
        docs/*) continue ;;
      esac
    fi
    if ! child_identity=$(_qbind_source_tree_state_identity_for_root \
      "${QBT_REPO_ROOT}/${path}" 0 "$((depth + 1))"); then
      rm -f -- "$entries_file" "$identity_file"
      return 1
    fi
    printf '%s\0%s\0' "$path" "$child_identity" >>"$identity_file" || {
      rm -f -- "$entries_file" "$identity_file"
      return 1
    }
  done <"$entries_file"
  rm -f -- "$entries_file"
  if ! submodule_hash=$(sha256sum -- "$identity_file" 2>/dev/null); then
    rm -f -- "$identity_file"
    return 1
  fi
  rm -f -- "$identity_file"
  submodule_hash=${submodule_hash%% *}
  printf '%s\n%s\n%s\n%s\n' "$head" "$index_stat" "$index_hash" "$submodule_hash"
}

_qbind_source_tree_state_identity() {
  _qbind_source_tree_state_identity_for_root "$QBT_REPO_ROOT" "$1" 0
}

_qbind_source_tree_state_check_index() {
  local exclude_docs=$1 record tag path temp_file

  if ! temp_file=$(mktemp "${TMPDIR:-/tmp}/qbind-source-tree-index.XXXXXX"); then
    return 1
  fi
  if ! _qbind_source_tree_state_git ls-files -v -z >"$temp_file" 2>/dev/null; then
    rm -f -- "$temp_file"
    return 1
  fi
  while IFS= read -r -d '' record; do
    tag=${record:0:1}
    path=${record:2}
    if [ "$exclude_docs" = 1 ]; then
      case "$path" in
        docs/*) continue ;;
      esac
    fi
    case "$tag" in
      [a-z]|S)
        rm -f -- "$temp_file"
        return 2
        ;;
    esac
  done <"$temp_file"
  rm -f -- "$temp_file"

  if ! temp_file=$(mktemp "${TMPDIR:-/tmp}/qbind-source-tree-unmerged.XXXXXX"); then
    return 1
  fi
  if ! _qbind_source_tree_state_git ls-files --unmerged -z >"$temp_file" 2>/dev/null; then
    rm -f -- "$temp_file"
    return 1
  fi
  if [ -s "$temp_file" ]; then
    rm -f -- "$temp_file"
    return 2
  fi
  rm -f -- "$temp_file"

  local sparse
  if sparse=$(_qbind_source_tree_state_git config --bool --get core.sparseCheckout 2>/dev/null); then
    if [ "$sparse" = true ]; then
      return 2
    fi
  else
    [ "$?" -eq 1 ] || return 1
  fi
  return 0
}

_qbind_source_tree_state_diff() {
  local staged=$1 exclude_docs=$2 rc
  local -a pathspec=(-- .)

  if [ "$exclude_docs" = 1 ]; then
    pathspec+=(':(exclude,top)docs/**')
  fi
  if [ "$staged" = 1 ]; then
    if _qbind_source_tree_state_git diff --cached --quiet --no-ext-diff --no-textconv \
      --ignore-submodules=untracked HEAD "${pathspec[@]}" 2>/dev/null; then
      return 0
    else
      rc=$?
    fi
  else
    if _qbind_source_tree_state_git diff --quiet --no-ext-diff --no-textconv \
      --ignore-submodules=untracked "${pathspec[@]}" 2>/dev/null; then
      return 0
    else
      rc=$?
    fi
  fi
  [ "$rc" -eq 1 ] && return 1
  return 2
}

_qbind_source_tree_state_submodules() {
  local exclude_docs=$1 temp_file record metadata path mode state dirty=0 rc

  if ! temp_file=$(mktemp "${TMPDIR:-/tmp}/qbind-source-tree-submodules.XXXXXX"); then
    return 2
  fi
  if ! _qbind_source_tree_state_git ls-files --stage -z >"$temp_file" 2>/dev/null; then
    rm -f -- "$temp_file"
    return 2
  fi
  while IFS= read -r -d '' record; do
    metadata=${record%%$'\t'*}
    path=${record#*$'\t'}
    mode=${metadata%% *}
    [ "$mode" = 160000 ] || continue
    if [ "$exclude_docs" = 1 ]; then
      case "$path" in
        docs/*) continue ;;
      esac
    fi
    if ! state=$(_qbind_source_tree_state_classify "${QBT_REPO_ROOT}/${path}" 0); then
      rm -f -- "$temp_file"
      return 2
    fi
    case "$state" in
      clean) ;;
      dirty) dirty=1 ;;
      unknown)
        rm -f -- "$temp_file"
        return 2
        ;;
      *)
        rm -f -- "$temp_file"
        return 2
        ;;
    esac
  done <"$temp_file"
  rm -f -- "$temp_file"
  [ "$dirty" -eq 1 ] && return 1
  return 0
}

_qbind_source_tree_state_observation() {
  local exclude_docs=$1 rc dirty=0

  _qbind_source_tree_state_check_index "$exclude_docs" || {
    rc=$?
    [ "$rc" -eq 2 ] && return 2
    return 3
  }
  _qbind_source_tree_state_diff 1 "$exclude_docs" || {
    rc=$?
    [ "$rc" -eq 1 ] && dirty=1 || {
      [ "$rc" -eq 2 ] && return 3
    }
  }
  _qbind_source_tree_state_diff 0 "$exclude_docs" || {
    rc=$?
    [ "$rc" -eq 1 ] && dirty=1 || {
      [ "$rc" -eq 2 ] && return 3
    }
  }
  _qbind_source_tree_state_submodules "$exclude_docs" || {
    rc=$?
    [ "$rc" -eq 1 ] && dirty=1 || {
      [ "$rc" -eq 2 ] && return 3
    }
  }
  [ "$dirty" -eq 1 ] && return 1
  return 0
}

_qbind_source_tree_state_classify() {
  local requested_root=$1 exclude_docs=$2
  local QBT_REPO_ROOT QBT_GIT_BIN QBT_ENV_BIN git_root observation_start observation_end
  local first=0 second=0 rc

  if ! QBT_GIT_BIN=$(type -P git 2>/dev/null) || [ -z "$QBT_GIT_BIN" ]; then
    printf '%s\n' 'source_tree_state=unknown: Git executable unavailable' >&2
    printf '%s\n' unknown
    return 0
  fi
  QBT_ENV_BIN=$(type -P env 2>/dev/null) || QBT_ENV_BIN=
  if [ -z "$QBT_ENV_BIN" ] || [ ! -x "$QBT_ENV_BIN" ]; then
    printf '%s\n' 'source_tree_state=unknown: required environment isolation unavailable' >&2
    printf '%s\n' unknown
    return 0
  fi
  if ! QBT_REPO_ROOT=$(cd -- "$requested_root" 2>/dev/null && pwd -P); then
    printf '%s\n' 'source_tree_state=unknown: repository path unavailable' >&2
    printf '%s\n' unknown
    return 0
  fi
  if ! git_root=$(_qbind_source_tree_state_git rev-parse --show-toplevel 2>/dev/null) ||
    [ "$git_root" != "$QBT_REPO_ROOT" ]; then
    printf '%s\n' 'source_tree_state=unknown: invalid Git repository' >&2
    printf '%s\n' unknown
    return 0
  fi
  if ! observation_start=$(_qbind_source_tree_state_identity "$exclude_docs"); then
    printf '%s\n' 'source_tree_state=unknown: HEAD or index identity unavailable' >&2
    printf '%s\n' unknown
    return 0
  fi
  if _qbind_source_tree_state_observation "$exclude_docs"; then
    first=0
  else
    rc=$?
    case "$rc" in
      1) first=1 ;;
      *) first=2 ;;
    esac
  fi
  if ! observation_end=$(_qbind_source_tree_state_identity "$exclude_docs") ||
    [ "$observation_start" != "$observation_end" ]; then
    printf '%s\n' 'source_tree_state=unknown: HEAD or index changed during observation' >&2
    printf '%s\n' unknown
    return 0
  fi
  if _qbind_source_tree_state_observation "$exclude_docs"; then
    second=0
  else
    rc=$?
    case "$rc" in
      1) second=1 ;;
      *) second=2 ;;
    esac
  fi
  if ! observation_end=$(_qbind_source_tree_state_identity "$exclude_docs") ||
    [ "$observation_start" != "$observation_end" ]; then
    printf '%s\n' 'source_tree_state=unknown: HEAD or index changed during observation' >&2
    printf '%s\n' unknown
    return 0
  fi
  if [ "$first" -eq 2 ] || [ "$second" -eq 2 ] || [ "$first" -ne "$second" ]; then
    printf '%s\n' 'source_tree_state=unknown: required observation failed or repeated observations disagreed' >&2
    printf '%s\n' unknown
    return 0
  fi
  if [ "$first" -eq 1 ]; then
    printf '%s\n' dirty
  else
    printf '%s\n' clean
  fi
}

qbind_classify_source_tree_state() {
  local repo_root=${1:-}
  if [ -z "$repo_root" ]; then
    repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." 2>/dev/null && pwd -P) || {
      printf '%s\n' 'source_tree_state=unknown: helper repository path unavailable' >&2
      printf '%s\n' unknown
      return 0
    }
  fi
  _qbind_source_tree_state_classify "$repo_root" 1
}

qbind_observe_source_tree_state() {
  local repo_root=${1:-} temp_file observed bytes expected_bytes rc

  if ! temp_file=$(mktemp "${TMPDIR:-/tmp}/qbind-source-tree-output.XXXXXX"); then
    printf '%s\n' 'source_tree_state=unknown: cannot capture classifier output' >&2
    return 1
  fi
  if qbind_classify_source_tree_state "$repo_root" >"$temp_file"; then
    :
  else
    rc=$?
    rm -f -- "$temp_file"
    printf 'source_tree_state helper failed (exit %s)\n' "$rc" >&2
    return 1
  fi
  if ! IFS= read -r observed <"$temp_file"; then
    rm -f -- "$temp_file"
    printf '%s\n' 'source_tree_state helper produced empty or unterminated output' >&2
    return 1
  fi
  case "$observed" in
    clean|dirty|unknown) ;;
    *)
      rm -f -- "$temp_file"
      printf '%s\n' 'source_tree_state helper produced an invalid value' >&2
      return 1
      ;;
  esac
  bytes=$(wc -c <"$temp_file") || {
    rm -f -- "$temp_file"
    printf '%s\n' 'cannot validate source_tree_state helper output length' >&2
    return 1
  }
  expected_bytes=$((${#observed} + 1))
  rm -f -- "$temp_file"
  if [ "$bytes" -ne "$expected_bytes" ]; then
    printf '%s\n' 'source_tree_state helper must produce exactly one enum line' >&2
    return 1
  fi
  printf '%s\n' "$observed"
}
