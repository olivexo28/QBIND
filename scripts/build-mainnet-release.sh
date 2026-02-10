#!/usr/bin/env bash
#
# QBIND MainNet Release Build Script (T239)
#
# This script produces deterministic release binaries for MainNet deployment.
# It builds for supported targets, computes SHA3-256 hashes, and outputs
# binaries to a predictable release directory structure.
#
# Usage:
#   ./scripts/build-mainnet-release.sh [--target <target>] [--binaries <list>]
#
# Options:
#   --target <target>   Build for specific target only (default: build all)
#   --binaries <list>   Comma-separated list of binaries to build (default: all)
#   --skip-cross        Skip cross-compilation targets if toolchain not available
#   --help              Show this help message
#
# Supported targets:
#   - x86_64-unknown-linux-gnu (native on x86_64 Linux)
#   - aarch64-unknown-linux-gnu (requires cross-compilation toolchain)
#
# Output:
#   release/bin/<binary>-<target>
#   release/hashes.txt
#   release/manifest-fragment.json
#
# Requirements:
#   - Rust toolchain (rustup, cargo)
#   - sha3sum utility (or Python 3 with hashlib fallback)
#   - Cross-compilation toolchain (optional, for aarch64 builds)
#
# Reference:
#   - docs/release/QBIND_MAINNET_V0_RELEASE_MANIFEST.md
#   - docs/mainnet/QBIND_MAINNET_V0_SPEC.md
#

set -euo pipefail

# --- Configuration ---

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RELEASE_DIR="${REPO_ROOT}/release"
BIN_DIR="${RELEASE_DIR}/bin"

# Supported targets
ALL_TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
)

# Binaries to build (binary name -> crate name)
# Note: qbind-envelope binary is provided by the qbind-gov crate
declare -A BINARY_CRATES=(
    ["qbind-node"]="qbind-node"
    ["qbind-envelope"]="qbind-gov"
    ["qbind-remote-signer"]="qbind-remote-signer"
)

# Default options
SELECTED_TARGETS=()
SELECTED_BINARIES=()
SKIP_CROSS=false

# --- Helper Functions ---

log_info() {
    echo "[INFO] $*"
}

log_warn() {
    echo "[WARN] $*" >&2
}

log_error() {
    echo "[ERROR] $*" >&2
}

show_help() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
    exit 0
}

# Compute SHA3-256 hash of a file
# Falls back to Python if sha3sum is not available
compute_sha3_256() {
    local file="$1"
    
    if command -v sha3sum &>/dev/null; then
        sha3sum -a 256 "$file" | awk '{print "0x" $1}'
    elif command -v python3 &>/dev/null; then
        # Pass filename as argument to avoid shell injection
        python3 - "$file" << 'EOF'
import hashlib
import sys
with open(sys.argv[1], 'rb') as f:
    h = hashlib.sha3_256()
    while chunk := f.read(8192):
        h.update(chunk)
    print('0x' + h.hexdigest())
EOF
    else
        log_error "No SHA3-256 tool available (need sha3sum or python3)"
        exit 1
    fi
}

# Check if a Rust target is installed
target_available() {
    local target="$1"
    rustup target list --installed 2>/dev/null | grep -q "^${target}$"
}

# Get current host target
get_host_target() {
    rustc -vV | grep "host:" | awk '{print $2}'
}

# --- Parse Arguments ---

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            IFS=',' read -ra SELECTED_TARGETS <<< "$2"
            shift 2
            ;;
        --binaries)
            IFS=',' read -ra SELECTED_BINARIES <<< "$2"
            shift 2
            ;;
        --skip-cross)
            SKIP_CROSS=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Default to all targets if none specified
if [[ ${#SELECTED_TARGETS[@]} -eq 0 ]]; then
    SELECTED_TARGETS=("${ALL_TARGETS[@]}")
fi

# Default to all binaries if none specified
if [[ ${#SELECTED_BINARIES[@]} -eq 0 ]]; then
    SELECTED_BINARIES=("${!BINARY_CRATES[@]}")
fi

# --- Pre-flight Checks ---

log_info "=== QBIND MainNet Release Build ==="
log_info ""

# Check Rust toolchain
if ! command -v cargo &>/dev/null; then
    log_error "cargo not found. Please install Rust toolchain."
    exit 1
fi

if ! command -v rustc &>/dev/null; then
    log_error "rustc not found. Please install Rust toolchain."
    exit 1
fi

# Determine Rust version
if [[ -n "${RUSTUP_TOOLCHAIN:-}" ]]; then
    RUST_VERSION="${RUSTUP_TOOLCHAIN}"
    log_info "Using RUSTUP_TOOLCHAIN: ${RUST_VERSION}"
else
    RUST_VERSION="$(rustc --version | awk '{print $2}')"
    log_info "Detected Rust version: ${RUST_VERSION}"
fi

HOST_TARGET="$(get_host_target)"
log_info "Host target: ${HOST_TARGET}"

# Check for Cargo.lock
if [[ ! -f "${REPO_ROOT}/Cargo.lock" ]]; then
    log_error "Cargo.lock not found. Cannot build with --locked."
    exit 1
fi

# Check Git state
if command -v git &>/dev/null && [[ -d "${REPO_ROOT}/.git" ]]; then
    GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")"
    GIT_TAG="$(git -C "${REPO_ROOT}" describe --exact-match --tags 2>/dev/null || echo "untagged")"
    GIT_DIRTY="$(git -C "${REPO_ROOT}" status --porcelain 2>/dev/null)"
    
    if [[ -z "${GIT_DIRTY}" ]]; then
        GIT_STATE="clean"
    else
        GIT_STATE="dirty"
        log_warn "Git tree is dirty. Release builds should be from clean state."
    fi
    
    log_info "Git commit: ${GIT_COMMIT}"
    log_info "Git tag: ${GIT_TAG}"
    log_info "Git state: ${GIT_STATE}"
else
    GIT_COMMIT="unknown"
    GIT_TAG="unknown"
    GIT_STATE="unknown"
    log_warn "Git information not available"
fi

log_info ""

# --- Setup Output Directory ---

log_info "Creating release directory: ${RELEASE_DIR}"
mkdir -p "${BIN_DIR}"

# Initialize hashes file
HASHES_FILE="${RELEASE_DIR}/hashes.txt"
: > "${HASHES_FILE}"

# Initialize manifest fragment
MANIFEST_FILE="${RELEASE_DIR}/manifest-fragment.json"

# --- Build Binaries ---

BUILD_SUCCESS=true
BINARIES_JSON="[]"

for target in "${SELECTED_TARGETS[@]}"; do
    log_info ""
    log_info "=== Building for target: ${target} ==="
    
    # Check if target is available
    if [[ "${target}" != "${HOST_TARGET}" ]]; then
        if ! target_available "${target}"; then
            if [[ "${SKIP_CROSS}" == "true" ]]; then
                log_warn "Target ${target} not installed, skipping (--skip-cross)"
                continue
            else
                log_info "Installing target: ${target}"
                rustup target add "${target}" || {
                    log_warn "Failed to install target ${target}, skipping"
                    continue
                }
            fi
        fi
    fi
    
    for binary in "${SELECTED_BINARIES[@]}"; do
        crate="${BINARY_CRATES[$binary]:-}"
        if [[ -z "${crate}" ]]; then
            log_warn "Unknown binary: ${binary}, skipping"
            continue
        fi
        
        log_info "Building ${binary} (crate: ${crate}) for ${target}..."
        
        # Build with locked dependencies
        if ! cargo build \
            --manifest-path "${REPO_ROOT}/Cargo.toml" \
            --release \
            --locked \
            --target "${target}" \
            --package "${crate}" \
            --bin "${binary}" 2>&1; then
            log_error "Failed to build ${binary} for ${target}"
            BUILD_SUCCESS=false
            continue
        fi
        
        # Copy binary to release directory
        SOURCE_BIN="${REPO_ROOT}/target/${target}/release/${binary}"
        DEST_BIN="${BIN_DIR}/${binary}-${target}"
        
        if [[ ! -f "${SOURCE_BIN}" ]]; then
            log_error "Binary not found: ${SOURCE_BIN}"
            BUILD_SUCCESS=false
            continue
        fi
        
        cp "${SOURCE_BIN}" "${DEST_BIN}"
        chmod +x "${DEST_BIN}"
        
        # Compute hash
        HASH="$(compute_sha3_256 "${DEST_BIN}")"
        
        log_info "  -> ${DEST_BIN}"
        log_info "  -> SHA3-256: ${HASH}"
        
        # Append to hashes file
        echo "${HASH}  ${binary}-${target}" >> "${HASHES_FILE}"
        
        # Append to JSON array
        BINARIES_JSON=$(echo "${BINARIES_JSON}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
data.append({
    'name': '${binary}',
    'target': '${target}',
    'sha3_256': '${HASH}'
})
print(json.dumps(data))
")
    done
done

# --- Generate Manifest Fragment ---

log_info ""
log_info "=== Generating manifest fragment ==="

cat > "${MANIFEST_FILE}" << EOF
{
  "chain_id": "qbind-mainnet-v0",
  "protocol_version": "v0",
  "git": {
    "commit": "${GIT_COMMIT}",
    "tag": "${GIT_TAG}",
    "tree_state": "${GIT_STATE}"
  },
  "binaries": ${BINARIES_JSON},
  "build": {
    "rust_toolchain": "${RUST_VERSION}",
    "cargo_profile": "release",
    "build_script": "scripts/build-mainnet-release.sh"
  }
}
EOF

log_info "Manifest fragment: ${MANIFEST_FILE}"

# --- Summary ---

log_info ""
log_info "=== Build Summary ==="
log_info "Release directory: ${RELEASE_DIR}"
log_info "Binaries: ${BIN_DIR}"
log_info "Hashes: ${HASHES_FILE}"
log_info "Manifest: ${MANIFEST_FILE}"
log_info ""

if [[ -f "${HASHES_FILE}" ]]; then
    log_info "SHA3-256 Hashes:"
    while read -r line; do
        log_info "  ${line}"
    done < "${HASHES_FILE}"
fi

log_info ""
if [[ "${BUILD_SUCCESS}" == "true" ]]; then
    log_info "=== Build completed successfully ==="
    exit 0
else
    log_error "=== Build completed with errors ==="
    exit 1
fi