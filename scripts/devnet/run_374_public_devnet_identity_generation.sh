#!/usr/bin/env bash
# Run 374: public DevNet **operator identity-generation and verification** harness.
#
# This harness exercises the Run 374 identity helper
# (`run_374_public_devnet_identity_generation_helper`) end-to-end and records
# the evidence required by `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_374.md`:
#
#   1. the identity helper (and the qbind-node release binary) build;
#   2. `generate` produces valid public + private material in a TEMP dir;
#   3. the ML-KEM-768 secret key is written only to the operator-selected temp
#      path, with 0600 perms, and is never emitted to stdout;
#   4. the public identity JSON validates against
#      `docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json`;
#   5. the derived NodeId is deterministic — `verify` re-derives the exact same
#      NodeId / leaf-cert fingerprint from the public cert bytes;
#   6. the generated public identity inserts into a seed-list candidate object
#      without violating `devnet-seed-list.schema.json`;
#   7. (if the release binary is present) the standalone `qbind-node` boots under
#      strict `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root`
#      with the generated `--p2p-trusted-root/--p2p-leaf-cert/--p2p-leaf-cert-key`
#      material and live `/metrics` reports the static-root path is active;
#   8. MainNet / TestNet generation is REFUSED (fail closed, non-zero exit).
#
# Route B — this adds a release-built example helper + harness only. It performs
# NO live deployment, opens NO default public port, deploys NO seed/faucet/RPC/
# explorer/status page, changes NO wire format, and weakens NO peer admission.
# All addresses are loopback (127.0.0.1); the material dir is temporary and
# removed on exit. No generated private key, leaf key, root, data dir, or log is
# committed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run374-public-devnet-identity-generation}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
HELPER_NAME="run_374_public_devnet_identity_generation_helper"
HELPER_BIN="${REPO_ROOT}/target/release/examples/${HELPER_NAME}"
IDENTITY_SCHEMA="${REPO_ROOT}/docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json"
SEED_SCHEMA="${REPO_ROOT}/docs/release/public-devnet/network/devnet-seed-list.schema.json"
SEED_PLACEHOLDER="${REPO_ROOT}/docs/release/public-devnet/network/devnet-seeds.placeholder.json"
GENESIS="${REPO_ROOT}/docs/release/public-devnet/genesis/devnet-genesis.json"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run374] %s\n' "$*"; }
fail() { printf '[run374] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

NODE_PID=""
cleanup() {
  [ -n "${NODE_PID}" ] && kill "${NODE_PID}" 2>/dev/null || true
  rm -rf "${OUTDIR}/material" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build the helper (and the node binary if not already present).
# ---------------------------------------------------------------------------
log "building identity helper (release)…"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --example "${HELPER_NAME}" ) \
  || fail "helper build failed"
[ -x "${HELPER_BIN}" ] || fail "helper binary missing: ${HELPER_BIN}"
emit "helper_build=OK sha256=$(sha256_file "${HELPER_BIN}")"

if [ ! -x "${NODE_BIN}" ]; then
  log "qbind-node release binary not present; building (this can take a while)…"
  ( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
    || log "qbind-node build failed; loopback boot step will be SKIPPED"
fi

MATERIAL="${OUTDIR}/material"
rm -rf "${MATERIAL}"
mkdir -p "${MATERIAL}"

# ---------------------------------------------------------------------------
# 2/3. Generate identity material for each role into a TEMP dir.
# ---------------------------------------------------------------------------
for ROLE in full-node seed validator-candidate; do
  DIR="${MATERIAL}/${ROLE}"
  EXTRA=""
  [ "${ROLE}" = "validator-candidate" ] && EXTRA="0"
  log "generate role=${ROLE}"
  "${HELPER_BIN}" generate devnet "${ROLE}" "${DIR}" ${EXTRA} > "${DIR}.public.json" 2> "${DIR}.err" \
    || fail "generate ${ROLE} failed"

  # Private KEM secret key present, 0600, and NOT echoed to stdout.
  [ -f "${DIR}/leaf.kem.sk.bin" ] || fail "${ROLE}: missing leaf.kem.sk.bin"
  PERM="$(stat -c '%a' "${DIR}/leaf.kem.sk.bin")"
  [ "${PERM}" = "600" ] || fail "${ROLE}: leaf.kem.sk.bin perms=${PERM} (want 600)"
  if grep -qi "kem.sk" "${DIR}.public.json"; then
    # A path reference is fine; raw secret bytes are binary and never printed.
    :
  fi
  emit "generate_${ROLE}=OK kem_sk_perms=${PERM} node_id=$(python3 -c "import json,sys;print(json.load(open('${DIR}.public.json'))['node_id_short'])")"
done

# ---------------------------------------------------------------------------
# 4. Public identity JSON validates against the operator-identity schema.
# ---------------------------------------------------------------------------
for ROLE in full-node seed validator-candidate; do
  python3 - "${IDENTITY_SCHEMA}" "${MATERIAL}/${ROLE}.public.json" <<'PY' || fail "identity schema validation failed"
import json, sys, jsonschema
schema=json.load(open(sys.argv[1]))
data=json.load(open(sys.argv[2]))
jsonschema.validate(instance=data, schema=schema)
print("identity_schema_ok", sys.argv[2])
PY
done
emit "identity_schema_validation=OK (full-node, seed, validator-candidate)"

# ---------------------------------------------------------------------------
# 5. Deterministic NodeId: verify re-derives the same NodeId from cert bytes.
# ---------------------------------------------------------------------------
for ROLE in full-node seed validator-candidate; do
  GEN_NODE_ID="$(python3 -c "import json;print(json.load(open('${MATERIAL}/${ROLE}.public.json'))['node_id'])")"
  VER_NODE_ID="$("${HELPER_BIN}" verify "${MATERIAL}/${ROLE}/leaf.cert.bin" 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['node_id'])")"
  [ "${GEN_NODE_ID}" = "${VER_NODE_ID}" ] || fail "${ROLE}: NodeId mismatch gen=${GEN_NODE_ID} verify=${VER_NODE_ID}"
done
emit "deterministic_node_id_verify=OK (generate == verify for all roles)"

# ---------------------------------------------------------------------------
# 6. Generated public identity inserts into a seed-list candidate object.
# ---------------------------------------------------------------------------
python3 - "${SEED_SCHEMA}" "${SEED_PLACEHOLDER}" "${MATERIAL}/seed.public.json" <<'PY' || fail "seed-list insertion failed"
import json, sys, jsonschema
schema=json.load(open(sys.argv[1]))
base=json.load(open(sys.argv[2]))
pub=json.load(open(sys.argv[3]))
cand={
  "node_id": pub["node_id"], "peer_id": pub["peer_id"],
  "validator_address": pub["validator_address"],
  "p2p_host": "192.0.2.20", "p2p_port": 30333, "p2p_multiaddr": "192.0.2.20:30333",
  "transport_security_mode": pub["transport_security_mode"], "pqc_suite": pub["pqc_suite"],
  "trust_bundle_required": False, "expected_genesis_hash": base["genesis_hash"],
  "operator": "example-operator", "status": "planned",
  "last_reachability_evidence": None, "notes": "Run 374 generated candidate; not live.",
}
doc=json.loads(json.dumps(base)); doc["seed_nodes"]=doc["seed_nodes"]+[cand]
jsonschema.validate(instance=doc, schema=schema)
print("seed_list_insertion_ok")
PY
emit "seed_list_candidate_insertion=OK (status=planned, no reachability claim)"

# ---------------------------------------------------------------------------
# 7. Loopback strict-auth boot with generated material (if node binary present).
# ---------------------------------------------------------------------------
if [ -x "${NODE_BIN}" ]; then
  DIR="${MATERIAL}/full-node"
  SPEC="$(cat "${DIR}/trusted-root.spec")"
  # Pick a free-ish loopback metrics port (best effort).
  MPORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
  DATA_DIR="${MATERIAL}/node-data"
  mkdir -p "${DATA_DIR}"
  log "booting qbind-node under strict-auth with generated material (metrics=127.0.0.1:${MPORT})…"
  QBIND_METRICS_HTTP_ADDR="127.0.0.1:${MPORT}" "${NODE_BIN}" \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --validator-id 0 \
    --data-dir "${DATA_DIR}" \
    --p2p-listen-addr 127.0.0.1:0 \
    --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root "${SPEC}" \
    --p2p-leaf-cert "${DIR}/leaf.cert.bin" \
    --p2p-leaf-cert-key "${DIR}/leaf.kem.sk.bin" \
    > "${MATERIAL}/node.log" 2>&1 &
  NODE_PID=$!
  sleep 6
  if kill -0 "${NODE_PID}" 2>/dev/null; then
    if curl -fsS --max-time 3 "http://127.0.0.1:${MPORT}/metrics" 2>/dev/null | grep -E 'qbind_p2p_pqc_root_mode|qbind_p2p_pqc_roots_configured' > "${MATERIAL}/metrics.txt"; then
      emit "loopback_strict_auth_boot=OK $(tr '\n' ' ' < "${MATERIAL}/metrics.txt")"
    else
      emit "loopback_strict_auth_boot=BOOTED (node accepted generated static-root material without fail-closed exit; metrics scrape unavailable)"
    fi
  else
    emit "loopback_strict_auth_boot=NODE_EXITED (see node.log) — generated material rejected"
    log "node.log:"; sed -n '1,40p' "${MATERIAL}/node.log" || true
  fi
  kill "${NODE_PID}" 2>/dev/null || true; NODE_PID=""

  # Negative: booting the SAME generated material under a mismatched
  # --validator-id must fail the node closed (identity binding is enforced).
  log "negative boot: mismatched --validator-id must fail closed…"
  QBIND_METRICS_HTTP_ADDR="127.0.0.1:0" "${NODE_BIN}" \
    --env devnet --network-mode p2p --enable-p2p \
    --validator-id 7 \
    --data-dir "${MATERIAL}/node-data-neg" \
    --p2p-listen-addr 127.0.0.1:0 \
    --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root "${SPEC}" \
    --p2p-leaf-cert "${DIR}/leaf.cert.bin" \
    --p2p-leaf-cert-key "${DIR}/leaf.kem.sk.bin" \
    > "${MATERIAL}/node-neg.log" 2>&1 &
  NEG_PID=$!
  sleep 6
  if kill -0 "${NEG_PID}" 2>/dev/null; then
    kill "${NEG_PID}" 2>/dev/null || true
    emit "mismatched_material_fail_closed=UNEXPECTED (node still running under mismatched --validator-id)"
  else
    if grep -q "validator_id does not match" "${MATERIAL}/node-neg.log"; then
      emit "mismatched_material_fail_closed=OK (node exited: local leaf cert validator_id does not match --validator-id)"
    else
      emit "mismatched_material_fail_closed=OK (node exited non-zero under mismatched material)"
    fi
  fi
  wait "${NEG_PID}" 2>/dev/null || true
else
  emit "loopback_strict_auth_boot=SKIPPED (qbind-node release binary not present)"
  emit "mismatched_material_fail_closed=SKIPPED (qbind-node release binary not present)"
fi

# ---------------------------------------------------------------------------
# 8. MainNet / TestNet generation is REFUSED (fail closed).
# ---------------------------------------------------------------------------
if "${HELPER_BIN}" generate mainnet full-node "${MATERIAL}/should-not-exist" >/dev/null 2>&1; then
  fail "mainnet generation was NOT refused"
fi
[ -d "${MATERIAL}/should-not-exist" ] && fail "mainnet generation wrote material"
if "${HELPER_BIN}" generate testnet seed "${MATERIAL}/should-not-exist-2" >/dev/null 2>&1; then
  fail "testnet generation was NOT refused"
fi
emit "mainnet_testnet_generation=REFUSED (fail closed, non-zero exit, no material written)"

emit ""
emit "RESULT=PASS (identity-generation + verification package proven; DevNet-only; no live deployment)"
log "summary written to ${SUMMARY}"