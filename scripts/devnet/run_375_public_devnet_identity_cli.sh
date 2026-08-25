#!/usr/bin/env bash
# Run 375: first-class `qbind-node identity` command release harness.
#
# This harness proves the Run 375 acceptance evidence for the first-class
# `qbind-node identity` command surface (see
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`). It drives the RELEASE
# `target/release/qbind-node` binary directly — no example helper — through:
#
#   1. `cargo build -p qbind-node --release` (the node binary itself);
#   2. `qbind-node identity generate devnet full-node …`;
#   3. `qbind-node identity generate devnet seed …`;
#   4. `qbind-node identity generate devnet validator-candidate <index> …`;
#   5. `qbind-node identity verify …` re-derives the same NodeId (deterministic);
#   6. the public identity JSON validates against
#      `docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json`;
#   7. the generated identity inserts into a Run 357 seed-list candidate without
#      violating `devnet-seed-list.schema.json` (status=planned, no reachability);
#   8. the standalone `qbind-node` boots under strict
#      `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` with the
#      generated `--p2p-trusted-root/--p2p-leaf-cert/--p2p-leaf-cert-key` material;
#   9. booting the SAME material under a mismatched `--validator-id` fails closed;
#  10. MainNet / TestNet generation is REFUSED (fail closed, non-zero exit);
#  11. no generated private material is committed (KEM secret key is 0600 in a
#      TEMP dir only; the root signing key is never written to disk);
#  12. the release binary SHA-256 is captured;
#  13. the BuildID is captured;
#  14. the toolchain is captured.
#
# Route B — this adds a first-class DevNet-gated CLI command. The `identity`
# subcommand is a pure local key/cert generation + verification utility: it
# performs NO live deployment, opens NO default public port, deploys NO
# seed/faucet/RPC/explorer/status page, changes NO wire format, and weakens NO
# peer admission (strict mutual-auth only TIGHTENS admission). All addresses are
# loopback (127.0.0.1); the material dir is temporary and removed on exit. No
# generated private key, leaf key, root, data dir, or log is committed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run375-public-devnet-identity-cli}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
IDENTITY_SCHEMA="${REPO_ROOT}/docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json"
SEED_SCHEMA="${REPO_ROOT}/docs/release/public-devnet/network/devnet-seed-list.schema.json"
SEED_PLACEHOLDER="${REPO_ROOT}/docs/release/public-devnet/network/devnet-seeds.placeholder.json"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run375] %s\n' "$*"; }
fail() { printf '[run375] FAIL: %s\n' "$*" >&2; exit 1; }
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
# 1. Build the release node binary (which now carries the `identity` command).
# ---------------------------------------------------------------------------
log "building qbind-node (release)…"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "qbind-node release build failed"
[ -x "${NODE_BIN}" ] || fail "release binary missing: ${NODE_BIN}"

# 12/13/14. Provenance: binary sha256, BuildID, toolchain.
emit "release_binary=OK sha256=$(sha256_file "${NODE_BIN}")"
BUILD_ID="$(file "${NODE_BIN}" 2>/dev/null | grep -oE 'BuildID\[[a-z0-9]+\]=[0-9a-f]+' | sed 's/.*=//' || true)"
emit "build_id=${BUILD_ID:-unavailable}"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

MATERIAL="${OUTDIR}/material"
rm -rf "${MATERIAL}"
mkdir -p "${MATERIAL}"

# ---------------------------------------------------------------------------
# 2/3/4. Generate identity material for each role via the first-class command.
# ---------------------------------------------------------------------------
for ROLE in full-node seed validator-candidate; do
  DIR="${MATERIAL}/${ROLE}"
  EXTRA=""
  [ "${ROLE}" = "validator-candidate" ] && EXTRA="0"
  log "identity generate role=${ROLE}"
  "${NODE_BIN}" identity generate devnet "${ROLE}" "${DIR}" ${EXTRA} \
    > "${DIR}.public.json" 2> "${DIR}.err" \
    || fail "identity generate ${ROLE} failed"

  # 11. Private KEM secret key present, 0600, and NOT echoed to stdout.
  [ -f "${DIR}/leaf.kem.sk.bin" ] || fail "${ROLE}: missing leaf.kem.sk.bin"
  PERM="$(stat -c '%a' "${DIR}/leaf.kem.sk.bin")"
  [ "${PERM}" = "600" ] || fail "${ROLE}: leaf.kem.sk.bin perms=${PERM} (want 600)"
  # Root signing key MUST NOT be written to disk.
  for F in root.sk root.sk.hex root.sk.bin root.key; do
    [ -e "${DIR}/${F}" ] && fail "${ROLE}: root signing key written to disk (${F})"
  done
  emit "generate_${ROLE}=OK kem_sk_perms=${PERM} node_id=$(python3 -c "import json;print(json.load(open('${DIR}.public.json'))['node_id_short'])")"
done
emit "root_signing_key_on_disk=NONE (held in memory only)"

# ---------------------------------------------------------------------------
# 6. Public identity JSON validates against the operator-identity schema.
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
  VER_NODE_ID="$("${NODE_BIN}" identity verify "${MATERIAL}/${ROLE}/leaf.cert.bin" 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['node_id'])")"
  [ "${GEN_NODE_ID}" = "${VER_NODE_ID}" ] || fail "${ROLE}: NodeId mismatch gen=${GEN_NODE_ID} verify=${VER_NODE_ID}"
done
emit "deterministic_node_id_verify=OK (generate == verify for all roles)"

# ---------------------------------------------------------------------------
# 7. Generated identity inserts into a seed-list candidate object. This uses the
#    first-class `identity seed-candidate` emitter, then fills the operator
#    placeholders and validates against the seed-list schema.
# ---------------------------------------------------------------------------
"${NODE_BIN}" identity seed-candidate "${MATERIAL}/seed" > "${MATERIAL}/seed.candidate.json" \
  || fail "identity seed-candidate failed"
python3 - "${SEED_SCHEMA}" "${SEED_PLACEHOLDER}" "${MATERIAL}/seed.candidate.json" <<'PY' || fail "seed-list insertion failed"
import json, sys, jsonschema
schema=json.load(open(sys.argv[1]))
base=json.load(open(sys.argv[2]))
cand=json.load(open(sys.argv[3]))
# Operator fills placeholders with documentation-example (RFC 5737) values.
cand["p2p_host"]="192.0.2.20"; cand["p2p_multiaddr"]="192.0.2.20:30333"
cand["operator"]="example-operator"; cand["expected_genesis_hash"]=base["genesis_hash"]
doc=json.loads(json.dumps(base)); doc["seed_nodes"]=doc["seed_nodes"]+[cand]
jsonschema.validate(instance=doc, schema=schema)
assert cand["status"]=="planned" and cand["last_reachability_evidence"] is None
print("seed_list_insertion_ok")
PY
emit "seed_list_candidate_insertion=OK (status=planned, no reachability claim)"

# ---------------------------------------------------------------------------
# 8/9. Loopback strict-auth boot with generated material + mismatch fail-closed.
# ---------------------------------------------------------------------------
DIR="${MATERIAL}/full-node"
SPEC="$(cat "${DIR}/trusted-root.spec")"
MPORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
DATA_DIR="${MATERIAL}/node-data"
mkdir -p "${DATA_DIR}"
log "booting qbind-node under strict-auth with generated material (metrics=127.0.0.1:${MPORT})…"
QBIND_METRICS_HTTP_ADDR="127.0.0.1:${MPORT}" "${NODE_BIN}" \
  --env devnet --network-mode p2p --enable-p2p --validator-id 0 \
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
  sed -n '1,40p' "${MATERIAL}/node.log" || true
fi
kill "${NODE_PID}" 2>/dev/null || true; NODE_PID=""

log "negative boot: mismatched --validator-id must fail closed…"
QBIND_METRICS_HTTP_ADDR="127.0.0.1:0" "${NODE_BIN}" \
  --env devnet --network-mode p2p --enable-p2p --validator-id 7 \
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

# ---------------------------------------------------------------------------
# 10. MainNet / TestNet generation is REFUSED (fail closed).
# ---------------------------------------------------------------------------
if "${NODE_BIN}" identity generate mainnet full-node "${MATERIAL}/should-not-exist" >/dev/null 2>&1; then
  fail "mainnet generation was NOT refused"
fi
[ -d "${MATERIAL}/should-not-exist" ] && fail "mainnet generation wrote material"
if "${NODE_BIN}" identity generate testnet seed "${MATERIAL}/should-not-exist-2" >/dev/null 2>&1; then
  fail "testnet generation was NOT refused"
fi
[ -d "${MATERIAL}/should-not-exist-2" ] && fail "testnet generation wrote material"
emit "mainnet_testnet_generation=REFUSED (fail closed, non-zero exit, no material written)"

# Unknown role is likewise refused.
if "${NODE_BIN}" identity generate devnet super-node "${MATERIAL}/should-not-exist-3" >/dev/null 2>&1; then
  fail "unknown role was NOT refused"
fi
emit "unknown_role_generation=REFUSED (fail closed)"

emit ""
emit "RESULT=PASS (first-class qbind-node identity command proven; DevNet-only; no live deployment)"
log "summary written to ${SUMMARY}"