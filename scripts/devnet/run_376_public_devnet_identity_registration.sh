#!/usr/bin/env bash
# Run 376: public DevNet identity registration / admission-check release harness.
#
# This harness proves the Run 376 acceptance evidence for the NON-MUTATING
# `qbind-node identity register-check` admission verifier (see
# `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md`). It drives the RELEASE
# `target/release/qbind-node` binary directly through:
#
#   1. `cargo build -p qbind-node --release --bin qbind-node`;
#   2. `qbind-node identity generate devnet seed …` (+ full-node, validator-candidate);
#   3. `qbind-node identity seed-candidate …`;
#   4. `qbind-node identity register-check …` ACCEPTS the planned candidate;
#   5. the emitted candidate validates against `devnet-seed-list.schema.json`
#      (inserted into the placeholder seed list; status=planned, no reachability);
#   6. `--status live` WITHOUT `--reachability-evidence` fails closed;
#   7. an embedded private-material public JSON fails closed;
#   8. a mismatched cert / identity fails closed;
#   9. MainNet / TestNet identity material is REFUSED;
#  10. no generated private material is committed (KEM secret key is 0600 in a
#      TEMP dir only; the root signing key is never written to disk);
#  11. the release binary SHA-256 is captured;
#  12. the BuildID is captured;
#  13. the toolchain is captured.
#
# Route B — this exercises a first-class, DevNet-gated, NON-MUTATING CLI command.
# `register-check` reads PUBLIC material only: it opens NO socket, registers NO
# peer, mutates NO trust/validator/epoch/sequence/marker state, changes NO wire
# format, and weakens NO peer admission. It makes NO live / reachability / M4 /
# C4 / C5 claim. All addresses used are RFC 5737 documentation-example values.
# The material dir is temporary and removed on exit. No generated private key,
# leaf key, root, data dir, or log is committed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run376-public-devnet-identity-registration}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
SEED_SCHEMA="${REPO_ROOT}/docs/release/public-devnet/network/devnet-seed-list.schema.json"
SEED_PLACEHOLDER="${REPO_ROOT}/docs/release/public-devnet/network/devnet-seeds.placeholder.json"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run376] %s\n' "$*"; }
fail() { printf '[run376] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

cleanup() { rm -rf "${OUTDIR}/material" 2>/dev/null || true; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build the release node binary (which carries the `identity` command).
# ---------------------------------------------------------------------------
log "building qbind-node (release)…"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "qbind-node release build failed"
[ -x "${NODE_BIN}" ] || fail "release binary missing: ${NODE_BIN}"

# 11/12/13. Provenance: binary sha256, BuildID, toolchain.
emit "release_binary=OK sha256=$(sha256_file "${NODE_BIN}")"
BUILD_ID="$(file "${NODE_BIN}" 2>/dev/null | grep -oE 'BuildID\[[a-z0-9]+\]=[0-9a-f]+' | sed 's/.*=//' || true)"
emit "build_id=${BUILD_ID:-unavailable}"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

MATERIAL="${OUTDIR}/material"
rm -rf "${MATERIAL}"
mkdir -p "${MATERIAL}"

# ---------------------------------------------------------------------------
# 2. Generate identity material for each role.
# ---------------------------------------------------------------------------
for ROLE in full-node seed validator-candidate; do
  DIR="${MATERIAL}/${ROLE}"
  EXTRA=""
  [ "${ROLE}" = "validator-candidate" ] && EXTRA="0"
  log "identity generate role=${ROLE}"
  "${NODE_BIN}" identity generate devnet "${ROLE}" "${DIR}" ${EXTRA} \
    > "${DIR}.public.json" 2> "${DIR}.err" \
    || fail "identity generate ${ROLE} failed"
  # 10. Private KEM secret key present, 0600. Root signing key not on disk.
  [ -f "${DIR}/leaf.kem.sk.bin" ] || fail "${ROLE}: missing leaf.kem.sk.bin"
  PERM="$(stat -c '%a' "${DIR}/leaf.kem.sk.bin")"
  [ "${PERM}" = "600" ] || fail "${ROLE}: leaf.kem.sk.bin perms=${PERM} (want 600)"
  for F in root.sk root.sk.hex root.sk.bin root.key; do
    [ -e "${DIR}/${F}" ] && fail "${ROLE}: root signing key written to disk (${F})"
  done
done
emit "generate_all_roles=OK (kem_sk 0600; no root signing key on disk)"

# ---------------------------------------------------------------------------
# 3. seed-candidate emits a planned candidate.
# ---------------------------------------------------------------------------
"${NODE_BIN}" identity seed-candidate "${MATERIAL}/seed" > "${MATERIAL}/seed.candidate.json" \
  || fail "identity seed-candidate failed"
emit "seed_candidate=OK (status=planned; no reachability claim)"

# ---------------------------------------------------------------------------
# 4. register-check ACCEPTS the planned candidate for each role.
# ---------------------------------------------------------------------------
for ROLE in full-node seed validator-candidate; do
  "${NODE_BIN}" identity register-check "${MATERIAL}/${ROLE}.public.json" \
    --seed-list "${SEED_PLACEHOLDER}" --role "${ROLE}" \
    --cert "${MATERIAL}/${ROLE}/leaf.cert.bin" \
    > "${MATERIAL}/${ROLE}.registercheck.json" 2>"${MATERIAL}/${ROLE}.registercheck.err" \
    || fail "register-check ${ROLE} did not accept a valid planned candidate"
  python3 - "${MATERIAL}/${ROLE}.registercheck.json" <<'PY' || fail "register-check verdict invalid"
import json, sys
v = json.load(open(sys.argv[1]))
assert v["admissible"] is True, v
assert v["candidate_status"] == "planned", v
assert v["cert_verified"] is True, v
assert v["socket_opened"] is False, v
assert v["runtime_state_mutated"] is False, v
assert v["live_reachability_claim"] is False, v
assert v["m4_green_claim"] is False, v
assert v["c4_c5_closure_claim"] is False, v
print("register_check_ok", sys.argv[1])
PY
done
emit "register_check_accept=OK (full-node, seed, validator-candidate; cert-verified; planned; no live/M4/C4/C5 claim)"

# ---------------------------------------------------------------------------
# 5. The register-check candidate validates against the seed-list schema when
#    inserted into the placeholder seed list (status=planned, no reachability).
# ---------------------------------------------------------------------------
python3 - "${SEED_SCHEMA}" "${SEED_PLACEHOLDER}" "${MATERIAL}/seed.registercheck.json" <<'PY' || fail "seed-list schema validation failed"
import json, sys, jsonschema
schema = json.load(open(sys.argv[1]))
base = json.load(open(sys.argv[2]))
cand = json.load(open(sys.argv[3]))["candidate"]
doc = json.loads(json.dumps(base))
doc["seed_nodes"] = doc["seed_nodes"] + [cand]
jsonschema.validate(instance=doc, schema=schema)
assert cand["status"] == "planned" and cand["last_reachability_evidence"] is None
print("seed_list_insertion_ok")
PY
emit "seed_list_schema_validation=OK (candidate inserted; status=planned, no reachability)"

# ---------------------------------------------------------------------------
# 6. `--status live` WITHOUT reachability evidence fails closed.
# ---------------------------------------------------------------------------
if "${NODE_BIN}" identity register-check "${MATERIAL}/full-node.public.json" \
    --seed-list "${SEED_PLACEHOLDER}" --status live >/dev/null 2>&1; then
  fail "status=live without reachability evidence was NOT refused"
fi
emit "live_without_reachability=REFUSED (fail closed; no live/M4 claim)"

# planned WITH reachability evidence also fails closed (schema forbids it).
if "${NODE_BIN}" identity register-check "${MATERIAL}/full-node.public.json" \
    --seed-list "${SEED_PLACEHOLDER}" --status planned \
    --reachability-evidence "docs/evidence.md" >/dev/null 2>&1; then
  fail "planned WITH reachability evidence was NOT refused"
fi
emit "planned_with_reachability=REFUSED (fail closed; schema forbids reachability on non-live)"

# ---------------------------------------------------------------------------
# 7. Embedded private material in the public JSON fails closed.
# ---------------------------------------------------------------------------
python3 - "${MATERIAL}/full-node.public.json" "${MATERIAL}/tampered-secret.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["leaf_kem_secret_key"] = "deadbeefdeadbeefdeadbeefdeadbeef"
json.dump(d, open(sys.argv[2], "w"))
PY
if "${NODE_BIN}" identity register-check "${MATERIAL}/tampered-secret.json" \
    --seed-list "${SEED_PLACEHOLDER}" >/dev/null 2>&1; then
  fail "embedded private material was NOT refused"
fi
rm -f "${MATERIAL}/tampered-secret.json"
emit "embedded_private_material=REFUSED (fail closed)"

# ---------------------------------------------------------------------------
# 8. Mismatched cert / identity fails closed.
# ---------------------------------------------------------------------------
if "${NODE_BIN}" identity register-check "${MATERIAL}/full-node.public.json" \
    --seed-list "${SEED_PLACEHOLDER}" \
    --cert "${MATERIAL}/seed/leaf.cert.bin" >/dev/null 2>&1; then
  fail "mismatched cert/identity was NOT refused"
fi
emit "mismatched_cert=REFUSED (fail closed; deterministic NodeId re-derivation)"

# ---------------------------------------------------------------------------
# 9. MainNet / TestNet identity material is REFUSED.
# ---------------------------------------------------------------------------
for ENV in mainnet testnet; do
  python3 - "${MATERIAL}/full-node.public.json" "${MATERIAL}/${ENV}.json" "${ENV}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["environment"] = sys.argv[3]
json.dump(d, open(sys.argv[2], "w"))
PY
  if "${NODE_BIN}" identity register-check "${MATERIAL}/${ENV}.json" \
      --seed-list "${SEED_PLACEHOLDER}" >/dev/null 2>&1; then
    fail "${ENV} identity material was NOT refused"
  fi
  rm -f "${MATERIAL}/${ENV}.json"
done
emit "mainnet_testnet_material=REFUSED (fail closed; DevNet-only)"

# ---------------------------------------------------------------------------
# 10. No private material committed (temp material dir only, removed on exit).
# ---------------------------------------------------------------------------
emit "committed_private_material=NONE (material dir is temporary; removed on exit)"

emit ""
emit "RESULT=PASS (non-mutating identity register-check admission verifier proven; DevNet-only; no live deployment; no M4 Green; C4/C5 OPEN)"
log "summary written to ${SUMMARY}"