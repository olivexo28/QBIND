#!/usr/bin/env bash
# Run 388: public DevNet M4 EXTERNAL seed/bootnode reachability execution harness.
#
# This harness produces the Run 388 acceptance evidence for M4 external
# seed/bootnode reachability (see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_388.md`).
# It drives the RELEASE `target/release/qbind-node` binary directly and records an
# HONEST, BOUNDED verdict about whether M4 can move Yellow -> Green via Route A
# (real external reachability from an independent off-host vantage point).
#
# DECISION GATE = Route C (no safe external seed infrastructure available). The
# primary objective is Route A: stand up or validate a real externally reachable
# seed and prove reachability from an INDEPENDENT OFF-HOST vantage point. In this
# sandboxed CI environment there is NO external ingress and NO independent off-host
# vantage point, so a real endpoint CANNOT be exposed and external reachability
# CANNOT be proven. Per Route C the harness does NOT expose a real endpoint, does
# NOT invent an off-host vantage point, and does NOT mark any committed seed entry
# `status: live`. M4 stays YELLOW; the infrastructure prerequisites for Route A
# are documented in the reachability evidence record. This is unchanged from the
# Run 378 finding (Run 386/387 preflight posture is likewise unchanged).
#
# What it still proves (continuity with Run 377/378):
#   1. `cargo build -p qbind-node --release --bin qbind-node`;
#   2. `qbind-node identity generate devnet seed ...` produces real PUBLIC
#      node_id / peer_id via the Run 375 identity path (KEM secret key 0600 in a
#      TEMP dir; root signing key never on disk);
#   3. `register-check --status live --reachability-evidence <ref>` ACCEPTS the
#      candidate (the live admission gate works) ...
#   4. ... and `--status live` WITHOUT `--reachability-evidence` fails closed;
#   5. `--status planned --reachability-evidence <ref>` fails closed (schema
#      forbids reachability on non-live);
#   6. LOOPBACK PREFLIGHT: a real release `qbind-node` P2P listener is booted on
#      127.0.0.1:<port> (`--network-mode p2p --enable-p2p`); a same-host TCP dial
#      succeeds and the node logs `Accepted connection`. Route type = LOOPBACK /
#      SAME-HOST. EXTERNAL reachability = NOT PROVEN;
#   7. the committed live-candidate document validates against
#      `devnet-seed-list.schema.json` (its single entry is `status: planned` with
#      `last_reachability_evidence: null` — an honest preflight, NOT a live claim);
#   8. release binary SHA-256, BuildID, and toolchain are captured.
#
# Run 388 opens NO externally reachable port, deploys NO seed/bootnode/faucet/RPC/
# explorer/status page, changes NO wire format, weakens NO peer admission (the
# `identity` command is read-only; the loopback listener uses the pre-existing
# default posture), and mutates NO trust/validator/epoch/sequence/marker/
# LivePqcTrustState. All addresses are loopback (127.0.0.1) or RFC 5737
# documentation-example values. Temporary data dirs and identity material are
# removed on exit; no private key, root signing key, KEM secret key, data dir, or
# log is committed.

set -euo pipefail

OUTDIR="${1:-/tmp/qbind-run388-public-devnet-m4-external-seed-reachability}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_BIN="${REPO_ROOT}/target/release/qbind-node"
SEED_SCHEMA="${REPO_ROOT}/docs/release/public-devnet/network/devnet-seed-list.schema.json"
LIVE_CANDIDATE="${REPO_ROOT}/docs/release/public-devnet/network/devnet-seeds.live-candidate.json"
REACH_REF="docs/release/public-devnet/network/reachability/RUN_388_qbind-devnet-seed-1.md"
SUMMARY="${OUTDIR}/summary.txt"

log()  { printf '[run388] %s\n' "$*"; }
fail() { printf '[run388] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
free_port() { python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()"; }

mkdir -p "${OUTDIR}"
: > "${SUMMARY}"
emit() { printf '%s\n' "$*" | tee -a "${SUMMARY}"; }

MATERIAL="${OUTDIR}/material"
NODE_DATA="${OUTDIR}/node-data"
NODE_PID=""
cleanup() {
  [ -n "${NODE_PID}" ] && kill "${NODE_PID}" 2>/dev/null || true
  rm -rf "${MATERIAL}" "${NODE_DATA}" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build the release node binary (which carries the `identity` command).
# ---------------------------------------------------------------------------
log "building qbind-node (release)…"
( cd "${REPO_ROOT}" && cargo build -p qbind-node --release --bin qbind-node ) \
  || fail "qbind-node release build failed"
[ -x "${NODE_BIN}" ] || fail "release binary missing: ${NODE_BIN}"

emit "release_binary=OK sha256=$(sha256_file "${NODE_BIN}")"
BUILD_ID="$(file "${NODE_BIN}" 2>/dev/null | grep -oE 'BuildID\[[a-z0-9]+\]=[0-9a-f]+' | sed 's/.*=//' || true)"
emit "build_id=${BUILD_ID:-unavailable}"
emit "toolchain=$(rustc --version 2>/dev/null || echo unknown) / $(cargo --version 2>/dev/null || echo unknown)"

rm -rf "${MATERIAL}"; mkdir -p "${MATERIAL}/seed"

# ---------------------------------------------------------------------------
# 2. Generate real seed identity material (Run 375 path).
# ---------------------------------------------------------------------------
log "identity generate devnet seed…"
"${NODE_BIN}" identity generate devnet seed "${MATERIAL}/seed" \
  > "${MATERIAL}/seed.public.json" 2> "${MATERIAL}/seed.err" \
  || fail "identity generate seed failed"
[ -f "${MATERIAL}/seed/leaf.kem.sk.bin" ] || fail "missing leaf.kem.sk.bin"
PERM="$(stat -c '%a' "${MATERIAL}/seed/leaf.kem.sk.bin")"
[ "${PERM}" = "600" ] || fail "leaf.kem.sk.bin perms=${PERM} (want 600)"
for F in root.sk root.sk.hex root.sk.bin root.key; do
  [ -e "${MATERIAL}/seed/${F}" ] && fail "root signing key written to disk (${F})"
done
NODE_ID="$(python3 -c "import json;print(json.load(open('${MATERIAL}/seed/public-identity.json'))['node_id'])")"
emit "identity_generate_seed=OK node_id=${NODE_ID} (kem_sk 0600; no root signing key on disk)"

PUB="${MATERIAL}/seed/public-identity.json"
CERT="${MATERIAL}/seed/leaf.cert.bin"

# ---------------------------------------------------------------------------
# 3. register-check --status live --reachability-evidence <ref> ACCEPTS
#    (referencing the Run 388 evidence record).
# ---------------------------------------------------------------------------
"${NODE_BIN}" identity register-check "${PUB}" \
  --seed-list "${LIVE_CANDIDATE}" --role seed --cert "${CERT}" \
  --status live --reachability-evidence "${REACH_REF}" \
  > "${MATERIAL}/live_accept.json" 2> "${MATERIAL}/live_accept.err" \
  || fail "register-check --status live --reachability-evidence did NOT accept"
python3 - "${MATERIAL}/live_accept.json" <<'PY' || fail "live-accept verdict invalid"
import json, sys
v = json.load(open(sys.argv[1]))
assert v["admissible"] is True, v
assert v["candidate_status"] == "live", v
assert v["cert_verified"] is True, v
# The command itself makes NO live/M4 claim even when admitting a live candidate.
assert v["socket_opened"] is False, v
assert v["runtime_state_mutated"] is False, v
assert v["live_reachability_claim"] is False, v
assert v["m4_green_claim"] is False, v
assert v["c4_c5_closure_claim"] is False, v
print("live_accept_ok")
PY
emit "register_check_live_accept=OK (cert-verified; status=live admitted WITH reachability ref; command makes no live/M4/C4/C5 claim)"

# ---------------------------------------------------------------------------
# 4. --status live WITHOUT reachability evidence fails closed.
# ---------------------------------------------------------------------------
if "${NODE_BIN}" identity register-check "${PUB}" \
    --seed-list "${LIVE_CANDIDATE}" --role seed --cert "${CERT}" \
    --status live >/dev/null 2>&1; then
  fail "status=live without reachability evidence was NOT refused"
fi
emit "live_without_reachability=REFUSED (fail closed; no live/M4 claim)"

# ---------------------------------------------------------------------------
# 5. --status planned WITH reachability evidence fails closed.
# ---------------------------------------------------------------------------
if "${NODE_BIN}" identity register-check "${PUB}" \
    --seed-list "${LIVE_CANDIDATE}" --role seed --cert "${CERT}" \
    --status planned --reachability-evidence "${REACH_REF}" >/dev/null 2>&1; then
  fail "planned WITH reachability evidence was NOT refused"
fi
emit "planned_with_reachability=REFUSED (fail closed; schema forbids reachability on non-live)"

# ---------------------------------------------------------------------------
# 6. LOOPBACK PREFLIGHT (continuity): boot a real release P2P listener; same-host
#    TCP dial. This is NOT the external step — external reachability is NOT
#    proven and is NOT attempted (no external ingress / vantage point here).
# ---------------------------------------------------------------------------
rm -rf "${NODE_DATA}"; mkdir -p "${NODE_DATA}"
P2P_PORT="$(free_port)"
log "booting loopback P2P listener on 127.0.0.1:${P2P_PORT}…"
"${NODE_BIN}" --network-mode p2p --enable-p2p \
  --p2p-listen-addr "127.0.0.1:${P2P_PORT}" \
  --validator-id 0 --data-dir "${NODE_DATA}" \
  > "${MATERIAL}/node.log" 2>&1 &
NODE_PID=$!
sleep 8
kill -0 "${NODE_PID}" 2>/dev/null || { tail -20 "${MATERIAL}/node.log" >&2; fail "loopback node died"; }

DIAL_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "${P2P_PORT}" <<'PY' || fail "loopback TCP dial failed"
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
peer = s.getpeername(); local = s.getsockname()
s.close()
assert peer[0] == "127.0.0.1", peer
print(f"loopback_tcp_dial_ok peer={peer} local={local}")
PY
sleep 1
grep -q "Accepted connection" "${MATERIAL}/node.log" \
  || fail "node did not log an accepted inbound connection"
kill "${NODE_PID}" 2>/dev/null || true; NODE_PID=""
emit "loopback_preflight=OK ts=${DIAL_TS} target=127.0.0.1:${P2P_PORT} route=loopback/same-host tcp_dial=accepted"
emit "external_reachability=NOT_PROVEN (Route C: no external ingress / no independent off-host vantage point in this environment; M4 stays Yellow)"

# ---------------------------------------------------------------------------
# 7. Committed live-candidate document validates against the seed-list schema.
#    Its single entry is status=planned with null reachability (honest preflight,
#    NOT a live claim — external reachability was not proven).
# ---------------------------------------------------------------------------
python3 - "${SEED_SCHEMA}" "${LIVE_CANDIDATE}" <<'PY' || fail "live-candidate schema validation failed"
import json, sys, jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
jsonschema.validate(instance=doc, schema=schema)
for n in doc["seed_nodes"]:
    assert n["status"] != "live", "committed entry must NOT be live (external reachability unproven)"
    if n["status"] in ("placeholder", "planned", "retired"):
        assert n["last_reachability_evidence"] is None, "non-live entry carries reachability evidence"
print("live_candidate_schema_ok")
PY
emit "live_candidate_schema_validation=OK (validates; single entry status=planned, no false live claim)"

# ---------------------------------------------------------------------------
# 8. No private material committed (temp material/data dirs removed on exit).
# ---------------------------------------------------------------------------
emit "committed_private_material=NONE (material/node-data dirs are temporary; removed on exit)"

emit ""
emit "RESULT=NEGATIVE-FOR-EXTERNAL (Route C: no safe external seed infrastructure available; live admission gate proven + loopback preflight only; external reachability NOT proven; M4 stays Yellow; C4/C5 OPEN)"
log "summary written to ${SUMMARY}"