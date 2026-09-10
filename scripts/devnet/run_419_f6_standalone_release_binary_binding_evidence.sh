#!/usr/bin/env bash
# =============================================================================
# Run 419 — F6 standalone release-binary consensus-binding runtime evidence
# =============================================================================
# Route A (evidence-only): this harness exercises the ALREADY-DEPLOYED Run 418
# authenticated-peer -> consensus-sender binding gate on the standalone
# `target/release/qbind-node` binary. It makes NO production behavior change.
#
# It launches real standalone release receivers on loopback, drives real
# KEMTLS/static-root sessions from the Run 419 driver helper (a Cargo example),
# submits crafted consensus frames with controlled claimed-senders, and records
# the live `qbind_consensus_binding_total{result=...}` /metrics deltas plus
# curated socket / handshake / rejection evidence.
#
# Scope guards (must all hold):
#   * loopback (127.0.0.1) endpoints only;
#   * DevNet env only;
#   * standalone release binary as the system-under-test receiver;
#   * no production source change; helper + harness + curated docs only.
#
# This is automated LOCAL cross-process operational evidence. It is NOT
# independent off-host attestation and does NOT prove external reachability.
# RS1 stays OPEN, C4/C5 stay OPEN, public DevNet stays NO-GO regardless.
#
# Usage:
#   scripts/devnet/run_419_f6_standalone_release_binary_binding_evidence.sh \
#       [EVIDENCE_DIR] [WORKDIR]
#
#   EVIDENCE_DIR  curated publish-safe output dir
#                 (default: docs/devnet/run_419_f6_standalone_release_binary_binding_evidence)
#   WORKDIR       temporary material/data/log dir (default: mktemp; always removed)
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

EVID_DIR="${1:-docs/devnet/run_419_f6_standalone_release_binary_binding_evidence}"
WORKDIR="${2:-$(mktemp -d /tmp/run419.XXXXXX)}"
mkdir -p "${EVID_DIR}" "${WORKDIR}"

NODE_BIN="target/release/qbind-node"
HELPER_NAME="run_419_f6_release_binary_binding_driver"
HELPER_BIN="target/release/examples/${HELPER_NAME}"

log()  { printf '[run419] %s\n' "$*"; }
fail() { printf '[run419] FAIL: %s\n' "$*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
build_id() { readelf -n "$1" 2>/dev/null | awk '/Build ID/ {print $3; exit}'; }
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0))
print(s.getsockname()[1]); s.close()
PY
}

# Scrape one binding-total label value; prints 0 if absent.
scrape_binding() {
  local mport="$1" result="$2"
  curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | awk -v r="qbind_consensus_binding_total{result=\"${result}\"}" \
        '$1==r {print $2; found=1} END{ if(!found) print 0 }'
}

# Dump every binding label line for curated before/after capture.
scrape_binding_block() {
  local mport="$1"
  curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | grep -E '^qbind_consensus_binding_total\{' || true
}

# Curated set of downstream delivered/accepted/mutation counters. Proves that a
# rejected frame does NOT advance delivery/engine-acceptance/commit state.
RELEVANT_METRICS='qbind_consensus_inbound_new_views_delivered_total qbind_consensus_inbound_new_views_engine_accepted_total qbind_consensus_inbound_timeouts_delivered_total qbind_consensus_proposals_total qbind_consensus_committed_height'
scrape_relevant_block() {
  local mport="$1" body name
  body="$(curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null || true)"
  for name in ${RELEVANT_METRICS}; do
    printf '%s\n' "${body}" | awk -v n="${name}" '$1==n {print $1" "$2; f=1} END{if(!f)print n" 0"}'
  done
}

# Sum of all binding-total counters (settle detector).
scrape_binding_sum() {
  local mport="$1"
  curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | awk '/^qbind_consensus_binding_total\{/ {s+=$2} END{print s+0}'
}

# Wait until binding counters register the driven frames and then stabilize.
# Polls up to ~12s. Breaks early only AFTER the counter sum has risen above its
# initial value and then held steady for 2 reads. If nothing ever moves (e.g.
# unauthenticated ingress that never establishes a session) it waits the full
# window so a genuine no-op is recorded honestly.
settle_binding() {
  local mport="$1" base prev cur stable=0 moved=0 i
  base="$(scrape_binding_sum "${mport}")"
  prev="${base}"
  for i in $(seq 1 24); do
    sleep 0.5
    cur="$(scrape_binding_sum "${mport}")"
    [ "${cur}" -gt "${base}" ] && moved=1
    if [ "${cur}" = "${prev}" ]; then
      stable=$(( stable + 1 ))
      [ "${moved}" = 1 ] && [ "${stable}" -ge 2 ] && break
    else
      stable=0
    fi
    prev="${cur}"
  done
}

# ---------------------------------------------------------------------------
# 0. Toolchain + build (release binary, Run 419 helper). PQC material is minted
#    in-memory by the helper's gen-material subcommand (no external PQC helper
#    binary is required for Run 419).
# ---------------------------------------------------------------------------
RUSTC_V="$(rustc --version)"
CARGO_V="$(cargo --version)"
log "rustc: ${RUSTC_V}"
log "cargo: ${CARGO_V}"

log "building release binary + helper ..."
cargo build --release -p qbind-node --bin qbind-node >/dev/null 2>&1 \
  || fail "release binary build failed"
cargo build --release -p qbind-node --example "${HELPER_NAME}" >/dev/null 2>&1 \
  || fail "helper build failed"

[ -x "${NODE_BIN}" ]   || fail "missing ${NODE_BIN}"
[ -x "${HELPER_BIN}" ] || fail "missing ${HELPER_BIN}"

RUNTIME_COMMIT="$(git rev-parse HEAD)"
NODE_SHA="$(sha256_file "${NODE_BIN}")"
NODE_BID="$(build_id "${NODE_BIN}")"
HELPER_SHA="$(sha256_file "${HELPER_BIN}")"
HELPER_BID="$(build_id "${HELPER_BIN}")"

# --help must not expose any Run 419 / forged-message production flag.
HELP_OUT="$("${NODE_BIN}" --help 2>&1 || true)"
if printf '%s' "${HELP_OUT}" | grep -Eiq 'run.?419|forge|forged|claimed.sender|spoof'; then
  fail "qbind-node --help unexpectedly exposes a Run 419 / forged-message flag"
fi
HELP_CLEAN="yes (no Run 419 / forged-message flag)"

# ---------------------------------------------------------------------------
# 1. PQC material (temporary; minted by the helper, never committed).
# ---------------------------------------------------------------------------
MAT="${WORKDIR}/material"
rm -rf "${MAT}"; mkdir -p "${MAT}"
"${HELPER_BIN}" gen-material "${MAT}" >/dev/null 2>&1 || fail "gen-material failed"
TRUSTED_ROOT="$(cat "${MAT}/trusted-root.spec")"

# ---------------------------------------------------------------------------
# 2. Topology (loopback only). 3 validators:
#      validator 0 = victim (impersonated), validator 1 = driver (authenticated),
#      validator 2 = standalone release receiver (system-under-test).
# ---------------------------------------------------------------------------
TOPOLOGY="3 validators on 127.0.0.1: v0=victim(impersonated) v1=driver(authenticated client) v2=standalone release receiver(server, system-under-test)"

RAW_LOG_DIR="${WORKDIR}/logs"; mkdir -p "${RAW_LOG_DIR}"
SOCKET_LOG="${WORKDIR}/socket_lines.txt";  : > "${SOCKET_LOG}"
HANDSHAKE_LOG="${WORKDIR}/handshake_lines.txt"; : > "${HANDSHAKE_LOG}"
METRICS_BA="${WORKDIR}/metrics_before_after.txt"; : > "${METRICS_BA}"
SCEN_MATRIX="${WORKDIR}/scenario_matrix.txt"; : > "${SCEN_MATRIX}"

# launch a fresh standalone receiver in $MODE; echoes "RP MP DEAD0 DLISTEN LOGFILE"
launch_receiver() {
  local scen="$1" mode="$2"
  local rp mp dead0 dlisten logf datadir
  rp="$(free_port)"; mp="$(free_port)"; dead0="$(free_port)"; dlisten="$(free_port)"
  datadir="${WORKDIR}/recv_${scen}"; rm -rf "${datadir}"; mkdir -p "${datadir}"
  logf="${RAW_LOG_DIR}/recv_${scen}.log"
  QBIND_METRICS_HTTP_ADDR="127.0.0.1:${mp}" timeout 60 "${NODE_BIN}" \
    --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr "127.0.0.1:${rp}" --validator-id 2 --data-dir "${datadir}" \
    --p2p-mutual-auth "${mode}" --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root "${TRUSTED_ROOT}" \
    --p2p-leaf-cert "${MAT}/v2.cert.bin" --p2p-leaf-cert-key "${MAT}/v2.kem.sk.bin" \
    --p2p-peer "0@127.0.0.1:${dead0}"   --p2p-peer-leaf-cert "0:${MAT}/v0.cert.bin" \
    --p2p-peer "1@127.0.0.1:${dlisten}" --p2p-peer-leaf-cert "1:${MAT}/v1.cert.bin" \
    > "${logf}" 2>&1 &
  echo "${rp} ${mp} ${dead0} ${dlisten} ${logf}"
}

# capture curated ss + handshake log lines for a scenario
capture_socket_and_logs() {
  local scen="$1" rp="$2" logf="$3"
  {
    echo "# ${scen}: ss --tcp (loopback, receiver listen :${rp})"
    ss --tcp --numeric 2>/dev/null | awk -v p=":${rp}" 'NR==1 || index($0,p)>0' \
      | sed -E 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/127.0.0.1/g' | head -8
    echo
  } >> "${SOCKET_LOG}"
  {
    echo "# ${scen}: KEMTLS / static-root / mutual-auth log lines"
    grep -Ei 'kemtls|static.root|mutual.auth|handshake|verified|leaf|binding|origin' "${logf}" 2>/dev/null \
      | grep -Eiv 'secret|private|0x[0-9a-f]{32,}' \
      | sed -E -e "s#${WORKDIR}#<TMP>#g" -e 's#/tmp/run419\.[A-Za-z0-9]+#<TMP>#g' \
               -e 's#/(home|root|tmp)/[^ ]*#<PATH>#g' \
      | head -12
    echo
  } >> "${HANDSHAKE_LOG}"
}

# run one scenario; args: scen mode expect_label expect_delta description
run_scenario() {
  local scen="$1" mode="$2" label="$3" want="$4" desc="$5"
  local rp mp dead0 dlisten logf
  read rp mp dead0 dlisten logf < <(launch_receiver "${scen}" "${mode}")
  # wait for /metrics
  local up=0 i
  for i in $(seq 1 30); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${mp}/metrics" >/dev/null 2>&1; then up=1; break; fi
    sleep 0.5
  done
  [ "${up}" = 1 ] || { log "${scen}: receiver /metrics did not come up"; }
  # Let the P2P listener finish binding + consensus-storage init before dialing,
  # so the driver's inbound KEMTLS session establishes cleanly (avoids a startup
  # race that can EOF the inbound handshake before frame delivery).
  sleep 3

  local before after t_start t_end drv_rc
  before="$(scrape_binding "${mp}" "${label}")"
  {
    echo "===== ${scen} (mode=${mode}) ====="
    echo "-- before (binding gate) --"; scrape_binding_block "${mp}"
    echo "-- before (downstream delivered/accepted/commit) --"; scrape_relevant_block "${mp}"
  } >> "${METRICS_BA}"

  t_start="$(now_utc)"
  set +e
  "${HELPER_BIN}" drive "${scen}" "${MAT}" "127.0.0.1:${rp}" "127.0.0.1:${dlisten}" \
    "${WORKDIR}/${scen}.out" > "${RAW_LOG_DIR}/drv_${scen}.log" 2>&1
  drv_rc=$?
  set -e
  t_end="$(now_utc)"
  settle_binding "${mp}"
  after="$(scrape_binding "${mp}" "${label}")"
  {
    echo "-- after (binding gate) --"; scrape_binding_block "${mp}"
    echo "-- after (downstream delivered/accepted/commit) --"; scrape_relevant_block "${mp}"
    echo "delta(${label}) = $(( after - before ))  driver_rc=${drv_rc}  window=${t_start}..${t_end}"
    echo
  } >> "${METRICS_BA}"

  capture_socket_and_logs "${scen}" "${rp}" "${logf}"

  local delta=$(( after - before ))
  local connected result
  connected="$(awk -F': ' '/^connected:/{print $2}' "${WORKDIR}/${scen}.out" 2>/dev/null)"
  if [ "${want}" = "PARTIAL" ]; then
    result="PARTIAL"
  elif [ "${delta}" = "${want}" ]; then
    result="PASS"
  else
    result="FAIL"
  fi
  printf '%-20s mode=%-8s label=%-24s expect_delta=%-7s observed=%-4s connected=%-6s rc=%-3s => %s\n' \
    "${scen}" "${mode}" "${label}" "${want}" "${delta}" "${connected:-n/a}" "${drv_rc}" "${result}" \
    | tee -a "${SCEN_MATRIX}" >&2
  echo "${result}"
}

log "=== running scenarios ==="
R_S1="$(run_scenario s1-honest         required accepted                1        'honest authenticated proposal admitted')"
R_S2="$(run_scenario s2-impersonation  required claimed_sender_mismatch  5        'impersonation of validator 0 across 5 message classes rejected')"
R_S3="$(run_scenario s3-newview        required accepted                1        'NewView origin admission for authenticated sender')"
R_S6="$(run_scenario s6-alt-leaf       required missing_origin          1        'root-valid unconfigured alternate leaf suppressed pre-gate')"
R_S4="$(run_scenario s4-optional-unauth optional accepted               PARTIAL  'unauthenticated ingress under Optional (fail-closed / not establishable)')"
R_S5="$(run_scenario s5-disabled-unauth disabled accepted               PARTIAL  'unauthenticated ingress under Disabled (fail-closed / not establishable)')"

# S7 outbound actual-server identity check is recorded PARTIAL. A dedicated S7
# vector (a listener presenting validator-0's KEM pk under a different signed
# validator-id) is not driven here. However, the standalone receiver's OWN
# outbound dialer DID exercise the Run 418 verified-server-identity comparison
# incidentally during S6: it refused the driver's root-valid alternate leaf with
# `verified server identity ... node_match=false ... rejecting session` (see
# socket_log_extract.txt). That confirms the outbound check is live on the
# release binary, but is not the full typed-vector S7 proof.
R_S7="PARTIAL"
printf '%-20s mode=%-8s label=%-24s expect_delta=%-7s observed=%-4s connected=%-6s rc=%-3s => %s\n' \
  "s7-outbound" "outbound" "verified_server_identity" "n/a" "n/a" "n/a" "n/a" "PARTIAL (outbound check observed incidentally in S6; dedicated vector not run)" \
  | tee -a "${SCEN_MATRIX}" >&2

# ---------------------------------------------------------------------------
# 3. Verdict
# ---------------------------------------------------------------------------
CORE_OK=1
for r in "${R_S1}" "${R_S2}" "${R_S3}" "${R_S6}"; do
  [ "${r}" = "PASS" ] || CORE_OK=0
done
ALL_OK=1
for r in "${R_S1}" "${R_S2}" "${R_S3}" "${R_S6}" "${R_S4}" "${R_S5}" "${R_S7}"; do
  [ "${r}" = "PASS" ] || ALL_OK=0
done

if [ "${ALL_OK}" = 1 ]; then
  RESULT="POSITIVE-FOR-F6-STANDALONE-RELEASE-BINARY-EVIDENCE"
  F6_STATUS="REMEDIATED-FOR-TESTED-RELEASE-BINARY-PATH"
elif [ "${CORE_OK}" = 1 ]; then
  RESULT="PARTIAL-FOR-F6-STANDALONE-RELEASE-BINARY-EVIDENCE"
  F6_STATUS="CODE-TEST-PLUS-PARTIAL-RUNTIME-EVIDENCE"
else
  RESULT="NEGATIVE-FOR-F6-STANDALONE-RELEASE-BINARY-EVIDENCE"
  F6_STATUS="CODE-TEST-ONLY"
fi
SECURITY_POSTURE="RS1-OPEN / PUBLIC-DEVNET-NO-GO"

# ---------------------------------------------------------------------------
# 4. Emit curated publish-safe deliverables into EVID_DIR
# ---------------------------------------------------------------------------
END_UTC="$(now_utc)"

cp "${METRICS_BA}"  "${EVID_DIR}/metrics_before_after.txt"
cp "${SOCKET_LOG}"  "${EVID_DIR}/socket_log_extract.txt"
# append handshake extract into socket_log_extract (curated, bounded)
{
  echo
  echo "================= KEMTLS / static-root / mutual-auth log lines ================="
  cat "${HANDSHAKE_LOG}"
} >> "${EVID_DIR}/socket_log_extract.txt"
cp "${SCEN_MATRIX}" "${EVID_DIR}/scenario_matrix.txt"

cat > "${EVID_DIR}/binary_identity.txt" <<EOF
Run 419 — binary identity (curated, publish-safe)

runtime_commit:      ${RUNTIME_COMMIT}
capture_end_utc:     ${END_UTC}

rustc:               ${RUSTC_V}
cargo:               ${CARGO_V}

target/release/qbind-node
  sha256:            ${NODE_SHA}
  elf_build_id:      ${NODE_BID}

Run 419 driver helper (target/release/examples/${HELPER_NAME})
  sha256:            ${HELPER_SHA}
  elf_build_id:      ${HELPER_BID}

PQC material helper: minted in-memory by the Run 419 helper 'gen-material'
                     subcommand (no separate committed PQC helper binary).

Note: SHA256SUMS protects committed curated evidence after capture; it does not
independently authenticate the original machine observations.
EOF

cat > "${EVID_DIR}/summary.txt" <<EOF
Run 419 — F6 standalone release-binary consensus-binding runtime evidence

RESULT=${RESULT}
F6_STATUS=${F6_STATUS}
SECURITY_POSTURE=${SECURITY_POSTURE}

Qualifiers: local loopback; multi-process; Required/static-root plus tested
Optional/Disabled paths; tested message classes only; NOT off-host; NOT durable
public deployment; NOT signature/QC/suite enforcement.

Topology: ${TOPOLOGY}

Scenario results (delta = live qbind_consensus_binding_total{result=...} change):
  S1 honest authenticated proposal      => ${R_S1} (accepted +1)
  S2 impersonation (5 message classes)  => ${R_S2} (claimed_sender_mismatch +5)
  S3 NewView origin admission           => ${R_S3} (accepted +1)
  S6 root-valid unconfigured alt leaf   => ${R_S6} (missing_origin +1)
  S4 unauthenticated ingress (Optional) => ${R_S4}
  S5 unauthenticated ingress (Disabled) => ${R_S5}
  S7 outbound actual-server identity    => ${R_S7} (outbound check observed incidentally in S6; dedicated vector not run)

Toolchain: ${RUSTC_V} / ${CARGO_V}
Runtime commit: ${RUNTIME_COMMIT}
qbind-node --help clean: ${HELP_CLEAN}

Trust model: automated LOCAL cross-process operational evidence; NOT independent
off-host attestation; does NOT prove external reachability. RS1 remains OPEN;
C4/C5 remain OPEN; no M/S item moves Green; public DevNet remains NO-GO.
EOF

cat > "${EVID_DIR}/commands.txt" <<EOF
Run 419 — representative commands (temporary paths normalized to placeholders)

# build
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example ${HELPER_NAME}

# mint temporary PQC material (root/leaf certs + KEM secrets; NEVER committed)
${HELPER_BIN} gen-material <MATERIAL_DIR>

# launch a standalone release receiver (validator 2, system-under-test)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:<MPORT> ${NODE_BIN} \\
  --env devnet --network-mode p2p --enable-p2p \\
  --p2p-listen-addr 127.0.0.1:<RPORT> --validator-id 2 --data-dir <DATA_DIR> \\
  --p2p-mutual-auth <required|optional|disabled> --p2p-pqc-root-mode pqc-static-root \\
  --p2p-trusted-root <TRUSTED_ROOT_SPEC> \\
  --p2p-leaf-cert <MATERIAL_DIR>/v2.cert.bin --p2p-leaf-cert-key <MATERIAL_DIR>/v2.kem.sk.bin \\
  --p2p-peer 0@127.0.0.1:<DEAD0> --p2p-peer-leaf-cert 0:<MATERIAL_DIR>/v0.cert.bin \\
  --p2p-peer 1@127.0.0.1:<DLISTEN> --p2p-peer-leaf-cert 1:<MATERIAL_DIR>/v1.cert.bin

# drive one scenario (real KEMTLS client -> receiver, crafted claimed-senders)
${HELPER_BIN} drive <SCENARIO> <MATERIAL_DIR> 127.0.0.1:<RPORT> 127.0.0.1:<DLISTEN> <OUT_FILE>
#   SCENARIO in: s1-honest s2-impersonation s3-newview s6-alt-leaf
#                s4-optional-unauth s5-disabled-unauth

# observe live binding counters
curl -fsS http://127.0.0.1:<MPORT>/metrics | grep qbind_consensus_binding_total
EOF

# source_trace.txt — static F6 wiring references (publish-safe grep)
cat > "${EVID_DIR}/source_trace.txt" <<EOF
Run 419 — F6 production wiring source trace (unchanged by Run 419)

Run 419 adds NO production source change. The gate below is the Run 418 path,
exercised here on the standalone release binary.

peer_consensus_binding.rs
$(grep -nE 'pub fn (authorize|authorize_origin|validate_pair)\b' crates/qbind-node/src/peer_consensus_binding.rs | sed 's/^/  /')
$(grep -nE 'qbind_consensus_binding_total' crates/qbind-node/src/peer_consensus_binding.rs | head -1 | sed 's/^/  /')

binary_consensus_loop.rs (claimed-sender extraction / origin admission)
$(grep -nE 'authorize_origin|fn handle_inbound_consensus_msg' crates/qbind-node/src/binary_consensus_loop.rs | head -4 | sed 's/^/  /')

p2p_node_builder.rs (gate construction) / main.rs (loop + shared node_metrics)
$(grep -nE 'consensus_binding|with_node_metrics' crates/qbind-node/src/p2p_node_builder.rs | head -3 | sed 's/^/  /')
$(grep -nE 'consensus_binding|with_node_metrics' crates/qbind-node/src/main.rs | head -3 | sed 's/^/  /')
EOF

# test_results.txt is filled by the caller (validation suite); seed a header.
if [ ! -f "${EVID_DIR}/test_results.txt" ]; then
  cat > "${EVID_DIR}/test_results.txt" <<EOF
Run 419 — validation exit codes (populated during the validation suite)
EOF
fi

# README.md
cat > "${EVID_DIR}/README.md" <<EOF
# Run 419 — F6 standalone release-binary consensus-binding runtime evidence

This directory holds **curated, publish-safe** evidence that the Run 418
authenticated-peer → consensus-sender **binding gate (F6)** is live on the
standalone \`target/release/qbind-node\` binary.

* **Route A**: evidence-only. No production behavior change. Run 419 adds a
  Cargo-example driver helper, this harness, and curated docs.
* **Scope**: local loopback, multi-process, DevNet-only, standalone release
  receiver as the system-under-test.
* **Trust model**: automated LOCAL cross-process operational evidence. **Not**
  independent off-host attestation. Does **not** prove external reachability.

## Verdict

See \`summary.txt\`. Core scenarios S1/S2/S3/S6 are exercised through real
KEMTLS sessions against the standalone binary with live
\`qbind_consensus_binding_total{result=...}\` deltas. S4/S5 (unauthenticated
ingress) and S7 (outbound actual-server identity) are partial where the present
transport configuration cannot establish the real socket without production
changes or an unsafe general-purpose helper.

Regardless of outcome: **RS1 remains OPEN**, C4/C5 remain OPEN, no M/S item
moves Green, and **public DevNet remains NO-GO**.

## Files

| File | Contents |
|------|----------|
| \`summary.txt\` | verdict, qualifiers, per-scenario results |
| \`scenario_matrix.txt\` | scenario → expected/observed delta + exit code |
| \`metrics_before_after.txt\` | before/after live binding counters per scenario |
| \`socket_log_extract.txt\` | curated \`ss\` + KEMTLS/static-root/mutual-auth lines |
| \`binary_identity.txt\` | runtime commit, SHA-256, ELF Build IDs, toolchain |
| \`source_trace.txt\` | F6 production wiring references (unchanged by Run 419) |
| \`commands.txt\` | representative commands, temp paths normalized |
| \`test_results.txt\` | validation-suite exit codes |
| \`SHA256SUMS.txt\` | integrity digests for the curated files above |

## Reproduce

\`\`\`
scripts/devnet/run_419_f6_standalone_release_binary_binding_evidence.sh
\`\`\`

Private keys, certificates, raw logs, raw metric dumps and data directories are
temporary and are **never** committed (see \`.gitignore\`).
EOF

# .gitignore — block all sensitive/raw material
cat > "${EVID_DIR}/.gitignore" <<'EOF'
# Run 419: never commit private material, raw logs, raw metrics, or data dirs.
material/
*material*/
*.key
*.sk.bin
*.kem.sk.bin
*.cert.bin
*.id.hex
trusted-root.spec
recv_*/
data/
*data-dir*/
*.rawlog
*raw*.log
logs/
*.pcap
*.bundle
*.tar
*.tar.gz
*.tgz
*.zip
EOF

# ---------------------------------------------------------------------------
# 5. SHA256SUMS over every committed publish-safe file except itself + .gitignore
# ---------------------------------------------------------------------------
( cd "${EVID_DIR}" && \
  find . -maxdepth 1 -type f ! -name 'SHA256SUMS.txt' ! -name '.gitignore' -printf '%P\n' \
  | LC_ALL=C sort | xargs -r sha256sum > SHA256SUMS.txt )

log "=== VERDICT: ${RESULT} (F6_STATUS=${F6_STATUS}) ==="
log "curated evidence in: ${EVID_DIR}"

# ---------------------------------------------------------------------------
# 6. Cleanup temporary material/data/logs (keep only curated EVID_DIR).
# ---------------------------------------------------------------------------
rm -rf "${MAT}" "${RAW_LOG_DIR}" "${WORKDIR}/recv_"* "${WORKDIR}"/*.out 2>/dev/null || true
if [[ "${WORKDIR}" == /tmp/run419.* ]]; then rm -rf "${WORKDIR}" 2>/dev/null || true; fi

# Exit non-zero only on a hard core failure so CI surfaces regressions.
[ "${CORE_OK}" = 1 ] || fail "core F6 scenarios S1/S2/S3/S6 did not all pass"
exit 0
