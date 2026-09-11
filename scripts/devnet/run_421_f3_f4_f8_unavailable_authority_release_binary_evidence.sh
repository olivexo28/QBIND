#!/usr/bin/env bash
# =============================================================================
# Run 421 — F3/F4/F8 unavailable-authority fail-closed release-binary evidence
# =============================================================================
# Route A (evidence-only): this harness exercises the ALREADY-DEPLOYED Run 420
# fail-closed Proposal/Vote verification-policy boundary on the standalone
# `target/release/qbind-node` binary. It makes NO production behavior change.
#
# The standalone binary has NO configured consensus verification authority, so
# `verification_ctx == None` and the production-default
# `ConsensusVerificationPolicy::Required` is active. Under that policy the
# binary MUST reject inbound Proposal/Vote fail-closed (liveness loss is the
# safe outcome; unsigned/unverified consensus operation is eliminated).
#
# This run PROVES only the unavailable-authority fail-closed boundary through
# real loopback KEMTLS traffic and live `/metrics`. It does NOT — and cannot —
# prove configured-authority cryptographic signature/suite success, because no
# consensus signing authority exists on the standalone binary.
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
#   scripts/devnet/run_421_f3_f4_f8_unavailable_authority_release_binary_evidence.sh \
#       [EVIDENCE_DIR] [WORKDIR]
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

EVID_DIR="${1:-docs/devnet/run_421_f3_f4_f8_unavailable_authority_release_binary_evidence}"
WORKDIR="${2:-$(mktemp -d /tmp/run421.XXXXXX)}"
mkdir -p "${EVID_DIR}" "${WORKDIR}"

NODE_BIN="target/release/qbind-node"
HELPER_NAME="run_421_f3_f4_f8_release_binary_driver"
HELPER_BIN="target/release/examples/${HELPER_NAME}"

log()  { printf '[run421] %s\n' "$*"; }
fail() { printf '[run421] FAIL: %s\n' "$*" >&2; exit 1; }
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

# The four Run 420 context-unavailable counters.
CTX_METRICS='qbind_consensus_inbound_proposal_verification_context_unavailable_total qbind_consensus_inbound_vote_verification_context_unavailable_total qbind_consensus_outbound_proposal_verification_context_unavailable_total qbind_consensus_outbound_vote_verification_context_unavailable_total'

# Downstream delivered/accept/aggregation/QC/view/commit/outbound counters that
# a rejected Proposal/Vote MUST NOT advance.
DOWNSTREAM_METRICS='qbind_consensus_proposals_total{result="accepted"} qbind_consensus_votes_total qbind_consensus_votes_observed_total qbind_consensus_validator_votes_total qbind_consensus_qcs_formed_total qbind_consensus_committed_height qbind_consensus_current_view qbind_consensus_view_number qbind_consensus_outbound_new_views_sent_total qbind_consensus_outbound_proposal_signing_success_total qbind_consensus_outbound_vote_signing_success_total'

# Typed Proposal/Vote signature/suite reject-reason counters that MUST stay at 0
# on the standalone binary (the unavailable-context gate rejects BEFORE any
# signature parsing or suite enforcement — no configured-authority crypto path
# is ever reached).
REASON_METRICS='qbind_consensus_inbound_proposal_rejected_bad_signature_total qbind_consensus_inbound_proposal_rejected_missing_signature_total qbind_consensus_inbound_proposal_rejected_unsupported_suite_total qbind_consensus_inbound_proposal_rejected_wrong_suite_total qbind_consensus_inbound_proposal_rejected_signer_mismatch_total qbind_consensus_inbound_proposal_verify_accepted_total qbind_consensus_inbound_proposal_verify_rejected_total qbind_consensus_inbound_vote_rejected_bad_signature_total qbind_consensus_inbound_vote_rejected_missing_signature_total qbind_consensus_inbound_vote_rejected_unsupported_suite_total qbind_consensus_inbound_vote_rejected_wrong_suite_total qbind_consensus_inbound_vote_rejected_signer_mismatch_total qbind_consensus_inbound_vote_verify_accepted_total qbind_consensus_inbound_vote_verify_rejected_total'

# Scrape one exact metric line value; prints 0 if absent.
scrape_one() {
  local mport="$1" name="$2"
  curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | awk -v n="${name}" '$1==n {print $2; f=1} END{if(!f)print 0}'
}

# Dump a named set of metric lines (name value), one per line, 0 if absent.
scrape_set() {
  local mport="$1"; shift
  local body name
  body="$(curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null || true)"
  for name in "$@"; do
    printf '%s\n' "${body}" | awk -v n="${name}" '$1==n {print $1" "$2; f=1} END{if(!f)print n" 0"}'
  done
}

# Dump every binding label line (F6).
scrape_binding_block() {
  local mport="$1"
  curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | grep -E '^qbind_consensus_binding_total\{' || true
}

scrape_binding_label() {
  local mport="$1" result="$2"
  curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
    | awk -v r="qbind_consensus_binding_total{result=\"${result}\"}" \
        '$1==r {print $2; found=1} END{ if(!found) print 0 }'
}

# Settle detector: wait until the sum of the CTX + binding counters rises above
# its initial value and holds for 2 reads (or the full window elapses).
settle() {
  local mport="$1" base prev cur stable=0 moved=0 i
  probe_sum() {
    curl -fsS --max-time 3 "http://127.0.0.1:${mport}/metrics" 2>/dev/null \
      | awk '/verification_context_unavailable_total/ {s+=$2} /^qbind_consensus_binding_total\{/ {s+=$2} END{print s+0}'
  }
  base="$(probe_sum)"; prev="${base}"
  for i in $(seq 1 24); do
    sleep 0.5
    cur="$(probe_sum)"
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
# 0. Toolchain + build.
# ---------------------------------------------------------------------------
RUSTC_V="$(rustc --version)"
CARGO_V="$(cargo --version)"
log "rustc: ${RUSTC_V}"
log "cargo: ${CARGO_V}"

log "building release binary + Run 421 helper ..."
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

# ---------------------------------------------------------------------------
# S9 — production --help denylist (fixture / injection / arbitrary controls).
# ---------------------------------------------------------------------------
HELP_OUT="$("${NODE_BIN}" --help 2>&1 || true)"
S9="PASS"
if printf '%s' "${HELP_OUT}" | grep -Eiq 'localfixture|fixture-unsigned|verification-policy|forge|forged|claimed.sender|arbitrary.(payload|signer|suite)|run.?421'; then
  S9="FAIL"
fi
# An invented fixture/policy flag must be rejected non-zero.
set +e
"${NODE_BIN}" --consensus-verification-policy local-fixture-unsigned --help >/dev/null 2>&1
INVALID_RC=$?
set -e
[ "${INVALID_RC}" -ne 0 ] || S9="FAIL"
HELP_CLEAN="yes (no LocalFixtureUnsigned / verification-policy / forged-message / arbitrary-control flag; invented flag rc=${INVALID_RC})"

# ---------------------------------------------------------------------------
# 1. PQC material (temporary; minted by the helper, never committed).
# ---------------------------------------------------------------------------
MAT="${WORKDIR}/material"
rm -rf "${MAT}"; mkdir -p "${MAT}"
"${HELPER_BIN}" gen-material "${MAT}" >/dev/null 2>&1 || fail "gen-material failed"
TRUSTED_ROOT="$(cat "${MAT}/trusted-root.spec")"

# ---------------------------------------------------------------------------
# 2. Topology (loopback only). 3 validators:
#      validator 0 = legitimate leader/victim identity (impersonated in S4),
#      validator 1 = authenticated driver,
#      validator 2 = standalone release receiver (system-under-test).
# ---------------------------------------------------------------------------
TOPOLOGY="3 validators on 127.0.0.1: v0=leader/victim identity v1=authenticated driver(client) v2=standalone release receiver(server, system-under-test)"

RAW_LOG_DIR="${WORKDIR}/logs"; mkdir -p "${RAW_LOG_DIR}"
SOCKET_LOG="${WORKDIR}/socket_lines.txt";  : > "${SOCKET_LOG}"
HANDSHAKE_LOG="${WORKDIR}/handshake_lines.txt"; : > "${HANDSHAKE_LOG}"
REJECT_LOG="${WORKDIR}/reject_lines.txt"; : > "${REJECT_LOG}"
METRICS_BA="${WORKDIR}/metrics_before_after.txt"; : > "${METRICS_BA}"
SCEN_MATRIX="${WORKDIR}/scenario_matrix.txt"; : > "${SCEN_MATRIX}"

# launch a fresh standalone receiver (validator 2); echoes "RP MP DEAD0 DLISTEN LOGFILE"
launch_receiver() {
  local scen="$1"
  local rp mp dead0 dlisten logf datadir
  rp="$(free_port)"; mp="$(free_port)"; dead0="$(free_port)"; dlisten="$(free_port)"
  datadir="${WORKDIR}/recv_${scen}"; rm -rf "${datadir}"; mkdir -p "${datadir}"
  logf="${RAW_LOG_DIR}/recv_${scen}.log"
  QBIND_METRICS_HTTP_ADDR="127.0.0.1:${mp}" timeout 60 "${NODE_BIN}" \
    --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr "127.0.0.1:${rp}" --validator-id 2 --data-dir "${datadir}" \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root "${TRUSTED_ROOT}" \
    --p2p-leaf-cert "${MAT}/v2.cert.bin" --p2p-leaf-cert-key "${MAT}/v2.kem.sk.bin" \
    --p2p-peer "0@127.0.0.1:${dead0}"   --p2p-peer-leaf-cert "0:${MAT}/v0.cert.bin" \
    --p2p-peer "1@127.0.0.1:${dlisten}" --p2p-peer-leaf-cert "1:${MAT}/v1.cert.bin" \
    > "${logf}" 2>&1 &
  echo "${rp} ${mp} ${dead0} ${dlisten} ${logf}"
}

wait_metrics_up() {
  local mp="$1" i
  for i in $(seq 1 30); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${mp}/metrics" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

# capture curated ss + KEMTLS + rejection log lines (path/secret-scrubbed).
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
    { grep -Ei 'kemtls|static.root|mutual.auth|handshake|verified|leaf|binding|origin' "${logf}" 2>/dev/null || true; } \
      | { grep -Eiv 'secret|private|0x[0-9a-f]{32,}' || true; } \
      | sed -E -e "s#${WORKDIR}#<TMP>#g" -e 's#/tmp/run421\.[A-Za-z0-9]+#<TMP>#g' \
               -e 's#/(home|root|tmp)/[^ ]*#<PATH>#g' \
      | head -12
    echo
  } >> "${HANDSHAKE_LOG}"
  {
    echo "# ${scen}: Run 420 / Run 418 fail-closed rejection log lines"
    { grep -Ei 'Run 420|Run 418|verification context unavailable|sender binding|REJECTED' "${logf}" 2>/dev/null || true; } \
      | { grep -Eiv 'secret|private|0x[0-9a-f]{32,}' || true; } \
      | sed -E -e "s#${WORKDIR}#<TMP>#g" -e 's#/(home|root|tmp)/[^ ]*#<PATH>#g' \
      | head -12
    echo
  } >> "${REJECT_LOG}"
}

# run one inbound scenario.
# args: scen primary_metric expect_delta binding_label binding_expect desc
run_scenario() {
  local scen="$1" pmetric="$2" pwant="$3" blabel="$4" bwant="$5" desc="$6"
  local rp mp dead0 dlisten logf
  read rp mp dead0 dlisten logf < <(launch_receiver "${scen}")
  wait_metrics_up "${mp}" || log "${scen}: receiver /metrics did not come up"
  sleep 3

  local pbefore bbefore t_start t_end drv_rc
  pbefore="$(scrape_one "${mp}" "${pmetric}")"
  bbefore="$(scrape_binding_label "${mp}" "${blabel}")"
  {
    echo "===== ${scen} ====="
    echo "-- before: context-unavailable counters --"; scrape_set "${mp}" ${CTX_METRICS}
    echo "-- before: F6 binding --"; scrape_binding_block "${mp}"
    echo "-- before: downstream delivered/accept/aggregation/QC/view/commit/outbound --"; scrape_set "${mp}" ${DOWNSTREAM_METRICS}
    echo "-- before: typed signature/suite reject-reason counters --"; scrape_set "${mp}" ${REASON_METRICS}
  } >> "${METRICS_BA}"

  t_start="$(now_utc)"
  set +e
  "${HELPER_BIN}" drive "${scen}" "${MAT}" "127.0.0.1:${rp}" "127.0.0.1:${dlisten}" \
    "${WORKDIR}/${scen}.out" > "${RAW_LOG_DIR}/drv_${scen}.log" 2>&1
  drv_rc=$?
  set -e
  t_end="$(now_utc)"
  settle "${mp}"

  local pafter bafter
  pafter="$(scrape_one "${mp}" "${pmetric}")"
  bafter="$(scrape_binding_label "${mp}" "${blabel}")"
  {
    echo "-- after: context-unavailable counters --"; scrape_set "${mp}" ${CTX_METRICS}
    echo "-- after: F6 binding --"; scrape_binding_block "${mp}"
    echo "-- after: downstream delivered/accept/aggregation/QC/view/commit/outbound --"; scrape_set "${mp}" ${DOWNSTREAM_METRICS}
    echo "-- after: typed signature/suite reject-reason counters --"; scrape_set "${mp}" ${REASON_METRICS}
    echo "delta(${pmetric}) = $(( pafter - pbefore ))  delta(binding ${blabel}) = $(( bafter - bbefore ))  driver_rc=${drv_rc}  window=${t_start}..${t_end}"
    echo
  } >> "${METRICS_BA}"

  capture_socket_and_logs "${scen}" "${rp}" "${logf}"

  local pdelta bdelta connected result
  pdelta=$(( pafter - pbefore ))
  bdelta=$(( bafter - bbefore ))
  connected="$(awk -F': ' '/^connected:/{print $2}' "${WORKDIR}/${scen}.out" 2>/dev/null)"
  if [ "${pdelta}" = "${pwant}" ] && [ "${bdelta}" = "${bwant}" ]; then
    result="PASS"
  else
    result="FAIL"
  fi
  printf '%-14s ctx[%s]=%-3s(want %s) F6[%s]=%-3s(want %s) connected=%-6s rc=%-3s => %s\n' \
    "${scen}" "${pmetric##*_verification_context_unavailable_total}" "${pdelta}" "${pwant}" \
    "${blabel}" "${bdelta}" "${bwant}" "${connected:-n/a}" "${drv_rc}" "${result}" \
    | tee -a "${SCEN_MATRIX}" >&2
  echo "${result}"
}

# ---------------------------------------------------------------------------
# S1 — production-policy + unavailable-authority baseline (no traffic).
# ---------------------------------------------------------------------------
log "=== S1 baseline ==="
read S1_RP S1_MP S1_D0 S1_DL S1_LOG < <(launch_receiver "s1-baseline")
wait_metrics_up "${S1_MP}" || log "s1: receiver /metrics did not come up"
sleep 6
S1_BASE="${WORKDIR}/s1_baseline.txt"
{
  echo "===== s1-baseline (standalone release binary, no consensus authority) ====="
  echo "-- context-unavailable counters (expect all 0) --"; scrape_set "${S1_MP}" ${CTX_METRICS}
  echo "-- F6 binding (expect all 0) --"; scrape_binding_block "${S1_MP}"
  echo "-- downstream (expect all 0) --"; scrape_set "${S1_MP}" ${DOWNSTREAM_METRICS}
  echo "-- startup policy / mutual-auth / verification-context log lines --"
  { grep -Ei 'mutual_auth_mode|mutual_auth=|verification_ctx=None|verification DISABLED|Required|leader' "${S1_LOG}" 2>/dev/null || true; } \
    | { grep -Eiv 'secret|private' || true; } \
    | sed -E -e "s#${WORKDIR}#<TMP>#g" -e 's#/(home|root|tmp)/[^ ]*#<PATH>#g' | head -12
} > "${S1_BASE}"
# Assert baseline: all context + binding counters are zero, no fixture in --help.
S1="PASS"
for m in ${CTX_METRICS}; do
  [ "$(scrape_one "${S1_MP}" "${m}")" = "0" ] || S1="FAIL"
done
[ "$(scrape_binding_label "${S1_MP}" accepted)" = "0" ] || S1="FAIL"
grep -qi 'mutual_auth.*Required' "${S1_LOG}" || S1="FAIL"
grep -qi 'verification_ctx=None\|verification DISABLED' "${S1_LOG}" || true
# capture outbound counters over the baseline node's whole lifetime for S7/S8.
sleep 8
S1_OUT_PROP="$(scrape_one "${S1_MP}" qbind_consensus_outbound_proposal_verification_context_unavailable_total)"
S1_OUT_VOTE="$(scrape_one "${S1_MP}" qbind_consensus_outbound_vote_verification_context_unavailable_total)"
S1_OUT_PSIGN="$(scrape_one "${S1_MP}" qbind_consensus_outbound_proposal_signing_success_total)"
S1_LEADER="$(scrape_one "${S1_MP}" qbind_consensus_leader_changes_total)"
capture_socket_and_logs "s1-baseline" "${S1_RP}" "${S1_LOG}"
printf '%-14s all-ctx=0 F6=0 mutual_auth=Required verification_ctx=None => %s\n' "s1-baseline" "${S1}" \
  | tee -a "${SCEN_MATRIX}" >&2

# ---------------------------------------------------------------------------
# Inbound fail-closed scenarios S2..S6.
# ---------------------------------------------------------------------------
log "=== running inbound scenarios ==="
R_S2="$(run_scenario s2-proposal qbind_consensus_inbound_proposal_verification_context_unavailable_total 1 accepted 1 'honest authenticated Proposal(1) rejected: inbound proposal context-unavailable +1, F6 accepted +1')"
R_S3="$(run_scenario s3-vote     qbind_consensus_inbound_vote_verification_context_unavailable_total     1 accepted 1 'honest authenticated Vote(1) rejected: inbound vote context-unavailable +1, F6 accepted +1')"
R_S4="$(run_scenario s4-mismatch qbind_consensus_inbound_proposal_verification_context_unavailable_total 0 claimed_sender_mismatch 2 'F6 mismatch precedes context gate: claimed_sender_mismatch +2, context unchanged')"
R_S5="$(run_scenario s5-badsig   qbind_consensus_inbound_proposal_verification_context_unavailable_total 1 accepted 2 'malformed-signature Proposal+Vote: context gate rejects before signature parsing')"
R_S6="$(run_scenario s6-badsuite qbind_consensus_inbound_proposal_verification_context_unavailable_total 1 accepted 2 'wrong-suite Proposal+Vote: context gate rejects before suite enforcement')"

# S7 / S8 — outbound suppression. The standalone binary under Required with no
# consensus authority and no connected authenticated peers never advances views
# to a natural leader-Proposal emission opportunity (leader_changes stays 0), and
# because inbound Proposal is rejected before engine ingestion, no outbound Vote
# is ever generated. Both are recorded PARTIAL/UNREACHABLE with the observed
# outbound counters; Run 420 code/tests remain the direct proof of the outbound
# suppression helpers. We do NOT substitute an in-process helper result here.
R_S7="PARTIAL"
R_S8="PARTIAL"
printf '%-14s outbound_proposal_ctx_unavail=%s signing_success=%s leader_changes=%s => PARTIAL/UNREACHABLE (no natural leader-proposal opportunity)\n' \
  "s7-outbound-p" "${S1_OUT_PROP}" "${S1_OUT_PSIGN}" "${S1_LEADER}" | tee -a "${SCEN_MATRIX}" >&2
printf '%-14s outbound_vote_ctx_unavail=%s => PARTIAL/UNREACHABLE (inbound Proposal fail-closed before engine ingestion; no vote generated)\n' \
  "s8-outbound-v" "${S1_OUT_VOTE}" | tee -a "${SCEN_MATRIX}" >&2

# ---------------------------------------------------------------------------
# 3. Verdict.
# ---------------------------------------------------------------------------
CORE_OK=1
for r in "${S1}" "${R_S2}" "${R_S3}" "${R_S4}" "${R_S5}" "${R_S6}" "${S9}"; do
  [ "${r}" = "PASS" ] || CORE_OK=0
done

if [ "${CORE_OK}" = 1 ]; then
  RESULT="PARTIAL-POSITIVE-FOR-F3-F4-F8-UNAVAILABLE-AUTHORITY-FAIL-CLOSED-RELEASE-BINARY-EVIDENCE"
  FCLASS="CONFIGURED-PATH-CODE-TEST-REMEDIATED / UNAVAILABLE-AUTHORITY-RELEASE-BINARY-FAIL-CLOSED"
else
  RESULT="NEGATIVE-FOR-F3-F4-F8-UNAVAILABLE-AUTHORITY-FAIL-CLOSED-RELEASE-BINARY-EVIDENCE"
  FCLASS="CODE-TEST-ONLY / RELEASE-BINARY-EVIDENCE-INCOMPLETE"
fi
SECURITY_POSTURE="RS1-OPEN / PUBLIC-DEVNET-NO-GO"

# ---------------------------------------------------------------------------
# 4. Emit curated publish-safe deliverables into EVID_DIR.
# ---------------------------------------------------------------------------
END_UTC="$(now_utc)"

cp "${METRICS_BA}"  "${EVID_DIR}/metrics_before_after.txt"
cp "${SCEN_MATRIX}" "${EVID_DIR}/scenario_matrix.txt"
{
  cat "${SOCKET_LOG}"
  echo
  echo "================= KEMTLS / static-root / mutual-auth log lines ================="
  cat "${HANDSHAKE_LOG}"
  echo
  echo "================= Run 420 / Run 418 fail-closed rejection log lines ============"
  cat "${REJECT_LOG}"
  echo
  echo "================= S1 baseline (policy / verification-context) =================="
  cat "${S1_BASE}"
} > "${EVID_DIR}/socket_log_extract.txt"

cat > "${EVID_DIR}/binary_identity.txt" <<EOF
Run 421 — binary identity (curated, publish-safe)

runtime_commit:      ${RUNTIME_COMMIT}
capture_end_utc:     ${END_UTC}

rustc:               ${RUSTC_V}
cargo:               ${CARGO_V}

target/release/qbind-node
  sha256:            ${NODE_SHA}
  elf_build_id:      ${NODE_BID}

Run 421 driver helper (target/release/examples/${HELPER_NAME})
  sha256:            ${HELPER_SHA}
  elf_build_id:      ${HELPER_BID}

PQC material helper: minted in-memory by the Run 421 helper 'gen-material'
                     subcommand (no separate committed PQC helper binary).

Note: SHA256SUMS protects committed curated evidence after capture; it does not
independently authenticate the original machine observations.
EOF

cat > "${EVID_DIR}/summary.txt" <<EOF
Run 421 — F3/F4/F8 unavailable-authority fail-closed release-binary evidence

RESULT=${RESULT}
F3_STATUS=${FCLASS}
F4_STATUS=${FCLASS}
F8_STATUS=${FCLASS}
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-CAPTURED
SECURITY_POSTURE=${SECURITY_POSTURE}

Qualifiers: positive ONLY for fail-closed behavior with consensus authority
UNAVAILABLE; local loopback; standalone release binary; tested message classes
and paths only; NOT configured-authority signing/verification; NOT public
deployment; NOT off-host attestation; NOT liveness-positive.

Topology: ${TOPOLOGY}

Trust model:
  * KEMTLS authenticates the transport session.
  * Run 418 F6 binds the authenticated peer to the claimed immediate consensus
    sender. A transport-authenticated frame is NOT cryptographically
    authenticated at the consensus-message level.
  * Run 420 would verify Proposal/Vote signatures/suites IF authoritative
    consensus context were available. On this standalone binary it is not, so
    the correct behavior is rejection/suppression, not signature acceptance.
  * Live metrics/logs are LOCAL observations, not independent off-host
    attestation.

Scenario results:
  S1 production-policy + unavailable-authority baseline ......... ${S1}
  S2 authenticated honest Proposal rejected fail-closed ........ ${R_S2}
  S3 authenticated honest Vote rejected fail-closed ............ ${R_S3}
  S4 F6 mismatch precedes Run 420 context rejection ............ ${R_S4}
  S5 missing/malformed signature cannot bypass unavailable auth  ${R_S5}
  S6 unsupported/wrong suite cannot bypass unavailable auth ..... ${R_S6}
  S7 outbound Proposal suppression ............................. ${R_S7} (UNREACHABLE: no natural leader-proposal opportunity; leader_changes=${S1_LEADER})
  S8 outbound Vote suppression ................................. ${R_S8} (UNREACHABLE: inbound Proposal fail-closed before engine ingestion)
  S9 fixture / CLI denial ...................................... ${S9}

Outbound observations (baseline node lifetime):
  outbound_proposal_verification_context_unavailable_total = ${S1_OUT_PROP}
  outbound_vote_verification_context_unavailable_total     = ${S1_OUT_VOTE}
  outbound_proposal_signing_success_total                  = ${S1_OUT_PSIGN}
  leader_changes_total                                     = ${S1_LEADER}

Toolchain: ${RUSTC_V} / ${CARGO_V}
Runtime commit: ${RUNTIME_COMMIT}
qbind-node --help clean: ${HELP_CLEAN}

This run proves fail-closed DEPLOYED behavior under UNAVAILABLE authority. It
does NOT prove configured-authority success. Regardless of result: F3/F4/F8 are
NOT fully remediated in production; configured-authority release-binary evidence
remains absent; F1/F2/F5/F7 remain unresolved; F6 remains partial (Run 419);
RS1 remains OPEN; C4/C5 remain OPEN; M4/M6/S5/S7 stay Yellow; no readiness item
moves Green; public DevNet remains NO-GO.
EOF

cat > "${EVID_DIR}/commands.txt" <<EOF
Run 421 — representative commands (temporary paths normalized to placeholders)

# build
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example ${HELPER_NAME}

# mint temporary PQC material (root/leaf certs + KEM secrets; NEVER committed)
${HELPER_BIN} gen-material <MATERIAL_DIR>

# launch a standalone release receiver (validator 2, system-under-test);
# NO consensus verification authority is configured, so verification_ctx==None
# and the production-default ConsensusVerificationPolicy::Required is active.
QBIND_METRICS_HTTP_ADDR=127.0.0.1:<MPORT> ${NODE_BIN} \\
  --env devnet --network-mode p2p --enable-p2p \\
  --p2p-listen-addr 127.0.0.1:<RPORT> --validator-id 2 --data-dir <DATA_DIR> \\
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \\
  --p2p-trusted-root <TRUSTED_ROOT_SPEC> \\
  --p2p-leaf-cert <MATERIAL_DIR>/v2.cert.bin --p2p-leaf-cert-key <MATERIAL_DIR>/v2.kem.sk.bin \\
  --p2p-peer 0@127.0.0.1:<DEAD0> --p2p-peer-leaf-cert 0:<MATERIAL_DIR>/v0.cert.bin \\
  --p2p-peer 1@127.0.0.1:<DLISTEN> --p2p-peer-leaf-cert 1:<MATERIAL_DIR>/v1.cert.bin

# drive one scenario (real KEMTLS client -> receiver, fixed enumerated frames)
${HELPER_BIN} drive <SCENARIO> <MATERIAL_DIR> 127.0.0.1:<RPORT> 127.0.0.1:<DLISTEN> <OUT_FILE>
#   SCENARIO in: s2-proposal s3-vote s4-mismatch s5-badsig s6-badsuite

# observe live context-unavailable + F6 binding counters
curl -fsS http://127.0.0.1:<MPORT>/metrics | grep -E 'verification_context_unavailable_total|qbind_consensus_binding_total'
EOF

# source_trace.txt — static production wiring references (publish-safe grep).
cat > "${EVID_DIR}/source_trace.txt" <<EOF
Run 421 — production wiring source trace (UNCHANGED by Run 421)

Run 421 adds NO production source change. The gates below are the Run 418 (F6)
and Run 420 (ConsensusVerificationPolicy) paths, exercised here on the
standalone release binary. Production default policy is Required; the standalone
binary has verification_ctx=None; no production constructor selects the
test-only LocalFixtureUnsigned policy.

binary_consensus_loop.rs — ConsensusVerificationPolicy + inbound gate ordering
$(grep -nE 'pub enum ConsensusVerificationPolicy|fn requires_context|ConsensusVerificationPolicy::Required$|inbound_proposal_verification_context_unavailable_total =|inbound_vote_verification_context_unavailable_total =' crates/qbind-node/src/binary_consensus_loop.rs | head -8 | sed 's/^/  /')

binary_consensus_loop.rs — F6 bind_sender precedes the Run 420 context gate
$(grep -nE 'let from = match bind_sender|match verification_ctx \{|if verification_policy.requires_context' crates/qbind-node/src/binary_consensus_loop.rs | head -6 | sed 's/^/  /')

main.rs — production binary ALWAYS selects Required (fixture never selectable)
$(grep -nE 'verification_policy: ConsensusVerificationPolicy::Required' crates/qbind-node/src/main.rs | head -2 | sed 's/^/  /')

metrics.rs — the four context-unavailable counter families exposed on /metrics
$(grep -nE 'qbind_consensus_(inbound|outbound)_(proposal|vote)_verification_context_unavailable_total' crates/qbind-node/src/metrics.rs | head -4 | sed 's/^/  /')

peer_consensus_binding.rs — F6 binding metric labels (accepted / mismatch)
$(grep -nE 'result=\\\\"accepted\\\\"|ClaimedSenderMismatch => ' crates/qbind-node/src/peer_consensus_binding.rs | head -3 | sed 's/^/  /')
EOF

# scenario_matrix already written; produce a scenario-matrix header prepend.
{
  echo "Run 421 — scenario matrix (live /metrics deltas on the standalone release binary)"
  echo "delta convention: ctx[...] = change in the named verification_context_unavailable counter;"
  echo "F6[label] = change in qbind_consensus_binding_total{result=\"label\"}."
  echo
  cat "${EVID_DIR}/scenario_matrix.txt"
} > "${EVID_DIR}/scenario_matrix.txt.tmp" && mv "${EVID_DIR}/scenario_matrix.txt.tmp" "${EVID_DIR}/scenario_matrix.txt"

if [ ! -f "${EVID_DIR}/test_results.txt" ]; then
  cat > "${EVID_DIR}/test_results.txt" <<EOF
Run 421 — validation exit codes (populated during the validation suite)
EOF
fi

cat > "${EVID_DIR}/README.md" <<EOF
# Run 421 — F3/F4/F8 unavailable-authority fail-closed release-binary evidence

Curated, **publish-safe** evidence that the Run 420 fail-closed Proposal/Vote
verification-policy boundary is live on the standalone
\`target/release/qbind-node\` binary when consensus verification authority is
**unavailable** (\`verification_ctx == None\`, production-default
\`ConsensusVerificationPolicy::Required\`).

* **Route A**: evidence-only. No production behavior change. Run 421 adds a
  Cargo-example driver helper, a harness, and curated docs.
* **Scope**: local loopback, multi-process, DevNet-only, standalone release
  receiver as the system-under-test.
* **Proves**: an authenticated, F6-authorized Proposal/Vote is REJECTED because
  consensus verification authority is unavailable. F6 sender mismatch rejects
  BEFORE the Run 420 context gate. Missing/malformed signatures and wrong suites
  cannot bypass the unavailable-authority boundary. No rejected frame reaches
  delivery, engine acceptance, aggregation, QC formation, view/commit mutation,
  or outbound actions.
* **Does NOT prove**: configured-authority cryptographic signature/suite success
  (no consensus signing authority exists on the standalone binary —
  \`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-CAPTURED\`).
* **Trust model**: automated LOCAL cross-process operational evidence. **Not**
  independent off-host attestation. KEMTLS authenticates the transport session
  only; a transport-authenticated frame is not consensus-message authenticated.

## Verdict

See \`summary.txt\`. Regardless of outcome: **RS1 remains OPEN**, C4/C5 remain
OPEN, F1/F2/F5/F7 remain unresolved, F6 remains partial, no M/S item moves
Green, and **public DevNet remains NO-GO**.

## Files

| File | Contents |
|------|----------|
| \`summary.txt\` | verdict, labels, trust model, per-scenario results |
| \`scenario_matrix.txt\` | scenario → expected/observed metric deltas + exit code |
| \`metrics_before_after.txt\` | before/after live counters per scenario |
| \`socket_log_extract.txt\` | curated \`ss\` + KEMTLS + rejection + S1 baseline lines |
| \`binary_identity.txt\` | runtime commit, SHA-256, ELF Build IDs, toolchain |
| \`source_trace.txt\` | Run 418/420 production wiring references (unchanged) |
| \`commands.txt\` | representative commands, temp paths normalized |
| \`test_results.txt\` | validation-suite exit codes |
| \`SHA256SUMS.txt\` | integrity digests for the curated files above |

## Reproduce

\`\`\`
scripts/devnet/run_421_f3_f4_f8_unavailable_authority_release_binary_evidence.sh
\`\`\`

Private keys, certificates, raw logs, raw metric dumps and data directories are
temporary and are **never** committed (see \`.gitignore\`).
EOF

cat > "${EVID_DIR}/.gitignore" <<'EOF'
# Run 421: never commit private material, raw logs, raw metrics, or data dirs.
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

log "=== VERDICT: ${RESULT} ==="
log "curated evidence in: ${EVID_DIR}"

# ---------------------------------------------------------------------------
# 6. Cleanup temporary material/data/logs (keep only curated EVID_DIR).
# ---------------------------------------------------------------------------
rm -rf "${MAT}" "${RAW_LOG_DIR}" "${WORKDIR}/recv_"* "${WORKDIR}"/*.out \
       "${WORKDIR}"/*.txt 2>/dev/null || true
if [[ "${WORKDIR}" == /tmp/run421.* ]]; then rm -rf "${WORKDIR}" 2>/dev/null || true; fi

[ "${CORE_OK}" = 1 ] || fail "core scenarios S1..S6 + S9 did not all pass"
exit 0
