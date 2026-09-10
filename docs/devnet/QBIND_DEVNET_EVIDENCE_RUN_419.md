# QBIND DevNet Evidence — Run 419

**Standalone release-binary evidence for the F6 authenticated-peer → consensus
sender binding.** Run 419 is a **Route A (evidence-only) run**: it captures real
cross-process, loopback-socket, standalone-`target/release/qbind-node` evidence
that the **Run 418** transport-session-to-consensus-sender binding gate (finding
**F6** of the Run 417 audit) is **live on the deployed release binary**. Run 419
adds **no production source change** — only a Cargo-example driver helper, a
fail-closed harness, and curated publish-safe evidence and reconciliation notes.

**F6 is transport-session-to-consensus-sender binding and accountability only.**
Exercising it on the release binary does **not** make cryptographic
proposal/vote/timeout/new-view/QC signatures meaningful and must **not** be
represented as fixing F1–F5, F7, F8, RS1, C4, or C5. Run 419 publishes **no**
live seed, moves **no** readiness item Green, and changes **no** TestNet/MainNet
posture.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
**partial release-binary evidence of F6 only** · automated **local loopback**
cross-process evidence · **NOT** off-host attestation · **NOT** external
reachability · NOT public-DevNet launch-ready · **M4 Yellow / launch-blocking** ·
M6 Yellow/Partial · S5 Yellow · S7 Yellow · **RS1 OPEN / launch-blocking** ·
**C4/C5 OPEN** · public DevNet **NO-GO** · no TestNet readiness · no MainNet
readiness. **No private key material, certificate, raw log, raw metric dump, or
data directory is committed.**

## 1. Exact verdict

- **Overall:** `F6 REMEDIATION EXERCISED ON THE RELEASE BINARY FOR THE CORE
  REQUIRED/STATIC-ROOT PATH; UNAUTHENTICATED-INGRESS AND OUTBOUND VECTORS
  PARTIAL`.
- **Run 419 harness:**
  `RESULT=PARTIAL-FOR-F6-STANDALONE-RELEASE-BINARY-EVIDENCE`,
  `F6_STATUS=CODE-TEST-PLUS-PARTIAL-RUNTIME-EVIDENCE`,
  `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`.
- **Qualifiers:** local loopback; multi-process; Required/static-root plus
  tested Optional/Disabled ingress paths; tested message classes only; **not**
  off-host; **not** durable public deployment; **not** signature/QC/suite
  enforcement.

Because two required unauthenticated-ingress scenarios (S4/S5) and the dedicated
outbound-identity vector (S7) could not be driven as decisive real-socket
evidence with the present transport configuration, the verdict is a clearly
defined **PARTIAL** — not POSITIVE. F6 stays at **code/test plus partial runtime
evidence** on the release binary.

## 2. Baseline and provenance

- Run 418 predecessor evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_418.md`.
- **Runtime/implementation commit** (helper + harness; the exact tree the
  release-binary capture ran from): `1ec128379f3ce215706959d50901bbd6e56abd6b`.
- **Final documentation/reconciliation commit:** recorded in the branch history
  for this evidence/documentation commit (this file and the §7 reconciliation
  edits land in that commit).
- Run 419 makes **no** production source change. The gate is unchanged Run 418
  code, now exercised on the standalone binary.

## 3. What was proven on the standalone release binary

The system-under-test is a standalone `target/release/qbind-node` process
(validator 2) launched with `--p2p-mutual-auth`, `--p2p-pqc-root-mode
pqc-static-root`, a trusted root, its own leaf credentials, and two configured
peers. A separate Cargo-example driver (validator 1) establishes a **real
KEMTLS/static-root session** to the receiver and submits crafted consensus
frames with controlled claimed-senders. Evidence is the **live**
`qbind_consensus_binding_total{result="…"}` `/metrics` delta on the receiver,
plus curated `ss`, KEMTLS/static-root/mutual-auth log lines, and downstream
delivered/engine-accepted/commit counters that confirm fail-closed behavior.

| Scenario | Vector | Expected | Observed live metric delta | Result |
| --- | --- | --- | --- | --- |
| **S1** honest authenticated proposal | authenticated v1 → receiver, Proposal(proposer=1) | admitted | `binding_total{result="accepted"} +1` | **PASS** |
| **S2** impersonation, 5 message classes | authenticated v1 claims v0 across Proposal/Vote/Timeout/RestoreReq/RestoreResp | fail-closed reject | `binding_total{result="claimed_sender_mismatch"} +5`; all delivered/engine-accepted/commit counters unchanged (0) | **PASS** |
| **S3** NewView origin admission | authenticated v1 → receiver, NewView(TimeoutCertificate) | authenticated origin admitted (transport-origin admission only) | `binding_total{result="accepted"} +1` | **PASS** |
| **S6** root-valid unconfigured alternate leaf | v1 alternate leaf (root-valid, non-configured NodeId), Proposal(proposer=1) | suppressed pre-gate, no invented origin | `binding_total{result="missing_origin"} +1` | **PASS** |
| **S4** unauthenticated ingress (Optional) | default-transport client → static-root receiver | fail-closed / not establishable | no session established (`connected=false`), no gate delta | **PARTIAL** |
| **S5** unauthenticated ingress (Disabled) | default-transport client → static-root receiver | fail-closed / not establishable | no session established (`connected=false`), no gate delta | **PARTIAL** |
| **S7** outbound actual-server identity | dedicated spoofing-listener vector | typed refusal + no authenticated registration | dedicated vector not driven; see §4 | **PARTIAL** |

The **S2 fail-closed proof** is the strongest signal: five crafted
impersonation frames all increment `claimed_sender_mismatch` while
`qbind_consensus_inbound_new_views_delivered_total`,
`qbind_consensus_inbound_new_views_engine_accepted_total`,
`qbind_consensus_inbound_timeouts_delivered_total`,
`qbind_consensus_proposals_total`, and `qbind_consensus_committed_height` all
stay `0` — the rejection happens **before** delivery, engine acceptance,
mutation, or commit.

## 4. Partial coverage — precise boundaries

- **S4/S5 (unauthenticated ingress).** A static-root receiver requires local
  ML-KEM-768 leaf credentials, and a static-root client cannot be constructed
  without local leaf credentials, so an "unauthenticated" static-root client is
  not expressible. The driver falls back to a default (non-static-root)
  transport, which cannot complete a KEMTLS/static-root session against the
  receiver (suite/handshake mismatch), so **no real socket session is
  established** (`connected=false`, no frames sent). Per the task, the actual
  behavior is reported and the coverage is left **partial**; **no** manually
  constructed in-process envelope is substituted.
- **S7 (outbound actual-server identity).** A dedicated S7 vector — a listener
  presenting validator 0's KEM public key under a different signed validator-id
  — was **not** driven. However, the standalone receiver's own outbound dialer
  **did** exercise the Run 418 verified-server-identity comparison incidentally
  during S6: when it dialed the driver's root-valid **alternate** leaf, it
  refused the session with
  `Run 418: verified server identity … does not match the configured
  authoritative mapping (authenticated=true, node_match=false, vid_match=true);
  rejecting session` (see `socket_log_extract.txt`). This confirms the outbound
  check is **live on the release binary**, but it is not the full typed-vector
  S7 proof, so S7 stays **partial** and F6 is **not** promoted to complete
  release-binary coverage.

## 5. Helper safety controls

The driver is a **Cargo example** (`crates/qbind-node/examples/
run_419_f6_release_binary_binding_driver.rs`), never a production `qbind-node`
subcommand or flag. It:

- refuses any non-loopback receiver/listen address (127.0.0.0/8 only);
- refuses any environment other than DevNet;
- mints PQC material in-memory via a `gen-material` subcommand and writes secrets
  at mode `0600` into a temporary directory that is never committed;
- degrades gracefully (no panic) when a session cannot be established.

`qbind-node --help` is asserted to contain **no** Run 419 or forged-message
production flag.

## 6. Trust model (unchanged limits)

- This is automated **local** cross-process operational evidence.
- It is **not** independent off-host attestation.
- It does **not** prove external reachability (that remains the separate Run 416
  Route A observation and its still-open durable-seed gate).
- `SHA256SUMS.txt` protects the committed curated evidence **after** capture; it
  does **not** independently authenticate the original machine observations.

## 7. Preserved posture (unchanged by this run)

- F1–F5 and F7–F8 remain **unresolved**.
- **RS1 OPEN / launch-blocking.**
- M4 Yellow / launch-blocking · M6 Yellow/Partial · S5 Yellow · S7 Yellow.
- **C4/C5 OPEN.**
- public DevNet **NO-GO / not launch-ready**.
- No `devnet-seeds.live.json`; candidate seed remains `planned` with null
  reachability evidence.
- TestNet and MainNet untouched.
- Run 416 and Run 417 history unchanged.

## 8. Provenance

- Evidence archive:
  `docs/devnet/run_419_f6_standalone_release_binary_binding_evidence/`.
- Driver helper:
  `crates/qbind-node/examples/run_419_f6_release_binary_binding_driver.rs`.
- Fail-closed harness:
  `scripts/devnet/run_419_f6_standalone_release_binary_binding_evidence.sh`.
- Standing reconciliation:
  `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md`.

## 9. Recommended next run (not implemented here)

Run 420 — production consensus proposal/vote signature and consensus-suite
enforcement for F3/F4/F8, followed later by F5/F7 and then F1/F2. Run 419 does
**not** claim public DevNet launch readiness.
