# QBIND DevNet Evidence — Run 417

**Foundational runtime-security reconciliation audit** of QBIND's four foundational
authentication boundaries, performed before any durable public DevNet seed is provisioned or
published. Run 417 is an **audit and evidence run**: it establishes what the current
**deployed** `qbind-node` binary actually enforces, where it fails closed, where it remains
incomplete, and whether documentation or readiness statuses overstate the implementation.

Run 417 changed **no production Rust behavior**, added **no** authentication bypass, published
**no** live seed, and moved **no** readiness item Green.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
**audit/evidence only** · NOT public-DevNet launch-ready · **M4 Yellow / launch-blocking** ·
M6 Yellow/Partial · S5 Yellow · S7 Yellow · **RS1 OPEN / launch-blocking** · **C4/C5 OPEN** ·
public DevNet **NO-GO** · no TestNet readiness · no MainNet readiness. **No private key material is committed.**

## 1. Exact verdict

**Overall:** `AUDIT-COMPLETE / NEGATIVE-FOR-RUNTIME-SECURITY`.
**Audit harness:** `RESULT=POSITIVE-FOR-AUDIT-COMPLETENESS`,
`SECURITY_VERDICT=NEGATIVE-FOR-RUNTIME-SECURITY`.

The deployed `qbind-node` consensus path is **fail-open** for consensus-message authentication:
proposals and votes are emitted **unsigned** with the **toy** suite id `0`; inbound proposals
and votes are accepted **without** signature, membership, or suite verification; the consensus
engine's sender is derived from a **self-declared** `proposer_index`/`validator_index`, not from
the authenticated KEMTLS peer; and proposal-carried **QCs are imported with empty signer
evidence**. Transaction empty-auth acceptance is fail-open in code but is **not reachable** from
the deployed binary today. No production behavior was modified in this run.

## 2. Audited baseline

- Expected base commit: `cb4c4dc94eaaa46689be15358ba48921e98a7797`.
- Actual audited working tree: `32b6561` — this adds **only** `task/RUN_417_TASK.txt` on top of
  the base and introduces **no** source difference in the audited crates. `main` had not
  advanced beyond this commit at audit time (fetched and confirmed).
- Working tree was clean before Run 417 authoring. No `AGENTS.md`/`CLAUDE.md` present.

## 3. Scope and method

Four domains audited:

1. Transaction authentication and authorization.
2. Consensus proposal / vote / timeout / new-view authentication.
3. Consensus sender identity binding to the authenticated KEMTLS peer.
4. Quorum-certificate validation and production signature-suite enforcement.

Every conclusion is traced from message/transaction construction or ingress **through the real
deployed runtime consumer**. The deployed consensus driver is
`crates/qbind-node/src/binary_consensus_loop.rs` (spawned by `main.rs`
`run_local_mesh_node`/`run_p2p_node`); `crates/qbind-node/src/hotstuff_node_sim.rs`
(`NodeHotstuffHarness`), which *does* sign and verify, is a **test** harness that `main.rs`
never references. Full file:line traces are in
`docs/devnet/run_417_foundational_runtime_security_reconciliation/source_trace.txt`; the
labelled finding matrix is in the same directory's `findings_matrix.txt`.

## 4. Findings

| ID | Domain | Finding | Classification | Severity | Reachability |
|----|--------|---------|----------------|----------|--------------|
| F1 | Transaction | `verify_transaction_auth` accepts `tx.auths.is_empty()` unconditionally (`auth.rs:31-33`) | VERIFIED-FAIL-OPEN (code) | High | MITIGATED-BY-CURRENT-UNREACHABILITY (deployed) |
| F2 | Transaction | keyset thresholds/weights not enforced; no signer/key dedup (`auth.rs:22-23,37-39`) | VERIFIED-INCOMPLETE | High | MITIGATED-BY-CURRENT-UNREACHABILITY |
| F3 | Consensus | proposals emitted unsigned, suite 0; inbound accepted without crypto (`basic_hotstuff_engine.rs:1357-1382`, `binary_consensus_loop.rs:2666-2714`) | VERIFIED-FAIL-OPEN | Critical | Reachable by any admitted peer (multi-node) |
| F4 | Consensus | votes emitted unsigned, suite 0; inbound accepted without crypto (`basic_hotstuff_engine.rs:1537-1539`, `binary_consensus_loop.rs:2726-2761`) | VERIFIED-FAIL-OPEN | Critical | Reachable by any admitted peer |
| F5 | Consensus | timeout/new-view signature verification is optional, default off (`binary_consensus_loop.rs:788,2827-2829`) | VERIFIED-INCOMPLETE | High | Reachable; off by default |
| F6 | Peer→sender binding | authenticated KEMTLS NodeId not propagated with consensus messages; engine `from` is self-declared (`p2p_inbound.rs:83,359-388`, `binary_consensus_loop.rs:2682,2730`) | VERIFIED-FAIL-OPEN | Critical | Reachable by any admitted peer |
| F7 | Quorum certificate | proposal-carried QC imported with empty signers; not cryptographically verified (`basic_hotstuff_engine.rs:1489-1506`, `consensus.rs:266-267`) | VERIFIED-FAIL-OPEN | Critical | Reachable by any admitted peer |
| F8 | Suite enforcement | `DEFAULT_CONSENSUS_SUITE_ID=0` "NOT FOR PRODUCTION" reachable; no inbound suite gating (`consensus.rs:13-18`) | VERIFIED-FAIL-OPEN | High | Deployed consensus uses suite 0 |

Severity is assigned independently of reachability. The absence of a durable public seed
constrains present external reachability only; it does **not** reduce the code-level severity.

## 5. Threat-model cases

| Case | Prerequisite | Entry point | Enforced checks | Result | Exploitability | Confidence |
|------|--------------|-------------|-----------------|--------|----------------|-----------|
| Malicious validator claims another validator ID | admitted KEMTLS peer | `binary_consensus_loop.rs:2682/2730` | epoch/leader/view only | accepted | High on a live multi-node net | High |
| Replay another validator's signed message | admitted peer | inbound vote/proposal | none (no sig, no nonce on msg) | accepted | High | High |
| Unsigned / empty-signature proposal or vote | admitted peer | inbound vote/proposal | none | accepted | High | High |
| Duplicate signer entries inflate quorum | admitted peer | imported QC | local accumulator dedups own votes, but imported QC signers discarded | QC accepted w/o proof | High | High |
| Forged QC / timeout certificate | admitted peer | proposal-carried QC / timeout | no crypto verify (QC), optional (timeout) | accepted | High | High |
| Wrong-suite / unknown-suite message | admitted peer | inbound consensus | no suite gating | accepted | High | High |
| Cross-chain / cross-view / cross-type reuse | admitted peer | inbound consensus | no signed preimage bound | accepted | High | High |
| Transaction with zero auth entries | tx execution wired | `auth.rs:31-33` | none | accepted | **Not reachable on deployed binary** | High |
| Signatures below keyset threshold | tx execution wired | `auth.rs` | thresholds unused | accepted | Not reachable on deployed binary | High |
| Duplicate tx signatures repeated weight | tx execution wired | `auth.rs:37-39` | no dedup | accepted | Not reachable on deployed binary | Medium |
| Authorized signer, unrelated account mutation | tx execution wired | keyset program | auth pre-check not bound to mutation set | partial | Not reachable on deployed binary | Medium |
| Restore/catch-up importing weak consensus evidence | admitted peer | restore/catch-up + QC import | QC signers discarded | accepted | Medium–High | Medium |

## 6. Canonical conclusion answers

1. **Can an unauthenticated transaction reach a state-mutating deployed execution path?**
   **No — not today.** The deployed binary has no RPC/mempool ingress, builds empty proposals
   (`tx_count:0`, `txs: vec![]`), and never calls `Node::apply_block` (only the test harness
   `hotstuff_node_sim.rs:3156` and `execution_adapter` tests do). In **code**, if the tx path
   were wired, empty auth would be accepted (`auth.rs:31-33`).
2. **Are keyset thresholds and weights enforced?** **No** (`auth.rs:22-23`; `weight`/`threshold`
   fields unused). Per-auth suite/key/signature checks *are* fail-closed.
3. **Are real binary proposals and votes cryptographically signed?** **No** — `signature: vec![]`,
   suite `0`.
4. **Are inbound proposal/vote signatures verified before engine acceptance?** **No.**
5. **Is the consensus sender bound to the authenticated KEMTLS peer?** **No** — the sender is a
   self-declared wire field; peer NodeId is not propagated to the engine.
6. **Are received QCs and timeout certificates independently verified?** **No** for QCs
   (imported with empty signers); timeout verification is **optional/off by default**.
7. **Are production suite IDs unambiguous and fail-closed?** **No** — toy suite `0` is reachable
   and inbound suite ids are not gated. Consensus suite `0`, the Run 416 transport
   `sig_suite_id=100`, and ledger/tx suite ids are **separate namespaces**.
8. **Which issues are verified vulnerabilities vs incomplete vs unreachable vs unknown?** F3, F4,
   F6, F7, F8 are verified fail-open (deployed, reachable on a multi-node net); F5 and F2 are
   verified incomplete; F1 is fail-open in code but mitigated by current unreachability; no
   finding is UNKNOWN.
9. **Which finding must be fixed first?** **F6** — bind the authenticated KEMTLS
   peer/session to an authorized consensus sender — is a suitable **first, narrow**
   implementation target and provides **transport-level accountability**. It is
   **not** what makes cryptographic signature verification meaningful: proposal,
   vote, timeout, new-view, and QC signatures remain **independently necessary** for
   **message-level cryptographic authorship**. **Closing F6 alone will not close F3,
   F4, F5, F7, F8, RS1, C4, or C5.**
10. **What evidence will prove the fix?** A two-node deployed `qbind-node` run where (a) inbound
    proposals/votes carry the authenticated peer NodeId; (b) messages with a mismatched or
    unsigned identity, wrong/unknown suite, or forged QC are rejected with a counter; (c) all
    signatures use a production suite and a domain-separated preimage; captured on the deployed
    `binary_consensus_loop` path (not a harness).

## 7. Recommended smallest security-first sequence

1. **Run 418 (F6):** propagate the authenticated KEMTLS peer identity with each
   `ConsensusNetMsg` and bind it to an authorized consensus sender in
   `binary_consensus_loop`. The design must derive the remote `NodeId` from the
   authenticated KEMTLS session and resolve it through an **authoritative,
   unambiguous `NodeId → ValidatorId` mapping**; unknown, duplicate, ambiguous, or
   mismatched identities must **fail closed**. F6 delivers transport-level
   accountability only; it does **not** substitute for message-level signature
   verification and does **not** by itself close F3/F4/F5/F7/F8/RS1/C4/C5.
2. **Run 419 (F3/F4/F8):** sign proposals and votes over a domain-separated preimage with a
   production suite; verify signature + validator-set membership before engine acceptance;
   fail closed on suite `0`/unknown/disabled suites.
3. **Run 420 (F7/F5):** cryptographically verify imported QCs (extract/validate
   `signer_bitmap`/`signatures`) and make timeout/new-view verification mandatory.
4. **Run 421 (F1/F2):** only after authored consensus lands, gate transaction execution behind
   `>=1` authorization with an explicit, domain-separated genesis exemption plus threshold/weight
   and signer-dedup enforcement.

No future readiness closure is assigned in advance.

## 8. Execution and validation

See `docs/devnet/run_417_foundational_runtime_security_reconciliation/commands.txt` for exact
commands and exit codes. Summary:

- `cargo test -p qbind-ledger --test tx_auth_verifier_tests` → **9 passed** (includes
  `verify_transaction_auth_empty_auths_succeeds`, confirming F1).
- `cargo test -p qbind-consensus --lib` → **162 passed** (validator_set / verify_job /
  timeout_verify units exist but are not wired into the deployed vote/proposal path).
- `cargo fmt --all -- --check` → **exit 1 (fails)**. This is a **pre-existing,
  repo-wide** formatting difference in ~574 `.rs` files (e.g.
  `crates/qbind-consensus/src/basic_hotstuff_engine.rs:492`), present in the audited
  base commit; **Run 417 changed no Rust source and claims no formatting pass**. The
  affected files are not touched by Run 417, so the failure is pre-existing, not
  introduced by this run. (An earlier draft of this record and `commands.txt`
  incorrectly stated exit 0; corrected in the Run 417 corrective pass.)
- `git diff --check` → clean (exit 0).
- Run 404, 405, 410, 411, 412, 413, 414, 415 harnesses → all `RESULT=POSITIVE` (unchanged).
- `scripts/devnet/run_417_foundational_runtime_security_reconciliation_audit.sh` →
  `RESULT=POSITIVE-FOR-AUDIT-COMPLETENESS` / `SECURITY_VERDICT=NEGATIVE-FOR-RUNTIME-SECURITY`.
- `sha256sum -c SHA256SUMS.txt` inside the archive → OK.
- Tracked-tree secret/private-material scan → clean.
- `devnet-seeds.live.json` → absent; candidate → `status: planned`, `last_reachability_evidence:
  null`; C4/C5 → OPEN; public DevNet → NO-GO (all re-confirmed).
- CodeQL: see §10.

## 9. Documentation reconciliation

**No existing M/S status is downgraded**, because those M/S item definitions do **not** directly
encode deployed consensus authentication. **C4 OPEN is compatible with the findings but did not
independently prevent launch.** The audit instead exposed a **launch-governance coverage gap**;
the corrective pass added **RS1** as the independent launch-blocking control. **No F1–F8 finding is
resolved.** Updated:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — added an "Updated Run 417" narrative
  row (audit-only; statuses unchanged).
- `docs/whitepaper/contradiction.md` — added the Run 417 contradiction-ledger entry recording the
  audited deployed-path authentication boundary and the launch-governance coverage gap RS1 corrects.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — added a Run 417 note reaffirming C4/C5 OPEN and
  recording the reconciled deployed-path authentication scope.

No anchor file (ARTIFACT_INDEX / OPERATOR_VERIFICATION_MAP / LAUNCH_GO_NO_GO / BLOCKER_REGISTER /
package-integrity manifest, or any group VERIFY.md) was edited **by the original audit run**, so
the Run 404/405/410 package integrity manifests remained valid at that point. Run 416 remains
untouched historical external-reachability evidence.

### 9a. Run 417 corrective pass

The Run 417 corrective pass (a follow-up commit on top of the audit commit; docs + shell + JSON
only, no production Rust/dependency/runtime/deployment change) additionally:

- **Adds the explicit foundational runtime-security launch blocker `RS1 — Foundational runtime
  authentication and authorization` (`OPEN / launch-blocking`)** to
  `docs/release/public-devnet/BLOCKER_REGISTER.md`,
  `docs/release/public-devnet/LAUNCH_GO_NO_GO.md`,
  `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`,
  `docs/release/public-devnet/ARTIFACT_INDEX.md`,
  `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md`,
  `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`,
  `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md`, and
  `docs/whitepaper/contradiction.md`. RS1 tracks findings **F1–F8**. Public DevNet **GO requires
  both** every required must-have (M1–M20) Green **and** RS1 closed with executable evidence that
  the deployed consensus path is fail-closed; RS1 OPEN forces **NO-GO even if every M1–M20 item is
  Green**.
- **Corrects the stale Run 416 reachability wording** in `LAUNCH_GO_NO_GO.md`: Run 416 produced
  operator-attested Route A evidence of external TCP and KEMTLS mutual-auth static-root
  reachability using a temporary, discarded seed identity; it did not establish a durable
  operator-controlled seed identity, genesis pinning was not evidenced, and
  `devnet-seeds.live.json` remains absent — so **M4 remains Yellow / launch-blocking**.
- **Corrects the `cargo fmt` and CodeQL records** (see §8 and §10).
- **Refreshes the package-integrity anchor SHA-256 + byte-size** in
  `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` for the anchor docs edited
  above (`ARTIFACT_INDEX.md`, `OPERATOR_VERIFICATION_MAP.md`, `LAUNCH_GO_NO_GO.md`,
  `BLOCKER_REGISTER.md`), and re-runs Run 404/405/410–415 to confirm consistency.

This corrective pass resolves **no** F1–F8 finding, changes **no** runtime-security verdict, and
moves **no** readiness item Green. Adding RS1 closes a **launch-governance coverage gap** — the
Run 417 findings previously were not represented by an independent launch blocker.

## 10. CodeQL

CodeQL is **SKIPPED / NOT APPLICABLE** for the Run 417 corrective pass: the changes
are documentation, text, JSON, and shell verification-harness edits only and contain
**no analyzable production-code change** (no `.rs`, `Cargo.toml`, `Cargo.lock`,
`build.rs`, or dependency change). **No CodeQL coverage is claimed.** Secret scanning
is a **separate** control and does **not** substitute for CodeQL. This status is kept
consistent across `commands.txt`, this record, the archive summary/README, and the
final report.

## 11. Confirmations

- **No production behavior changed** (docs + audit-only shell only).
- **No live seed published**; `devnet-seeds.live.json` remains absent.
- **M4 remains Yellow**, **C4/C5 remain OPEN**, public DevNet remains **NO-GO**.
- **No readiness item moved Green.**
- **RS1 (foundational runtime authentication and authorization) is OPEN / launch-blocking**; the
  corrective pass adds it to the launch governance record but resolves no F1–F8 finding.
- Run 416 remains valid historical external-reachability evidence and is not weakened.

## 12. Remaining unknowns

- Behavioral confirmation of each fail-open case on a live two-node deployed net was **not**
  performed (would require production-source changes to sign/verify, which Run 417 forbids); the
  fail-open conclusions rest on end-to-end source tracing of the deployed path.
- Restore/catch-up QC import severity is bounded as Medium–High pending a wired verification path.