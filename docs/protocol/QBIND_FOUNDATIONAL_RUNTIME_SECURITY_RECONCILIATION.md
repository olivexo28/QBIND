# QBIND Foundational Runtime-Security Reconciliation

**Status:** Active reconciliation record. First established by **Run 417**
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_417.md`).
**Scope:** the four foundational authentication boundaries of the **deployed** `qbind-node`
binary. **This document reconciles source, runtime, and readiness claims; it does not implement
fixes and asserts no launch readiness.**

**Safety envelope:** DevNet · experimental · audit/evidence only · **no production behavior
changed** · NOT launch-ready · M4 Yellow · M6 Yellow/Partial · S5/S7 Yellow · **RS1 OPEN /
launch-blocking** · **C4/C5 OPEN** · public DevNet **NO-GO**. No TestNet/MainNet readiness claim.
No private key material committed.

## 1. Purpose

Establish, from source-to-runtime tracing, **what the deployed binary actually enforces** at its
authentication boundaries, so that documentation and readiness statuses cannot overstate the
implementation. The authoritative deployed consensus driver is
`crates/qbind-node/src/binary_consensus_loop.rs` (spawned by `main.rs`); the signing/verifying
`crates/qbind-node/src/hotstuff_node_sim.rs` harness is **not** on the deployed path.

## 2. Reconciled boundaries (Run 417)

### 2.1 Transaction authentication
- `verify_transaction_auth` accepts empty `auths` unconditionally
  (`crates/qbind-ledger/src/auth.rs:31-33`); thresholds/weights are unenforced
  (`auth.rs:22-23`); no signer/key dedup (`auth.rs:37-39`). Per-auth suite/key/signature checks
  are otherwise fail-closed (`auth.rs:52-100`). Signing bytes are domain-separated (`QBIND:TX`)
  and bind chain_id/nonce/body but exclude `auths[]` (`crates/qbind-hash/src/tx.rs`).
- **Deployed reachability:** none today — no tx ingress, empty proposals
  (`basic_hotstuff_engine.rs:1359,1381`), and `Node::apply_block` (`qbind-node/src/lib.rs:2553`)
  is invoked only by test harnesses (`hotstuff_node_sim.rs:3156`, `execution_adapter` tests).
- **Classification:** VERIFIED-FAIL-OPEN (code) / MITIGATED-BY-CURRENT-UNREACHABILITY (deployed).

### 2.2 Consensus message authentication
- Proposals and votes are constructed **unsigned** (`signature: vec![]`) with the toy suite id
  `0` (`basic_hotstuff_engine.rs:1357-1382`, `:1537-1539`;
  `crates/qbind-wire/src/consensus.rs:13-18`). Inbound proposals/votes are accepted with only
  epoch/leader/view checks and **no** signature/membership/suite verification
  (`binary_consensus_loop.rs:2666-2714`, `:2726-2761`). Timeout/new-view verification is
  **optional and off by default** (`binary_consensus_loop.rs:788,2827-2829`).
- **Classification:** VERIFIED-FAIL-OPEN (proposals/votes/suite); VERIFIED-INCOMPLETE (timeout).

### 2.3 Authenticated peer → consensus sender binding
- KEMTLS authenticates the transport (leaf key / derived NodeId). That identity is **not**
  propagated with consensus messages: `handle_consensus_msg(msg)` carries no sender
  (`p2p_inbound.rs:83`), unlike `handle_dag_msg_from(_, sender: NodeId)` (`p2p_inbound.rs:118`);
  `ChannelConsensusHandler` forwards only `ConsensusNetMsg` (`p2p_inbound.rs:359-388`). The engine
  sender is the self-declared `proposer_index`/`validator_index`
  (`binary_consensus_loop.rs:2682,2730`). Connection authentication and consensus-message
  authentication are **independent**; KEMTLS admission is **not** a substitute for consensus
  authorship authentication.
- **Classification:** VERIFIED-FAIL-OPEN.

### 2.4 Quorum certificate and suite enforcement
- A proposal-carried QC is imported with **empty** signer evidence
  (`basic_hotstuff_engine.rs:1493`); the wire QC's `signer_bitmap`/`signatures`
  (`consensus.rs:266-267`) are discarded and never cryptographically verified. The local vote
  accumulator dedups voters and enforces membership/quorum (`vote_accumulator.rs`, `qc.rs`) but
  only over self-declared `ValidatorId`s. No inbound suite gating exists; suite `0` is reachable.
- **Classification:** VERIFIED-FAIL-OPEN.

## 3. Suite-namespace reconciliation

Three separate suite namespaces must not be conflated:

| Namespace | Deployed value | Source |
|-----------|----------------|--------|
| Consensus message suite | `0` (toy, "NOT FOR PRODUCTION") | `consensus.rs:13-18` |
| Transport / KEMTLS provider suite | `100` (ml-dsa-44) — Run 416 captured log | Run 416 evidence |
| Ledger / transaction suite | resolved via `CryptoProvider` per auth | `auth.rs:89` |

Run 416's `sig_suite_id=100` is a **transport** value and is **not** evidence that consensus
messages or transactions use ML-DSA-44.

## 4. Relationship to C4/C5, RS1, and readiness

These findings are consistent with, and further specify, **C4 OPEN** (the deployed binary does
not boot a fully operating, authenticated node) and **M4/M6 Yellow**. Run 417 requires **no
downgrade** because no current document claims deployed consensus/transaction authentication.
Run 417 moves **no** item Green.

The Run 417 corrective pass adds an **independent, launch-blocking** governance blocker,
**`RS1 — Foundational runtime authentication and authorization` (`OPEN / launch-blocking`)**, to
carry findings **F1–F8** in the launch decision. RS1 is recorded in
`docs/release/public-devnet/BLOCKER_REGISTER.md`,
`docs/release/public-devnet/LAUNCH_GO_NO_GO.md`,
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`,
`docs/release/public-devnet/ARTIFACT_INDEX.md`,
`docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md`,
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and `docs/whitepaper/contradiction.md`. **Public
DevNet GO requires both** every required must-have (M1–M20) Green **and** RS1 closed with
executable evidence that the deployed consensus path is fail-closed; RS1 OPEN forces **NO-GO even
if every M1–M20 item is Green**. RS1 is **distinct from C4/C5**: adding it closes a launch-governance
coverage gap, not any F1–F8 finding, and it changes no runtime-security verdict.

## 5. Smallest security-first follow-up sequence

**F6 is a suitable first, narrow implementation target, but it is not what makes cryptographic
signature verification meaningful.** F6 is required for **binding an authenticated KEMTLS
peer/session to an authorized consensus sender** and for **transport-level accountability**;
proposal, vote, timeout, new-view, and QC signatures remain **independently necessary** for
**message-level cryptographic authorship**. **Closing F6 alone will not close F3, F4, F5, F7, F8,
RS1, C4, or C5.**

1. Bind the authenticated KEMTLS peer/session to an authorized consensus sender (**F6**). The
   future Run 418 design must derive the remote `NodeId` from the authenticated KEMTLS session and
   resolve it through an authoritative, unambiguous `NodeId → ValidatorId` mapping; unknown,
   duplicate, ambiguous, or mismatched identities must **fail closed**. (Design only — not
   implemented in this corrective pass.)
2. Sign + verify proposals/votes with a production suite; reject suite `0`/unknown (**F3/F4/F8**).
3. Cryptographically verify imported QCs; make timeout/new-view verification mandatory (**F7/F5**).
4. Only then gate transaction execution behind `>=1` auth + threshold/weight/dedup with an explicit
   genesis exemption (**F1/F2**). F1/F2 must be resolved **before** transaction ingress is enabled;
   their current lack of ingress is a **reachability mitigation, not cryptographic closure**.

Fix evidence must be captured on the deployed `binary_consensus_loop` path (not a harness), showing
rejection of mismatched-identity, unsigned, wrong-suite, and forged-QC inputs with counters.

## 6. Provenance

- Canonical evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_417.md`.
- Source trace and findings matrix:
  `docs/devnet/run_417_foundational_runtime_security_reconciliation/`.
- Audit harness: `scripts/devnet/run_417_foundational_runtime_security_reconciliation_audit.sh`.
- Audited base commit `cb4c4dc94eaaa46689be15358ba48921e98a7797` (working tree `32b6561`,
  task-file-only delta).