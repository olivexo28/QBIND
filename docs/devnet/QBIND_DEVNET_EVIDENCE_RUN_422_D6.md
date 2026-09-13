# QBIND DevNet Evidence — Run 422 D6

Versioned Proposal/Vote signing-domain isolation (code + test).

```
RESULT=POSITIVE-FOR-PROPOSAL-VOTE-DOMAIN-ISOLATION-CODE-TEST
D6_STATUS=VERSIONED-PROPOSAL-VOTE-BOUNDARY-CODE-TEST-POSITIVE
D7_STATUS=UNRESOLVED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PROPOSAL_VOTE_AUTHORITY_FROM_LEGACY_CLI=DISALLOWED
LEGACY_TIMEOUT_CONTEXT=EXISTING-POLICY-PRESERVED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

This is a **CODE + TEST** evidence record. It contains no public deployment,
external-network, or standalone release-binary adversarial evidence. Security
(CodeQL) analysis status is reported separately and is not converted into a
zero-alert conclusion.

## Branch / ancestry

* Branch: `copilot/run-422-d6-versioned-proposal-vote-signing-domain`
* Accepted baseline: `5b7ea51a9b123e1952bd966b5e414531cd2ad898`
* The baseline object is available locally; `git merge-base HEAD <baseline>`
  returns the baseline, i.e. the baseline is a direct ancestor of this work
  (no invented ancestry, no squash reliance).
* Clone is shallow/single-branch; full history before the baseline is not
  present, which does not affect the baseline-relative comparison above.

## Prerequisites confirmed on the starting tree

* Separate `ProposalVoteAuthority` and `TimeoutVerificationContext` types.
* Production `proposal_vote_authority: None`.
* `ConsensusVerificationPolicy::Required` as the production default.
* Unconditional genesis-authority startup refusal.
* Preflight before P2P construction and consensus-task startup (D4).
* D4 process runner with finite deadlines and drained output.
* D5 combined-context, F6-ordering, cached-reemit, and active-restore tests.

## What changed

See `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md` for the full
specification. Summary:

* New module `crates/qbind-wire/src/pv_signing_domain.rs`:
  `ProposalVoteSigningDomainV2` (validated, immutable) + v2 preimage builders +
  format/family enums + typed error.
* `crates/qbind-wire/src/consensus.rs`: added `Vote::canonical_body()` and
  `BlockProposal::canonical_body()`; refactored the v1
  `signing_preimage_with_chain_id` to reuse them (v1 bytes byte-identical).
* `crates/qbind-consensus/src/proposal_vote_verify.rs`: fail-closed
  `verify_proposal_msg_with_preimage` / `verify_vote_msg_with_preimage`;
  the v1 functions delegate to the same core.
* `crates/qbind-node/src/binary_consensus_loop.rs`: optional
  `signing_domain` on `ProposalVoteAuthority`, wire-chain mismatch counters,
  inbound/outbound integration, and in-module `run422_d6` handler tests.
  Production stays `None`.

Diff vs baseline (7 files):

```
 crates/qbind-consensus/src/lib.rs                  |   3 +-
 crates/qbind-consensus/src/proposal_vote_verify.rs |  67 ++-
 .../tests/run_422_d6_pv_domain_isolation_tests.rs  | 613 +++++++++++++++++++++
 crates/qbind-node/src/binary_consensus_loop.rs     | 596 +++++++++++++++++++-
 crates/qbind-wire/src/consensus.rs                 |  70 ++-
 crates/qbind-wire/src/lib.rs                       |   1 +
 crates/qbind-wire/src/pv_signing_domain.rs         | 458 +++++++++++++++
```

## Test evidence

* `qbind-consensus` replay-isolation matrix
  (`run_422_d6_pv_domain_isolation_tests`, 19 tests, real ML-DSA-44 backend):
  same-key controls plus cross-chain (A, incl. two custom ids both mapping to
  legacy `UNK`), different genesis (B), different authority commitment (C),
  v1→v2 (D) and v2→v1 (E) cross-format rejection, wrong family (F), unsupported
  version with no fallback (G), tamper (H), the existing missing-sig / wrong
  key / unknown validator / wrong suite / unsupported suite taxonomy (I),
  invalid domain metadata fails construction (J), expected-wire-chain binding
  (K), plus deterministic golden vectors and a real-backend smoke check.
* `qbind-node` in-module `run422_d6` handler tests: correct-domain accept /
  foreign-domain reject for Proposal and Vote via the real handler + real F6
  gate + Required policy; wire `chain_id` mismatch rejected before crypto; F6
  mismatch precedes domain/crypto; missing PV authority rejects even with a
  valid Timeout context; outbound signs only under the selected domain.
* Regressions green: `qbind-wire` + `qbind-consensus` full suites,
  `qbind-node --lib` (1474), run_420 policy/reachability, run_422
  genesis/startup-refusal/D4, run_418 sender-binding/NewView.

Exact commands and counts are in
`run_422_d6_proposal_vote_domain_isolation/commands.txt` and
`.../test_results.txt`.

## Boundaries and blockers preserved

* Production `proposal_vote_authority` remains `None`; genesis-authority startup
  refusal remains in force; no activation CLI flag / env switch / fallback was
  added.
* Legacy Timeout/NewView context is unchanged and cannot establish
  Proposal/Vote authority.
* Runtime `ChainId` (u64) ↔ wire `chain_id` (u32) mapping remains unresolved;
  `expected_wire_chain_id` is supplied from trusted config only (fixtures/tests),
  never derived from messages. This blocks safe production construction.
* Downstream engine/QC verification still reconstructs the legacy preimage;
  v2 boundary success is not QC or engine validation.
* **D7 (authority freshness/lifetime) remains unresolved.**

## Preserved posture

F3/F4/F8 not fully activated; D7 unresolved; F1/F2/F5/F7 unresolved; F6 partial;
RS1 and C4/C5 OPEN; M4/M6/S5/S7 Yellow; Public DevNet **NO-GO**. No live seed
file or TestNet/MainNet readiness claim.