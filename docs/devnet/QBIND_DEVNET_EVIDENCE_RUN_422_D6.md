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

## Branch / ancestry (completion checkout and Ubuntu import)

* Completion task branch:
  `copilot/copilotcopilotrun-422-d6-corrective-continuation`.
  The supplied name differed from the expected
  `copilot/copilotrun-422-d6-corrective-continuation`; it was recorded,
  not renamed.
* Verified Git ancestry, oldest to newest:
  `2a18b47bb12843597ca1bd783bdf92e07f48cb7e` ->
  `7d87849892f25f3e84403b5a11f635e38f5a1127` ->
  `76246eb2fffc354085a892a4eca4a300104a752d` ->
  `4b9dae3e5489e3491bd27af7fa2dc8bc8b5662e4`.
* `76246eb2` contains the documentation corrections and one test-comment
  correction. `4b9dae3e` regenerates the archive checksum manifest.
  The final task tip's direct parent is `76246eb2`, not `7d87849`
  or `2a18b47`; earlier direct-parent descriptions are superseded.
* Ubuntu `main` was fast-forwarded from `7d878498` to `4b9dae3e`
  after fetching the task branch: two commits ahead, zero behind.
  This records the completed local import; a subsequent push is separate.
* The completion agent reported a shallow checkout with `2a18b47` as
  its earliest available commit. The reviewed tips `a071c53` and
  `010788b`, and historical bases `b585768` and `5b7ea51`, were
  unavailable in that checkout. Those missing-object observations describe
  the agent's checkout, not the later Ubuntu repository.
* `7d87849` already contains the implementation and both added Vote tests.
  The two imported commits change documentation and one comment only.
  Historical validation results retain their reported attribution.
  This import verifies ancestry and archive integrity; it does not rerun
  Cargo or independently establish historical test-execution SHAs.
* The task branch did not modify `main`; the operator performed the later
  fast-forward. No rebase, amend, force-push, or PR was used for this import.

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
* `crates/qbind-consensus/src/proposal_vote_verify.rs`: fail-closed **public,
  message-bound** entrypoints `verify_proposal_msg_with_domain` /
  `verify_vote_msg_with_domain` (they recompute the canonical preimage from the
  actual message + trusted domain and enforce wire-chain consistency before
  crypto). The raw-preimage helpers `verify_*_with_preimage` are **private**
  (not a caller entrypoint); the v1 functions delegate to the same core.
* `crates/qbind-node/src/binary_consensus_loop.rs`: **mandatory**
  `signing_domain: ProposalVoteSigningDomainV2` on `ProposalVoteAuthority` (not
  `Option`; there is no missing-domain → legacy-v1 selection), typed inbound
  `WireChainMismatch` before crypto, outbound wire-chain refusal before signing,
  and in-module `run422_d6` handler tests. Production stays `None`.

> **Reconciliation note (completion pass).** Earlier D6 records described an
> `Option<ProposalVoteSigningDomainV2>` field and public
> `verify_*_with_preimage` entrypoints. Those implementation descriptions are
> **superseded**: the domain is mandatory and the public entrypoints are the
> message-bound `verify_*_with_domain` (raw-preimage helpers are private). The
> diff-stat block below is the **original corrective** diff vs the historical
> baseline and is retained as a historical record. The earlier Vote-test
> completion added the two coverage tests; they are already present at
> `7d87849`. The subsequent two imported commits correct documentation,
> one test comment, and archive checksums only.

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
  (`run_422_d6_pv_domain_isolation_tests`, **34** tests, real ML-DSA-44
  backend): same-key controls plus cross-chain (A), different genesis (B),
  different authority commitment (C), v1→v2 (D) and v2→v1 (E) cross-format
  rejection, wrong family (F), unsupported version with no fallback (G), tamper
  (H), the missing-sig / wrong key / unknown validator / wrong suite /
  unsupported-suite taxonomy (I), invalid domain metadata fails construction
  (J), expected-wire-chain binding (K), the Vote replay family (`ca_vote_*`),
  family-byte isolation (`cb_*`), the stale-preimage substitution guard, the
  full independent Proposal vector, deterministic golden vectors, and a
  real-backend smoke check.
* **UnsupportedSuite vs BackendError** (gap B): a **missing** backend for the
  governed suite yields `UnsupportedSuite` through the public
  `verify_proposal_msg_with_domain` / `verify_vote_msg_with_domain`
  (`case_i_unsupported_suite_no_backend_rejected` for Proposal and
  `case_i_unsupported_suite_no_backend_rejected_vote` for Vote). This is
  **distinct** from a registered-but-faulting backend, which maps to
  `BackendError` (`cc_backend_error_distinct_from_unsupported_suite`, both
  families). `UnsupportedSuite` is not evidence of a backend fault.
* `qbind-node` in-module `run422_d6` handler tests (**10**): correct-domain
  accept / foreign-domain reject for Proposal and Vote via the real handler +
  real F6 gate + Required policy; wire `chain_id` mismatch rejected before
  crypto; F6 mismatch precedes domain/crypto; missing PV authority rejects even
  with a valid Timeout context; outbound signs only under the selected domain;
  **active-restore foreign-domain rejection with no effects** and **v2 cached
  re-emission on late-peer connect** (so v2 cache/restore behavior is proven by
  actual v2-authority tests — D5 coverage, which wires no PV authority, is NOT
  sufficient proof of v2 cache/restore); and the independent **outbound Vote
  wire-chain refusal** through `forward_actions_to_facade`
  (`run422_d6_outbound_vote_wire_chain_refusal_through_forward_actions`, gap A),
  which directly observes that the signer is not invoked on refusal.
* Regressions green: `qbind-wire` lib (9, all `pv_signing_domain`) +
  `qbind-consensus` lib (182) + integration/doctests, `qbind-node --lib`
  (**1478**), run_420 policy/reachability (3); run_422
  genesis/startup-refusal/D4 and run_418 sender-binding/NewView preserved from
  the corrective revision.

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
