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

## Branch / ancestry (rechecked at the completion pass)

Recoverable facts verified with `git` in this shallow, single-branch clone
(historical bases from earlier passes are **not** re-derived here):

* Task branch (actual name in this clone):
  `copilot/copilotcopilotrun-422-d6-corrective-continuation`. The prompt's
  *expected* name was `copilot/copilotrun-422-d6-corrective-continuation`; the
  actual branch carries a **doubled `copilot`** segment. Recorded, not renamed.
* Available ancestry: the completion tip of this branch is the commit produced by
  this documentation pass (its own SHA cannot be embedded in its own committed
  text; it is the branch tip after commit). Its parent documentation commit is
  `7d87849892f25f3e84403b5a11f635e38f5a1127`, whose parent is
  `2a18b47bb12843597ca1bd783bdf92e07f48cb7e` — the **earliest commit present**
  in this clone (`git rev-list --parents -n 1` shows it with no parent object
  here).
* Tested implementation/worktree identity vs the documentation commit: the D6
  implementation and the 34 consensus + 10 node tests are the source tree at
  `7d87849…`. This completion pass changes only documentation plus a **single
  test comment** on top of it; the two identities are kept distinct and the doc
  commit is not presented as the tested implementation revision.
* **NOT present** locally (`git cat-file -t` → missing): the prompt's reviewed
  tip `a071c53caa4700b9a00b0d1fb8fe17071a267887`, the earlier reviewed tip
  `010788bcd00bb3725cebc0e8fe26f3502a2c00d4`, and the historical bases
  `b585768de8ea79f22f16a6f3c028bfee3f9c6ed7` and
  `5b7ea51a9b123e1952bd966b5e414531cd2ad898`. Their exact relationships cannot
  be reproven here; matching diff statistics alone would not prove identical
  source or ancestry, and no merge-base against a missing object is re-executed.
* No fast-forward importability from any historical baseline is claimed.
  Integration with `main` is left for a separate reviewed step. This completion
  pass adds only documentation (plus the one test comment) and does not modify
  `main`, rebase, amend, or open a PR.
* Clone is shallow/single-branch; full history before `2a18b47` is not present.

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
> baseline and is retained as a historical record; this completion pass adds
> only the two Vote coverage tests (gap A in `binary_consensus_loop.rs`, gap B
> in the crypto test) plus this documentation reconciliation.

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
