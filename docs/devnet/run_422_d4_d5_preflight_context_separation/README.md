RUN 422 D4/D5 — CONSENSUS-SECURITY PREFLIGHT AND MESSAGE-FAMILY CONTEXT SEPARATION
Evidence archive README

============================================================================
VERDICT (see summary.txt for the exact label block)
============================================================================

RESULT=POSITIVE-FOR-CONSENSUS-SECURITY-PREFLIGHT-AND-CONTEXT-SEPARATION-CODE-TEST
D4_STATUS=PRE-P2P-AND-CONSENSUS-PREFLIGHT-CODE-TEST-POSITIVE
D5_STATUS=MESSAGE-FAMILY-AUTHORITY-SEPARATION-CODE-TEST-POSITIVE
GENESIS_AUTHORITY_ACTIVATION=DISABLED-PENDING-REMAINING-BOUNDARIES
LEGACY_TIMEOUT_CONTEXT=EXISTING-POLICY-PRESERVED
PROPOSAL_VOTE_AUTHORITY_FROM_LEGACY_CLI=DISALLOWED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO

This archive is a CODE + TEST evidence archive. It does NOT contain public
deployment, external-network, or standalone release-binary adversarial
evidence. Security (CodeQL) analysis status is reported separately in
summary.txt and was NOT run to a zero-alert conclusion here.

============================================================================
SCOPE
============================================================================

This continuation completes the missing behavioral proof for two boundaries
that the reviewed D4/D5 implementation asserted but did not fully exercise:

  D4  Fatal consensus-security preflight failures occur BEFORE P2P service
      construction (builder.build()), peer dialing, and consensus-task
      startup. This is preflight-before-P2P-SERVICE-CONSTRUCTION, explicitly
      NOT before "any networking": the optional metrics HTTP task is started
      earlier in main() and is out of scope (see startup_order.txt).

  D5  Timeout/NewView authority cannot automatically establish Proposal/Vote
      authority. A valid legacy Timeout context coexists with an absent
      Proposal/Vote authority while Proposal/Vote remains fail-closed.

The reviewed implementation is preserved: distinct ProposalVoteAuthority and
TimeoutVerificationContext types, production proposal_vote_authority = None,
ConsensusVerificationPolicy::Required in production, legacy
--validator-consensus-key supplying ONLY Timeout/NewView authority,
run_p2p_consensus_security_preflight(...) called before builder.build(), and
the existing early refusal of --consensus-authority-from-genesis. This run
does not activate genesis authority and does not start Run 423.

============================================================================
REVISIONS
============================================================================

Accepted baseline (comparison base for this continuation):
  26fa246c769158c31cbb570d2d13ccb3a963928f

Reviewed D4/D5 implementation tip (named in the task):
  b709f7b30c26fccd2fc0b36f0855f5ce8e9a77c7
  NOTE: this object is ABSENT from the supplied shallow single-branch
  checkout (git cat-file -t reports "could not get object info"). The
  functionally equivalent reviewed D4/D5 work is present at the task-branch
  tip f14c3dd (parent = the accepted baseline 26fa246), which carries the
  D4 preflight-before-build wiring, the typed ProposalVoteAuthority /
  TimeoutVerificationContext split, and production proposal_vote_authority =
  None. This continuation builds on f14c3dd and records the deviation rather
  than claiming direct ancestry to an object not in the checkout.

Tested revision (all counts in test_results.txt were produced at):
  the current worktree tip of the supplied task branch. The task-named prior
  revision e1b95948c6ce604aa97f317e88f8c8b2e41a6b2b and the reviewed tip
  6ecec71439afec6c007d628ab6d31d5190b7be51 are BOTH ABSENT from this
  shallow/squashed single-branch checkout (git cat-file -t fails on each);
  the reviewed D4/D5 implementation is nonetheless demonstrably present in the
  worktree, so validation was executed against the current tip and the
  deviation is recorded here rather than claiming unverifiable ancestry.

This continuation additionally lands the follow-up review findings:
  A  Deadline-bounded, output-draining process runner for the D4 startup tests
     (crates/qbind-node/tests/run_422_d4_startup_ordering_tests.rs) — no
     unbounded wait; timeout is a TEST FAILURE; child killed+reaped on every
     path; corrected resource-discipline comments.
  B  Two new Required-policy library tests in binary_consensus_loop.rs:
     run422_d5g (late-peer re-emission suppression through the ACTUAL
     maybe_reemit_on_late_peer_connect) and run422_d5h (active restore-mode
     Proposal authority-unavailable rejection with a recording facade).
  C  Evidence-claim corrections throughout this archive (test-setup
     categories, Timeout attribution to run030, precise production-wiring and
     CodeQL status).

Final revision:
  The commit(s) that add/adjust this archive on the supplied task branch. The
  full SHA is recorded in the task's final report; this continuation changes
  only tests and documentation relative to the reviewed implementation.

Actual working branch (as supplied to this environment):
  copilot/copilotcopilotrun-422-follow-up-d4-d5-startup
  (NOTE the doubled "copilot" prefix vs. the task-named
  copilot/copilotrun-422-follow-up-d4-d5-startup; the environment supplied the
  former and it is reported verbatim rather than assumed.)

============================================================================
FILE INDEX
============================================================================

  README.md                  This file.
  summary.txt                Verdict block, scope, limitations, security note.
  source_trace.txt           Source-line trace of the D4 ordering and the D5
                             message-family split (main.rs + binary loop).
  activation_matrix.txt      Which configurations enable Timeout vs
                             Proposal/Vote authority, per message family.
  startup_order.txt          Exact P2P/consensus startup boundary and the
                             metrics HTTP exception.
  message_family_matrix.txt  Per-test message-family context table. It
                             distinguishes the setups: combined-context inbound
                             tests, F6-mismatch tests, action-forwarding tests,
                             the new cached/re-emission test (d5g), the new
                             active restore-mode test (d5h), and the
                             type/source-wiring inspection — NOT every test
                             supplies both contexts + origin + gate + facade.
  commands.txt               Exact commands, profiles, and features.
  test_results.txt           Test names, counts, and exit codes.
  SHA256SUMS.txt             SHA-256 of every publish-safe file here except
                             SHA256SUMS.txt and .gitignore.
  .gitignore                 Excludes private/generated material.

============================================================================
PRESERVED LIMITATIONS (unchanged by this run)
============================================================================

  * Genesis-authority activation remains DISABLED pending D4-D7.
  * D6 (signed-domain) and D7 (epoch/restore authority lifetime) UNRESOLVED.
  * F3/F4/F8 not fully remediated/activated in production; F6 partial;
    F1/F2/F5/F7 unresolved. F5 (TimeoutCertificate signer) is NOT closed.
  * RS1 and C4/C5 remain OPEN. M4/M6/S5/S7 remain Yellow.
  * Public DevNet remains NO-GO. No live seed / TestNet / MainNet claim.
  * Configured-authority RELEASE-BINARY adversarial evidence NOT captured
    (default-profile process tests are not standalone release-binary
    evidence).
  * Liveness limitation is intentional: under Required, absent Proposal/Vote
    authority means inbound Proposal/Vote are rejected and outbound
    Proposal/Vote are suppressed (fail-closed, not fail-open).