RUN 422 D7 — GENESIS-STATIC CONSENSUS-AUTHORITY FRESHNESS / LIFETIME
Evidence archive README
============================================================================

VERDICT (see summary.txt for the exact label block)
============================================================================

RESULT=POSITIVE-FOR-GENESIS-STATIC-AUTHORITY-LIFETIME-CODE-TEST
D7_STATUS=GENESIS-STATIC-LIFETIME-STALE-KEY-GUARD-CODE-TEST-POSITIVE
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PROPOSAL_VOTE_AUTHORITY_FROM_LEGACY_CLI=DISALLOWED
LEGACY_TIMEOUT_CONTEXT=EXISTING-POLICY-PRESERVED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO

This archive is a CODE + TEST evidence archive. It contains no public
deployment, external-network, or standalone release-binary adversarial
evidence. Security (CodeQL) analysis status is reported separately in
summary.txt and is NOT converted into a zero-alert conclusion.

============================================================================
SCOPE
============================================================================

D7 addresses the last open genesis-authority defect from the Run 422
containment review: an immutable authority PROVIDER does not, by itself,
prove continued authorization across epoch / membership / restore
transitions. D6 (versioned Proposal/Vote signing-domain isolation) is
complete; D7 adds and tests the genesis-static authority lifetime /
freshness guard.

D7 implements an additive, fail-closed lifetime guard on the immutable
`GenesisConsensusAuthority` snapshot:

  * `GENESIS_STATIC_AUTHORITY_EPOCH = 0` — the single founding epoch a
    genesis-static authority is valid for (QBIND genesis is epoch 0).
  * `ObservedConsensusConfiguration` — the already-validated live
    configuration identity a caller presents (chain id, canonical genesis
    hash, authority commitment, membership count, epoch). The epoch is
    supplied from a validated source; it is never synthesized here and is
    never used to activate a trust bundle.
  * `GenesisConsensusAuthority::authorize_configuration(&observed)` —
    returns Ok only for the exact founding configuration at the founding
    epoch; otherwise fails closed with a bounded `AuthorityLifetimeError`
    (ChainIdChanged / GenesisHashChanged / MembershipCountChanged /
    AuthorityCommitmentChanged / EpochTransitionUnauthorized).

Because this run implements NO key rotation, revocation, or membership
transition (task section 10), any epoch other than the founding epoch, or
any changed chain / genesis / commitment / membership, has NO authorized
transition and is rejected. This is a real stale-key guard, not an
operational note.

The guard is implemented and tested only. It is NOT wired to any production
activation: production `proposal_vote_authority` stays None, the
genesis-authority startup refusal is preserved (release binary exits 1 with
"genesis-authority activation is disabled pending D4-D7"), and no CLI flag /
environment switch / fallback enables a genesis-static authority in a
release binary. Configured-authority release-binary adversarial evidence
remains deferred to Run 423.

============================================================================
ARCHIVE CONTENTS
============================================================================

README.md               This file.
summary.txt             Full summary and exact verdict block.
source_trace.txt        Exact source additions (types, guard, ordering) with
                        file/line anchors, and unchanged-boundary inventory.
lifetime_matrix.txt     The lifetime/freshness rejection matrix mapped to the
                        section 12.E test cases.
commands.txt            Exact validation commands and their results/exit codes.
test_results.txt        Test target names and pass counts.
SHA256SUMS.txt          SHA-256 of every publish-safe archive file except
                        itself and .gitignore.
.gitignore              Excludes private/generated material.

============================================================================
CANONICAL DOCUMENTS
============================================================================

docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md    D7 canonical evidence doc.
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D6.md    D6 (predecessor) evidence.
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422.md       Run 422 containment record.

============================================================================
PRESERVED POSTURE (UNCHANGED BY D7)
============================================================================

Production genesis-authority activation stays DISABLED and the standalone
release binary refuses `--consensus-authority-from-genesis` (exit 1) before
any P2P service / consensus task. F3/F4/F8 not fully activated in
production; F1/F2/F5/F7 unresolved; F6 partial; RS1 and C4/C5 OPEN;
M4/M6/S5/S7 Yellow; Public DevNet NO-GO. No live seed file, no
TestNet/MainNet readiness claim, no readiness item moved Green.