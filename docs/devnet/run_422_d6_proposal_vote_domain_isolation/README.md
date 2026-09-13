RUN 422 D6 — VERSIONED PROPOSAL/VOTE SIGNING-DOMAIN ISOLATION
Evidence archive README
============================================================================

VERDICT (see summary.txt for the exact label block)
============================================================================

RESULT=POSITIVE-FOR-PROPOSAL-VOTE-DOMAIN-ISOLATION-CODE-TEST
D6_STATUS=VERSIONED-PROPOSAL-VOTE-BOUNDARY-CODE-TEST-POSITIVE
D7_STATUS=UNRESOLVED
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

Run 422 D6 implements and tests an explicitly versioned Proposal/Vote signing
domain (v2) that cryptographically binds a consensus signature to the intended
network and accepted-authority snapshot. A signature produced for one domain
does not authenticate the same message under a different domain, even when the
signing key, validator index, message payload, and wire chain_id are all
unchanged.

The v2 domain is implemented and tested only. It is NOT wired to any production
authority: production proposal_vote_authority stays None, the genesis-authority
startup refusal is preserved, and no CLI flag / environment switch / fallback
can enable a v2-backed authority in a release binary. Authority
freshness/lifetime activation (D7) remains unresolved.

============================================================================
ARCHIVE CONTENTS
============================================================================

README.md               This file.
summary.txt             Full summary and exact verdict block.
source_trace.txt        Call-site inventory (legacy vs v2 boundary vs other
                        consumers vs Timeout/NewView unchanged).
domain_format.txt       Exact v2 byte layout + golden-vector references.
replay_matrix.txt       Cryptographic replay-isolation matrix (cases A–K) with
                        same-key controls.
compatibility_matrix.txt v1<->v2 compatibility and downstream dependencies.
commands.txt            Exact validation commands and results.
test_results.txt        Test target names and pass counts.
SHA256SUMS.txt          SHA-256 of every publish-safe archive file except
                        itself and .gitignore.
.gitignore              Excludes private/generated material.

============================================================================
CANONICAL DOCUMENTS
============================================================================

Specification: docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md
Evidence:      docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D6.md

============================================================================
PRESERVED POSTURE
============================================================================

F3/F4/F8 not fully activated; D7 unresolved; F1/F2/F5/F7 unresolved; F6
partial; RS1 and C4/C5 OPEN; M4/M6/S5/S7 Yellow; Public DevNet NO-GO. No live
seed file or TestNet/MainNet readiness claim.
