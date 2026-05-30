# QBIND DevNet Evidence Run 157 — Unified TestNet Fixture Universe

**Status:** Source/test fixture tooling only. No release-binary positive TestNet apply claim is made in this run.

Run 157 adds `run_157_unified_testnet_peer_apply_fixture_helper`, a fixture helper that mints one coherent TestNet universe for a future Run 158 positive peer-driven apply harness. The helper outputs `unified_testnet_manifest.json` and all paths needed by source tests and a later release-binary harness.

## What Run 157 fixes

Run 156 proved that the previous TestNet live transport universe and TestNet apply-candidate universe were disjoint: the live N=3 material came from `devnet_pqc_trust_bundle_helper signed-testnet`, while candidate/ratification material came from `run_133_v2_validation_only_fixture_helper`. The receiver correctly rejected that candidate before staging because it was not a valid successor of the live baseline trust state.

Run 157 fixes only that fixture-tooling blocker by minting, in one invocation:

- TestNet genesis and expected canonical genesis hash;
- baseline trust bundle at sequence 1;
- candidate trust bundle at sequence 2;
- v2 ratification sidecar for the candidate authority-domain sequence;
- seeded v2 authority marker at sequence 1;
- V0/V1/V2 leaf certificates and ML-KEM secret keys;
- one shared transport root used by both live transport certs and trust-bundle roots;
- valid and negative peer-candidate envelopes.

## Explicit non-claims

Run 157 does not claim full C4 or C5 closure. Release-binary positive TestNet apply evidence remains deferred to Run 158. MainNet remains refused / fixture-only; governance remains unimplemented; KMS/HSM remains unimplemented; signing-key rotation/revocation lifecycle remains open; validator-set rotation remains open.

Run 157 introduces no production MainNet enablement, no governance implementation, no KMS/HSM implementation, no signing-key rotation/revocation lifecycle, no validator-set rotation, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, no wire-format change, and no trust-bundle / ratification sidecar / authority-marker / sequence-file / peer-candidate envelope schema change.

## Validation targets

The focused source tests live in `crates/qbind-node/tests/run_157_unified_testnet_fixture_universe_tests.rs`. They cover manifest completeness, TestNet bundle validation, baseline-to-candidate successor ordering, v2 ratification verification, marker higher-sequence acceptance, peer-candidate validation-only acceptance, live P2P transport material coherence, dry-run command construction, and negative disjoint-universe / wrong-domain / bad-signature / rollback / equivocation / ambiguous-material cases.