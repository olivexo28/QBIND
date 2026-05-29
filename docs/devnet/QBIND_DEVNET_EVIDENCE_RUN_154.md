# QBIND DevNet Evidence — Run 154

## Subject

Run 154: **source/test TestNet fixture tooling** for a future Run 155
release-binary TestNet peer-driven apply evidence harness.

## Verdict

**Source/test fixture tooling only.**

Run 154 adds the smallest TestNet fixture tooling required to produce
signed TestNet trust-bundle material, v2 ratification sidecars, transport
credentials, and peer-candidate `0x05` fixtures. It closes the
fixture-tooling blocker that caused the **Run 153 A2 TestNet evidence to
be deferred**.

Run 154 does **NOT** run or claim release-binary TestNet end-to-end apply
closure. Release-binary TestNet end-to-end peer-driven apply evidence
remains **deferred to Run 155**.

## Source Delta

Run 154 extends the existing Run 133 v2 fixture helper rather than
creating a parallel system. There is **no production runtime source
change**.

1. `crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`
   - The environment loop now also mints a `testnet/` fixture directory
     (`Devnet`, `Mainnet`, **`Testnet`**).
   - A TestNet-only generator writes an explicit valid v2 peer-candidate
     `0x05` envelope plus the negative peer-candidate matrix
     (lower-sequence, same-sequence different-digest, bad-signature,
     wrong-environment, wrong-chain, duplicate). These are written
     **only** under `testnet/`, so DevNet and MainNet output remain
     byte-for-byte unchanged.
   - The shared per-environment matrix (signed baseline/candidate trust
     bundles, ML-DSA-44 bundle-signing public key spec, v1 + v2
     ratification sidecars including lower/equivocation/bad-signature/
     wrong-environment/wrong-chain/wrong-genesis/sequence-zero, and
     seeded v1/v2 markers) is now produced for TestNet too.

2. `crates/qbind-node/tests/run_154_testnet_peer_apply_fixture_tests.rs`
   - New test suite (21 tests) that mints TestNet material with the same
     public library APIs the helper uses and proves the verify/reject
     matrix below.

No new CLI flag. No new library code. No new wire format. No
trust-bundle / ratification-sidecar / authority-marker / sequence-file /
peer-candidate-envelope schema change. No new metric family.

## Generated TestNet Material

Every TestNet artifact is explicitly domain-bound:

- `environment = TestNet`;
- TestNet `chain_id` (`qbind-testnet-v0` genesis chain id /
  `51424e4454535400` chain-id hex);
- TestNet genesis hash (canonical hash over the TestNet genesis bound to
  the minted authority key);
- the minted authority-root fingerprint;
- the correct v2 authority-domain sequence.

Artifacts written under `<outdir>/testnet/`:

- `genesis.json` + `expected-genesis-hash.txt` — TestNet genesis /
  runtime-domain metadata;
- `baseline-bundle.json` / `candidate-bundle.json` — signed TestNet trust
  bundles;
- `signing-key.ratified.spec` — ML-DSA-44 bundle-signing public key spec;
- `ratification.v1.valid.json` — v1 regression sidecar;
- `ratification.v2.*.json` — v2 ratification sidecars (ratify@seq1/seq2,
  rotate, revoke, same, equivocation, lower, bad-signature,
  wrong-environment, wrong-chain, wrong-genesis, sequence-zero);
- `seed-marker.v1.json` / `seed-marker.v2.seq1.json` /
  `seed-marker.v2.seq2.json` — seeded markers;
- `peer-candidate.json` / `peer-candidate.valid.json` — valid v2
  peer-candidate `0x05` fixtures;
- `peer-candidate.duplicate.json`,
  `peer-candidate.lower-sequence.json`,
  `peer-candidate.same-sequence-different-digest.json`,
  `peer-candidate.bad-signature.json`,
  `peer-candidate.wrong-environment.json`,
  `peer-candidate.wrong-chain.json` — invalid negative peer-candidate
  fixtures.

Transport root / leaf credentials suitable for mutual-auth TestNet
evidence are produced by the existing DevNet/TestNet helper crates
(`devnet_pqc_root_helper`, `devnet_pqc_trust_bundle_helper`,
`devnet_consensus_signer_keystore_helper`) reused verbatim by the Run 155
harness; Run 154's helper mints the ephemeral transport root that the
trust bundles are anchored to.

### Ambiguous v1+v2 and expired material

- **Ambiguous v1+v2**: both `ratification.v1.valid.json` and the
  `ratification.v2.*.json` sidecars are present under `testnet/`; the
  ambiguity fail-closed path is the simultaneous presence of both, which
  the live `0x05` dispatcher (Run 142) and the operator sidecar loader
  reject.
- **Expired candidate**: candidate expiry is a runtime property of the
  Run 145 staging queue TTL (`PeerCandidateStagingQueue::purge_expired`),
  not an envelope field, and is covered by the Run 145 / Run 150 staging
  TTL tests. A valid TestNet peer-candidate fixture replayed past the
  staging TTL exercises that path.

### Determinism

The TestNet domain fields are deterministic (`environment`, `chain_id`,
genesis chain id). The following fields are **non-deterministic** and are
recorded explicitly: the ephemeral ML-DSA-44 authority key, bundle-signing
keys, the ephemeral transport root, all signatures, and the canonical
genesis hash (which is derived from the minted authority key). Evidence
harnesses must capture these per-run rather than assuming fixed values.

## Verify / Reject Matrix (source/test)

Proven in `run_154_testnet_peer_apply_fixture_tests.rs` (21/21 green):

| Scenario | Expectation |
|----------|-------------|
| TestNet valid bundle under TestNet context | verifies |
| TestNet valid v2 ratification under TestNet context | verifies |
| TestNet peer-candidate under TestNet context | validates |
| TestNet bundle under DevNet context | fails |
| TestNet bundle under MainNet context | fails (MainNet refused) |
| TestNet v2 ratification under DevNet context | fails |
| TestNet v2 ratification under MainNet context | fails (MainNet refused) |
| TestNet peer-candidate under DevNet context | rejected |
| TestNet peer-candidate under MainNet context | rejected |
| wrong-chain v2 ratification | fails |
| wrong-genesis v2 ratification | fails |
| bad-signature v2 ratification | fails |
| bad-signature bundle | fails |
| lower-sequence (vs seq=5 marker) | fails via v2 marker comparison |
| same-sequence different-digest (vs seq=3 marker) | fails via v2 marker comparison |
| higher-sequence (vs seq=3 marker) | accepted (upgrade-compatible) |
| TestNet artifacts domain-bound | env/chain/genesis/authority/sequence asserted |
| DevNet fixture behaviour | unchanged + distinct from TestNet |
| domain fields deterministic / keys non-deterministic | asserted |
| no production anchor / no fallback root or signing key | asserted (ephemeral) |
| Run 133 helper mints TestNet | asserted |

The lower-sequence and same-sequence different-digest rejections route
through the validation-only v2 authority-marker comparison
(`verify_marker_for_validation_only_v2`); the on-disk marker is
byte-identical pre/post in every marker-comparison test.

## Validation Results

### Build

```
cargo build -p qbind-node --lib                                            # ✅
cargo build -p qbind-node --example run_133_v2_validation_only_fixture_helper  # ✅
```

### Tests

```
cargo test -p qbind-node --test run_154_testnet_peer_apply_fixture_tests   # 21 passed ✅
cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests  # 23 passed ✅
cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests      # 19 passed ✅
cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests     # 20 passed ✅
cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests  # 16 passed ✅
cargo test -p qbind-node --lib pqc_authority                               # 148 passed ✅
cargo test -p qbind-node --lib                                             # 1277 passed ✅
```

> No Run 153 source-level test target exists (Run 153 is a release-binary
> harness/script); the closest source/test target — Run 152 — is run
> instead, per the task's allowance.

## Denylist / Negative Invariants

- ❌ No production MainNet enablement (MainNet remains refused).
- ❌ No governance implementation.
- ❌ No KMS/HSM implementation.
- ❌ No signing-key rotation/revocation lifecycle.
- ❌ No validator-set rotation.
- ❌ No autonomous background drain.
- ❌ No automatic apply on receipt.
- ❌ No peer-majority authority.
- ❌ No new wire format.
- ❌ No trust-bundle / ratification-sidecar / authority-marker /
  sequence-file / peer-candidate-envelope schema change.
- ❌ No weakening of Runs 070, 142, 143, 145–153.
- ❌ No production source-code anchor introduced.
- ❌ No fallback root or fallback signing key introduced.

## Required Statements

- Run 154 is **source/test fixture tooling only**.
- It closes the fixture-tooling blocker that caused the Run 153 A2
  TestNet evidence to be deferred.
- Release-binary TestNet end-to-end peer-driven apply evidence remains
  **deferred to Run 155**.
- MainNet remains refused.
- Governance remains unimplemented.
- KMS/HSM remains unimplemented.
- Signing-key rotation/revocation lifecycle remains open.
- Validator-set rotation remains open.
- Full C4 remains open.
- C5 remains open.

## Cross-References

- `task/RUN_154_TASK.txt` — task specification
- `crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs` — fixture helper (extended)
- `crates/qbind-node/tests/run_154_testnet_peer_apply_fixture_tests.rs` — Run 154 fixture tests
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_153.md` — Run 153 evidence (A2 deferral)
- `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` — safety spec
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — authority model
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — operator playbook
- `docs/whitepaper/contradiction.md` — contradiction tracker
