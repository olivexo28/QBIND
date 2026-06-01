# QBIND DevNet Evidence — Run 163

## Subject

Run 163: **source/test governance ratification authority verifier** for
v2 bundle-signing-key lifecycle transitions
(`crates/qbind-node/src/pqc_governance_authority.rs`,
`verify_governance_authority_proof`,
`validate_lifecycle_with_governance_authority`,
`GovernanceAuthorityProof`, `GovernanceAuthorityClass`,
`GovernanceAuthorityVerificationOutcome`,
`CombinedLifecycleGovernanceOutcome`,
`GovernanceIssuerSignatureVerifier`,
`FixtureIssuerSignatureVerifier`, `GovernanceThreshold`).

Run 163 builds on top of Run 159 (typed pure v2 lifecycle validator),
Run 161 (lifecycle validator wired into the shared marker-decision
helper), and Run 162 (release-binary lifecycle enforcement evidence).

Run 163 is **source/test only**. It does **not**:

* enable MainNet peer-driven apply,
* implement a governance execution engine,
* implement on-chain governance integration,
* implement KMS/HSM custody,
* implement validator-set rotation,
* mutate any live trust state,
* write a v2 marker, sequence file, or trust bundle,
* introduce a new wire format,
* introduce a marker schema change,
* introduce a sequence-file schema change,
* introduce a trust-bundle schema change,
* weaken any Run 070 / Run 130–162 acceptance or rejection behaviour.

**Release-binary governance verifier evidence is deferred to Run 164.**

## Verdict

Run 163 lands a **typed, pure, non-mutating governance ratification
authority verifier** that defines and validates the local proof object
that, in a future run, can authorize MainNet/TestNet governance-
controlled bundle-signing-key lifecycle transitions. The verifier:

* is **pure**: performs no I/O, never reads or writes a sequence
  file, never touches the persisted v2 marker, never mutates a live
  trust bundle;
* is **typed**: its decision is a single
  [`GovernanceAuthorityVerificationOutcome`] enum value, with
  separate accept variants for `AcceptedGenesisBound`,
  `AcceptedEmergencyCouncil`, and `AcceptedIdempotent`, and precise
  reject variants for every binding (env, chain, genesis, authority
  root, lifecycle action, candidate digest, sequence, signature,
  suite, threshold, replay, malformed proof, on-chain unsupported,
  local-operator-config-only, peer-majority);
* is **fail-closed** for `OnChainGovernance`: no on-chain proof
  format exists, the verifier rejects with
  `UnsupportedOnChainGovernance`;
* is **integration-bounded**: NOT wired into mutating apply surfaces;
  the pure helper `validate_lifecycle_with_governance_authority`
  composes Run 159 lifecycle validation + Run 163 governance
  authority verification into a single typed combined decision and
  is itself non-mutating.

Acceptance from this verifier carries **no side effect**: it does not
write a marker, does not write a sequence number, does not mutate
`LivePqcTrustState`, does not evict sessions, does not begin Run 070
apply, and does not enable MainNet peer-driven apply.

## Scope summary

| Item                                         | Run 163 status                          |
|----------------------------------------------|-----------------------------------------|
| Source/test governance authority verifier    | ✅ landed                               |
| Pure non-mutating composition with Run 159   | ✅ landed (`validate_lifecycle_…`)      |
| Release-binary governance verifier evidence  | ⏭️ deferred to Run 164                  |
| MainNet peer-driven apply enablement         | ❌ remains refused                       |
| Governance execution engine                  | ❌ unimplemented (out of scope)         |
| On-chain governance integration              | ❌ unimplemented; verifier fail-closed  |
| KMS / HSM custody                            | ❌ unimplemented                         |
| Validator-set rotation                       | ❌ open                                  |
| Wire-format / marker / sequence schema change| ❌ none introduced                       |
| Full C4 closure                              | ❌ remains open                          |
| C5 closure                                   | ❌ remains open                          |

## Authority classes and proof shape

The verifier models three authority classes
(`GovernanceAuthorityClass`):

1. **GenesisBound** — proof chains to the genesis-bound
   bundle-signing authority root. Valid for DevNet/TestNet fixtures
   today, future MainNet-compatible. Does **not** enable MainNet
   apply on its own.
2. **EmergencyCouncil** — proof represents emergency revocation
   authority. Domain-bound. Does **not** bypass signature, genesis,
   chain, environment, lifecycle-action, candidate-digest, or
   sequence checks. Run 163 only authorizes
   `LocalLifecycleAction::EmergencyRevoke` for this class; any other
   declared lifecycle action returns
   `AuthorityClassDoesNotAuthorizeAction`.
3. **OnChainGovernance** — placeholder. No on-chain proof format
   exists yet, the verifier rejects with
   `UnsupportedOnChainGovernance`.

The proof object (`GovernanceAuthorityProof`) carries:

* `environment`, `chain_id`, `genesis_hash`,
  `authority_root_fingerprint`, `authority_root_suite_id`;
* `lifecycle_action` (the local sub-classification, NOT just the
  on-wire action byte);
* `active_bundle_signing_key_fingerprint`,
  optional `new_bundle_signing_key_fingerprint`,
  optional `revoked_bundle_signing_key_fingerprint`;
* `authority_domain_sequence`;
* `candidate_v2_digest`;
* `issuer_authority_class`, `issuer_signature_suite_id`,
  `issuer_signature` (Vec<u8>);
* optional `threshold` (`GovernanceThreshold {approvals, required, total}`).

Run 163 does **not** introduce a new wire format. The fields above
are sufficient to represent the genesis-bound and emergency-council
classes; on-chain governance is deliberately fail-closed pending an
explicit on-chain proof schema in a future run. If a future run
determines that the existing v2 ratification proof fields are
insufficient, that run is the one that must extend the wire format
— Run 163 does not silently invent a schema.

## Issuer signature hook

Run 163 source/test fixtures use a deterministic
`FixtureIssuerSignatureVerifier` whose accept condition is the
canonical concatenation:

```
b"qbind-run163-gov:" || class_tag || b":" || authority_root_fingerprint
                    || b":" || candidate_v2_digest
                    || b":" || authority_domain_sequence (be u64)
```

The hook is bound to authority root, candidate digest, and sequence.
A stale lower-sequence signature is rejected by the signature check
alone (R13). A wrong-root or wrong-digest signature is rejected by
the signature check independently of the binding checks (R4, R6,
R8). A future run will replace the hook with a real PQC signature
verifier without changing the verifier surface.

## Test matrix

`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`
covers:

| Case  | Description                                                                       | Status |
|-------|-----------------------------------------------------------------------------------|--------|
| A1    | Genesis-bound Rotate proof accepted                                               | ✅     |
| A2    | Genesis-bound Revoke proof accepted                                               | ✅     |
| A3    | Genesis-bound EmergencyRevoke proof accepted                                      | ✅     |
| A4    | EmergencyCouncil EmergencyRevoke proof accepted                                   | ✅     |
| A5    | Replay-safe same-proof same-candidate accepted                                    | ✅     |
| R1    | Wrong environment rejected                                                        | ✅     |
| R2    | Wrong chain rejected                                                              | ✅     |
| R3    | Wrong genesis rejected                                                            | ✅     |
| R4    | Wrong authority root rejected                                                     | ✅     |
| R5    | Wrong lifecycle action rejected                                                   | ✅     |
| R6    | Wrong candidate digest rejected                                                   | ✅     |
| R7    | Wrong authority-domain sequence rejected                                          | ✅     |
| R8    | Invalid issuer signature rejected                                                 | ✅     |
| R9    | Unsupported issuer suite rejected                                                 | ✅     |
| R10   | Non-PQC suite rejected (`Ed25519`/`Secp256k1`/`RsaPss`)                           | ✅     |
| R11   | Threshold not met rejected; threshold met accepted (R11b)                         | ✅     |
| R12   | Malformed proof rejected (empty signature, empty authority root)                  | ✅     |
| R13   | Stale / replayed lower-sequence proof rejected                                    | ✅     |
| R14   | OnChainGovernance proof rejected as unsupported                                   | ✅     |
| R15   | Local operator config alone rejected (no signature → `MalformedProof`)            | ✅     |
| R16   | Peer-majority / gossip-count rejected (typed `PeerMajorityProofRejected` variant) | ✅     |
| extra | EmergencyCouncil declaring Rotate rejected (class/action gating)                  | ✅     |
| extra | Pure verifier performs no I/O (input bytes unchanged)                             | ✅     |
| extra | Combined helper accepts when both pass                                            | ✅     |
| extra | Combined helper rejects when lifecycle passes but governance fails                | ✅     |
| extra | Combined helper rejects when governance passes but lifecycle fails                | ✅     |
| extra | Combined helper accepts initial activation with no persisted marker               | ✅     |
| extra | Acceptance does not imply MainNet apply enablement                                | ✅     |

## Validation runs

The following commands were executed against the Run 163 working tree:

* `cargo build -p qbind-node --lib` — clean build, no errors, no
  warnings introduced by Run 163.
* `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests`
  — 32 tests, all green.
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
  — Run 159 lifecycle tests remain green (no regression).
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests`
  — Run 161 lifecycle/marker integration tests remain green.
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
  — TestNet fixture universe remains green.
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
  — release-binary peer-drain plumbing remains green.
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
  — peer-driven apply drain tests remain green.
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
  — DevNet peer-driven apply tests remain green.
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
  — live inbound 0x05 v2 validation tests remain green.
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
  — Run 134 reload-apply v2 marker tests remain green.
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
  — Run 138 SIGHUP v2 marker tests remain green.
* `cargo test -p qbind-node --lib pqc_authority` — 148 lib tests
  green.
* `cargo test -p qbind-node --lib` — 1277 lib tests green.

## Non-goals (explicit)

Run 163 does **not**:

* enable MainNet peer-driven apply,
* implement a governance execution engine,
* implement on-chain governance integration (the on-chain class is
  deliberately fail-closed),
* implement KMS / HSM custody,
* implement validator-set rotation,
* mutate any live trust state, write a v2 marker, write a sequence
  number, or evict sessions,
* introduce a new wire format, marker schema, sequence-file schema,
  or trust-bundle schema,
* weaken Runs 070, 130–162.

DevNet/TestNet peer-driven apply evidence from Runs 153/158 remains
unaffected. Run 159/161/162 lifecycle behaviour remains unchanged.

## Forward boundary

* **Run 164** captures release-binary governance authority verifier
  evidence on real `target/release/qbind-node`.
* **Future runs** add the real PQC signature verifier behind the
  `GovernanceIssuerSignatureVerifier` hook, define the on-chain
  governance proof schema, and gate the verifier into mutating
  apply surfaces (only after explicit governance-execution and
  KMS/HSM design).
* **Full C4 closure** remains open.
* **C5 closure** remains open.