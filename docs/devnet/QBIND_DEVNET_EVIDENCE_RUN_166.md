# QBIND DevNet Evidence — Run 166

## Subject

Run 166: **release-binary governance gate enforcement / boundary
evidence** for the Run 165 wiring of the Run 163 governance ratification
authority verifier into the v2 lifecycle / marker-decision path.

Run 166 is the partner deliverable to Run 165. It produces release-
binary evidence on the real `target/release/qbind-node` that the Run 165
governance gate is reachable and exercised through real production
marker-decision surfaces, and it captures fail-closed
`RequiredButMissing` / `Rejected` behaviour on a release-built helper
that links the same production helper symbol the four mutating v2
surfaces call.

## Verdict

**Run 166 is release-binary governance gate enforcement / boundary
evidence.**

* **Governance verification is production-source reachable after
  Run 165.** A grep over `crates/qbind-node/src/**.rs` for the
  governance-aware decide helper / gate / typed reject variants returns
  hits in `pqc_authority_marker_acceptance.rs` (definition + reject
  variants) and in the four production callers
  (`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`,
  `main.rs` reload-apply pre-flight, `main.rs` startup pre-flight),
  superseding Run 164's *"zero production-surface caller"* partial-
  positive boundary.
* **Existing production v2 wire material cannot yet carry real
  governance proofs.** The four production callers currently supply
  `GovernanceProofPolicy::NotRequired` and
  `GovernanceProofContext::Unavailable`. Run 166 deliberately does NOT
  invent a proof-carrying wire / marker / sequence / trust-bundle
  schema; that schema-design run is named explicitly below.
* **`RequiredButMissing` is fail-closed on release binaries** where a
  governance proof is required: the release-built helper
  `target/release/examples/run_166_governance_gate_release_binary_helper`,
  which links the same
  `decide_v2_marker_acceptance_with_lifecycle_and_governance` symbol
  `target/release/qbind-node` links, returns
  `Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing
  { action: Rotate })` for a Rotate transition under
  `policy=RequiredForLifecycleSensitive` + `context=Unavailable`, and
  asserts the persisted seed marker bytes are byte-for-byte unchanged.
* **The full governance proof corpus remains helper-evidenced**, not
  production-surface proof-carrying evidenced. Run 164's release-built
  helper replays A1–A5 / R1–R16 against `verify_governance_authority_proof`
  / `validate_lifecycle_with_governance_authority` on this checkout; the
  Run 166 helper additionally exercises an end-to-end accept (H5) and an
  end-to-end reject (H6 — `Rejected(InvalidIssuerSignature)`) through
  the production marker-decision helper.
* **`OnChainGovernance` remains unsupported / fail-closed.** No on-chain
  governance proof format exists; the Run 163 verifier returns
  `UnsupportedOnChainGovernance` and Run 166 does NOT silently invent
  one.
* **No MainNet apply is enabled.** MainNet peer-driven apply remains
  refused unconditionally; the surface environment gate, unchanged by
  Runs 165 / 166, owns the refusal. A valid governance proof does NOT
  enable MainNet peer-driven apply on any surface.
* **Governance execution / on-chain proof remains unimplemented.**
* **KMS / HSM remains unimplemented.**
* **Validator-set rotation remains open.**
* **Full C4 remains open. C5 remains open.** Run 166 claims neither.

## Deliverables

* Release-binary harness:
  `scripts/devnet/run_166_governance_gate_release_binary_enforcement.sh`.
* Release-built helper:
  `crates/qbind-node/examples/run_166_governance_gate_release_binary_helper.rs`
  (built as
  `target/release/examples/run_166_governance_gate_release_binary_helper`).
* Evidence archive:
  `docs/devnet/run_166_governance_gate_release_binary_enforcement/`
  (curated `README.md` + `summary.txt` tracked; per-run generated
  artifacts ignored via the same convention as
  Runs 153 / 155 / 156 / 158 / 160 / 162 / 164).
* This canonical evidence report:
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_166.md`.

## Surfaces investigated

For each of the seven surfaces named in `task/RUN_166_TASK.txt
§Required investigation`, Run 166 documents:

| # | surface | routes through `decide_v2_marker_acceptance_with_lifecycle_and_governance`? | policy today | context today | wire can carry `GovernanceAuthorityProof`? | expected behaviour when proof required but unavailable |
|---|---------|---------------------------------------------------------------------------|--------------|---------------|--------------------------------------------|--------------------------------------------------------|
| 1 | startup `--p2p-trust-bundle` | yes (`crates/qbind-node/src/main.rs` startup pre-flight) | `NotRequired` | `Unavailable` | no | startup refusal before P2P/network start; no marker / sequence / live-trust mutation; no trusted-root fallback |
| 2 | reload-check validation-only | yes (governance-aware decision is composed source-locally per Run 132 / Run 165) | `NotRequired` | `Unavailable` | no | typed `GovernanceAuthorityRequiredButMissing`; validation-only contract preserved (no mutation) |
| 3 | local peer-candidate-check validation-only | yes (same composition) | `NotRequired` | `Unavailable` | no | same as (2) |
| 4 | process-start reload-apply | yes (`crates/qbind-node/src/main.rs` reload-apply pre-flight) | `NotRequired` | `Unavailable` | no | typed `GovernanceAuthorityRequiredButMissing`; Run 070 apply NOT called; no live-trust / sequence / marker mutation |
| 5 | SIGHUP live reload | yes (`crates/qbind-node/src/pqc_live_trust_reload.rs`) | `NotRequired` | `Unavailable` | no | same as (4) |
| 6 | live inbound `0x05` | yes (lifecycle marker decision path; Run 142 / Run 143) | `NotRequired` | `Unavailable` | no | typed `GovernanceAuthorityRequiredButMissing`; validation-only contract preserved |
| 7 | peer-driven drain / `ProductionV2MarkerCoordinator` | yes (`crates/qbind-node/src/pqc_peer_candidate_apply.rs`) | `NotRequired` | `Unavailable` | no | candidate may stage; drain refuses before Run 070 apply; no live trust swap; no session eviction; no sequence / marker write |

## Release-binary scenario matrix

The full matrix and per-scenario expected outcomes are described in
`docs/devnet/run_166_governance_gate_release_binary_enforcement/README.md`.
Summary:

* **A1 — reload-check NotRequired compatibility.** Real
  `target/release/qbind-node` accepts a v2 ratify@seq=1 candidate via
  `--p2p-trust-bundle-reload-check`; no marker write, no sequence
  write; validation-only semantics preserved.
* **A2 — reload-apply NotRequired compatibility (ActivateInitial).**
  Real `target/release/qbind-node` accepts the same candidate via
  `--p2p-trust-bundle-reload-apply-path`; Run 070 apply + Run 055
  sequence commit + post-commit v2 marker persist; existing Run 134 /
  Run 162 semantics preserved; no
  `GovernanceAuthorityRequiredButMissing` / `Rejected` line.
* **A2' — reload-apply NotRequired compatibility (Rotate).** Same real
  release binary accepts a Rotate@seq=2 lifecycle-sensitive candidate
  over a seeded v2-seq=1 marker; missing proof under the production
  `NotRequired` policy does NOT refuse the lifecycle-sensitive
  transition.
* **A3 / A4 / A5 / A6 — RequiredButMissing fail-closed.** Release-built
  helper `run_166_governance_gate_release_binary_helper` invokes the
  same `decide_v2_marker_acceptance_with_lifecycle_and_governance`
  symbol with `policy=RequiredForLifecycleSensitive`,
  `context=Unavailable`, on a Rotate candidate over a seeded v2-seq=1
  marker; helper asserts
  `Err(GovernanceAuthorityRequiredButMissing { action: Rotate })` and
  asserts the seed marker bytes are byte-for-byte unchanged. A6
  (peer-driven drain on the release binary) is infeasible without
  changing the peer-candidate envelope schema or adding a CLI / env
  knob to flip the production policy — both forbidden by Run 166's
  strict scope; the release-built helper is the strongest honest
  release-binary evidence currently obtainable, and the next required
  schema-carrying run (Run 167) is named below.
* **A7 — full governance proof corpus.** Release-built
  `target/release/examples/run_164_governance_authority_fixture_helper`
  replays the A1–A5 / R1–R16 typed corpus on this checkout; per-
  scenario assertions captured in `scenario_assertions.run164_corpus.txt`.

## Rejection matrix

The Run 163 rejection matrix
(wrong environment / wrong chain / wrong genesis / wrong authority root
/ wrong lifecycle action / wrong candidate digest / wrong authority-
domain sequence / invalid issuer signature / unsupported issuer suite /
non-PQC suite / threshold not met / malformed proof / stale-replayed
proof / `OnChainGovernance` unsupported / local operator config alone /
peer-majority alone) is replayed end-to-end on the release-built
Run 164 helper (A7). Through the production helper symbol, the release-
built Run 166 helper additionally exercises:

* `GovernanceAuthorityRejected(InvalidIssuerSignature ..)` end-to-end on
  a tampered governance proof under
  `policy=RequiredForLifecycleSensitive` (helper scenario H6);
* `GovernanceAuthorityRequiredButMissing { action: Rotate }` on a
  Rotate transition with `context=Unavailable` (helper scenario H3).

## Source-reachability proof

The harness writes the source-level grep that supersedes Run 164's
boundary into `reachability/src_grep.txt` and a human-readable summary
into `reachability/reachability.txt`. The grep targets:

```
evaluate_governance_marker_gate
decide_v2_marker_acceptance_with_lifecycle_and_governance
GovernanceAuthorityRequiredButMissing
GovernanceAuthorityRejected
validate_lifecycle_with_governance_authority
verify_governance_authority_proof
pqc_governance_authority
```

After Run 165, the grep returns hits in `pqc_authority_marker_acceptance.rs`
(definition + reject variants), `pqc_live_trust_reload.rs`,
`pqc_peer_candidate_apply.rs`, and `main.rs`. Before Run 165 (Run 164's
recorded boundary), the same grep returned hits only in
`pqc_governance_authority.rs` and `lib.rs`.

The harness asserts each of these production-call-site hits via
`assert_grep`; if any of them is missing, the harness fails fast with a
clear message.

The release-binary log proof that the gate is exercised at minimum
through `RequiredButMissing` is captured in
`helper_evidence/scenarios/H3_required_rotate_required_but_missing/actual.txt`,
which contains the exact `Err(GovernanceAuthorityRequiredButMissing {
action: Rotate })` from the production helper symbol on the release-
built helper.

## Negative invariants

Across all production-surface scenarios:

* No MainNet apply.
* No autonomous apply.
* No apply on receipt.
* No peer-majority authority.
* No governance execution claim.
* No on-chain governance claim.
* No KMS / HSM claim.
* No validator-set rotation claim.
* No fallback to `--p2p-trusted-root`.
* No active `DummySig` / `DummyKem` / `DummyAead`.
* No schema / wire / metric drift.
* No marker write before sequence commit.
* No sequence write on validation-only surfaces.
* No marker write on validation-only surfaces.
* Rejected governance-gate scenarios produce no mutation: the helper
  asserts `pre==post` on every reject scenario; the harness asserts no
  sequence file exists under any reject data dir; the denylist grep is
  clean (banner-excluded only).

## Captured metadata

* `qbind-node` SHA-256 + ELF Build ID;
* `run_166_governance_gate_release_binary_helper` SHA-256 + ELF
  Build ID;
* `run_164_governance_authority_fixture_helper` SHA-256 + ELF
  Build ID;
* `run_133_v2_validation_only_fixture_helper` SHA-256 + ELF
  Build ID;
* git commit hash, rustc / cargo versions;
* exact commands invoked;
* per-scenario stdout / stderr logs;
* per-scenario exit codes;
* marker / sequence JSON + SHA before / after;
* data-dir inventories;
* denylist grep results.

All recorded under `docs/devnet/run_166_governance_gate_release_binary_enforcement/`
by the harness. Per repository convention only the curated `README.md`
and `summary.txt` are tracked; the rest is regenerated by the harness.

## Validation commands

The harness builds the release binaries and runs:

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper
cargo build --release -p qbind-node --example run_164_governance_authority_fixture_helper
cargo build --release -p qbind-node --example run_166_governance_gate_release_binary_helper
bash scripts/devnet/run_166_governance_gate_release_binary_enforcement.sh
cargo test -p qbind-node --test run_165_governance_marker_integration_tests
cargo test -p qbind-node --test run_163_governance_authority_verifier_tests
cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests
cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests
cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests
cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests
cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests
cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests
cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

Per-test stdout / stderr / exit code is captured under
`docs/devnet/run_166_governance_gate_release_binary_enforcement/test_results/`
by the harness.

## Crosscheck against existing design / spec

Run 166 was crosschecked against the existing design / spec
(`docs/whitepaper/contradiction.md`,
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`) and the
following narrow updates were made (per
`task/RUN_166_TASK.txt §Required deliverables 4`):

* `docs/whitepaper/contradiction.md` — Run 166 entry added recording
  the release-binary boundary (governance gate reachable / NotRequired
  compatibility green / RequiredButMissing fail-closed on release-built
  helper / no production-surface proof-carrying path until Run 167).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — operator-facing
  note that release builds now exercise the governance gate on every v2
  marker decision and that fail-closed `GovernanceAuthorityRequiredButMissing`
  is the typed error to expect under a future schema-carrying run.
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` —
  records that the peer-driven drain `ProductionV2MarkerCoordinator`
  routes through the governance-aware helper at
  `policy=NotRequired`, `context=Unavailable` after Run 165 / Run 166,
  and that release-binary `RequiredButMissing` evidence is captured
  through the release-built helper pending the Run 167 schema-carrying
  run.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — records that
  governance authority verification is production-source reachable
  after Run 165, exercised on release builds after Run 166, and that
  the wire material does not yet carry a `GovernanceAuthorityProof`
  (schema design deferred to Run 167).

No contradictions were found; no inconsistency required entry beyond
the Run 166 record itself.

## Standing limitations (unchanged)

* MainNet peer-driven apply remains **refused** even with a valid
  governance proof.
* Governance execution / on-chain proof remains **unimplemented**;
  `OnChainGovernance` is fail-closed.
* KMS / HSM remains **unimplemented**.
* validator-set rotation remains **open**.
* full **C4 remains open**; **C5 remains open** — Run 166 claims
  neither.

## Next required run

**Run 167 — governance-proof carrying schema design / implementation.**
Run 167 must define the wire-format extension that carries a real
`GovernanceAuthorityProof` through the v2 ratification or authority-
marker envelope without weakening any existing rejection class, and
flip the four mutating production surfaces from `policy=NotRequired` to
`policy=RequiredForLifecycleSensitive` so accepted-governance-proof
evidence becomes captureable directly on `target/release/qbind-node`.