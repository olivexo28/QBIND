# Run 166 — Release-Binary Governance Gate Enforcement Evidence

## Scope

Run 166 produces release-binary evidence that the Run 165 governance
gate (`qbind_node::pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance`,
`qbind_node::pqc_governance_authority::evaluate_governance_marker_gate`,
typed errors `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected`
and `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`)
is reachable and enforced through real `target/release/qbind-node` v2
marker-decision surfaces.

Per `task/RUN_166_TASK.txt`, Run 166 honestly proves:

1. governance-gate source reachability from production surfaces;
2. behaviour-preserving `NotRequired` compatibility on the real release
   binary;
3. fail-closed `GovernanceAuthorityRequiredButMissing` behaviour when a
   production-equivalent surface requires a governance proof but the
   existing wire cannot carry one;
4. no marker / sequence / live-trust / session mutation on governance-
   gate rejection;
5. release-built helper evidence for the full Run 163 governance proof
   corpus remains green.

Run 166 does **not** silently invent a governance-proof wire / schema
path. The four production-surface call sites of
`decide_v2_marker_acceptance_with_lifecycle_and_governance` (process-
start reload-apply pre-flight, `--p2p-trust-bundle` startup pre-flight,
SIGHUP live-reload, peer-driven drain via
`ProductionV2MarkerCoordinator`) continue to supply
`GovernanceProofPolicy::NotRequired` and
`GovernanceProofContext::Unavailable`. The fail-closed
`GovernanceAuthorityRequiredButMissing` evidence is captured on a
release-built helper (`run_166_governance_gate_release_binary_helper`)
that links the same production helper symbol `target/release/qbind-node`
links.

## Verdict

**`positive (release-binary boundary): governance-gate reachable from
production surfaces; NotRequired compatibility proven on
target/release/qbind-node; RequiredButMissing fail-closed proven on
release-built helper; rejection produces no mutation.`**

This supersedes Run 164's *"zero production-surface caller"*
partial-positive boundary.

## Reachability — Run 164 boundary superseded

Run 164's `reachability/src_grep.txt` showed
`verify_governance_authority_proof`,
`validate_lifecycle_with_governance_authority`, and
`pqc_governance_authority::*` had no caller in
`crates/qbind-node/src/` outside the module itself
(`pqc_governance_authority.rs`) and the `pub mod` declaration in
`lib.rs`. After Run 165, the corresponding grep returns hits in:

* `crates/qbind-node/src/pqc_authority_marker_acceptance.rs` — the
  shared marker-decision helper
  `decide_v2_marker_acceptance_with_lifecycle_and_governance` and the
  pure governance gate `evaluate_governance_marker_gate` are both called
  here, and the typed reject variants
  `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`
  and `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected` are
  constructed here.
* `crates/qbind-node/src/pqc_live_trust_reload.rs` — SIGHUP marker
  pre-flight calls
  `decide_v2_marker_acceptance_with_lifecycle_and_governance`
  (`policy=NotRequired`, `context=Unavailable`).
* `crates/qbind-node/src/pqc_peer_candidate_apply.rs` — peer-driven
  drain (`ProductionV2MarkerCoordinator`) calls the same helper at
  `policy=NotRequired`, `context=Unavailable`.
* `crates/qbind-node/src/main.rs` — process-start reload-apply
  pre-flight and `--p2p-trust-bundle` startup pre-flight both call the
  same helper at `policy=NotRequired`, `context=Unavailable`.

The harness records this grep in `reachability/src_grep.txt` and
`reachability/reachability.txt` and asserts the production callers via
`assert_grep`.

## Surfaces investigated

| # | surface | reachable? | governance policy today | governance context today | wire can carry proof? | expected behaviour when proof required but unavailable |
|---|---------|-----------|-------------------------|--------------------------|----------------------|--------------------------------------------------------|
| 1 | startup `--p2p-trust-bundle` | yes | `NotRequired` | `Unavailable` | no | `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { action }` (release-built helper H3) |
| 2 | reload-check validation-only | yes | `NotRequired` | `Unavailable` | no | same fail-closed error class; validation-only contract preserved (no mutation) |
| 3 | local peer-candidate-check validation-only | yes | `NotRequired` | `Unavailable` | no | same fail-closed error class; validation-only contract preserved |
| 4 | process-start reload-apply | yes | `NotRequired` | `Unavailable` | no | same fail-closed error class; Run 070 apply NOT called; no marker / sequence / live-trust mutation |
| 5 | SIGHUP live reload | yes | `NotRequired` | `Unavailable` | no | same fail-closed error class; no marker / sequence / live-trust mutation |
| 6 | live inbound `0x05` | yes (via lifecycle marker decision path) | `NotRequired` | `Unavailable` | no | same fail-closed error class; validation-only contract preserved |
| 7 | peer-driven drain / `ProductionV2MarkerCoordinator` | yes | `NotRequired` | `Unavailable` | no | candidate may stage; drain refuses before Run 070 apply; no live trust swap; no session eviction; no sequence / marker write |

## Release-binary scenario matrix

### A1 — reload-check NotRequired compatibility (real `target/release/qbind-node`)

* Inputs: DevNet baseline trust bundle + DevNet candidate trust bundle
  + DevNet v2 ratify@seq=1 sidecar (Run 133 fixture corpus).
* Real release binary invoked with `--p2p-trust-bundle-reload-check`
  and `--p2p-trust-bundle-allow-unratified-testnet-devnet`.
* Expected on the real release binary:
  - exit 0;
  - `[run-132] reload-check v2 authority-marker check passed: ...`
    on stderr (governance-aware decide helper accepted under
    `NotRequired`);
  - `VERDICT=valid`;
  - no sequence file under data dir;
  - no authority marker file under data dir;
  - no `GovernanceAuthorityRequiredButMissing` line;
  - no `GovernanceAuthorityRejected` line.

### A2 — reload-apply NotRequired compatibility (real `target/release/qbind-node`)

* Same DevNet fixture corpus, mutating
  `--p2p-trust-bundle-reload-apply-path`.
* Expected on the real release binary:
  - exit 0;
  - `[run-134] reload-apply v2 ratification path SELECTED`;
  - `trust-bundle candidate APPLIED live` (Run 070 ordering);
  - `sequence_commit=ok` (Run 055 ordering);
  - `VERDICT=applied`;
  - `[run-134] v2 authority-marker persisted ... candidate
    latest_authority_domain_sequence=1` (post-Run-055 commit boundary);
  - persisted v2 marker present, `record_version: 2`,
    `latest_authority_domain_sequence: 1`,
    `latest_lifecycle_action: "ratify"`;
  - no `GovernanceAuthorityRequiredButMissing` line;
  - no `GovernanceAuthorityRejected` line.

### A2' — reload-apply NotRequired compatibility on Rotate (real `target/release/qbind-node`)

* Seeds `seed-marker.v2.seq1.json`, applies Rotate@seq=2 over it.
* Expected on the real release binary:
  - exit 0;
  - `latest_authority_domain_sequence=2`;
  - `latest_lifecycle_action: "rotate"`;
  - missing governance proof under the production `NotRequired` policy
    does NOT refuse the lifecycle-sensitive transition.

### A3 — reload-check governance-required-but-missing fail-closed (release-built helper H3)

* The four production surfaces hardcode `policy=NotRequired`. To
  evidence the `RequiredButMissing` fail-closed semantics on a
  release-binary boundary without inventing a wire schema, the
  release-built helper
  `target/release/examples/run_166_governance_gate_release_binary_helper`
  is invoked. The helper links the same
  `decide_v2_marker_acceptance_with_lifecycle_and_governance` symbol
  `target/release/qbind-node` links.
* Helper scenario `H3`:
  - seeds A@seq=1 via `policy=NotRequired`, `context=Unavailable`
    accept + post-commit persist (mirrors A2);
  - calls
    `decide_v2_marker_acceptance_with_lifecycle_and_governance(
      Rotate@seq=2,
      policy=RequiredForLifecycleSensitive,
      context=Unavailable )`;
  - asserts
    `Err(GovernanceAuthorityRequiredButMissing { action: Rotate })`;
  - asserts seed marker bytes byte-for-byte unchanged after the reject.

### A4 — reload-apply governance-required-but-missing fail-closed (release-built helper H3)

* Same scenario as A3 — the helper exercises the production helper
  symbol the four mutating production surfaces (including reload-apply
  pre-flight) call. Run 070 apply is **not** called by the helper, no
  live trust mutation occurs, no sequence write occurs, no marker write
  occurs.

### A5 — startup governance-required-but-missing fail-closed

* Same evidence path as A3 / A4 (the release-built helper covers the
  same `decide_v2_marker_acceptance_with_lifecycle_and_governance`
  symbol the startup pre-flight in `main.rs` calls). Startup refusal
  before P2P / network start, no marker write, no sequence write, no
  trusted-root fallback are guaranteed by the same source-level
  contract.

### A6 — peer-driven drain governance-required-but-missing fail-closed

* Infeasible to drive on `target/release/qbind-node` today without
  changing the peer-candidate envelope schema to carry a governance
  proof, **or** without adding a CLI / environment knob to flip the
  four production surfaces' policy from `NotRequired` to
  `RequiredForLifecycleSensitive`. Run 166's strict scope forbids both.
  The release-built helper H3 is therefore the strongest honest
  release-binary evidence currently obtainable for this scenario, and
  the next required schema-carrying / policy-flipping run (Run 167) is
  named in `enforcement_proof.txt`.

### A7 — full governance proof corpus on release-built helper

* Release-built `target/release/examples/run_164_governance_authority_fixture_helper`
  replays the full A1–A5 / R1–R16 typed governance proof corpus on this
  checkout; per-scenario assertions captured in
  `scenario_assertions.run164_corpus.txt`.

## Helper (`run_166_governance_gate_release_binary_helper`) scenario matrix

| ID | Policy | Context | Candidate / proof | Expected result |
|----|--------|---------|-------------------|-----------------|
| H1 | `NotRequired` | `Unavailable` | Ratify@seq=1 | `Ok(.. FirstV2Write ..)` |
| H2 | `NotRequired` | `Unavailable` | Rotate@seq=2 over seeded v2-seq=1 | `Ok(.. UpgradeV2 1 -> 2 ..)` |
| H3 | `RequiredForLifecycleSensitive` | `Unavailable` | Rotate@seq=2 over seeded v2-seq=1 | `Err(GovernanceAuthorityRequiredButMissing { action: Rotate })`; seed marker bytes UNCHANGED |
| H4 | `RequiredForLifecycleSensitive` | `Unavailable` | Ratify@seq=1 (`ActivateInitial`) | `Ok(.. FirstV2Write ..)` (genesis-bound first activation governance-optional, Run 165 §A5) |
| H5 | `RequiredForLifecycleSensitive` | `Supplied(GenesisBound, Rotate, good)` | Rotate@seq=2 | `Ok(.. UpgradeV2 1 -> 2 ..)` |
| H6 | `RequiredForLifecycleSensitive` | `Supplied(GenesisBound, ActivateInitial, tampered signature)` | Ratify@seq=1 | `Err(GovernanceAuthorityRejected(InvalidIssuerSignature ..))`; no marker write |
| H7 | `NotRequired` (deterministic x2) | `Unavailable` | Ratify@seq=1 | identical structurally-equal `Ok(FirstV2Write)` decisions; no marker write |

## Negative invariants

* MainNet peer-driven apply remains refused unconditionally.
* No autonomous apply.
* No apply on receipt.
* No peer-majority authority.
* No governance execution claim.
* No on-chain governance claim (`OnChainGovernance` remains
  fail-closed / `UnsupportedOnChainGovernance`).
* No KMS / HSM claim.
* No validator-set rotation claim.
* No fallback to `--p2p-trusted-root`.
* No active `DummySig` / `DummyKem` / `DummyAead`.
* No schema / wire / metric drift.
* No CLI flag added or renamed.
* No environment variable added.
* No marker write before sequence commit.
* No sequence write on validation-only surfaces.
* No marker write on validation-only surfaces.
* Rejected governance-gate scenarios produce no mutation: every
  rejected scenario asserts `pre==post` on the seeded marker (`H3`) or
  asserts the marker is absent post-rejection (`H6`).

## Captured metadata

The harness writes (per `task/RUN_166_TASK.txt §Required captured
metadata`):

* `provenance.txt`: `qbind-node` SHA-256 + ELF Build ID + git commit
  hash + rustc/cargo versions; helper SHA-256s and Build IDs.
* `logs/`: per-scenario stdout / stderr.
* `exit_codes/`: per-scenario exit codes.
* `marker_hashes/`: per-scenario `pqc_authority_state.json` SHA-256
  before and after; copies of `marker_post.json` where applicable.
* `sequence_hashes/`: per-scenario `pqc_trust_bundle_sequence.json`
  SHA-256 + JSON copy where applicable.
* `data_inventories/`: per-scenario data-dir inventory.
* `helper_evidence/`: Run 166 release-built helper outputs (one
  directory per scenario H1–H7).
* `helper_corpus/`: Run 164 release-built helper governance-proof
  corpus replay.
* `reachability/src_grep.txt`,
  `reachability/tests_grep.txt`,
  `reachability/reachability.txt`: source-level grep evidence
  superseding Run 164's "zero production caller" boundary.
* `grep_summaries/denylist.txt`: out-of-scope denylist (must be empty
  post banner-exclusion).
* `negative_invariants.txt`,
  `scenario_assertions.txt`,
  `scenario_assertions.run164_corpus.txt`,
  `enforcement_proof.txt`,
  `summary.txt`.
* `test_results/`: stdout / stderr / exit code for each cargo regression
  test suite named in `task/RUN_166_TASK.txt §Validation commands`.

Per repository convention, the curated `README.md` and `summary.txt`
are tracked; everything else is generated by the harness and ignored
via `.gitignore`.

## Validation commands

The harness builds the release binaries and runs the regression test
suites named in `task/RUN_166_TASK.txt §Validation commands`. Exact
commands invoked:

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper`
* `cargo build --release -p qbind-node --example run_164_governance_authority_fixture_helper`
* `cargo build --release -p qbind-node --example run_166_governance_gate_release_binary_helper`
* `bash scripts/devnet/run_166_governance_gate_release_binary_enforcement.sh`
* `cargo test -p qbind-node --test run_165_governance_marker_integration_tests`
* `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests`
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests`
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`

## Standing limitations

* MainNet peer-driven apply remains **refused** even with a valid
  governance proof (the surface environment gate, unchanged by
  Runs 165 / 166, owns the MainNet refusal).
* Governance execution / on-chain proof remains **unimplemented**;
  `OnChainGovernance` is fail-closed.
* KMS / HSM remains **unimplemented**.
* validator-set rotation remains **open**.
* full **C4 remains open**.
* **C5 remains open**.
* The full Run 163 governance proof corpus remains **helper-evidenced**;
  it is not yet production-surface proof-carrying evidenced through
  `target/release/qbind-node` because the v2 ratification / authority-
  marker wire material does not yet carry governance-proof fields.

## Next required run

**Run 167 — governance-proof carrying schema design / implementation.**
Run 167 must define the wire-format extension that carries a real
`GovernanceAuthorityProof` through the v2 ratification or authority-
marker envelope without weakening any existing rejection class, and flip
the four mutating production surfaces from `policy=NotRequired` to
`policy=RequiredForLifecycleSensitive` so accepted-governance-proof
evidence becomes captureable directly on `target/release/qbind-node`.

Until Run 167 lands, governance enforcement on `target/release/qbind-
node` remains in the configuration evidenced by Run 166: the gate is
production-source reachable and exercised on every v2 marker decision,
the `NotRequired` compatibility path is green on the real release
binary, and the fail-closed `RequiredButMissing` and `Rejected`
behaviour is proven on the release-built helper that links the same
production helper symbol.