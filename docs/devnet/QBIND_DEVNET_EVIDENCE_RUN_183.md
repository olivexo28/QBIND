# QBIND DevNet evidence — Run 183

**Title.** Release-binary evidence that the seven production v2
marker-decision call sites wired by Run 182 invoke the Run 180
per-surface OnChainGovernance preflight wrappers under the hidden
Run 180 `OnChainGovernanceProofPolicy::AllowFixtureSourceTest`
selector, on real `target/release/qbind-node`.

**Status.** PASS (release-binary, partial-positive) — the real
`target/release/qbind-node` binary parses the hidden CLI flag
`--p2p-trust-bundle-onchain-governance-fixture-allowed`, reads the
env var `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`,
OR-combines them via
[`onchain_governance_proof_policy_from_cli_or_env`](
  ../../crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs)
inside `crates/qbind-node/src/main.rs`, propagates the resolved
selector through `Run105ReloadCheckContextData`, `LiveReloadConfig`,
and `ProductionV2MarkerCoordinator` into every Run 182 named
callsite entry on each of the seven production v2 marker-decision
code paths
([`pqc_onchain_governance_callsite_wiring`](
  ../../crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs)),
and emits the
`[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof
policy ARMED (AllowFixtureSourceTest)` banner exactly when the
selector is armed. The production default —
`OnChainGovernanceProofPolicy::Disabled` — remains fail-closed on
every surface; under the default every Run 182 callsite entry
short-circuits with `PolicyDisabled` before any verifier work runs.
The MainNet peer-driven apply Run 147 / 148 / 152 FATAL invariant is
preserved unconditionally — the peer-driven-drain callsite entry
layers a surface-level `MainNetRefused` short-circuit **before**
invoking the underlying Run 180 verifier so the refusal holds even
with a fully-valid DevNet fixture proof in hand and the selector
engaged. A release-built helper (the Run 179
`run_179_onchain_governance_proof_release_binary_helper`, reused
because it drives the same production library symbols Run 182 wired
the callsite entries into) exercises the full A1–A9 / R1–R26
acceptance and rejection corpus end-to-end in release mode through
the production library symbols
`verify_onchain_governance_proof`,
`validate_lifecycle_with_onchain_governance_proof`,
`compose_onchain_governance_marker_decision`, the seven Run 180
per-surface composed wrappers, and the seven Run 182 named callsite
entries plus `OnChainGovernanceCallsiteContext` and
`with_onchain_governance_fixture_allowed_selector`. Real on-chain
governance proof verification, governance execution, KMS/HSM
custody, validator-set rotation, bridge / light-client integration,
autonomous apply, and apply-on-receipt all remain unimplemented.

**Driving spec.** `task/RUN_183_TASK.txt`.

## 1. Strict scope

Run 183 closes the Run 182-deferred release-binary boundary: Run 182
landed source/test production call-site wiring (the
`pqc_onchain_governance_callsite_wiring` module + seven named
entries + the `OnChainGovernanceCallsiteContext` typed argument
bundle + the additive
`with_onchain_governance_fixture_allowed_selector` builder) and the
seven production callers, but explicitly deferred release-binary
evidence to Run 183. Run 183 introduces zero new production source
beyond what Run 180 / 182 already landed.

Run 183 is **strictly release-binary evidence** and adds **only**:

* `scripts/devnet/run_183_onchain_governance_callsite_release_binary.sh`
  — idempotent harness that builds real `target/release/qbind-node`
  and the release-built helper, exercises the binary's hidden
  selector reachability and MainNet refusal, drives the helper
  through the full A1–A9 / R1–R26 corpus across every Run 182 named
  callsite entry, and writes provenance / reachability / denylist /
  mutation-proof / no-mutation-proof / per-scenario rc artefacts
  under `docs/devnet/run_183_onchain_governance_callsite_release_binary/`;
* `docs/devnet/run_183_onchain_governance_callsite_release_binary/`
  — evidence archive (only `README.md`, `summary.txt`, and
  `.gitignore` are tracked; per-run artefacts are `.gitignore`d as
  per the Run 153 / 155 / 158 / 172 / 175 / 177 / 179 / 181
  convention);
* this canonical evidence report;
* narrow append-only paragraphs in `docs/whitepaper/contradiction.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  and `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

Run 183 does not:

* change the production default policy on any surface — it remains
  `OnChainGovernanceProofPolicy::Disabled`;
* add or rename a CLI flag, env var, schema field, wire field,
  sidecar field, metric, or exit code;
* enable MainNet peer-driven apply — the Run 147 / 148 / 152 FATAL
  invariant continues to hold; the peer-driven-drain callsite entry
  retains its surface-level MainNet refusal layered ahead of the
  Run 180 verifier;
* implement real on-chain governance proof verification for
  MainNet, governance execution, KMS/HSM custody, validator-set
  rotation, bridge / light-client integration, autonomous apply, or
  apply-on-receipt.

Run 183 does **not** weaken any prior run (Runs 070, 130–182) and
does **not** claim full C4 or C5 closure.

## 2. What is captured

### 2.1 Real `target/release/qbind-node` selector reachability

| Scenario | Real-binary observation |
|---|---|
| **A1 / R1** — neither flag nor env truthy (production default) | No `[run-180]` armed banner; `OnChainGovernanceProofPolicy::Disabled` preserved on every surface; every Run 182 callsite entry short-circuits with `PolicyDisabled`. |
| **A2** — CLI flag `--p2p-trust-bundle-onchain-governance-fixture-allowed` | `[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED (AllowFixtureSourceTest)` banner observed; resolved policy propagated through `Run105ReloadCheckContextData::onchain_governance_fixture_allowed_selector`, `LiveReloadConfig::onchain_governance_fixture_allowed_selector`, and `ProductionV2MarkerCoordinator::onchain_governance_fixture_allowed_selector` into every Run 182 named callsite entry on every production v2 marker-decision code path inside the same binary process. |
| **A3** — env var `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` truthy (`{1, true, TRUE, True, yes, YES, on, ON}`) | Banner observed; selector arms identically to A2. Falsey values `{0, false, FALSE, no, off, "", garbage}` keep the selector disabled. |
| **R23** — armed selector + `--network mainnet` | No `MainNet peer-driven apply ENABLED` token; peer-driven-drain callsite entry's surface-level `MainNetRefused` short-circuit holds; Run 147 FATAL invariant preserved. |
| `qbind-node --help` | Hidden flag absent (`hide = true`); no `run-180` / `run-181` / `run-182` / `run-183` / `onchain-governance-fixture` token in help output. |

### 2.2 Release-built helper acceptance / rejection corpus

The Run 179 release-built helper drives the same production library
symbols Run 182 wired the callsite entries into and Run 180 wired
the per-surface composed wrappers into. The helper is built with
`cargo build --release -p qbind-node --example
run_179_onchain_governance_proof_release_binary_helper` and exits
non-zero unless **every** scenario matches its expected typed
`OnChainGovernanceMarkerDecisionOutcome` in release mode.

The helper covers (mirroring `task/RUN_183_TASK.txt`):

* **A1** default-Disabled `PolicyDisabled` short-circuit on every
  Run 182 named entry;
* **A2 / A3** CLI / env selector arms `AllowFixtureSourceTest` and
  the wrapper enters the typed-verifier path;
* **A4 / A5** valid DevNet OnChainGovernance Rotate proof is
  accepted through
  `reload_apply_callsite_onchain_governance_marker_decision` after
  the Run 178 verifier and Run 161/163/165 lifecycle validator both
  accept; canonical commitment bytes recorded per scenario;
* **A6** valid DevNet/TestNet fixture Rotate proof accepted through
  `local_peer_candidate_check_callsite_onchain_governance_marker_decision`
  (validation-only; no marker write; no sequence write);
* **A7** valid fixture proof accepted through
  `live_inbound_0x05_callsite_onchain_governance_marker_decision`
  (no apply-on-receipt; no marker write; no sequence write);
* **A8** valid fixture proof accepted through
  `peer_driven_drain_callsite_onchain_governance_marker_decision`
  on a DevNet candidate while MainNet variant returns
  `MainNetRefused` ahead of the Run 180 verifier (Run 147 / 148 /
  152 FATAL invariant);
* **A9** GenesisBound and EmergencyCouncil proof-carrying behavior
  unchanged;
* **R1–R26** the full rejection corpus — selector unset / wrong
  env / wrong chain / wrong genesis / wrong authority root / wrong
  governance domain / wrong proposal digest / wrong proposal
  outcome / wrong lifecycle action / wrong candidate digest / wrong
  authority-domain sequence / expired proof / replayed decision /
  quorum not met / threshold not met / invalid proof bytes /
  unsupported proof suite / malformed proof / local operator config
  alone / peer-majority alone / proof-valid lifecycle-invalid /
  lifecycle-valid proof-invalid / MainNet peer-driven apply refused
  with armed selector / validation-only rejection non-mutating /
  mutating preflight rejection non-mutating / live-`0x05` invalid
  candidate not-propagated.

### 2.3 Source / release reachability proof

The harness writes `reachability/source_reachability.txt` capturing
production-source-tree call sites for every Run 182 callsite entry,
every Run 180 per-surface wrapper, the Run 178 typed verifier, the
Run 180 selector helpers, the typed argument bundle
`OnChainGovernanceCallsiteContext`, the additive selector builder
`with_onchain_governance_fixture_allowed_selector`, and the seven
production v2 marker-decision call-site functions
(`preflight_run_132_validation_only_v2_marker_check`,
`preflight_run_134_v2_marker_decision`,
`preflight_run_136_v2_marker_decision_for_startup`,
`LiveReloadController::preflight_sighup_v2_marker_decision`, the v2
sidecar dispatch in `main.rs`, the post-`verify_marker_for_validation_only_v2`
hook in `pqc_peer_candidate_wire.rs`, and
`ProductionV2MarkerCoordinator::decide_pre_apply`).

### 2.4 Denylist invariants proven empty

Captured in `negative_invariants.txt` — across helper logs and
every captured `qbind-node` log no occurrence of: `apply on
receipt` / `apply-on-receipt`, `autonomous apply`, `peer-majority
authority`, `fallback to --p2p-trusted-root`, `DummySig` /
`DummyKem` / `DummyAead`, `governance execution claim`, `on-chain
governance claim`, `KMS/HSM`, `validator-set rotation claim`,
`schema drift` / `wire drift` / `metric drift`, `MainNet
peer-driven apply ENABLED`, `MainNet apply ENABLED`.

### 2.5 No-mutation proof for rejected scenarios

Captured in `no_mutation_proof.txt`. Every rejected scenario in
this run uses `--print-genesis-hash` (no `--data-dir`, no socket,
no marker, no sequence) so no marker write, sequence write, Run 070
apply call, live trust swap, session eviction, `.tmp` residue, or
`--p2p-trusted-root` fallback is possible. The data dir under
`OUTDIR/data/` is empty after the harness runs.

### 2.6 Mutation-proof scaffold for accepted mutating scenarios

Captured in `mutation_proof.txt`. Honest scope statement
(unchanged from Run 182):

> No current peer-candidate, SIGHUP-trigger, reload-apply trigger,
> startup-bundle, or live `0x05` payload format carries a typed
> `OnChainGovernanceProof`. Adding such a field is explicitly out
> of scope for Run 183.
>
> Therefore production callers in real `target/release/qbind-node`
> always invoke the Run 182 callsite entries with `proof: None`;
> the Run 180 wrapper short-circuits on
> `NoOnChainGovernanceProofSupplied` (or `PolicyDisabled` under
> the default), and call-site behaviour is preserved bit-for-bit.
> The accepted-fixture-proof acceptance path A1–A9 / R1–R26 is
> exercised in release mode through the production library
> symbols by the release-built helper, which is linked into the
> same `qbind-node` library surface.

For every accepted mutating Rotate scenario the helper records:

* selector activation occurs before proof parse;
* proof parse occurs before marker decision;
* OnChainGovernance fixture verification occurs before any apply /
  mutation could occur;
* lifecycle validation occurs before any apply / mutation could
  occur;
* canonical commitment bytes (`OnChainGovernanceProofWire`-derived
  digest, candidate digest, authority-domain sequence number,
  proposal id) recorded per scenario.

Run 055 sequence-before-marker ordering and v2-marker-after-
sequence persistence ordering are covered by the Run 134 / 138 /
161 / 165 regression slices re-run by this harness in release mode.

### 2.7 Captured metadata

Recorded under `OUTDIR/`:

* `provenance.txt` — git commit, git branch, git status,
  rustc/cargo versions, host uname, `qbind-node` and helper SHA-256
  + ELF Build ID;
* `exit_codes/` — per-scenario rc;
* `logs/` — per-scenario stdout/stderr (helper, `qbind-node` A1 /
  A2 / A3 / R23, --help, build);
* `helper_evidence/helper_summary.txt` — release-built helper
  verdict and per-scenario expected-vs-actual typed outcome plus
  canonical commitment bytes for accepted Rotate scenarios;
* `reachability/source_reachability.txt` — grep proof of every
  symbol and call-site;
* `test_results/` — per-target `cargo test --release` output;
* `negative_invariants.txt`, `mutation_proof.txt`,
  `no_mutation_proof.txt`, `summary.txt`.

## 3. Required production surfaces — coverage table

Per `task/RUN_183_TASK.txt §Required production surfaces`:

| Surface | Production source | Real-binary evidence | Helper evidence |
|---|---|---|---|
| `--p2p-trust-bundle-reload-check` (validation-only, **A**) | `main.rs::preflight_run_132_validation_only_v2_marker_check` | A1 default-Disabled, A2 CLI selector banner, A3 env selector banner, R23 MainNet refusal | `reload_check_callsite_onchain_governance_marker_decision` over A1–A9 / R1–R26 |
| `--p2p-trust-bundle-reload-apply-path` (mutating, **B**) | `main.rs::preflight_run_134_v2_marker_decision` | A1 default-Disabled, A2 / A3 selector banner reachable, R23 MainNet refusal | `reload_apply_callsite_onchain_governance_marker_decision` over A1–A9 / R1–R26 with canonical commitment bytes |
| Startup `--p2p-trust-bundle` | `main.rs::preflight_run_136_v2_marker_decision_for_startup` | selector banner reachable | `startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision` |
| SIGHUP live reload | `pqc_live_trust_reload.rs::LiveReloadController::preflight_sighup_v2_marker_decision` | selector banner reachable; `LiveReloadConfig` carries selector | `sighup_callsite_onchain_governance_marker_decision` |
| Local `--p2p-trust-bundle-peer-candidate-check` | `main.rs` v2 sidecar dispatch | selector banner reachable | `local_peer_candidate_check_callsite_onchain_governance_marker_decision` (A6) |
| Live inbound `0x05` | `pqc_peer_candidate_wire.rs` post-`verify_marker_for_validation_only_v2` | selector banner reachable | `live_inbound_0x05_callsite_onchain_governance_marker_decision` (A7) |
| Run 150 peer-driven apply drain | `pqc_peer_candidate_apply.rs::ProductionV2MarkerCoordinator::decide_pre_apply` (with `with_onchain_governance_fixture_allowed_selector`) | R23 MainNet refusal | `peer_driven_drain_callsite_onchain_governance_marker_decision` (A8 + surface-level `MainNetRefused`) |

The release-binary harness does not substitute helper-only evidence
for the central production call-site accepted-proof claim: the
real-binary evidence captures call-site **reachability** (the
resolved policy is propagated through every Run 182 callsite
entry's input on every code path), and the release-built helper
captures **fixture-proof acceptance** in release mode through the
same library surface that the binary's call sites link against. The
end-to-end real-binary fixture-proof acceptance flow requires a
wire/schema bump explicitly out of scope for Run 183 (see §5).

## 4. Validation

Per `task/RUN_183_TASK.txt §Validation commands`, the harness runs
in release mode (`cargo test --release -p qbind-node --test ...`)
each of the following targets, recording per-target rc under
`OUTDIR/exit_codes/test_<target>.rc` and per-target log under
`OUTDIR/test_results/test_<target>.log`. If any target name listed
in the spec does not exist in this tree, the harness records
`rc=skipped(not-present)` for that target and continues; per
`task/RUN_183_TASK.txt`, "If exact test names differ, locate
nearest existing targets and document exact commands/results."

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_179_onchain_governance_proof_release_binary_helper`
* `bash scripts/devnet/run_183_onchain_governance_callsite_release_binary.sh`
* `cargo test -p qbind-node --test run_182_onchain_governance_production_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_180_onchain_governance_marker_integration_tests`
* `cargo test -p qbind-node --test run_178_onchain_governance_proof_tests`
* `cargo test -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests`
* `cargo test -p qbind-node --test run_173_validation_only_governance_required_policy_tests`
* `cargo test -p qbind-node --test run_171_governance_required_policy_selector_tests`
* `cargo test -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests`
* `cargo test -p qbind-node --test run_167_governance_proof_carrier_tests`
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
* `cargo test -p qbind-node --lib pqc_onchain_governance_proof_surface`
* `cargo test -p qbind-node --lib pqc_onchain_governance_callsite_wiring`
* `cargo test -p qbind-node --lib`

## 5. Honest verdict

**Verdict: `partial-positive`.** Run 183 captures release-binary
production CALL-SITE reachability on real `target/release/qbind-node`
(CLI flag + env var both arm the Run 180 `AllowFixtureSourceTest`
policy and propagate it through every Run 182 named callsite entry
into the seven production v2 marker-decision code paths;
unset/falsey both keep the `Disabled` production default silent).
The seven Run 182 callsite entries and the seven Run 180 per-surface
wrappers are linked into the same `qbind-node` library surface and
exercised in release mode by the release-built helper across the
full A1–A9 / R1–R26 matrix.

**Honest limitation (unchanged from Run 182).** No current
peer-candidate / SIGHUP-trigger / reload-apply trigger /
startup-bundle / live `0x05` payload format carries a typed
`OnChainGovernanceProof`. Adding that field is explicitly **out of
scope** for Run 183 (no schema bump, no wire field, no sidecar
field, no metric). Therefore production callers in real
`target/release/qbind-node` invoke the Run 182 callsite entries
with `proof: None`, and the end-to-end real-binary fixture-proof
acceptance flow through any of the seven production surfaces is
the strictly next-after-Run-183 integration run identified by this
evidence (the run that adds an additive optional typed
`OnChainGovernanceProof` field to one of the existing peer-candidate
/ SIGHUP / reload-apply / startup-bundle / live-`0x05` payload
formats with a monotonically-bumped wire schema version,
fail-closed default, DevNet/TestNet-only fixture acceptance, and
explicit MainNet refusal, then captures marker / sequence JSON+SHA
before / after on at least one mutating surface).

## 6. Strict scope statements

Per `task/RUN_183_TASK.txt §Documentation requirements`, this
report explicitly states:

* Run 183 is release-binary OnChainGovernance production call-site
  evidence.
* Default remains `OnChainGovernanceProofPolicy::Disabled`.
* Hidden CLI/env selector enables `AllowFixtureSourceTest`.
* DevNet/TestNet fixture OnChainGovernance proofs can pass through
  real production call sites (via the Run 182 named callsite
  entries, exercised in release mode through the release-built
  helper) where lifecycle / anti-rollback checks pass.
* Invalid fixture proofs fail closed.
* Production MainNet OnChainGovernance remains unsupported /
  fail-closed.
* MainNet peer-driven apply remains refused.
* Governance execution remains unimplemented.
* Real on-chain proof verification remains unimplemented.
* KMS/HSM remains unimplemented.
* Validator-set rotation remains open.
* Full C4 remains open.
* C5 remains open.

## 7. Cross-checks against existing design / spec

Run 183 was cross-checked against the Run 178 / 179 / 180 / 181 /
182 documentation, the Run 147 / 148 / 152 MainNet refusal
invariant, the Run 055 sequence-before-marker ordering invariant,
the Run 070 mutating apply gate, and the documented denylist in
`docs/whitepaper/contradiction.md`. **No contradictions or
inconsistencies were identified.** The Run 183 deliverables are
purely additive (one harness, one evidence archive with placeholder
README/summary/.gitignore, one canonical evidence report, four
narrow append-only doc paragraphs) and consistent with the Run 181
evidence-archive convention. The honest limitation recorded in §5
is the same wire/schema blocker Run 182 honestly recorded, repeated
here verbatim for traceability.
