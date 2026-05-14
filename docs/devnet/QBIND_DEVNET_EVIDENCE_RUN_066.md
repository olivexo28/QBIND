# QBIND DevNet Evidence — Run 066: Operator Lifecycle Runbook Update for Run 065 (DOCS-ONLY; full C4 still OPEN)

## Exact objective

Run 066 updates the Run 064 operator playbook
(`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`) so that operators
have accurate, production-honest guidance for the per-environment
minimum activation-margin policy landed by Run 065:

- the per-environment constants
  `MIN_DEVNET_ACTIVATION_MARGIN = 0`,
  `MIN_TESTNET_ACTIVATION_MARGIN = 8`, and
  `MIN_MAINNET_ACTIVATION_MARGIN = 32` and the single source of
  truth `ActivationPolicy::for_environment(env)`;
- the half-open `[current_height, current_height + margin)`
  reject window and its three scopes (bundle-level
  `activation_height`, per-active-root `activation_height`, and
  per-entry revocation `activation_height` when `Some(_)`);
- the explicit emergency-revocation-preserved boundary —
  per-entry revocations with `activation_height = None` are
  immediate and NEVER subject to Run 065 regardless of
  environment;
- the snapshot-rejoin-preserved boundary — bundles whose
  `activation_height` is strictly less than `current_height`
  (already-effective in the past) are NOT retroactively rejected;
- the strict load-path ordering: Run 065 fires AFTER signature /
  chain_id / environment / revocation structural validation and
  BEFORE Run 057's future-height gate, Run 055's sequence
  persistence, and Run 050's root merge — a rejected too-soon
  bundle does NOT create `pqc_trust_bundle_sequence.json` and
  does NOT update `loaded.active_roots`;
- the reschedule / FATAL-message shapes, the explicit
  "No fallback to --p2p-trusted-root" non-fallback marker, and
  the static "Emergency revocations should be published without
  activation_height (immediate)" remedy on the scheduled-
  revocation error path.

Run 066 is **documentation-only**. No `crates/**/src/**` source,
no test source, no helper source, no `Cargo.toml`, no
`main.rs` / `pqc_trust_bundle.rs` / `pqc_trust_sequence.rs` /
`pqc_trust_activation.rs` / `pqc_root_config.rs` /
`p2p_node_builder.rs` / `metrics.rs` was touched in this run; Run
037, Run 040, Run 044, and the entire Run 050–065 chain are
preserved bit-for-bit.

The scope is intentionally narrow (per task `RUN_066_TASK.txt`):

- update the existing runbook in place to record the Run 065
  closure and the new constants;
- create this evidence document;
- update `docs/whitepaper/contradiction.md` with a Run 066 C4 row
  recording that the operator-playbook-prose gap left open by
  Run 065 §10 item (h) is now closed/narrowed;
- preserve every Run 050–065 fail-closed claim accurately
  (signature verification, chain_id crosscheck, sequence anti-
  rollback, bundle-level activation, per-entry revocation
  active/pending split, local-leaf startup self-check, local-
  issuer-root startup self-check, per-environment minimum
  activation margin, no-fallback to `--p2p-trusted-root`, no
  `Dummy*` under `pqc-static-root`);
- do NOT recommend static-root fallback, `Dummy*` crypto,
  unsigned MainNet bundles, or key reuse between transport
  roots / bundle-signing keys / validator consensus keys / leaf
  KEM material;
- do NOT redesign anything; do NOT implement KMS/HSM,
  signing-key ratification, hot reload, or epoch-runtime source.

## Exact verdict

**Strongest positive for the scoped Run 066 documentation update.**

- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` is updated to
  reflect Run 065 behaviour without introducing any contradiction
  against the implementation. All operator guidance for the
  minimum activation-margin policy is anchored in the
  implementation: the per-environment constants, the half-open
  reject window, the three scopes (bundle, active root, per-entry
  revocation when `Some(_)`), the immediate-revocation-preserved
  boundary, the snapshot-rejoin-preserved boundary, the strict
  load-path ordering (Run 065 BEFORE Run 057 / Run 055 / Run 050
  in the loader), and the reschedule / non-fallback FATAL message
  shapes.
- A new evidence doc (this file) records the investigation,
  changed runbook sections, and check status.
- `docs/whitepaper/contradiction.md` is updated with a Run 066 C4
  row stating the operator-playbook-prose gap for Run 065 is
  closed/narrowed; full C4 explicitly remains OPEN.
- All unsafe-guidance grep checks pass on the updated runbook: no
  `--p2p-trusted-root` fallback recommendation, no `Dummy*`
  recommendation, no unsigned-MainNet recommendation, no
  transport-root / bundle-signing-key reuse recommendation.
- `cargo check -p qbind-node --bin qbind-node` is clean (only
  pre-existing `bincode::config` deprecation warnings, identical
  to the Run 065 baseline; Run 066 changed no Rust source).
- No source changes were required: investigation found no
  contradiction between the runbook prose and the Run 065
  implementation in `crates/qbind-node/src/pqc_trust_activation.rs`,
  `pqc_trust_bundle.rs`, and `main.rs`. The runbook simply lagged
  the implementation on the minimum-activation-margin boundary
  Run 065 closed. Run 066 brings the prose forward to match.

## Exact files changed

| File | Change |
|---|---|
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | Header bumped to Run 066 with an explicit "this is a docs-only update of the Run 064 playbook for Run 065" note; status line expanded to "Runs 050–065"; anchors list for `pqc_trust_activation.rs` extended with the Run 065 constants (`MIN_DEVNET_ACTIVATION_MARGIN`, `MIN_TESTNET_ACTIVATION_MARGIN`, `MIN_MAINNET_ACTIVATION_MARGIN`), `ActivationPolicy::for_environment`, `minimum_activation_margin_for_environment`, the new policy helper `check_min_activation_height_policy`, the two new error variants, and the `RevocationScope` struct; `main.rs` anchor extended with the Run 065 load-path ordering claim ("AFTER signature/chain_id/environment/revocation structural validation and BEFORE Run 057 / Run 055 / Run 050"); evidence-doc anchor extended to `RUN_065.md`; §1.2 non-goals: the previous "per-environment minimum activation-height policy enforced by the binary" non-goal is rewritten to record that Run 065 enforces it on the `--p2p-trust-bundle` load path and that the only remaining piece is the gossiped/peer-supplied path (hot reload); §1.3 invariants table extended with a new "Per-environment minimum activation-margin policy (Run 065)" row pinning the constants, the half-open window, the three scopes, the immediate-revocation-preserved boundary, the snapshot-rejoin-preserved boundary, the strict load-path ordering, and the `u64::MAX` saturating-add defence; §3.9 (revocation entries) `current_height` source paragraph extended to note that the same `Option<u64>` source feeds Run 065; §3.9 operational-recommendation paragraph rewritten — emergency revocations omit `activation_height` (immediate, exempt from Run 065); scheduled revocations on TestNet/MainNet MUST satisfy the Run 065 minimum margin; §3.10 (activation height / epoch field) rewritten to incorporate the new minimum-margin policy paragraph (constants, half-open window, snapshot-rejoin), the operator-policy change (`activation_height == current_height` is rejected on TestNet/MainNet by Run 065), and the explicit emergency-immediate-revocation exception; §5.1 (DevNet) extended with the `MIN_DEVNET_ACTIVATION_MARGIN = 0` claim and the immediate-cutover preservation note; §5.2 (TestNet) extended with the `MIN_TESTNET_ACTIVATION_MARGIN = 8` claim and the explicit reject window; §5.3 (MainNet) rewritten — replaced the old "binary does not enforce a minimum margin today" wording with the actual Run 065 floor `MIN_MAINNET_ACTIVATION_MARGIN = 32` blocks, the exact FATAL marker phrase, and the operator-guidance distinction ("32 is the binary floor, not the operator target"); §6.A step 3 extended — the overlap bundle's `activation_height` MUST satisfy the binary-enforced Run 065 floors on TestNet/MainNet; §6.B step 1 rewritten — the emergency revocation MUST set per-entry `activation_height = None` (immediate, exempt from Run 065); the bundle-level `activation_height` SHOULD be omitted (no restriction) for emergency rotation, or MUST satisfy the Run 065 floor on TestNet/MainNet if set; the old "no margin — emergency" wording removed; §6.E step 1 rewritten — replaced the old "binary does not today enforce a minimum margin" wording with the concrete per-environment floors enforced by the binary; §7 promotion checklist: existing `activation_height` margin item rewritten to reference the Run 065 floor directly (with the half-open reject window) and to record that a rejected too-soon bundle will NOT advance the persisted sequence file; existing per-entry-revocation `activation_height` item rewritten the same way; five new checklist items added — `current_height` source confirmation (Run 057 / Run 065), explicit outside-reject-window confirmation across all three scopes, sequence-not-burned confirmation, a Run 065 too-soon negative smoke (Run 065 Smokes 2/4 shape), and a sufficient-margin / Run-057 boundary smoke (Run 065 Smokes 3/5 shape); banner-order line extended to record that a too-soon TestNet/MainNet bundle emits the Run 065 FATAL BEFORE any of the post-load banners; §8 incident checklist: existing `activation_height` triage item rewritten with the explicit immediate-vs-scheduled distinction under Run 065 (immediate = `activation_height = None`, exempt; scheduled = `Some(h)`, `h >= current_height + minimum_activation_margin` or refused at load); new items added — liveness-impact-before-immediate-root-revocation confirmation, replacement-cert-deployed-before-scheduled-revocation confirmation; existing "Mint an (N+1) bundle … with `activation_height = current_finalised_height` (no margin — emergency)" item rewritten — per-entry revocation MUST be `None` for compromise; bundle-level `activation_height` SHOULD be omitted or MUST satisfy the Run 065 floor on TestNet/MainNet; §9 evidence checklist: three new items added — Run 065 too-soon negative smoke transcript (with the exact FATAL marker phrase, the explicit "No fallback to --p2p-trusted-root" claim, and the filesystem check confirming `pqc_trust_bundle_sequence.json` is absent), sufficient-margin / Run-057 boundary smoke transcript, and explicit `h >= current_height + minimum_activation_margin` confirmation for scheduled TestNet/MainNet revocations; §10 residual risks rewritten — removed the now-closed "per-environment minimum activation-height policy" item, renumbered the remaining items, narrowed item 2 to the gossiped/peer-supplied-bundle path (the only remaining open piece on the minimum-margin axis), updated item 4 (production fast-sync) to reference the Run 057 + Run 065 shared `current_height` source via `ActivationContext::height_only`, added a new "Closed by Run 065" entry to the "Closed by Runs 061–063" sub-list (renamed to "Closed by Runs 061–063 and Run 065"); §11 mapping header renamed from "050–063" to "050–065"; new rows added for Run 064 (operator-playbook prose update for Runs 061–063) and Run 065 (per-environment minimum activation-margin policy — full description anchored on the live smokes); new row added for Run 066 (this docs-only update). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_066.md` | NEW evidence document (this file). |
| `docs/whitepaper/contradiction.md` | NEW C4 Run 066 row appended after the existing C4 Run 065 row: records that the operator-playbook-prose gap from Run 065 §10 item (h) is now closed/narrowed; explicitly preserves all other open C4 items; explicitly does NOT claim full C4 closure or any C5 closure. |

No other files are touched. No `crates/**/src/**` change. No test
file change. No helper-example change. No `Cargo.toml` change.

## Exact commands run

```
# Investigation (read-only):
view of:
  docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md (current Run 064 prose)
  docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_064.md (shape reference)
  docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_065.md (Run 065 source-of-truth)
  docs/whitepaper/contradiction.md (Run 063/064/065 rows)
  crates/qbind-node/src/pqc_trust_activation.rs
    (MIN_DEVNET_ACTIVATION_MARGIN / MIN_TESTNET_ACTIVATION_MARGIN /
     MIN_MAINNET_ACTIVATION_MARGIN constants, ActivationPolicy,
     check_min_activation_height_policy, error variants,
     RevocationScope)

# Unsafe-guidance grep checks (post-edit; see "Tests/checks"):
grep -in -- '--p2p-trusted-root' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
grep -in -i -- 'dummysig|dummykem|dummyaead' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
grep -in -i -- 'unsigned' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
grep -in -i -- 'reuse|same key' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md

# Build sanity (no source touched but task discipline requires this):
cargo check -p qbind-node --bin qbind-node
```

## Tests / checks run and pass/fail status

| Check | Result |
|---|---|
| `grep --p2p-trusted-root` on the runbook | PASS — every occurrence is either (a) inside the §1.3 invariants table or §6.B step 3 forbidding the fallback, (b) inside §6.A / §6.D documenting how the binary refuses the flag combination, (c) the §12 glossary entry explaining the flag is forbidden with `--p2p-trust-bundle` on TestNet/MainNet, or (d) inside the explicit "No fallback to `--p2p-trusted-root` on bundle-revoked …" FATAL phrases quoted from Run 061/063/065. No occurrence recommends using it as a fallback. |
| `grep -i 'dummysig\|dummykem\|dummyaead'` on the runbook | PASS — every occurrence is inside a "MUST NOT register `Dummy*`" / "no `Dummy*` is registered" claim anchored in Runs 037/039/040/041. No occurrence recommends using a `Dummy*` primitive. |
| `grep -i 'unsigned'` on the runbook | PASS — every occurrence either (a) records that unsigned bundles ARE allowed only on DevNet (§5.1), (b) explicitly forbids unsigned bundles on TestNet (§5.2) and MainNet (§5.3 / §1.3 invariants table), or (c) cites RUN_059 Smoke 2 as proof MainNet rejects unsigned bundles. No occurrence recommends accepting an unsigned MainNet bundle. |
| `grep -i 'reuse\|same key'` on the runbook | PASS — every occurrence is inside §2.1 / §2.2 / §4.4 / §3.4 forbidding reuse between transport root keys, bundle-signing keys, validator consensus keys, and leaf KEM material. No occurrence recommends reuse. |
| `cargo check -p qbind-node --bin qbind-node` | PASS — clean with only the pre-existing `bincode::config` deprecation warnings (lines 2332 and 2461 in `crates/qbind-node/src/binary_consensus_loop.rs`), identical to the Run 065 baseline. Run 066 changed no Rust source. |
| Regression test suites | Not re-run by Run 066: this run modifies no Rust source. The Run 065 baseline (`cargo test -p qbind-node --lib pqc_trust_activation` 34/34, `--lib pqc_trust_bundle` 100/100, `--lib pqc_trust_sequence` 21/21, `--lib` 946/946, `--test run_065_pqc_min_activation_margin_tests` 12/12, every Run 050–064 suite, `cargo build --release -p qbind-node --bin qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper` clean) is preserved bit-for-bit. |

## Investigation findings (with file / function references)

1. **Run 064 runbook accurately reflected Runs 050–063** but was
   intentionally not updated by Run 065 (Run 065 §10 item (h)
   "Operator playbook prose for the new minimum margin"
   explicitly defers this to a future docs-only run). Specifically:
   - §3.10 still said "binary does not enforce a minimum margin
     today (recorded in §10); this is an operator policy" —
     superseded by the Run 065 `check_min_activation_height_policy`
     helper wired into the load path
     (`crates/qbind-node/src/pqc_trust_bundle.rs::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`).
   - §5.3 (MainNet) said "Note: the binary does not enforce a
     minimum margin today (recorded in §10); this is an operator
     policy" — superseded by `MIN_MAINNET_ACTIVATION_MARGIN = 32`
     enforced at load.
   - §6.B step 1 said `activation_height = current_finalised_height
     (no margin — emergency)` — superseded by the Run 065 policy
     for the bundle-level field (the correct emergency shape is
     per-entry `activation_height = None`, exempt from Run 065,
     plus an omitted bundle-level `activation_height`).
   - §6.E step 1 said "The binary does not today enforce a minimum
     margin (§10); the recommended floor is the same as §5.3" —
     superseded by the Run 065 per-environment binary-enforced
     floor.
   - §10 item 2 ("Per-environment minimum activation-height
     policy") said "The binary does not enforce a minimum margin
     between `activation_height` … and the current finalised
     height" — now closed by Run 065 on the `--p2p-trust-bundle`
     load path; the only remaining open piece on this axis is the
     gossiped/peer-supplied trust-bundle path (item 2 in the Run
     066 §10 renumbering).
   - §11 mapping table stopped at Run 063 with no rows for Runs
     064/065.

2. **No contradictions found between the runbook and the
   implementation.** The per-environment constants quoted in
   `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_065.md`
   (`MIN_DEVNET_ACTIVATION_MARGIN = 0`,
   `MIN_TESTNET_ACTIVATION_MARGIN = 8`,
   `MIN_MAINNET_ACTIVATION_MARGIN = 32`) match
   `crates/qbind-node/src/pqc_trust_activation.rs` lines 134, 140,
   145 exactly. The strict ordering DevNet < TestNet < MainNet is
   pinned by `run065_policy_constants_are_deterministic` (lines
   1026–1030). The half-open reject window
   `[current_height, current_height + margin)` matches the loop
   logic at lines 694, 714, 734. The `RevocationScope` struct at
   line 301 carries only public material (8-hex prefix on
   `root_id` / `leaf_fingerprint`). The two new error variants
   `ActivationHeightBelowMinimumMargin` (line 269) and
   `RevocationActivationHeightBelowMinimumMargin` (line 287)
   carry only public material in their `Display` impl (lines 382
   and 400). The `check_min_activation_height_policy` public
   signature at line 652 takes `(&TrustBundle,
   TrustBundleEnvironment, Option<u64>)` — no private key material.
   The load-path call-site ordering described in
   `QBIND_DEVNET_EVIDENCE_RUN_065.md` ("AFTER
   `validate_at_with_signing_keys_chain_id_and_revocation_activation`,
   BEFORE `check_bundle_activation`") matches the source. No
   runtime code change required.

3. **No unsafe guidance found before or after the edit.** The
   four grep checks listed in "Tests / checks" above all pass.
   In particular, the rewritten §3.9 emergency-revocation
   paragraph and the §6.B step 1 emergency-revocation block both
   correctly preserve the `activation_height = None` exemption
   without introducing any "use static-root fallback" or
   "soften the revocation" guidance.

## Runbook sections changed

- **Header (lines ~1–17).** Run number bumped from 064 to 066;
  status line expanded to "Runs 050–065"; added an explicit
  Run-066-is-docs-only note that scopes it as the prose update
  for Run 065.
- **Anchors list (immediately after the header).** Extended the
  `pqc_trust_activation.rs` anchor with the Run 065 constants,
  the `ActivationPolicy::for_environment` API, the
  `check_min_activation_height_policy` helper, the two new error
  variants, and `RevocationScope`. Extended the `main.rs` anchor
  with the Run 065 load-path ordering claim. Extended the
  evidence-doc anchor to `RUN_065.md`.
- **§1.2 In/out of scope (non-goals).** The previous
  "per-environment minimum activation-height policy enforced by
  the binary" non-goal is rewritten — Run 065 enforces it on the
  `--p2p-trust-bundle` load path, so the only remaining open
  piece is the gossiped/peer-supplied trust-bundle path (the
  same `check_min_activation_height_policy` helper must be
  threaded through that path when on-the-fly distribution lands).
- **§1.3 Strictly preserved invariants.** New row pinning the
  per-environment minimum activation-margin policy (Run 065):
  the constants, the half-open reject window, the three scopes
  (bundle-level, per-active-root, per-entry revocation when
  `Some(_)`), the immediate-revocation-preserved boundary, the
  snapshot-rejoin-preserved boundary, the strict load-path
  ordering, and the `u64::MAX` saturating-add defence.
- **§3.9 Revocation entries.** `current_height` source paragraph
  extended to note that the same `Option<u64>` source feeds Run
  065. Operational-recommendation paragraph rewritten —
  emergency-compromise revocations omit `activation_height`
  (immediate; exempt from Run 065); scheduled revocations with
  `activation_height = Some(h)` on TestNet/MainNet MUST satisfy
  the Run 065 minimum margin.
- **§3.10 Activation height / epoch field.** Rewritten end to
  end. New minimum-margin policy paragraph (constants, half-open
  window, snapshot-rejoin); operator policy changed from
  "recommended" to "required" with the explicit binary-floor
  numbers; emergency-immediate-revocation exception called out;
  the `activation_epoch` boundary preserved and clarified that
  Run 065 does NOT introduce a minimum-margin policy on the
  epoch axis.
- **§5.1 DevNet.** New bullet recording
  `MIN_DEVNET_ACTIVATION_MARGIN = 0` and the immediate-cutover
  preservation property.
- **§5.2 TestNet.** New bullet recording
  `MIN_TESTNET_ACTIVATION_MARGIN = 8` and the explicit reject
  window.
- **§5.3 MainNet.** "Recommended minimum activation-height
  margin" bullet rewritten — replaced "binary does not enforce a
  minimum margin today" with the actual binary-enforced
  `MIN_MAINNET_ACTIVATION_MARGIN = 32`, the exact FATAL marker
  phrase, and the operator-guidance distinction ("32 is the
  binary floor, not the operator target"). The emergency
  immediate-revocation exception is preserved.
- **§6.A Normal transport root rotation, step 3.** Overlap
  bundle's `activation_height` MUST satisfy the binary-enforced
  Run 065 floors on TestNet (8 blocks) and MainNet (32 blocks).
- **§6.B Emergency transport root revocation, step 1.** Rewritten
  end to end — per-entry revocation MUST set
  `activation_height = None` (immediate; exempt from Run 065);
  bundle-level `activation_height` SHOULD be omitted (no
  restriction) for emergency rotation, or MUST satisfy the
  Run 065 floor on TestNet/MainNet if set. The old "no margin —
  emergency" wording is removed.
- **§6.E Scheduled revocation via per-entry `activation_height`,
  step 1.** Rewritten — replaced the old "binary does not today
  enforce a minimum margin (§10); the recommended floor is the
  same as §5.3" with the concrete per-environment binary-enforced
  floors and the "floor is what the binary will refuse, not the
  operator target" distinction.
- **§7 Promotion checklist.** Existing `activation_height` margin
  item rewritten to reference the Run 065 floor directly with
  the half-open reject window and the "rejected too-soon bundle
  will NOT advance the persisted sequence" note. Existing
  per-entry-revocation `activation_height` item rewritten the
  same way. Five new checklist items added: `current_height`
  source confirmation, outside-reject-window confirmation across
  all three scopes, sequence-not-burned confirmation, Run 065
  too-soon negative smoke (Run 065 Smokes 2/4 shape), and
  sufficient-margin / Run-057 boundary smoke (Run 065 Smokes 3/5
  shape). Banner-order line extended to record that a too-soon
  TestNet/MainNet bundle emits the Run 065 FATAL BEFORE any of
  the post-load banners.
- **§8 Incident checklist.** Existing `activation_height` triage
  item rewritten with the explicit immediate-vs-scheduled
  distinction under Run 065 (`None` = immediate, exempt; `Some(h)`
  = scheduled, `h >= current_height + minimum_activation_margin`
  or refused at load). New items added — liveness-impact-before-
  immediate-root-revocation confirmation; replacement-cert-
  deployed-before-scheduled-revocation confirmation. Existing
  "Mint an (N+1) bundle … with `activation_height =
  current_finalised_height` (no margin — emergency)" item
  rewritten — per-entry revocation MUST be `None` for
  compromise; bundle-level `activation_height` SHOULD be omitted
  or MUST satisfy the Run 065 floor on TestNet/MainNet.
- **§9 Evidence checklist.** Three new items added — Run 065
  too-soon negative smoke transcript (with the exact FATAL
  marker phrase, the "No fallback to --p2p-trusted-root" claim,
  and the filesystem check confirming
  `pqc_trust_bundle_sequence.json` is absent under the data
  dir); sufficient-margin / Run-057 boundary smoke transcript;
  explicit `h >= current_height + minimum_activation_margin`
  confirmation for scheduled TestNet/MainNet revocations.
- **§10 Residual risks.** Renumbered. Removed the now-closed
  "per-environment minimum activation-height policy" item.
  Narrowed item 2 to the gossiped/peer-supplied-bundle path (the
  only remaining open piece on the minimum-margin axis), citing
  the load-path-only helper boundary and the on-the-fly hot-
  reload prerequisite. Item 4 (production fast-sync) updated to
  reference the Run 057 + Run 065 shared `current_height` source
  via `ActivationContext::height_only`. Sub-list header renamed
  from "Closed by Runs 061–063" to "Closed by Runs 061–063 and
  Run 065"; new entry added for Run 065 naming the helper, the
  constants, the half-open reject window scope, and the
  emergency-immediate-revocation exception.
- **§11 Mapping to Runs.** Header renamed from "050–063" to
  "050–065". New rows added for Run 064 (operator-playbook
  prose update for Runs 061–063), Run 065 (per-environment
  minimum activation-margin policy — full description anchored
  on the five live smokes), and Run 066 (this docs-only update).

## How Run 065 is represented

| Run | Representation in the updated runbook |
|---|---|
| 065 | Anchors list (`pqc_trust_activation.rs` extended with constants, helper, error variants, `RevocationScope`; `main.rs` anchor extended with load-path ordering); §1.2 non-goals (rewritten to record load-path closure and remaining gossiped-path open piece); §1.3 invariants table (new row); §3.9 (`current_height` source paragraph + operational-recommendation paragraph); §3.10 (full rewrite); §5.1 / §5.2 / §5.3 (per-environment constants and reject-window descriptions); §6.A step 3 (overlap bundle margin); §6.B step 1 (emergency rotation — `activation_height = None` exempt, bundle-level omit or satisfy floor); §6.E step 1 (concrete binary-enforced floor); §7 promotion checklist (rewritten margin items + five new smoke / source items); §8 incident checklist (rewritten triage item + new liveness / replacement-cert items + rewritten "Mint (N+1) bundle" item); §9 evidence checklist (three new transcript items); §10 residual risks ("Closed by … Run 065" sub-list entry + narrowed gossiped-path item); §11 mapping table row. |

## Contradictions found

**None.** The investigation found no contradiction between the
Run 064 runbook and the implementation in
`crates/qbind-node/src/{pqc_trust_activation.rs,pqc_trust_bundle.rs,main.rs}`
after Run 065. The runbook simply lagged the implementation on
the per-environment minimum-activation-margin boundary that Run
065 closed. Run 066 brings the prose forward to match.

No `contradiction.md` entry beyond the new Run 066 C4 row is
required.

## Remaining open items (NOT closed by Run 066)

Run 066 does NOT close any of the following — they remain open
under C4 and are reflected accurately in the updated runbook §10:

1. Bundle-level and per-entry `activation_epoch` runtime source
   (Run 057 + Run 062 boundary). Run 065 did NOT introduce a
   minimum-margin policy on the epoch axis.
2. Per-environment minimum activation-margin policy on the
   gossiped / peer-supplied trust-bundle path. Run 065 enforces
   the policy on the `--p2p-trust-bundle` load path; the same
   `pqc_trust_activation::check_min_activation_height_policy`
   helper must be threaded through the gossiped/peer-supplied
   path when on-the-fly distribution lands.
3. On-the-fly trust-bundle hot reload.
4. Production fast-sync / consensus-storage restore (the Run 065
   `current_height` source is already fed by
   `--restore-from-snapshot.snapshot_height` via
   `ActivationContext::height_only`; a fully-fledged production
   fast-sync surface is a separate boundary).
5. Per-environment production trust-anchor operation (HSM /
   offline custody).
6. In-binary / on-chain bundle-signing-key rotation /
   ratification.
7. Two-node / N-node MainNet release-binary peer-connection smoke
   evidence.
8. External KMS / HSM integration.

**Full C4 remains OPEN. C5 remains NOT closed.**

## Exact immediate next action

Pick one of (in C4 priority order):

1. **In-binary / on-chain bundle-signing-key ratification.**
   Replace the §6.D out-of-band CLI overlap with an in-bundle
   `ratified_signing_key_id` / `ratified_signing_key_pk` surface
   that the next-sequence bundle's signature covers, enabling a
   single-bundle rotation with no operator CLI restart loop.

2. **Production multi-validator MainNet release-binary
   peer-connection smoke.** Pre-blocked on production-config
   items called out in Run 059's evidence doc (validator
   keystore loading on startup, per-peer consensus-key
   distribution); landing those unlocks the smoke.

3. **On-the-fly trust-bundle hot reload (and the gossiped path
   for Run 065).** A future run adds in-process bundle reload so
   pending revocations can transition to active without a
   process restart; the same Run 065
   `check_min_activation_height_policy` helper threads through
   the reload site and through any peer-supplied bundle path
   that lands later.

4. **`qbind_p2p_pqc_trust_bundle_activation_min_margin_rejected_total`
   metric (and `*_scheduled_revocation_*` sibling).** Optional
   operator-dashboard refinement if/when operators need to
   distinguish margin rejections from future-height rejections
   at scrape time. Run 065's existing
   `qbind_p2p_pqc_trust_bundle_activation_rejected{required_height_label}`
   already surfaces `required_min_height` on its label.