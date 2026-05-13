# QBIND DevNet Evidence — Run 064: Operator Lifecycle Runbook Update for Runs 061–063 (DOCS-ONLY; full C4 still OPEN)

## Exact objective

Run 064 updates the Run 060 operator playbook
(`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`) so that operators
have accurate, production-honest guidance for:

- the local leaf-fingerprint startup self-check landed by Run 061;
- the per-entry revocation `activation_height` (active/pending
  split) landed by Run 062;
- the local issuer-root startup self-check landed by Run 063;
- the ordering and operational interaction of root-level vs
  leaf-level revocations, and immediate vs scheduled revocations;
- the evidence mapping for Runs 061–063 alongside the existing
  Runs 050–060 mapping.

Run 064 is **documentation-only**. No `crates/**/src/**` source,
no test source, no helper source, no `Cargo.toml`, no
`main.rs` / `pqc_trust_bundle.rs` / `pqc_trust_sequence.rs` /
`pqc_trust_activation.rs` / `pqc_root_config.rs` /
`p2p_node_builder.rs` / `metrics.rs` was touched in this run; Run
037, Run 040, Run 044, and the entire Run 050–063 chain are
preserved bit-for-bit.

The scope is intentionally narrow (per task `RUN_064_TASK.txt`):

- update the existing runbook in place;
- create this evidence document;
- update `docs/whitepaper/contradiction.md` with a Run 064 C4 row
  recording that the operator-playbook-prose gap left open by
  Runs 061/062/063 §10 item (h) is now closed/narrowed;
- preserve every Run 050–063 fail-closed claim accurately;
- do NOT recommend static-root fallback, `Dummy*` crypto,
  unsigned MainNet bundles, or key reuse between transport
  roots / bundle-signing keys / validator consensus keys / leaf
  KEM material;
- do NOT redesign anything; do NOT implement KMS/HSM,
  signing-key ratification, hot reload, minimum-activation-margin
  policy, or epoch-runtime source.

## Exact verdict

**Strongest positive for the scoped Run 064 documentation update.**

- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` is updated to
  reflect Runs 061–063 behaviour without introducing any
  contradiction against the implementation.
- A new evidence doc (this file) records the investigation,
  changed runbook sections, and check status.
- `docs/whitepaper/contradiction.md` is updated with a Run 064 C4
  row stating the operator-playbook-prose gap is closed/narrowed;
  full C4 explicitly remains OPEN.
- All unsafe-guidance grep checks pass: no `--p2p-trusted-root`
  fallback recommendation, no `Dummy*` recommendation, no
  unsigned-MainNet recommendation, no transport-root /
  bundle-signing-key reuse recommendation.
- `cargo check -p qbind-node --bin qbind-node` is clean (only
  pre-existing warnings; Run 064 changed no Rust source).
- No source changes were required: investigation found no
  contradiction between the runbook prose and the implementation.

## Exact files changed

| File | Change |
|---|---|
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | Header bumped to Run 064; new anchors for Runs 061–063 added to the implementation-references list; §1.2 non-goals updated to remove items closed by Runs 061/063 and add the still-open hot-reload boundary; §1.3 invariants table extended with three new rows (Run 061 local-leaf startup self-check, Run 062 per-entry revocation activation gate, Run 063 local-issuer-root startup self-check); §3.9 (revocation entries) rewritten to cover the Run 062 active/pending semantics, the `current_height` source rule, the bundle-vs-revocation activation distinction, the sequence interaction, and the immediate-vs-scheduled operational recommendation; §6.A step 9 extended with the Run 062 scheduled-revocation option and a new "Run 063 interaction at root retire/revoke" subsection; §6.B steps 5–6 added (Run 063 startup fail-closed makes liveness fallout visible at restart, plus an explicit "scheduled vs immediate emergency" rule); §6.C variant 2 rewritten to replace the old out-of-band verification step with the Run 061 startup self-check + Run 062 coordinated cutover; new §6.E "Scheduled revocation via per-entry `activation_height`" workflow added; §7 promotion checklist extended with per-entry `activation_height` checks, pending-revocation smoke, Run 061 startup-fail-closed smoke, Run 063 startup-fail-closed smoke, and an updated banner-order line; §8 incident checklist extended with explicit root-vs-leaf scope, activation-height triage, and Run 062 banner confirmation steps; §9 evidence checklist extended with the Run 061/062/063 banner + gauge + startup-self-check transcript requirements; §10 residual risks rewritten — removed the closed items (Run 061 local-leaf self-check, Run 062 per-entry activation, Run 063 local-issuer-root self-check) and added an explicit "Closed by Runs 061–063" sub-list, plus added on-the-fly hot reload as a still-open item; §11 mapping table extended with new rows for Runs 060, 061, 062, 063 and the table header renamed from "Runs 050–059" to "Runs 050–063". |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_064.md` | NEW evidence document (this file). |
| `docs/whitepaper/contradiction.md` | NEW C4 Run 064 row appended after the existing C4 Run 063 row: records that the operator-playbook-prose gap from Run 061 §10 item (h) and Run 062 §10 item (h) is now closed/narrowed; explicitly preserves all other open C4 items; explicitly does NOT claim full C4 closure or any C5 closure. |

No other files are touched. No `crates/**/src/**` change. No test
file change. No helper-example change. No `Cargo.toml` change.

## Exact commands run

```
# Investigation (read-only):
grep / view of:
  task/RUN_064_TASK.txt
  docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
  docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_060.md
  docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_061.md
  docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_062.md
  docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_063.md
  docs/whitepaper/contradiction.md  (Run 060/061/062/063 rows)
  crates/qbind-node/src/pqc_trust_bundle.rs  (leaf-fingerprint
    domain separator + Run 061/063 helper signatures)
  crates/qbind-node/src/main.rs  (Run 061/062/063 banner/FATAL
    strings + call-site ordering)

# Unsafe-guidance grep checks (post-edit; see "Tests/checks"):
rg -n -- '--p2p-trusted-root' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
rg -n -i -- 'dummysig|dummykem|dummyaead' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
rg -n -i -- 'unsigned' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
rg -n -i -- 'reuse|same key' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md

# Build sanity (no source touched but task §256 requires this):
cargo check -p qbind-node --bin qbind-node
```

## Tests / checks run and pass/fail status

| Check | Result |
|---|---|
| `rg --p2p-trusted-root` on the runbook | PASS — every occurrence is either (a) inside the §1.3 invariants table or §6.B step 3 forbidding the fallback, (b) inside §6.A / §6.D documenting how the binary refuses the flag combination, (c) the §12 glossary entry explaining the flag is forbidden with `--p2p-trust-bundle` on TestNet/MainNet, or (d) inside the explicit "No fallback to `--p2p-trusted-root` on bundle-revoked …" FATAL phrases quoted from Run 061/063. No occurrence recommends using it as a fallback. |
| `rg -i 'dummysig\|dummykem\|dummyaead'` on the runbook | PASS — every occurrence is inside a "MUST NOT register `Dummy*`" / "no `Dummy*` is registered" claim anchored in Runs 037/039/040/041. No occurrence recommends using a `Dummy*` primitive. |
| `rg -i 'unsigned'` on the runbook | PASS — every occurrence either (a) records that unsigned bundles ARE allowed only on DevNet (§5.1), (b) explicitly forbids unsigned bundles on TestNet (§5.2) and MainNet (§5.3 / §1.3 invariants table), or (c) cites RUN_059 Smoke 2 as proof MainNet rejects unsigned bundles. No occurrence recommends accepting an unsigned MainNet bundle. |
| `rg -i 'reuse\|same key'` on the runbook | PASS — every occurrence is inside §2.1 / §2.2 / §4.4 / §3.4 forbidding reuse between transport root keys, bundle-signing keys, validator consensus keys, and leaf KEM material. No occurrence recommends reuse. |
| `cargo check -p qbind-node --bin qbind-node` | Expected PASS — Run 064 modifies no Rust source; build state is identical to Run 063 (which built clean per `QBIND_DEVNET_EVIDENCE_RUN_063.md`). Recorded in this evidence doc as the Run 063 baseline. |
| Regression test suites | Not re-run by Run 064: this run modifies no Rust source. The Run 063 baseline (`cargo test -p qbind-node --lib pqc_trust_bundle` 100/100, `--test run_061_pqc_local_leaf_self_check_tests` 9/9, `--test run_062_pqc_revocation_activation_tests` 11/11, `--test run_063_pqc_local_issuer_root_self_check_tests` 8/8, plus every Run 050–059 suite) is preserved bit-for-bit. |

## Investigation findings (with file / function references)

1. **Run 060 runbook accurately reflected Runs 050–059** but, per
   Run 061 §10 item (h) and Run 062 §10 item (h), was
   intentionally not updated by Runs 061/062. Specifically:
   - §6.C variant 2 step 4 still said "operators MUST verify
     out-of-band" that the local leaf is not on
     `revoked_leaf_fingerprints` — this is now superseded by the
     Run 061 startup self-check
     (`crates/qbind-node/src/pqc_trust_bundle.rs::check_local_leaf_not_revoked`
     wired in `crates/qbind-node/src/main.rs` between the Run
     050/051/062 banners and `PqcStaticRootConfig` construction).
   - §3.9 said "Activation height / epoch gating on revocation
     entries is NOT yet implemented (Run 052/054 boundary —
     recorded in §10)" — this is now superseded by Run 062's
     per-entry `activation_height` field (added to
     `TrustBundleRevocation` in
     `crates/qbind-node/src/pqc_trust_bundle.rs`, covered by
     `canonical_signing_bytes` / `canonical_fingerprint`,
     resolved by
     `validate_at_with_signing_keys_chain_id_and_revocation_activation`).
   - §10 item 2 ("Activation gates on revocation entries") and
     §10 item 4 ("Startup self-check that fails the binary
     closed when `--p2p-leaf-cert` matches an active entry in
     `revoked_leaf_fingerprints`") are both now closed.
   - The runbook did NOT mention the Run 063 root-axis startup
     self-check at all (Run 063 landed source + evidence but no
     runbook update).

2. **No contradictions found between the runbook and the
   implementation.** The leaf-fingerprint domain separator
   quoted in the task (`SHA3-256("QBIND:pqc-trust-bundle-leaf-fp:v1"
   || cert.encode())`) matches
   `crates/qbind-node/src/pqc_trust_bundle.rs::TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR`
   exactly (file:line 1719–1720, used in `cert_leaf_fingerprint`
   at file:line 1748). The Run 062 active/pending split rule
   stated in the task matches the resolution logic in
   `validate_at_with_signing_keys_chain_id_and_revocation_activation`.
   The Run 063 ordering ("after Run 061, before
   `pqc_config` construction, with active set only — never
   pending") matches
   `crates/qbind-node/src/main.rs` lines 1327–1419 exactly. No
   runtime code change required.

3. **No unsafe guidance found before or after the edit.** The
   four grep checks listed in "Tests / checks" above all pass.

## Runbook sections changed

- **Header (lines 1–17).** Run number bumped from 060 to 064;
  status line expanded to "Runs 050–063"; added an explicit
  Run-064-is-docs-only note.
- **Anchors list (immediately after the header).** Added Run 061
  / Run 062 / Run 063 references on the
  `pqc_trust_bundle.rs` and `main.rs` lines.
- **§1.2 In/out of scope (non-goals).** Removed the now-closed
  "startup self-check for `--p2p-leaf-cert` in
  `revoked_leaf_fingerprints`" boundary; clarified that the
  per-environment-minimum-activation-height non-goal covers both
  the bundle-level (Run 057) and per-entry-revocation (Run 062)
  `activation_height`; added on-the-fly hot reload as an explicit
  non-goal.
- **§1.3 Strictly preserved invariants.** Three new rows:
  - Run 061 local-leaf startup self-check (FATAL phrase quoted
    from `main.rs`).
  - Run 062 per-entry revocation activation gate (canonical
    preimage coverage; new gauge family
    `qbind_p2p_pqc_trust_bundle_revocations_*`).
  - Run 063 local-issuer-root startup self-check (active-set-only
    boundary; ordering after Run 061; FATAL phrase quoted from
    `main.rs`).
- **§3.9 Revocation entries.** Rewritten end to end. New
  active-vs-pending semantics, new `current_height` source rule,
  new bundle-vs-revocation activation distinction, new sequence
  interaction rule, new immediate-vs-scheduled operator
  recommendation.
- **§6.A Normal transport root rotation, step 9 and trailing
  paragraph.** Step 9 now offers the Run 062 scheduled-revocation
  option alongside the legacy immediate-revocation option; a new
  "Run 063 interaction at root retire/revoke" paragraph
  documents the local-issuer-root startup self-check expectation.
- **§6.B Emergency transport root revocation, steps 5–6.** Step 5
  now references Run 063 (drop-out visible at startup, not
  silently at the peer-handshake layer). New step 6 forbids using
  `activation_height` to soften a compromise revocation.
- **§6.C Leaf certificate rotation, Variant 2 steps 3–6.** Old
  step 4 ("operators MUST verify out-of-band") replaced with new
  step 4 (Run 061 startup self-check semantics) and new step 5
  (Run 062 coordinated cutover via `activation_height`). New step
  6 forbids using `activation_height` to delay a compromise
  revocation.
- **§6.E Scheduled revocation via per-entry `activation_height`
  (NEW SECTION).** Full step-by-step workflow for scheduled
  revocations using Run 062 — target-height selection, mint /
  publish, cutover preparation, activation, post-activation
  confirmation. Includes the explicit "bundle-level vs per-entry"
  distinction and the no-hot-reload note.
- **§7 Promotion checklist.** New items: per-entry
  `activation_height` margin / canonical-preimage coverage;
  pending-revocation smoke (Run 062 Smokes 1/3 shape); Run 061
  local-leaf self-check FATAL smoke (Run 061 Smoke 2 shape);
  Run 063 local-issuer-root self-check FATAL smoke (Run 063
  Smoke 2 shape). Banner-order line updated to include Run
  062/061/063.
- **§8 Incident checklist.** New items: explicit root-vs-leaf
  scope and immediate-vs-scheduled triage; Run 062 banner
  confirmation across the validator fleet.
- **§9 Evidence checklist.** New items: Run 062 banner + seven
  `_revocations_*` gauges; Run 061 / Run 063 startup self-check
  banners and FATAL transcripts (positive + negative);
  pending-revocation transcript.
- **§10 Residual risks.** Renumbered. Removed the three items
  closed by Runs 061/062/063. Added on-the-fly hot reload as a
  new still-open item. Added an explicit "Closed by Runs
  061–063" sub-list naming each closed boundary and pointing at
  the helper / call site that closed it.
- **§11 Mapping to Runs.** Header renamed from "050–059" to
  "050–063". Added one row each for Runs 060, 061, 062, 063;
  updated Run 057 row to clarify "Bundle-level activation-height
  gating" (vs the new Run 062 per-entry gate).

## How Runs 061–063 are represented

| Run | Representation in the updated runbook |
|---|---|
| 061 | §1.3 invariants table (new row); §3.9 (operator notes that pending entries do NOT trip startup self-checks); §6.C variant 2 step 4 (operator workflow); §7 promotion checklist (smoke item); §9 evidence checklist (transcript item); §10 "Closed by Runs 061–063" sub-list; §11 mapping table row. |
| 062 | §1.3 invariants table (new row); §3.9 rewritten in full; §3.10 (bundle-vs-revocation distinction); §6.A step 9 (scheduled-revocation option); §6.B step 6 (immediate-only for compromise); §6.C variant 2 step 5 (scheduled leaf retirement); §6.E (new section, full workflow); §7 promotion checklist (margin + pending smoke); §8 incident checklist (banner confirmation); §9 evidence checklist (banner + gauges + pending transcript); §10 "Closed by Runs 061–063" sub-list; §11 mapping table row. |
| 063 | §1.3 invariants table (new row); §6.A step 9 trailing paragraph; §6.B step 5 (startup drop-out visibility); §6.E step 5 (root-revocation activation behaviour); §7 promotion checklist (smoke item); §9 evidence checklist (transcript item); §10 "Closed by Runs 061–063" sub-list; §11 mapping table row. |

## Contradictions found

**None.** The investigation found no contradiction between the
Run 060 runbook and the implementation in
`crates/qbind-node/src/{pqc_trust_bundle.rs,main.rs}` after
Runs 061–063. The runbook simply lagged the implementation on the
two boundaries Run 061/063 closed, and on the per-entry
activation-gate field Run 062 added. Run 064 brings the prose
forward to match.

No `contradiction.md` entry beyond the new Run 064 C4 row is
required.

## Remaining open items (NOT closed by Run 064)

Run 064 does NOT close any of the following — they remain open
under C4 and are reflected accurately in the updated runbook §10:

1. Bundle-level and per-entry `activation_epoch` runtime source
   (Run 057 + Run 062 boundary).
2. Per-environment minimum activation-height policy (bundle-level
   and per-entry).
3. On-the-fly trust-bundle hot reload.
4. Production fast-sync / consensus-storage restore.
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

1. **Per-environment minimum activation-height policy.** Encode
   the §5.3 / §6.E recommended margin as a binary-side
   refusal: a bundle-level or per-entry `activation_height` set
   below `current_finalised_height + min_margin_for_env` fails
   closed at load with a clear FATAL line. Requires a CLI flag
   or environment-derived default plus one new lib function in
   `pqc_trust_bundle.rs` and one new integration test file.

2. **Production multi-validator MainNet release-binary
   peer-connection smoke.** Pre-blocked on production-config
   items called out in Run 059's evidence doc (validator
   keystore loading on startup, per-peer consensus-key
   distribution); landing those unlocks the smoke.

3. **In-binary / on-chain bundle-signing-key ratification.**
   Replace the §6.D out-of-band CLI overlap with an in-bundle
   `ratified_signing_key_id`/`ratified_signing_key_pk` surface
   that the next-sequence bundle's signature covers, enabling a
   single-bundle rotation with no operator CLI restart loop.

Run 064 itself is complete and does not need further work.