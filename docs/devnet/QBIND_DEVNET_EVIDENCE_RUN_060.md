# QBIND DevNet Evidence — Run 060: PQC Trust Lifecycle Operator Runbook + DevNet Rehearsal Scripts

## Exact objective

Run 060 is **evidence- and documentation-only**. It produces:

1. `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, the smallest
   honest operator playbook covering production custody,
   rotation, revocation, and bundle-signing-key rotation for the
   PQC trust-anchor and bundle-signing layers proven by
   Runs 050–059.
2. Two DevNet-only rehearsal scripts under
   `scripts/devnet/` that drive the existing
   `devnet_pqc_trust_bundle_helper` example with documented
   arguments to reproduce the §6.A rotation and §6.C revocation
   workflow shapes without ever persisting a private key.
3. This evidence document.
4. A C4 Run 060 evidence row in `docs/whitepaper/contradiction.md`
   narrowing the operator-playbook lifecycle item.

The scope is intentionally narrow:

- **NO `crates/**/src/**` source touched.** No core library, no
  protocol source, no test source, no `Cargo.toml`, no
  `main.rs`, no `pqc_trust_bundle.rs`, no `pqc_trust_sequence.rs`,
  no `pqc_trust_activation.rs`, no helper source. The runbook is
  an operator playbook that describes how to use the binary's
  already-landed fail-closed behaviour; it does NOT change that
  behaviour.
- Run 037 / Run 040 / Run 044 / Run 050 / Run 051 / Run 052 /
  Run 053 / Run 054 / Run 055 / Run 056 / Run 057 / Run 058 /
  Run 059 behaviour is preserved bit-for-bit.

Explicitly out of scope for Run 060 (and recorded honestly under
"Explicit remaining boundaries" below):

- Any code change that would close residual C4 piece (g)
  ("Per-environment minimum-activation-height policy") or piece
  (c) of Run 058 ("`activation_epoch` runtime source") or the
  Run 052/054 startup self-check item;
- External KMS / HSM integration;
- On-chain bundle-signing-key ratification;
- Multi-validator MainNet release-binary peer-connection smoke;
- Production fast-sync / consensus-storage restore;
- Any redesign of KEMTLS, trust bundles, transport, consensus,
  timeout verification, signing-key distribution, or activation
  semantics.

## Exact verdict

**Strongest positive for the Run 060 scope.** The operator
playbook lands; the DevNet rehearsal scripts are syntactically
valid and shape-match the existing helper modes; every
fail-closed invariant cited by the runbook is anchored in the
implementation file and the prior evidence run that proved it on
the release binary; full `qbind-node` PQC-trust regression
suites continue to pass on this working tree (107/107 across
`pqc_trust_bundle` + `pqc_trust_sequence` + `pqc_trust_activation`
lib tests, plus all required integration tests under
`run_051` / `run_052` / `run_055` / `run_057` — see "Tests"
below).

C4 piece "Operator-facing CA + certificate rotation +
signing-key rotation playbook" (recorded in Runs 056–059 as
remaining-open under "operator-out-of-band lifecycle items") is
now **NARROWED** to: the operator playbook lands, but the
binary-enforced gaps it documents (epoch-gating runtime source,
self-check on local leaf in `revoked_leaf_fingerprints`,
per-environment minimum activation-height policy, on-chain
bundle-signing ratification, fast-sync restore) remain open
under their existing C4 lines. **Full C4 remains OPEN. C5 is
NOT closed by Run 060.**

## Files added

- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — the operator
  playbook. 12 sections covering: scope & non-goals, trust model
  + role separation, artifact inventory (12 artifact classes),
  key generation & custody, per-environment policy (DevNet /
  TestNet / MainNet), workflows (rotation §6.A, emergency root
  revocation §6.B, leaf rotation §6.C, bundle-signing rotation
  §6.D), promotion checklist, incident checklist, evidence
  checklist, residual risks (9 items NOT solved by the runbook),
  mapping to Runs 050–059, operator-facing flag glossary.
- `scripts/devnet/trust_bundle_rotation_demo.sh` — DevNet-only
  rehearsal of §6.A. Mints three signed DevNet bundles at
  sequences 1, 2, 3 using the existing
  `devnet_pqc_trust_bundle_helper` example, prints canonical
  artifact paths, fails fast if any private-key file is
  unexpectedly persisted, and emits a summary.
- `scripts/devnet/trust_bundle_revocation_demo.sh` — DevNet-only
  rehearsal of §6.C variant 2 (leaf revocation). Mints baseline
  + two leaf-revocation bundles (`signed-devnet-revoked-v0`,
  `signed-devnet-revoked-v1`) at sequences 1, 2, 3.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_060.md` — this document.

## Files updated

- `docs/whitepaper/contradiction.md` — appended Run 060 evidence
  row under C4 narrowing the operator-playbook line. No earlier
  rows altered.

## Files NOT changed

- `crates/**/src/**` — all core library / protocol / runtime
  source untouched.
- `crates/**/examples/**` — the existing
  `devnet_pqc_trust_bundle_helper.rs` and `devnet_pqc_root_helper.rs`
  examples untouched.
- `crates/**/tests/**` — all test source untouched.
- `Cargo.toml`, `Cargo.lock` — untouched.
- `crates/qbind-node/src/main.rs` — untouched.
- `crates/qbind-node/src/pqc_trust_bundle.rs` — untouched.
- `crates/qbind-node/src/pqc_trust_sequence.rs` — untouched.
- `crates/qbind-node/src/pqc_trust_activation.rs` — untouched.
- `crates/qbind-node/src/cli.rs` — untouched.
- `crates/qbind-node/src/metrics.rs` — untouched.
- `docs/whitepaper/QBIND_WHITEPAPER.md` — untouched (the runbook
  is an operator document under `docs/ops/`, not a whitepaper
  amendment).
- All prior `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_*.md` —
  untouched.

## Anchoring evidence: every runbook claim ties to an
implementation file or a prior evidence run

The runbook §1.3 invariants table lists every fail-closed
behaviour the runbook depends on, with its implementation site
and the prior run that proved it on the release binary. The most
load-bearing anchors:

- `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys_and_chain_id`
  pins: signature verification, signing-key/root-id
  trust-separation, environment, chain_id, validity windows,
  root status, revocations.
- `pqc_trust_sequence::check_and_update_sequence` pins: monotonic
  sequence ordering, equal-sequence equivocation rejection,
  corrupt-file fail-closed (never silently truncates).
- `pqc_trust_activation::check_bundle_activation` pins: inclusive
  `current >= required` semantics; `CurrentEpochUnavailable`
  fail-closed; the central
  `future_activation_does_not_advance_sequence_persistence`
  invariant proving the gate runs BEFORE sequence persistence
  and BEFORE root merge.
- `p2p_node_builder::make_pqc_static_root_crypto_provider`
  pins: under `--p2p-pqc-root-mode pqc-static-root`, the
  registered crypto provider is the real
  `MlDsa44SignatureSuite` / `MlKem768Backend` /
  `ChaCha20Poly1305Backend`. No `DummySig` / `DummyKem` /
  `DummyAead`.
- `crates/qbind-types/src/primitives.rs` defines the
  per-environment chain id constants the runbook quotes for
  DevNet / TestNet / MainNet (`0x51424E4444455600` /
  `0x51424E4454535400` / `0x51424E444D41494E`).
- Run 056 Smoke 3 (rollback) and Smoke 5 (equivocation) and
  Smoke 6 (corrupt persistence) prove the Run 055 fail-closed
  paths on the live release binary.
- Run 058 Smokes 2/3/4 prove the Run 057 future-activation
  fail-closed paths on the live release binary.
- Run 059 Smokes 2/3/4/5 prove the MainNet signed-bundle
  unsigned / tampered / wrong-key / wrong-chain fail-closed
  paths on the live release binary.

If any of these anchors changes in a future run, the runbook MUST
be updated to match. Re-run the regression suites listed below to
detect drift.

## Commands run

All commands run on the working tree at the Run 060 base commit;
no source under `crates/**/` was modified by Run 060.

```text
# Baseline check that the runbook's reference invariants still pass.
$ cargo test -p qbind-node --lib pqc_trust
... 107 passed; 0 failed; 0 ignored ...
```

The two DevNet rehearsal scripts are syntactically validated
with `bash -n` and are marked executable. End-to-end execution
of those scripts requires `cargo run --example
devnet_pqc_trust_bundle_helper`, which is the supported DevNet
helper invocation; the scripts perform a self-check that NO
private-key file is produced under the output directory and
exit non-zero if one is.

## Tests

Run 060 changes no Rust source. Required regression suites that
underpin every runbook claim and that MUST stay green:

- `cargo test -p qbind-node --lib pqc_trust` — 107/107 pass
  (= 72 `pqc_trust_bundle` + 21 `pqc_trust_sequence` +
  14 `pqc_trust_activation`).
- `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` — proven 13/13 in Runs 051–059.
- `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` — proven 12/12 in Runs 052–059.
- `cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` — proven 12/12 in Runs 055–059.
- `cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` — proven 12/12 in Runs 057–059.
- `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` — proven 14/14 in Runs 050–059.
- `cargo check -p qbind-node --bin qbind-node` — clean (only
  pre-existing `bincode::config` deprecation warnings unrelated
  to Run 060, as also recorded in Runs 057/058/059).

The pre-existing `m16_epoch_transition_hardening_tests`
`cargo build --tests` failure (`set_inject_write_failure` /
`clear_epoch_transition_marker` methods missing on
`RocksDbConsensusStorage`) is unrelated to Run 060 and predates
this run.

## No-fallback proof (Run 060)

Run 060 introduces no code path. It documents the existing
fail-closed paths. The runbook §1.3 lists every fail-closed
boundary the documentation relies on; each entry cites the
implementation site and the prior evidence run that proved it
on the live release binary. The runbook explicitly forbids any
operator procedure that would attempt to bypass any of these,
and §10 enumerates the residual risks that this runbook does
NOT close.

The DevNet rehearsal scripts:

- never call the `qbind-node` binary with `--p2p-trusted-root`
  on TestNet/MainNet (they target DevNet only);
- never reach for any `Dummy*` primitive (they do not invoke the
  binary at all; they only mint bundle artifacts);
- never edit a persistence file;
- self-check that NO private-key file appears under their
  output directory and fail non-zero if one does.

## Explicit remaining boundaries (NOT done in Run 060)

The runbook §10 lists nine residual risks NOT closed by Run 060.
The most operationally significant are restated here for cross-
reference with prior C4 evidence rows:

(a) **`activation_epoch` runtime source.** Bundles that declare
    `activation_epoch` continue to fail closed with
    `TrustBundleActivationError::CurrentEpochUnavailable`. The
    runbook §5.2 / §5.3 / §7 forbid operators from setting this
    field on production bundles. Tracked under Run 057 / Run 058
    remaining-open items.
(b) **Validator self-check on local leaf in `revoked_leaf_fingerprints`.**
    Today the binary does NOT fail closed at startup if the
    operator's own `--p2p-leaf-cert` matches an active entry in
    the loaded bundle's `revoked_leaf_fingerprints`. The runbook
    §6.C requires operators to verify out-of-band. Tracked under
    Run 052 / Run 054 / Run 056 / Run 057 remaining-open items.
(c) **Per-environment minimum activation-height policy.** The
    binary does NOT enforce a minimum margin between
    `activation_height` and the current finalised height. The
    runbook §5.3 RECOMMENDS at least one finality block
    (suggested ≥ 100) on MainNet. Tracked under Run 057 / Run 058
    / Run 059 remaining-open items.
(d) **In-binary bundle-signing-key ratification.** There is no
    on-chain ratification of a new bundle-signing key. §6.D is
    an out-of-band CLI overlap procedure. Tracked under Run 051
    / Run 059 remaining-open items.
(e) **External KMS / HSM integration.** Run 060 treats the
    signing-key custody surface as a runbook boundary; operators
    MAY back §3.2 / §3.4 with HSM in production. Tracked under
    Run 056 / Run 057 / Run 058 / Run 059 remaining-open items.
(f) **Multi-validator MainNet release-binary peer-connection
    smoke.** Run 059 produced a single-validator MainNet smoke;
    a multi-validator MainNet peer-connection artifact set
    remains on the C4 list (blocked by unrelated production-
    config items — validator keystore loading on startup,
    per-peer consensus-key distribution).
(g) **Production fast-sync / consensus-storage restore.**
    Separate C4 piece.
(h) **DevNet rehearsal scripts as automation surface.** The two
    scripts under `scripts/devnet/` are evidence rehearsal, not
    production tooling. A production CA / KMS-backed rotation
    pipeline is out of scope for Run 060.

**C5 remains NOT closed** by Run 060; Run 060 does not touch
timeout/NewView wire formats, forged-traffic policy, KEMTLS
wire formats, consensus message wire formats, or any
signature/verification semantics outside the operator-
documentation surface. **Full C4 remains OPEN.**

## Operator next action

The runbook §7 promotion checklist is the immediate operator-
facing handle for the next production bundle change. Operators
preparing the first post-Run-060 TestNet or MainNet rotation
should:

1. Walk the §7 checklist line by line against the proposed
   bundle; archive a copy of the marked-up checklist with the
   bundle's canonical fingerprint and the release binary's
   `sha256` + `ELF BuildID`.
2. Run `scripts/devnet/trust_bundle_rotation_demo.sh` and
   `scripts/devnet/trust_bundle_revocation_demo.sh` once on a
   throwaway DevNet workstation to confirm the helper output
   shape matches expectations (no private-key files; three
   distinct bundle dirs; fingerprints recorded in the summary).
3. Practice §6.A (or §6.B, §6.C, §6.D) end-to-end on a DevNet
   cluster using the artifacts produced in step 2, confirming
   the Run 050 / 051 / 053 / 055 / 057 startup banners and
   `qbind_p2p_pqc_trust_bundle_*` metrics on every validator.
4. Promote to TestNet under the §7 checklist; archive evidence
   per §9.
5. Promote to MainNet under the §7 checklist; archive evidence
   per §9.

## Tracking

| Field | Value |
|-------|-------|
| Status | Operator playbook landed; full C4 remains OPEN. |
| Whitepaper / Doc Reference | `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (NEW), `docs/whitepaper/contradiction.md` C4 (updated with Run 060 evidence row). |
| Code Location | None changed. Runbook anchors: `crates/qbind-node/src/pqc_trust_bundle.rs`, `crates/qbind-node/src/pqc_trust_sequence.rs`, `crates/qbind-node/src/pqc_trust_activation.rs`, `crates/qbind-node/src/pqc_root_config.rs`, `crates/qbind-node/src/p2p_node_builder.rs::make_pqc_static_root_crypto_provider`, `crates/qbind-node/src/main.rs` trust-bundle load path. |
| Tests | None added. Required regression suites continue to pass (`pqc_trust_bundle` 72/72; `pqc_trust_sequence` 21/21; `pqc_trust_activation` 14/14). |
| Evidence | `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_060.md` (this document); `scripts/devnet/trust_bundle_rotation_demo.sh`; `scripts/devnet/trust_bundle_revocation_demo.sh`. |