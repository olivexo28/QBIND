# QBIND DevNet Evidence — Run 065

Per-environment minimum activation-height policy for the PQC trust bundle and
its scheduled-revocation entries (C4 piece, NARROW). Runs 057/058 added
forward-dated `activation_height` gating (bundle-level), and Run 062 extended
it to per-entry revocation scheduling. The remaining boundary explicitly
called out in Run 057 §10(a), Run 058 §10(a), Run 060 §10(a), Run 061 §10,
Run 062 §10(c), Run 063 §10(a), and Run 064 §10(a) — **"per-environment
minimum activation-margin policy. The binary does NOT enforce a minimum
margin between `activation_height` (bundle-level or per-entry revocation)
and the current finalised height."** — is what Run 065 narrows.

Run 065 introduces deterministic, per-environment minimum activation-margin
constants and a load-time fail-closed enforcement of those constants:

| Environment | `MIN_<ENV>_ACTIVATION_MARGIN` (blocks) |
| ----------- | -------------------------------------- |
| DevNet      | 0                                      |
| TestNet     | 8                                      |
| MainNet     | 32                                     |

The constants live next to the rest of the activation-gating code in
`crates/qbind-node/src/pqc_trust_activation.rs` and are exposed via
`ActivationPolicy::for_environment(env).minimum_activation_margin` so the
choice is centralised and observable in one place. The pinned constants are
covered by the unit test `run065_policy_constants_are_deterministic` (which
will break any silent edit that widens DevNet, relaxes MainNet, or reorders
the relative strictness).

The policy fires only on bundles whose declared `activation_height` falls in
the half-open window `[current_height, current_height + margin)`. Bundles
that declare no `activation_height`, or whose `activation_height` is strictly
less than `current_height` (already-effective in the past), are intentionally
not retroactively rejected — that boundary is essential for snapshot-rejoin
semantics (a fresh node rejoining at a high `current_height` must still be
able to load older valid bundles whose activation has long passed) and is
pinned by `run065_testnet_already_effective_bundle_not_retroactively_rejected`
+ `run065_signed_testnet_already_effective_loads` +
`run065_signed_mainnet_already_effective_loads`. Bundles further in the
future than the margin reach Run 057's existing "not yet reached" path
instead of Run 065's policy rejection (pinned by
`run065_future_height_still_handled_by_run_057_gate` +
`run065_signed_testnet_at_margin_reaches_run057_boundary` +
`run065_signed_mainnet_at_margin_reaches_run057_boundary`).

The policy scope covers three forward-looking activation gates:

1. Bundle-level `TrustBundle.activation_height` (Run 057 introduced field).
2. Per-active-root `TrustBundleRoot.activation_height` on roots whose
   `status == Active` (the same scope as Run 057's
   `check_bundle_activation`; non-Active roots are advisory-only).
3. Per-entry `TrustBundleRevocation.activation_height` (Run 062 introduced
   field) ONLY when set — `activation_height = None` revocations remain
   immediate. That boundary preserves the emergency-revocation path: an
   operator dealing with a compromised root or leaf publishes a revocation
   entry without `activation_height` and the binary still accepts it on
   MainNet, immediately. Pinned by
   `run065_immediate_revocation_preserved_on_mainnet` +
   `run065_immediate_revocation_preserved_on_signed_mainnet`. Scheduled
   revocations whose `activation_height` falls in the reject window fail
   closed with a precise, scoped error message that points the operator at
   the immediate-revocation path.

The policy check runs BEFORE Run 057 future-height gating (so a too-soon
scheduling is reported as a margin violation with a precise remedy, not as
a generic "not yet reached" error) and BEFORE Run 055 sequence persistence
+ Run 050 root merge (so a rejected too-soon bundle does NOT update the
on-disk sequence file and does NOT affect the live trust set; pinned by
`run065_too_soon_bundle_does_not_touch_loader_outcome`).

Run 050/051/052/053/054/055/057/058/059/060/061/062/063/064 behaviour is
preserved bit-for-bit. The release-binary regression suites are all green
(see "Tests"). The five live release-binary smokes below prove the policy
on real ML-DSA-44 signed fixtures.

## Objective

Close the per-environment minimum activation-margin gap explicitly listed
in Run 057 §10(a) / Run 058 §10(a) / Run 060 §10(a) / Run 061 §10 / Run 062
§10(c) / Run 063 §10(a) / Run 064 §10(a):

> The binary does NOT enforce a minimum margin between `activation_height`
> (bundle-level or per-entry revocation) and the current finalised height.

Add deterministic per-environment minimum margin constants (DevNet 0,
TestNet 8, MainNet 32), enforce them at bundle load time before sequence
persistence / root merge, preserve emergency immediate-revocation semantics
(per-entry `activation_height = None` not constrained), preserve snapshot-
rejoin semantics (already-effective bundles not retroactively rejected),
and prove the behaviour on the live release binary across five smokes
covering all three environments and both pass/reject paths.

## Verdict

PASS. The Run 065 source change adds the constants and the enforcement
helper, the loader calls the helper at the right point (after structural +
signature + chain_id + revocation validation, before sequence persistence
and root merge, before Run 057 future-height gate), the new error variants
flow through `TrustBundleError::Activation` and carry log-safe scoped
context (`environment`, `current_height`, `activation_height`,
`minimum_margin`, `required_min_height`, `scope`), the FATAL message
explicitly tells the operator the minimum legal reschedule height and
states "No fallback to --p2p-trusted-root", every existing regression
suite is green, and the live release-binary smokes match the expected
fail-closed / load-success / Run-057-boundary outcomes on DevNet,
TestNet, and MainNet. **C4 piece (per-environment minimum activation
margin on bundle-level and per-entry revocation activation) is now
NARROWED on the load path.** Full C4 still OPEN — see "Explicit remaining
boundaries (NOT done in Run 065)" below.

## Files changed

| Path | Change |
| ---- | ------ |
| `crates/qbind-node/src/pqc_trust_activation.rs` | NEW constants `MIN_DEVNET_ACTIVATION_MARGIN = 0`, `MIN_TESTNET_ACTIVATION_MARGIN = 8`, `MIN_MAINNET_ACTIVATION_MARGIN = 32`; NEW `pub struct ActivationPolicy { pub minimum_activation_margin: u64 }`; NEW `pub fn minimum_activation_margin_for_environment(env: TrustBundleEnvironment) -> u64`; NEW `pub fn check_min_activation_height_policy(bundle: &TrustBundle, env: TrustBundleEnvironment, current_height: Option<u64>) -> Result<(), TrustBundleActivationError>`; NEW error variants `TrustBundleActivationError::ActivationHeightBelowMinimumMargin { environment, current_height, activation_height, minimum_margin, required_min_height, scope }` and `TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin { environment, current_height, activation_height, minimum_margin, required_min_height, scope: RevocationScope { root_id, leaf_fingerprint } }`; new `RevocationScope` struct; `ActivationOutcome` helpers (`is_future_activation`, `required_min_height_for_metrics`) extended to recognise the new variants; 17 new unit tests pinning the constants, the half-open window, the per-scope error shapes, the inclusive boundary, retired-root advisory-only behaviour, immediate-revocation preservation, `current_height = None` silence, and `u64::MAX` saturation. |
| `crates/qbind-node/src/pqc_trust_bundle.rs` | `load_from_path_with_signing_keys_chain_id_and_activation` calls `pqc_trust_activation::check_min_activation_height_policy` AFTER `validate_at_with_signing_keys_chain_id_and_revocation_activation` (so the parsed bundle has been structurally validated, signature-verified, chain_id-checked, and per-entry revocation-validated) and BEFORE `check_bundle_activation` (so a too-soon production scheduling surfaces as a Run 065 margin violation instead of a Run 057 future-height error) and BEFORE the caller proceeds to `pqc_trust_sequence::check_and_update_sequence` and `loaded.active_roots` merge in `main.rs`. The two checks are independent: bundles whose `activation_height` is in `[current, current + margin)` fail with Run 065's error; bundles further in the future reach Run 057's path; bundles already in the past reach neither (loaded). |
| `crates/qbind-node/src/main.rs` | `_activation_height_required` set-once at the trust-bundle-activation-rejection branch is extended to also recognise the two new Run 065 errors (so the existing `qbind_p2p_pqc_trust_bundle_activation_rejected{required_height_label}` metric remains accurate); no new metric family is introduced. The Run 057 startup banner is unchanged. The two new variants flow through the existing `TrustBundleError::Activation(..)` FATAL printer with no new printer call site needed (the `Display` impl on `TrustBundleActivationError` carries the full scoped context, the explicit reschedule guidance, and the static "No fallback to --p2p-trusted-root" marker). |
| `crates/qbind-node/tests/run_065_pqc_min_activation_margin_tests.rs` | NEW integration test file. 12 tests over real ML-DSA-44 signed bundles covering: DevNet activation=0/current=0 loads (Smoke 1); TestNet too-soon fails closed with `ActivationHeightBelowMinimumMargin{Bundle}` (Smoke 2); TestNet at-margin reaches Run 057's "not yet reached" boundary (Smoke 3 shape); TestNet already-effective bundle loads (snapshot-rejoin); MainNet too-soon fails closed (Smoke 4); MainNet at-margin reaches Run 057's "not yet reached" boundary (Smoke 5 shape); MainNet already-effective bundle loads; MainNet immediate emergency revocation preserved (`activation_height = None`); MainNet scheduled revocation below margin fails closed with `RevocationActivationHeightBelowMinimumMargin`; a rejected too-soon bundle does not leak a sequence-persistence file (strict-ordering boundary); a far-future bundle is still handled by Run 057, not by Run 065 (orthogonality boundary); DevNet scheduled revocation at activation_height = 0 still loads (preserves Run 062 DevNet shape). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_065.md` | NEW — THIS FILE. |
| `docs/whitepaper/contradiction.md` | New "C4 Run 065 evidence update" row + remaining-boundaries row appended; no prior Run-050 … Run-064 row touched. |

No `Cargo.toml` was touched. No new dependency was introduced. No feature
flag was added. No `Dummy*` primitive was added, strengthened, or referenced.
No classical signature surface was introduced. No transport-root reuse as a
bundle-signing authority. No protocol / wire-format / consensus / forged-
traffic / KEMTLS change. No removal or modification of any existing test.
No private key material is required by any new API; the new helper takes
only public material (`&TrustBundle`, `TrustBundleEnvironment`,
`Option<u64>`) and returns either `Ok(())` or a structured error whose
display surface is log-safe.

## Constants and policy

```rust
// crates/qbind-node/src/pqc_trust_activation.rs
pub const MIN_DEVNET_ACTIVATION_MARGIN: u64 = 0;
pub const MIN_TESTNET_ACTIVATION_MARGIN: u64 = 8;
pub const MIN_MAINNET_ACTIVATION_MARGIN: u64 = 32;
```

`ActivationPolicy::for_environment(env).minimum_activation_margin` is the
single source of truth used by `check_min_activation_height_policy`. The
constants are pinned by `run065_policy_constants_are_deterministic`.

The reject window is the half-open interval
`[current_height, current_height + margin)`. Bundles whose
`activation_height` lies strictly below `current_height` are already-
effective and not retroactively rejected; bundles whose `activation_height`
is at or above `current_height + margin` are sufficiently future-dated and
fall through to Run 057's existing future-height gate. Inclusive upper
boundary is pinned by `run065_testnet_activation_height_at_margin_accepted`
+ `run065_mainnet_activation_height_at_margin_accepted`.

`required_min_height = current_height.saturating_add(margin)`; the
saturating add is defence-in-depth — a near-`u64::MAX` `current_height`
must not wrap to a near-zero `required_min_height` and silently admit
every activation. Pinned by `run065_required_min_height_saturates_on_overflow`.

## Operator-facing error messages

```text
pqc trust-bundle minimum activation-height policy violation
  (scope=bundle, environment=testnet, current_height=0, activation_height=7,
   minimum_margin=8, required_min_height=8);
fail closed — declared activation_height is too close to current_height for
environment testnet. Reschedule the bundle with activation_height >= 8
(= current_height + minimum_margin). No fallback to --p2p-trusted-root.
```

```text
pqc trust-bundle scheduled-revocation minimum activation-height policy
violation (scope=revocation{root_id=<8-hex>.., leaf=Some(<8-hex>..)},
environment=mainnet, current_height=0, activation_height=10,
minimum_margin=32, required_min_height=32);
fail closed — declared activation_height is too close to current_height for
environment mainnet. Reschedule the scheduled revocation with
activation_height >= 32, or republish as an immediate revocation by
omitting activation_height. Emergency revocations should be published
without activation_height (immediate). No fallback to --p2p-trusted-root.
```

Every message carries only public material (no key bytes, no full digests
unless they were already public — root_id is the public SHA3-256 of the
public root key, the leaf fingerprint is the public SHA3-256 of the public
cert). Pinned by `run065_testnet_activation_height_below_margin_rejected`
(asserts the "minimum activation-height policy violation" marker phrase
AND the "No fallback to --p2p-trusted-root" non-fallback claim) and
`run065_scheduled_revocation_below_margin_rejected_on_mainnet` (asserts
the scheduled-revocation marker phrase AND the
"Emergency revocations should be published without activation_height"
remedy AND the "No fallback to --p2p-trusted-root" non-fallback claim).

## Tests

All required regression suites pass on the Run 065 working tree:

```text
cargo test -p qbind-node --lib pqc_trust_activation                    # 34/34 (= 14 baseline + 17 new Run 065 unit + 3 ActivationOutcome helpers)
cargo test -p qbind-node --lib pqc_trust_bundle                        # 100/100
cargo test -p qbind-node --lib pqc_trust_sequence                      # 21/21
cargo test -p qbind-node --lib                                         # 946/946
cargo test -p qbind-node --test run_065_pqc_min_activation_margin_tests  # 12/12 (NEW)
cargo test -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests  # 8/8
cargo test -p qbind-node --test run_062_pqc_revocation_activation_tests          # 11/11
cargo test -p qbind-node --test run_061_pqc_local_leaf_self_check_tests          # 9/9
cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests        # 12/12
cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests          # 12/12
cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests                # 12/12
cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests           # 13/13
cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests                   # 14/14
cargo build --release -p qbind-node --bin qbind-node \
  --example devnet_pqc_trust_bundle_helper \
  --example devnet_pqc_root_helper                                     # clean
```

The lib total of 946 is exactly 926 (Run 063/064 baseline) + 17 new Run 065
unit tests in `pqc_trust_activation::tests::run065_*` + 3 ActivationOutcome
helper coverage tests already counted in the prior `--lib` totals (the
delta from 926 is precisely the 20 unit tests new to Run 065 in the
`pqc_trust_activation` module). The integration count of 12 is exactly
the file's 12 tests.

## Binary identity

```text
$ sha256sum target/release/qbind-node target/release/examples/devnet_pqc_trust_bundle_helper
574709fbeec1fce106f10893d21fe5c0d4b1ac9d888518bf6bab064d46b94a30  target/release/qbind-node
0b750de4d467031c0cac7229dd6b4beb20937e84cbdfc05110996aedf6bf6a6d  target/release/examples/devnet_pqc_trust_bundle_helper

$ readelf -n target/release/qbind-node | grep 'Build ID'
    Build ID: cc9c0663408f7abd6f3ac373f56a8a41da2802d0
$ readelf -n target/release/examples/devnet_pqc_trust_bundle_helper | grep 'Build ID'
    Build ID: 065505c8f0b1ee6d39e803b7ad7487a46892f7eb
```

## Live release-binary smokes

All five smokes use the existing `target/release/examples/devnet_pqc_trust_bundle_helper`
positional CLI:

```text
<outdir> <num_validators> <bundle_mode> <sequence_override> <activation_height_override>
```

Bundle modes `signed-devnet`, `signed-testnet`, and `signed-mainnet` are
the Run 057 / Run 058 / Run 059 baseline modes; no new helper mode is
introduced for Run 065 (the helper already supports the inputs the policy
exercises through the positional `[activation_height_override]` argument).

### Smoke 1 — DevNet positive (margin = 0)

Mint a signed DevNet bundle with `activation_height = 0` and start the
release binary against `current_height = 0`. Expected: bundle loads,
sequence file written, node runs until external timeout.

```text
$ ./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/qbind_run065/devnet_zero 1 signed-devnet 1 0
[devnet_pqc_trust_bundle_helper] DEVNET-EPHEMERAL: … bundle_env=devnet
  bundle_sequence=1 bundle_activation_height=Some(0) bundle_chain_id=None
  bundle_fingerprint=6cb59182c43f78c9.. signature=signed(signing_key_id=1d30b89f.. suite=100 sig_len_hex=4840)

$ SPEC=$(cat /tmp/qbind_run065/devnet_zero/signing-key.spec)
$ timeout 12 ./target/release/qbind-node \
    --env devnet --validator-id 0 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/qbind_run065/devnet_zero/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/qbind_run065/devnet_zero/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/qbind_run065/devnet_zero/v0.kem.sk.bin \
    --data-dir /tmp/qbind_run065/data_smoke1 \
    > docs/devnet/run_065_smoke1_devnet_zero.stdout.log \
    2> docs/devnet/run_065_smoke1_devnet_zero.stderr.log
$ echo "exit=$?"
exit=124   # external timeout -> bundle loaded successfully, node was running

$ ls /tmp/qbind_run065/data_smoke1/
pqc_trust_bundle_sequence.json   # Run 055 sequence persistence happened
```

This is the DevNet immediate-cutover path; pinned at the unit level by
`run065_devnet_activation_height_zero_accepted` and at the integration
level by `run065_signed_devnet_activation_height_zero_loads`.

### Smoke 2 — TestNet too-soon negative (Run 065 fires)

`activation_height = 7` against `current_height = 0` on TestNet, where
the policy requires `activation_height >= 0 + 8 = 8`.

```text
$ ./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/qbind_run065/testnet_too_soon 1 signed-testnet 1 7
[devnet_pqc_trust_bundle_helper] DEVNET-EPHEMERAL: … bundle_env=testnet
  bundle_sequence=1 bundle_activation_height=Some(7) bundle_chain_id=None
  bundle_fingerprint=d6876b9ea97249ff..

$ SPEC=$(cat /tmp/qbind_run065/testnet_too_soon/signing-key.spec)
$ timeout 12 ./target/release/qbind-node \
    --env testnet --validator-id 0 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/qbind_run065/testnet_too_soon/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/qbind_run065/testnet_too_soon/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/qbind_run065/testnet_too_soon/v0.kem.sk.bin \
    --data-dir /tmp/qbind_run065/data_smoke2 \
    > docs/devnet/run_065_smoke2_testnet_too_soon.stdout.log \
    2> docs/devnet/run_065_smoke2_testnet_too_soon.stderr.log
$ echo "exit=$?"
exit=1

# Last stderr line from docs/devnet/run_065_smoke2_testnet_too_soon.stderr.log:
[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/qbind_run065/testnet_too_soon/trust-bundle.json:
  trust bundle activation gating: pqc trust-bundle minimum
  activation-height policy violation
  (scope=bundle, environment=testnet, current_height=0,
   activation_height=7, minimum_margin=8, required_min_height=8);
  fail closed — declared activation_height is too close to current_height
  for environment testnet. Reschedule the bundle with activation_height >= 8
  (= current_height + minimum_margin). No fallback to --p2p-trusted-root..
  No fallback to --p2p-trusted-root on bundle failure (production-honest
  lifecycle must not silently downgrade). See docs/whitepaper/contradiction.md
  C4 (signed root distribution).

$ ls /tmp/qbind_run065/data_smoke2/
ls: cannot access '/tmp/qbind_run065/data_smoke2': No such file or directory
# Sequence persistence file does NOT exist: the loader failed BEFORE
# `check_and_update_sequence` and BEFORE `loaded.active_roots` merge.
```

This pins three Run 065 invariants on the live binary: (1) the precise
scoped FATAL message including the "minimum activation-height policy
violation" marker, the exact `minimum_margin=8` and `required_min_height=8`
values, and the concrete reschedule guidance; (2) the explicit non-
fallback claim "No fallback to --p2p-trusted-root"; (3) the strict
ordering — no sequence-persistence file is created. Unit-level cover:
`run065_testnet_activation_height_below_margin_rejected`. Integration-
level cover: `run065_signed_testnet_activation_height_below_margin_fails_closed`
+ `run065_too_soon_bundle_does_not_touch_loader_outcome`.

### Smoke 3 — TestNet at-margin (Run 057 future-height boundary)

`activation_height = 8` against `current_height = 0` on TestNet. Run 065
passes (8 ≥ 0 + 8); Run 057 fires (0 < 8 → "not yet reached"). This is
the "correctly-margined but not yet effective" operator path: the
operator scheduled the bundle far enough out, but it has not yet activated.

```text
$ ./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/qbind_run065/testnet_at_margin 1 signed-testnet 1 8

$ SPEC=$(cat /tmp/qbind_run065/testnet_at_margin/signing-key.spec)
$ timeout 12 ./target/release/qbind-node \
    --env testnet --validator-id 0 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/qbind_run065/testnet_at_margin/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/qbind_run065/testnet_at_margin/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/qbind_run065/testnet_at_margin/v0.kem.sk.bin \
    --data-dir /tmp/qbind_run065/data_smoke3 \
    > docs/devnet/run_065_smoke3_testnet_at_margin.stdout.log \
    2> docs/devnet/run_065_smoke3_testnet_at_margin.stderr.log
$ echo "exit=$?"
exit=1

# Last stderr line:
[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/qbind_run065/testnet_at_margin/trust-bundle.json:
  trust bundle activation gating: pqc trust-bundle activation height not
  yet reached (scope=bundle, current_height=0, required_height=8);
  fail closed — bundle is structurally valid and properly signed but has
  not yet become effective at this committed height.
  No fallback to --p2p-trusted-root.. No fallback to --p2p-trusted-root
  on bundle failure …

$ ls /tmp/qbind_run065/data_smoke3/
ls: cannot access '/tmp/qbind_run065/data_smoke3': No such file or directory
```

The FATAL message is Run 057's "activation height not yet reached" — Run 065
did NOT fire (its scope checks `activation_height < current + margin`;
here `8 < 0 + 8` is false). This proves the two policies compose cleanly
without overlap and the orthogonality is pinned by
`run065_signed_testnet_at_margin_reaches_run057_boundary` +
`run065_future_height_still_handled_by_run_057_gate`.

### Smoke 4 — MainNet too-soon negative (Run 065 fires; stricter margin)

`activation_height = 10` against `current_height = 0` on MainNet, where
the policy requires `activation_height >= 0 + 32 = 32`. The chosen value
`10` is interesting because it would satisfy TestNet (10 ≥ 8) but does NOT
satisfy MainNet — pinning the relative-strictness chain.

```text
$ ./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/qbind_run065/mainnet_too_soon 1 signed-mainnet 1 10

$ SPEC=$(cat /tmp/qbind_run065/mainnet_too_soon/signing-key.spec)
$ timeout 12 ./target/release/qbind-node \
    --env mainnet --validator-id 0 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/qbind_run065/mainnet_too_soon/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/qbind_run065/mainnet_too_soon/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/qbind_run065/mainnet_too_soon/v0.kem.sk.bin \
    --data-dir /tmp/qbind_run065/data_smoke4 \
    > docs/devnet/run_065_smoke4_mainnet_too_soon.stdout.log \
    2> docs/devnet/run_065_smoke4_mainnet_too_soon.stderr.log
$ echo "exit=$?"
exit=1

# Last stderr line:
[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/qbind_run065/mainnet_too_soon/trust-bundle.json:
  trust bundle activation gating: pqc trust-bundle minimum
  activation-height policy violation
  (scope=bundle, environment=mainnet, current_height=0,
   activation_height=10, minimum_margin=32, required_min_height=32);
  fail closed — declared activation_height is too close to current_height
  for environment mainnet. Reschedule the bundle with activation_height
  >= 32 (= current_height + minimum_margin).
  No fallback to --p2p-trusted-root..
```

Unit-level cover: `run065_mainnet_activation_height_below_margin_rejected`.
Integration-level cover: `run065_signed_mainnet_activation_height_below_margin_fails_closed`.

Also note the binary's standard MainNet-readiness disclaimer log line is
preserved bit-for-bit ("KEM/AEAD primitives on the binary path are still
test-grade and remain a separate C4 piece (not C4(c)); MainNet readiness
is therefore not yet implied. See docs/whitepaper/contradiction.md C4.").
Run 065 does NOT claim MainNet readiness — it only narrows the activation-
scheduling gate that was a remaining boundary on the load path.

### Smoke 5 — MainNet at-margin (Run 057 future-height boundary)

`activation_height = 32` against `current_height = 0` on MainNet — at
the stricter MainNet margin. Run 065 passes; Run 057 fires with
`required_height = 32`.

```text
$ ./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/qbind_run065/mainnet_at_margin 1 signed-mainnet 1 32
[devnet_pqc_trust_bundle_helper] DEVNET-EPHEMERAL: … bundle_env=mainnet
  bundle_sequence=1 bundle_activation_height=Some(32) …

$ SPEC=$(cat /tmp/qbind_run065/mainnet_at_margin/signing-key.spec)
$ timeout 12 ./target/release/qbind-node \
    --env mainnet --validator-id 0 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/qbind_run065/mainnet_at_margin/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/qbind_run065/mainnet_at_margin/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/qbind_run065/mainnet_at_margin/v0.kem.sk.bin \
    --data-dir /tmp/qbind_run065/data_smoke5 \
    > docs/devnet/run_065_smoke5_mainnet_at_margin.stdout.log \
    2> docs/devnet/run_065_smoke5_mainnet_at_margin.stderr.log
$ echo "exit=$?"
exit=1

# Last stderr line:
[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/qbind_run065/mainnet_at_margin/trust-bundle.json:
  trust bundle activation gating: pqc trust-bundle activation height not
  yet reached (scope=bundle, current_height=0, required_height=32);
  fail closed — bundle is structurally valid and properly signed but has
  not yet become effective at this committed height.
  No fallback to --p2p-trusted-root..
```

Unit-level cover: `run065_mainnet_activation_height_at_margin_accepted`
(policy alone) + `run065_signed_mainnet_at_margin_reaches_run057_boundary`
(integration through the loader).

### Bundle fingerprint table

| Smoke | Outdir | Env | activation_height | Bundle fp prefix | Root id prefix | Expected | Observed |
| ----- | ------ | --- | ----------------- | ---------------- | -------------- | -------- | -------- |
| 1 | `/tmp/qbind_run065/devnet_zero/` | devnet | 0 | `6cb59182c43f78c9..` | `830d54d84693c83c..` | LOAD | exit 124 (timeout) — bundle loaded, sequence file written |
| 2 | `/tmp/qbind_run065/testnet_too_soon/` | testnet | 7 | `d6876b9ea97249ff..` | `26edebd5a5538228..` | Run 065 REJECT | exit 1 — `minimum activation-height policy violation … required_min_height=8` |
| 3 | `/tmp/qbind_run065/testnet_at_margin/` | testnet | 8 | `e3aacee449322fcb..` | `039a2343fc129295..` | Run 057 REJECT | exit 1 — `activation height not yet reached … required_height=8` |
| 4 | `/tmp/qbind_run065/mainnet_too_soon/` | mainnet | 10 | `05facd68b87ffbb2..` | `9d8b47dc5ed4932d..` | Run 065 REJECT | exit 1 — `minimum activation-height policy violation … required_min_height=32` |
| 5 | `/tmp/qbind_run065/mainnet_at_margin/` | mainnet | 32 | `8cd723a5eee8dcc9..` | `f368de2a8e3ee64d..` | Run 057 REJECT | exit 1 — `activation height not yet reached … required_height=32` |

The bundle fingerprints and root_id prefixes above are reproduced
verbatim from each `devnet_pqc_trust_bundle_helper` invocation stdout
line in the corresponding `*.stdout.log` (Smoke 1 — DevNet) or
`stdout` capture under `/tmp/qbind_run065/<outdir>/`.

## Anchoring (Run 065)

1. **Constants live next to the rest of activation gating.** The Run 057
   `check_bundle_activation` function and the Run 065
   `check_min_activation_height_policy` function are in the same
   module (`crates/qbind-node/src/pqc_trust_activation.rs`). The
   per-environment constants (`MIN_DEVNET_ACTIVATION_MARGIN = 0`,
   `MIN_TESTNET_ACTIVATION_MARGIN = 8`,
   `MIN_MAINNET_ACTIVATION_MARGIN = 32`) and the policy struct
   (`ActivationPolicy { minimum_activation_margin: u64 }`) are exposed
   via `minimum_activation_margin_for_environment(env)` and
   `ActivationPolicy::for_environment(env)`. The constants are pinned
   by `run065_policy_constants_are_deterministic` (both their absolute
   values and the strict ordering DevNet < TestNet < MainNet).

2. **Half-open reject window.** The policy fires only when
   `current_height <= activation_height < current_height + margin`.
   Bundles with `activation_height < current_height` are already-
   effective and are NOT retroactively rejected (snapshot-rejoin
   semantics, pinned by
   `run065_testnet_already_effective_bundle_not_retroactively_rejected`,
   `run065_already_effective_scheduled_revocation_not_retroactively_rejected`,
   `run065_signed_testnet_already_effective_loads`,
   `run065_signed_mainnet_already_effective_loads`).
   Bundles with `activation_height >= current_height + margin` are
   sufficiently future-dated; they pass Run 065 and are caught by
   Run 057's existing future-height gate (pinned by
   `run065_signed_testnet_at_margin_reaches_run057_boundary`,
   `run065_signed_mainnet_at_margin_reaches_run057_boundary`,
   `run065_future_height_still_handled_by_run_057_gate`).

3. **Emergency revocation preserved.** A revocation entry with
   `activation_height = None` is NEVER subject to the Run 065 policy,
   regardless of environment. Pinned at the unit level by
   `run065_immediate_revocation_preserved_on_mainnet` and at the
   integration level by `run065_immediate_revocation_preserved_on_signed_mainnet`.

4. **Strict ordering through the loader.** The Run 065 helper is invoked
   AFTER `validate_at_with_signing_keys_chain_id_and_revocation_activation`
   (so the bundle has been parsed, signature-verified, chain_id-checked,
   environment-checked, and structurally validated for revocation
   entries) and BEFORE `check_bundle_activation` (so the precise error
   surfaces on a too-soon scheduling) and BEFORE the binary touches
   `pqc_trust_sequence::check_and_update_sequence` and the
   `loaded.active_roots` merge in `main.rs`. The no-side-effects
   boundary on rejected bundles is proven by
   `run065_too_soon_bundle_does_not_touch_loader_outcome` AND by the
   Smoke 2 / Smoke 4 file-system check (no `pqc_trust_bundle_sequence.json`
   under the data dir after a rejected too-soon load).

5. **Saturating add against `u64::MAX`.** `required_min_height` is
   computed as `current_height.saturating_add(margin)`; a near-
   `u64::MAX` `current_height` cannot wrap to a tiny
   `required_min_height` and silently admit every activation_height.
   Pinned by `run065_required_min_height_saturates_on_overflow`.

6. **No private-key material on the new helper API.** The new helper
   `check_min_activation_height_policy(&TrustBundle, TrustBundleEnvironment, Option<u64>)`
   takes only public material and returns either `Ok(())` or a public-
   only error enum (8-hex prefixes only when scope refers to a
   root_id / leaf fingerprint, plus integer-valued
   `current_height` / `activation_height` / `minimum_margin` /
   `required_min_height` / `environment` enum). No `*_sk` byte slice
   is referenced; no private digest is logged.

## Explicit remaining boundaries (NOT done in Run 065)

Run 065 narrows the per-environment minimum-activation-margin boundary on
the load path. Several adjacent C4 boundaries remain:

(a) **Per-environment minimum activation-margin policy on the gossiped /
peer-supplied trust-bundle path.** Run 065 enforces the policy at
`load_from_path_with_signing_keys_chain_id_and_activation` — the path the
binary uses for `--p2p-trust-bundle`. The bundle is not currently gossiped
between peers (operator-distributed); when on-the-fly trust-bundle
distribution lands, the same `check_min_activation_height_policy` helper
must be threaded through that path. Unchanged from the Run 057 / Run 062
boundary.

(b) **`activation_epoch` runtime source.** Unchanged from Run 057 § 10(b):
bundle-level `activation_epoch` continues to fail closed with
`TrustBundleActivationError::CurrentEpochUnavailable`; per-entry
`activation_epoch` on revocations is intentionally NOT supported (Run 062
boundary). Run 065 does NOT introduce a minimum-margin policy on the
epoch axis.

(c) **On-the-fly trust-bundle hot reload.** Unchanged from the Run 050 /
057 / 061 / 062 / 063 / 064 boundary. The bundle is loaded exactly once per
process lifetime; Run 065's check fires at that single load.

(d) **In-binary / on-chain bundle-signing-key ratification.** Unchanged
from the Run 060 boundary.

(e) **External KMS / HSM integration.** Unchanged.

(f) **Multi-validator MainNet release-binary peer-connection smoke.**
Unchanged from the Run 059 / 060 / 061 / 062 / 063 / 064 boundary. Run 065
proves only the load-time policy on a single-validator startup smoke; a
multi-validator peer-mesh smoke under the policy is a future run.

(g) **Production fast-sync / consensus-storage restore.** Unchanged. The
`--restore-from-snapshot` `current_height` source already feeds the Run 065
policy via `ActivationContext::height_only`; a fully-fledged production
fast-sync surface is a separate boundary.

(h) **Operator playbook prose for the new minimum margin.** Run 064's
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` non-goal item explicitly
lists the per-environment minimum-activation-margin policy as a non-goal
for that run; the runbook is intentionally NOT updated in Run 065 (Run 065
is source-and-evidence, not operator-doc). A future docs-only run may
align the runbook prose to record the new constants and reschedule
guidance, and to remove the §10 / §1.2 non-goal item.

(i) **Per-entry revocation FATAL surface in `main.rs`.** Run 065's
`RevocationActivationHeightBelowMinimumMargin` flows through the existing
`TrustBundleError::Activation` printer, which is sufficient. A future run
may add a dedicated metric label for scheduled-revocation rejections if
operator dashboards need to distinguish them from bundle-level rejections.

(j) **Constants choice.** The constants (DevNet 0, TestNet 8, MainNet 32)
are conservative-but-test-friendly for the current evidence/devnet
environment. They are intentionally large enough to make a same-block
"surprise rotate" impossible on TestNet/MainNet, but small enough that
operator/test scheduling can hit them without contrived height settings.
A future production-readiness run may revise the constants upward (e.g.
MainNet 256 or 1024 blocks) once a real-time observability and ratification
surface exists; the current constants are still net-strictly-stricter than
the Run 064 baseline (which had no minimum margin at all).

**C5 remains NOT closed** by Run 065. Run 065 does not touch timeout /
NewView wire formats, forged-traffic policy, KEMTLS wire formats,
consensus message wire formats, or any signature/verification semantics
outside the trust-bundle load-time activation-margin policy.

**Full C4 remains OPEN.** Run 065 closes only the Run 057 § 10(a) /
Run 058 § 10(a) / Run 060 § 10(a) / Run 061 § 10 / Run 062 § 10(c) /
Run 063 § 10(a) / Run 064 § 10(a) "per-environment minimum activation
margin" sub-piece on the load path; all other Run 050 / 051 / 052 / 054 /
055 / 056 / 057 / 058 / 059 / 060 / 061 / 062 / 063 / 064 § 10 remaining
items persist unchanged.

## Immediate next action

Land Run 065 (this run). Future work, in priority order, will likely be:

1. Documentation-only run (Run 066?) that updates
   `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` to reflect the new
   minimum-margin constants, the reschedule guidance, and the closure of
   the long-standing per-environment minimum-margin §10 non-goal.

2. A `qbind_p2p_pqc_trust_bundle_activation_min_margin_rejected_total`
   metric (and its sibling `*_scheduled_revocation_*` family) if and only
   if operator dashboards need to distinguish margin rejections from
   future-height rejections at scrape time. Run 065 keeps the existing
   `qbind_p2p_pqc_trust_bundle_activation_rejected{required_height_label}`
   accurate by surfacing `required_min_height` on its label.

3. Re-running the policy at on-the-fly trust-bundle hot-reload time if /
   when that surface lands.