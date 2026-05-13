# QBIND DevNet Evidence — Run 058: Release-Binary Live Artifacts for Run 057 Trust-Bundle Activation-Height Gating

## Exact objective

Run 058 is **evidence-only**. It produces the live release-binary
artifact set for the Run 057 trust-bundle **activation-height** gating
layer on the real `qbind-node` release binary in `pqc-static-root` +
signed `--p2p-trust-bundle` mode. The explicit artifact gap left open
in Run 057 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_057.md`, "Explicit
remaining boundaries (NOT done in Run 057)" → "Live release-binary
smoke artefact set for the Run 057 activation gate") is the only
target.

The scope is intentionally narrow:

- prove on the live release binary that a fresh-data-dir startup with
  a valid signed DevNet bundle at `sequence=1` and
  `activation_height=0` (active-now) is accepted, the activation gate
  is satisfied, the sequence persistence record is written, the
  bundle's roots are merged into the live trust set, and
  `/metrics` reports the five `qbind_p2p_pqc_trust_bundle_activation_*`
  series with the satisfied values;
- prove on the live release binary that a fresh-data-dir startup with
  a valid signed DevNet bundle at `sequence=1` and
  `activation_height=1_000_000` (future) **fails closed BEFORE** any
  bundle root is merged and **BEFORE** any sequence persistence file
  is created — the data dir stays empty;
- prove on the live release binary that a restart with a future
  `activation_height` bundle at `sequence=2` on a data dir that has
  already accepted a `sequence=1` bundle **fails closed BEFORE** the
  new bundle's roots are merged and **without updating** the
  persisted `highest_sequence` (still `1`, byte-for-byte identical);
- prove on the live release binary that a subsequent restart with a
  validly-signed `sequence=2` bundle whose `activation_height=0`
  (satisfied) is then accepted as a normal upgrade and the persisted
  `highest_sequence` advances from `1` to `2` — proving the failed
  future-activation attempt did NOT poison the sequence state;
- prove no fallback to `--p2p-trusted-root`, `DummySig`, `DummyKem`,
  or `DummyAead` on any path;
- preserve Run 037 / Run 040 / Run 044 / Run 050 / Run 051 / Run 052 /
  Run 053 / Run 054 / Run 055 / Run 056 / Run 057 behaviour
  bit-for-bit.

Explicitly out of scope for Run 058 (and listed in
`docs/whitepaper/contradiction.md`):

- epoch gating runtime source (no safe pre-consensus epoch source
  exists today; bundles declaring `activation_epoch` continue to fail
  closed with `CurrentEpochUnavailable`, pinned by Run 057 unit
  `bundle_activation_epoch_requires_runtime_source_today` and
  integration `activation_epoch_present_without_current_epoch_refuses`);
- activation gates on revocation entries;
- per-environment minimum activation-height policy;
- operator-facing CA + certificate rotation + signing-key rotation
  playbook;
- production fast-sync / consensus-storage restore;
- MainNet live signed-bundle release-binary smoke with a
  production-grade signing key;
- any redesign of KEMTLS, trust bundles, transport, or consensus;
- the `--restore-from-snapshot` satisfied-height live smoke (Case 3 in
  the Run 058 task). Producing this on the release binary requires a
  pre-existing valid VM-v0 RocksDB state-store + matching
  `StateSnapshotMeta` snapshot artefact set, which is a separate
  cross-domain operational artefact (snapshot-creation tooling sits in
  `crates/qbind-ledger/examples/qbind_state_snapshot.rs` and requires
  a running `RocksDbAccountState` that has actually committed blocks
  through consensus). The activation-height restore path is already
  exercised at the unit + integration test layer end-to-end (Run 057
  `bundle_activation_height_satisfied_accepted`,
  `bundle_activation_height_equal_accepted_inclusive`,
  `future_activation_does_not_advance_sequence_persistence`,
  `activation_height_satisfied_accepts_bundle`,
  `activation_height_inclusive_equal_accepts`) — boundary documented
  honestly per the Run 058 task's "If not feasible: document boundary
  honestly and rely on unit/integration tests for restore-height
  path. do not fake restore height." instruction.

## Exact verdict

**Strongest positive for the scoped Run 058 release-binary
activation-height evidence run.** On the live release `qbind-node`
binary (sha256 `5f249fe2929135f11d38d95df4b1b13a603713a8208d0ede53b195efaadc3bcc`,
ELF BuildID `77553328e1ee90a1a9f808974c6d9b66b0cbe9d8`) driven from
the live release helper `devnet_pqc_trust_bundle_helper` (sha256
`1cc204907e5801f703877b4a4690017be45c9a7b2f7ba0e3a962e543315c7e9a`,
ELF BuildID `6844e274f512e1c92ebcc1526d5fff592782587e`), every Run 057
activation-height gating policy case behaved exactly as the Run 057
design promises:

- **Smoke 2 — positive active-now `sequence=1 activation_height=0`.**
  Fresh `--data-dir`, signed DevNet bundle
  `fp=1b804a67…f8b6` at `sequence=1` with bundle-level
  `activation_height=Some(0)`. The binary printed `[binary] Run 057:
  trust-bundle activation gate satisfied (required_height=Some(0)
  current_height=Some(0) required_epoch=None current_epoch=None)`,
  then `[binary] Run 055: trust-bundle sequence persistence
  env=devnet chain_id=51424e4444455600
  path=/tmp/run058/data_main/pqc_trust_bundle_sequence.json
  first-load persisted_sequence=1 fp=1b804a67`, then `[binary]
  Run 050/051: trust bundle loaded … sequence=1 …
  signature=verified(signing_key_id=4a0fb1c1..)
  signing_keys_configured=1`. The persistence file appeared with
  `{"record_version":1,"environment":"devnet",
  "chain_id":"51424e4444455600","highest_sequence":1,
  "bundle_fingerprint":"1b804a6737688def0cbf4e290beb9f11158228016d8c9578fcdc9148c94cf8b6",
  "updated_at_unix_secs":1778657986}`. `/metrics` reported
  `qbind_p2p_pqc_trust_bundle_loaded 1`,
  `qbind_p2p_pqc_trust_bundle_active_roots 1`,
  `qbind_p2p_pqc_trust_bundle_sequence 1`,
  `qbind_p2p_pqc_trust_bundle_sequence_highest 1`,
  `qbind_p2p_pqc_trust_bundle_signature_verified_total 1`,
  and the full activation series at the satisfied values
  `qbind_p2p_pqc_trust_bundle_activation_height_required 0`,
  `qbind_p2p_pqc_trust_bundle_activation_height_current 0`,
  `qbind_p2p_pqc_trust_bundle_activation_epoch_required 0`,
  `qbind_p2p_pqc_trust_bundle_activation_epoch_current 0`,
  `qbind_p2p_pqc_trust_bundle_activation_rejected_total 0`.
- **Smoke 4 — negative future `sequence=1 activation_height=1_000_000`
  on a fresh data dir.** Fresh `--data-dir`, signed DevNet bundle
  `fp=04e923cb…cd6c` at `sequence=1` with
  `activation_height=Some(1_000_000)`. The binary exited `1` with
  FATAL `[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/run058/seq1_actfuture/trust-bundle.json: trust bundle
  activation gating: pqc trust-bundle activation height not yet
  reached (scope=bundle, current_height=0,
  required_height=1000000); fail closed — bundle is structurally
  valid and properly signed but has not yet become effective at this
  committed height. No fallback to --p2p-trusted-root.. No fallback
  to --p2p-trusted-root on bundle failure (production-honest
  lifecycle must not silently downgrade). See
  docs/whitepaper/contradiction.md C4 (signed root distribution).`.
  The data dir (`/tmp/run058/data_smoke4_freshfuture`) is empty
  after the smoke — **no `pqc_trust_bundle_sequence.json` was
  created**, proving the activation gate rejection runs BEFORE the
  Run 055 sequence-persistence step.
- **Smoke 5 — negative future `sequence=2
  activation_height=1_000_000` on the data dir already holding
  persisted `sequence=1`.** Same `--data-dir` used by Smoke 2 (so
  `pqc_trust_bundle_sequence.json` already records
  `highest_sequence=1 bundle_fingerprint=1b804a67…f8b6
  updated_at_unix_secs=1778657986`). Signed DevNet bundle
  `fp=427e5178…7a09` at `sequence=2` with
  `activation_height=Some(1_000_000)`. The binary exited `1` with
  FATAL `[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/run058/seq2_actfuture/trust-bundle.json: trust bundle
  activation gating: pqc trust-bundle activation height not yet
  reached (scope=bundle, current_height=0,
  required_height=1000000); fail closed — bundle is structurally
  valid and properly signed but has not yet become effective at this
  committed height. No fallback to --p2p-trusted-root.. No fallback
  to --p2p-trusted-root on bundle failure (production-honest
  lifecycle must not silently downgrade). See
  docs/whitepaper/contradiction.md C4 (signed root distribution).`.
  The persistence file was verified **byte-for-byte identical**
  before/after the smoke (`diff … && echo IDENTICAL` printed
  `IDENTICAL`); `highest_sequence` stayed at `1`, the
  `bundle_fingerprint` stayed at `1b804a67…f8b6`, and the
  `updated_at_unix_secs` stayed at `1778657986`. The activation gate
  rejection of the future `sequence=2` bundle did NOT burn the
  higher sequence, did NOT update the persisted record, and did NOT
  inject the `sequence=2` bundle's roots into the live trust set.
- **Smoke 6 — positive normal upgrade `sequence=2
  activation_height=0` after the failed future activation.** Same
  `--data-dir` (now still holding the same `sequence=1` record from
  Smoke 2 — confirmed unchanged by Smoke 5). Signed DevNet bundle
  `fp=db25777e…8559` at `sequence=2` with
  `activation_height=Some(0)`. The binary printed `[binary] Run 057:
  trust-bundle activation gate satisfied (required_height=Some(0)
  current_height=Some(0) required_epoch=None current_epoch=None)`,
  then `[binary] Run 055: trust-bundle sequence persistence
  env=devnet chain_id=51424e4444455600
  path=/tmp/run058/data_main/pqc_trust_bundle_sequence.json
  upgraded previous_sequence=1 -> new_sequence=2 fp=db25777e`, then
  `[binary] Run 050/051: trust bundle loaded … sequence=2 …
  signature=verified(signing_key_id=703285f1..)`. The persistence
  file's `highest_sequence` flipped from `1` to `2`, and the
  `bundle_fingerprint` flipped to `db25777e…8559`. `/metrics`
  reported `qbind_p2p_pqc_trust_bundle_sequence 2`,
  `qbind_p2p_pqc_trust_bundle_sequence_highest 2`,
  `qbind_p2p_pqc_trust_bundle_signature_verified_total 1`, and the
  full activation series at satisfied values
  (`_height_required=0`, `_height_current=0`,
  `_rejected_total 0`). This proves the failed future-activation
  attempt in Smoke 5 did NOT poison the persisted sequence state —
  a later validly-signed satisfied-activation `sequence=2` bundle is
  still accepted as a normal monotonic upgrade.

On every positive smoke (Smoke 2, Smoke 6), the Run 040
`[Run040] P2pNodeBuilder` log line emitted verbatim
`pqc_root_mode=pqc-static-root sig_suite_id=100
transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768
dummy_kem_registered=false transport_aead_suite_id=101
transport_aead_suite_name=chacha20-poly1305
dummy_aead_registered=false configured_roots=1
leaf_credentials_present=true` — proving real ML-DSA-44 + real
ML-KEM-768 + real ChaCha20-Poly1305 on the active cert-verify path
and the absence of `DummySig` / `DummyKem` / `DummyAead`. Every Run
050/051 log line on a positive smoke emitted
`signature=verified(signing_key_id=…)` — proving signed-bundle
verification (not unsigned fallback). On every negative smoke (Smoke
4, Smoke 5), the binary exited BEFORE the Run 040 `[Run040]
P2pNodeBuilder` line was reached, so no `Dummy*` primitive could be
installed even hypothetically; the FATAL line literally ends with
`No fallback to --p2p-trusted-root on bundle failure
(production-honest lifecycle must not silently downgrade). See
docs/whitepaper/contradiction.md C4 (signed root distribution).`,
exactly as Run 057's source surface in
`crates/qbind-node/src/main.rs` requires. No `--p2p-trusted-root`
flag was supplied on any Run 058 smoke; the trust set was sourced
exclusively from the signed `--p2p-trust-bundle` (and was never
populated at all on the negative smokes).

All required regression suites stay green (numbers below). Full C4
remains OPEN for the items listed in the Run 057 evidence document,
minus the live-binary activation-height artefact item which Run 058
narrows. Smoke 3 (`--restore-from-snapshot` satisfied-height live
smoke) and Smoke 7 (epoch-declaration negative live smoke) are
explicit Run 058 boundaries documented honestly below; the
underlying code paths are already pinned by Run 057 unit +
integration tests.

## Exact files changed

| File | Change |
| --- | --- |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_058.md` | This evidence document (new). |
| `docs/devnet/run_058_smoke_*.{stdout,stderr}.log` and `run_058_metrics_*.txt` | Live release-binary smoke logs and `/metrics` excerpts for Smokes 2, 4, 5, 6. |
| `docs/whitepaper/contradiction.md` | Append "C4 Run 058 evidence update" recording that the live-binary release-build smoke artifact set for the Run 057 activation-height gating path (the explicit remaining boundary called out in Run 057) is now closed/narrowed on DevNet; the still-open C4 pieces are listed explicitly (epoch gating runtime source, activation gates on revocation entries, per-environment minimum activation-height policy, CA / rotation playbook, production fast-sync / consensus-storage restore, MainNet live signed-bundle release-binary smoke, restore-from-snapshot satisfied-height live smoke). |

**No `crates/**/src/**` files were touched.** **No example helper code
was touched** (the Run 057 helper already supports the optional 5th
positional `[activation_height_override]` u64 argument used by Run
058 — additive evidence-tooling extension landed by Run 057, not by
Run 058). **No tests were removed or weakened.** **No `Cargo.toml`
changes.** **No `--p2p-trusted-root` weakening.** **No KEMTLS /
transport / consensus / trust-bundle / sequence-persistence /
activation-gating library source changes.**

## Exact commands run

```bash
# 0) Baseline identity.
git rev-parse --abbrev-ref HEAD    # copilot/run-058-task
git rev-parse HEAD                  # b19bd54d2db354fcbdd5a9c34e9065940e28fc88
git status --porcelain | wc -l      # 0 (clean tree before evidence-doc edits)

# 1) Build release artefacts.
cargo build --release -p qbind-node \
  --bin qbind-node \
  --example devnet_pqc_trust_bundle_helper \
  --example devnet_pqc_root_helper

# 2) Identify binaries.
sha256sum target/release/qbind-node
# 5f249fe2929135f11d38d95df4b1b13a603713a8208d0ede53b195efaadc3bcc
readelf -n target/release/qbind-node | grep Build
# BuildID[sha1]=77553328e1ee90a1a9f808974c6d9b66b0cbe9d8
sha256sum target/release/examples/devnet_pqc_trust_bundle_helper
# 1cc204907e5801f703877b4a4690017be45c9a7b2f7ba0e3a962e543315c7e9a
# BuildID[sha1]=6844e274f512e1c92ebcc1526d5fff592782587e
sha256sum target/release/examples/devnet_pqc_root_helper
# 0e04fd1f9a1464de9ecf670987ca4f54d07df11a0e6fac2a2094389cd992e8a4
# BuildID[sha1]=dcee024f842845da7648a568c309c760b51df5c3

# 3) Confirm hidden flag stays hidden, required flags surface.
./target/release/qbind-node --help | grep -c devnet-forged-inject   # 0
./target/release/qbind-node --help | grep -E -- \
  '--p2p-trust-bundle|--p2p-trust-bundle-signing-key|--p2p-pqc-root-mode|--p2p-leaf-cert|--p2p-leaf-cert-key|--p2p-peer-leaf-cert|--p2p-mutual-auth|--data-dir|--restore-from-snapshot'

# 4) Regression test rerun (release profile).
cargo test --release -p qbind-node --lib pqc_trust_activation         # 14/14
cargo test --release -p qbind-node --lib pqc_trust_sequence           # 21/21
cargo test --release -p qbind-node --lib pqc_trust_bundle             # 72/72
cargo test --release -p qbind-node --lib metrics                      # 108/108
cargo test --release -p qbind-node --lib p2p                          # 138/138
cargo test --release -p qbind-node --lib                              # 898/898
cargo test --release -p qbind-node --test run_057_pqc_trust_bundle_activation_tests   # 12/12
cargo test --release -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests     # 12/12
cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests              # 14/14
cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests      # 13/13
cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests           # 12/12
cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests   # 12/12
cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests     # 14/14
cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests # 10/10
cargo test --release -p qbind-net  --test run_052_leaf_revocation_handshake_tests     # 9/9
cargo test --release -p qbind-net  --lib                              # 17/17
cargo test --release -p qbind-crypto --lib                            # 68/68
cargo check --release -p qbind-node --bin qbind-node                  # clean

# 5) Mint signed DevNet fixtures.
#    Helper CLI: <outdir> <num_validators> <bundle_mode> <sequence_override> <activation_height_override>
./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run058/seq1_act0       1 signed-devnet 1 0
./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run058/seq1_actfuture  1 signed-devnet 1 1000000
./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run058/seq2_actfuture  1 signed-devnet 2 1000000
./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run058/seq2_act0       1 signed-devnet 2 0

# 6) Live release-binary smokes.

# --- Smoke 4: negative future-height seq=1 act=1_000_000 on a FRESH data dir ---
SPEC=$(cat /tmp/run058/seq1_actfuture/signing-key.spec)
timeout 15 ./target/release/qbind-node \
  --env devnet --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle /tmp/run058/seq1_actfuture/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert /tmp/run058/seq1_actfuture/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run058/seq1_actfuture/v0.kem.sk.bin \
  --data-dir /tmp/run058/data_smoke4_freshfuture \
  > docs/devnet/run_058_smoke_negative_future_fresh.stdout.log \
  2> docs/devnet/run_058_smoke_negative_future_fresh.stderr.log
# exit_code=1; /tmp/run058/data_smoke4_freshfuture/ stays EMPTY (no pqc_trust_bundle_sequence.json created).

# --- Smoke 2: positive active-now seq=1 act=0 on a fresh data dir, with /metrics scrape ---
SPEC=$(cat /tmp/run058/seq1_act0/signing-key.spec)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9158 ./target/release/qbind-node \
  --env devnet --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle /tmp/run058/seq1_act0/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert /tmp/run058/seq1_act0/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run058/seq1_act0/v0.kem.sk.bin \
  --data-dir /tmp/run058/data_main \
  > docs/devnet/run_058_smoke_positive_active_now.stdout.log \
  2> docs/devnet/run_058_smoke_positive_active_now.stderr.log &
sleep 5
curl -s --max-time 3 http://127.0.0.1:9158/metrics > docs/devnet/run_058_metrics_positive_active_now.txt
kill -TERM %1; wait
# Persistence file appears at /tmp/run058/data_main/pqc_trust_bundle_sequence.json with highest_sequence=1.

# --- Smoke 5: negative future-height seq=2 act=1_000_000 on the SAME data dir (already seq=1) ---
cp /tmp/run058/data_main/pqc_trust_bundle_sequence.json \
   /tmp/run058/data_main/pqc_trust_bundle_sequence.json.before_smoke5
SPEC=$(cat /tmp/run058/seq2_actfuture/signing-key.spec)
timeout 15 ./target/release/qbind-node \
  --env devnet --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle /tmp/run058/seq2_actfuture/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert /tmp/run058/seq2_actfuture/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run058/seq2_actfuture/v0.kem.sk.bin \
  --data-dir /tmp/run058/data_main \
  > docs/devnet/run_058_smoke_negative_future_after_seq1.stdout.log \
  2> docs/devnet/run_058_smoke_negative_future_after_seq1.stderr.log
# exit_code=1; persistence file byte-for-byte unchanged.
diff /tmp/run058/data_main/pqc_trust_bundle_sequence.json.before_smoke5 \
     /tmp/run058/data_main/pqc_trust_bundle_sequence.json   # (no output: IDENTICAL)

# --- Smoke 6: positive seq=2 act=0 upgrade after rejected future activation ---
cp /tmp/run058/data_main/pqc_trust_bundle_sequence.json \
   /tmp/run058/data_main/pqc_trust_bundle_sequence.json.before_smoke6
SPEC=$(cat /tmp/run058/seq2_act0/signing-key.spec)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9159 ./target/release/qbind-node \
  --env devnet --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle /tmp/run058/seq2_act0/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert /tmp/run058/seq2_act0/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run058/seq2_act0/v0.kem.sk.bin \
  --data-dir /tmp/run058/data_main \
  > docs/devnet/run_058_smoke_positive_upgrade_after_rejection.stdout.log \
  2> docs/devnet/run_058_smoke_positive_upgrade_after_rejection.stderr.log &
sleep 5
curl -s --max-time 3 http://127.0.0.1:9159/metrics > docs/devnet/run_058_metrics_positive_upgrade_after_rejection.txt
kill -TERM %1; wait
# Persistence file flipped from highest_sequence=1 → 2.
```

## Test evidence (release profile)

| Suite | Tests | Result |
|---|---|---|
| `cargo test --release -p qbind-node --lib pqc_trust_activation` | 14 | **passed** |
| `cargo test --release -p qbind-node --lib pqc_trust_sequence` | 21 | **passed** |
| `cargo test --release -p qbind-node --lib pqc_trust_bundle` | 72 | **passed** |
| `cargo test --release -p qbind-node --lib metrics` | 108 | **passed** |
| `cargo test --release -p qbind-node --lib p2p` | 138 | **passed** |
| `cargo test --release -p qbind-node --lib` (full) | 898 | **passed** |
| `cargo test --release -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests` | 14 | **passed** |
| `cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | 13 | **passed** |
| `cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | 14 | **passed** |
| `cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | 10 | **passed** |
| `cargo test --release -p qbind-net  --test run_052_leaf_revocation_handshake_tests` | 9 | **passed** |
| `cargo test --release -p qbind-net  --lib` | 17 | **passed** |
| `cargo test --release -p qbind-crypto --lib` | 68 | **passed** |
| `cargo check --release -p qbind-node --bin qbind-node` | — | **clean** (only pre-existing `bincode::config` deprecation warnings unrelated to Run 058) |
| `cargo build --release -p qbind-node --bin qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper` | — | **clean** |

`binary_consensus`, `forged_injection`, `run030`, and
`qbind-consensus --lib timeout` were intentionally not rerun: Run 058
did not modify any source on those paths (only docs + evidence
artefacts were added). The Run 056-recorded pre-existing
`m16_epoch_transition_hardening_tests` `cargo build --tests` failure
(`set_inject_write_failure` / `clear_epoch_transition_marker` methods
missing on `RocksDbConsensusStorage`) is unrelated to Run 058 and
remains present on `b19bd54` before Run 058's docs-only edits.

## Binary identity

| Artefact | sha256 | ELF BuildID |
| --- | --- | --- |
| `target/release/qbind-node` | `5f249fe2929135f11d38d95df4b1b13a603713a8208d0ede53b195efaadc3bcc` | `77553328e1ee90a1a9f808974c6d9b66b0cbe9d8` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `1cc204907e5801f703877b4a4690017be45c9a7b2f7ba0e3a962e543315c7e9a` | `6844e274f512e1c92ebcc1526d5fff592782587e` |
| `target/release/examples/devnet_pqc_root_helper` | `0e04fd1f9a1464de9ecf670987ca4f54d07df11a0e6fac2a2094389cd992e8a4` | `dcee024f842845da7648a568c309c760b51df5c3` |

`./target/release/qbind-node --help | grep -c devnet-forged-inject` →
`0` (hidden flag stays hidden from normal `--help`). All required
operator flags surface: `--p2p-trust-bundle`,
`--p2p-trust-bundle-signing-key`, `--p2p-pqc-root-mode`,
`--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-peer-leaf-cert`,
`--p2p-mutual-auth`, `--data-dir`, `--restore-from-snapshot`.

git identity: branch `copilot/run-058-task`, commit
`b19bd54d2db354fcbdd5a9c34e9065940e28fc88`, status clean
(`git status --porcelain | wc -l` = `0` before evidence-doc edits).

## Trust-bundle material procedure

All four DevNet fixtures were minted by the live release helper
`./target/release/examples/devnet_pqc_trust_bundle_helper`. Each
invocation generates an ephemeral fresh ML-DSA-44 root keypair, an
ephemeral fresh ML-DSA-44 bundle-signing keypair, and an ephemeral
fresh ML-KEM-768 leaf keypair for one validator (v0). All secret
keys are held in process memory only and never written to disk
(helper prints `[devnet_pqc_trust_bundle_helper] root_sk and bundle
signing_sk were held in memory only; never written to disk.`). The
bundle is signed BEFORE the `[activation_height_override]` is
folded into the canonical preimage; therefore the
`activation_height` is part of the signed body and the canonical
fingerprint, exactly as Run 057's unit
`tampering_activation_height_after_signing_invalidates_signature`
and integration `canonical_fingerprint_covers_activation_height`
require.

Bundle inventory (verified by parsing each `trust-bundle.json`):

| Outdir | `sequence` | `activation_height` | `activation_epoch` | `environment` | `chain_id` (in-JSON) | canonical_fingerprint | bundle signing_key_id (8-char prefix) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `/tmp/run058/seq1_act0` | `1` | `Some(0)` | `None` | `devnet` | `null` (matches any) | `1b804a6737688def0cbf4e290beb9f11158228016d8c9578fcdc9148c94cf8b6` | `4a0fb1c1` |
| `/tmp/run058/seq1_actfuture` | `1` | `Some(1000000)` | `None` | `devnet` | `null` | `04e923cbd69b8bb337c0e411eabc611954c4314603b1a25f5a4b7d254b00cd6c` | `d49a0452` |
| `/tmp/run058/seq2_actfuture` | `2` | `Some(1000000)` | `None` | `devnet` | `null` | `427e5178d660c53c5ce2c97bc43490af5fd1df1b95b64f76a2f22dbea5d37a09` | `3bddbeef` |
| `/tmp/run058/seq2_act0` | `2` | `Some(0)` | `None` | `devnet` | `null` | `db25777e3751675aef87c5080550ca9aa0b5d63aa854072b953cb6ba089e8559` | `703285f1` |

## Signed-bundle verification proof

Every positive smoke (Smoke 2, Smoke 6) emitted the Run 050/051 log
line `[binary] Run 050/051: trust bundle loaded path=… env=devnet
fp=… active_roots=1 revoked_roots=0 sequence=… valid_from=0
valid_until=18446744073709551615
signature=verified(signing_key_id=…) signing_keys_configured=1.` —
proving the ML-DSA-44 signature on the canonical signing preimage
verified against the `--p2p-trust-bundle-signing-key` operator
input. The `--p2p-trust-bundle-signing-key` argument passed to the
binary on each smoke was the full `KEYID:100:PK` spec written by the
helper (`signing-key.spec`), so each smoke verifies against the
exact key it was signed with; this is also pinned by the Run 051
integration suite (13/13 green above).

`/metrics` on every positive smoke reports
`qbind_p2p_pqc_trust_bundle_signature_verified_total 1`,
`qbind_p2p_pqc_trust_bundle_signing_keys_configured 1`, and
`qbind_p2p_pqc_trust_bundle_loaded 1`.

## chain_id compatibility / matching status

All four DevNet fixtures emit `chain_id = null` in the JSON envelope
(the helper omits the field). On DevNet the bundle loader treats
`chain_id = null` as compatible with the runtime DevNet
`chain_id_u64 = 0x51424e4444455600` per Run 053 policy (the bundle
declares "no chain pin"; the runtime accepts it on its declared
environment). The persistence record written by the runtime stores
the **runtime's** `chain_id_hex = 51424e4444455600` regardless of
whether the bundle pinned it, so the on-disk
`pqc_trust_bundle_sequence.json` shows
`"chain_id":"51424e4444455600"` on every positive smoke. This is
identical to the chain_id behaviour observed and pinned by Run 056
on the same DevNet helper shape.

## Activation-height fixture details

| Smoke | Bundle | `activation_height` in bundle | `current_height` source | Expected gate outcome | Observed gate outcome |
| --- | --- | --- | --- | --- | --- |
| Smoke 2 | `seq1_act0` (sequence=1) | `Some(0)` | `0` (fresh data dir, no `--restore-from-snapshot`) | satisfied (`0 ≥ 0`, inclusive) | satisfied — `[binary] Run 057: trust-bundle activation gate satisfied (required_height=Some(0) current_height=Some(0) …)` |
| Smoke 4 | `seq1_actfuture` (sequence=1) | `Some(1_000_000)` | `0` (fresh data dir) | future / fail-closed (`0 < 1_000_000`) | future / fail-closed — `[binary] FATAL: … pqc trust-bundle activation height not yet reached (scope=bundle, current_height=0, required_height=1000000) …`, `exit_code=1` |
| Smoke 5 | `seq2_actfuture` (sequence=2) | `Some(1_000_000)` | `0` (data dir from Smoke 2; no `--restore-from-snapshot`) | future / fail-closed BEFORE sequence persistence is touched | future / fail-closed — same FATAL shape, `exit_code=1`, persistence file byte-for-byte identical (still `highest_sequence=1`) |
| Smoke 6 | `seq2_act0` (sequence=2) | `Some(0)` | `0` (same data dir, no `--restore-from-snapshot`) | satisfied (`0 ≥ 0`, inclusive) AND sequence advance (`1 → 2`) | satisfied — `[binary] Run 057: trust-bundle activation gate satisfied (required_height=Some(0) current_height=Some(0) …)`, then `[binary] Run 055: … upgraded previous_sequence=1 -> new_sequence=2 fp=db25777e` |

## Runtime current-height source for each smoke

For every Run 058 smoke, the runtime `current_height` passed into
`ActivationContext` is `0`. This is the Run 057 binary contract for
the "no `--restore-from-snapshot`" path: `activation_current_height =
restore_baseline.as_ref().map(|b| b.snapshot_height).unwrap_or(0)` in
`crates/qbind-node/src/main.rs`. No Run 058 smoke passes
`--restore-from-snapshot`, so `restore_baseline = None` and
`current_height = 0` deterministically. This is verifiable in every
positive smoke's `[binary] Run 057: trust-bundle activation gate
satisfied (… current_height=Some(0) …)` line and every negative
smoke's `[binary] FATAL: … current_height=0 …` line.

## Sequence persistence file path

`<data_dir>/pqc_trust_bundle_sequence.json` (Run 055 layout, unchanged
by Run 057 and Run 058). For the Run 058 smokes:

- Smoke 2 / Smoke 5 / Smoke 6 → `/tmp/run058/data_main/pqc_trust_bundle_sequence.json`
- Smoke 4 → `/tmp/run058/data_smoke4_freshfuture/pqc_trust_bundle_sequence.json` (**does NOT exist** after Smoke 4)

## Smoke evidence (detailed)

### Smoke 2 — positive active-now `sequence=1 activation_height=0`

- Data dir: `/tmp/run058/data_main` (created fresh, empty before
  smoke).
- Bundle: `/tmp/run058/seq1_act0/trust-bundle.json`, signed,
  `sequence=1`, `activation_height=Some(0)`,
  `fp=1b804a6737688def0cbf4e290beb9f11158228016d8c9578fcdc9148c94cf8b6`,
  signing_key_id 8-char prefix `4a0fb1c1`.
- Exit: binary continued to run consensus and metrics scrape; the
  smoke ended by SIGTERM after the `/metrics` scrape completed.
- Stderr key lines (verbatim, also in
  `docs/devnet/run_058_smoke_positive_active_now.stderr.log`):

  ```
  [binary] Run 057: trust-bundle activation gate satisfied (required_height=Some(0) current_height=Some(0) required_epoch=None current_epoch=None)
  [binary] Run 055: trust-bundle sequence persistence env=devnet chain_id=51424e4444455600 path=/tmp/run058/data_main/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=1b804a67
  [binary] Run 050/051: trust bundle loaded path=/tmp/run058/seq1_act0/trust-bundle.json env=devnet fp=1b804a6737688def0cbf4e290beb9f11158228016d8c9578fcdc9148c94cf8b6 active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=4a0fb1c1..) signing_keys_configured=1. Bundle root IDs: [c5ae8563..]
  [binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=0 (root fingerprints: [id=c5ae8563.. suite=100 fp=7ffa3f3a])
  [Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
  ```

- Sequence persistence record contents AFTER smoke (`cat
  /tmp/run058/data_main/pqc_trust_bundle_sequence.json`):

  ```json
  {"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":1,"bundle_fingerprint":"1b804a6737688def0cbf4e290beb9f11158228016d8c9578fcdc9148c94cf8b6","updated_at_unix_secs":1778657986}
  ```

- `/metrics` excerpt (`docs/devnet/run_058_metrics_positive_active_now.txt`):

  ```
  qbind_p2p_pqc_trust_bundle_loaded 1
  qbind_p2p_pqc_trust_bundle_environment 0
  qbind_p2p_pqc_trust_bundle_active_roots 1
  qbind_p2p_pqc_trust_bundle_sequence 1
  qbind_p2p_pqc_trust_bundle_signature_verified_total 1
  qbind_p2p_pqc_trust_bundle_signing_keys_configured 1
  qbind_p2p_pqc_trust_bundle_sequence_highest 1
  qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0
  qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0
  qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0
  qbind_p2p_pqc_trust_bundle_activation_height_required 0
  qbind_p2p_pqc_trust_bundle_activation_height_current 0
  qbind_p2p_pqc_trust_bundle_activation_epoch_required 0
  qbind_p2p_pqc_trust_bundle_activation_epoch_current 0
  qbind_p2p_pqc_trust_bundle_activation_rejected_total 0
  ```

### Smoke 3 — positive satisfied-height via `--restore-from-snapshot` — BOUNDARY (not run as live release-binary smoke)

Producing this on the release binary requires a pre-existing valid
VM-v0 RocksDB state-store + matching `StateSnapshotMeta` snapshot
artefact set (`<snapshot_dir>/meta.json` + `<snapshot_dir>/state/`
per `crates/qbind-ledger/src/state_snapshot.rs`). The helper
`crates/qbind-ledger/examples/qbind_state_snapshot.rs` requires a
populated `RocksDbAccountState` — which in turn requires a previous
release-binary run with `--execution-profile vm-v0 --data-dir` that
actually committed blocks through consensus. Building such a
snapshot is a separate cross-domain operational artefact and is
outside the Run 058 activation-height evidence scope.

The activation-height **restore path itself** is already pinned
end-to-end at the unit + integration test layer:

- `pqc_trust_activation::tests::bundle_activation_height_satisfied_accepted`
  — `current_height=10, required_height=5` → `Outcome { activated:
  true, … }`.
- `pqc_trust_activation::tests::bundle_activation_height_equal_accepted_inclusive`
  — `current_height=5, required_height=5` → satisfied (inclusive
  boundary).
- `run_057_pqc_trust_bundle_activation_tests::activation_height_satisfied_accepts_bundle`
  — full signed-bundle load with `current_height=10,
  activation_height=5`.
- `run_057_pqc_trust_bundle_activation_tests::activation_height_inclusive_equal_accepts`
  — same with equal values.
- `run_057_pqc_trust_bundle_activation_tests::future_activation_does_not_advance_sequence_persistence`
  — the central invariant (future-activation rejection is
  cycle-clean for a later satisfied bundle at the same sequence).

The binary surface in `crates/qbind-node/src/main.rs` derives
`activation_current_height` exclusively from
`restore_baseline.as_ref().map(|b| b.snapshot_height).unwrap_or(0)`
— this is plain Rust `Option::map(...).unwrap_or(...)` and is the
same single line that the Run 058 negative smokes prove yields `0`
when no snapshot is supplied. The restore-path branch (`Some(b)
=> b.snapshot_height`) is exercised whenever
`--restore-from-snapshot` is honoured, which is the same code path
the B3 restore-from-snapshot suite already exercises end-to-end in
its own evidence (Run 002). Run 058 explicitly documents this as a
boundary per the task's "If not feasible: document boundary
honestly and rely on unit/integration tests for restore-height
path. do not fake restore height." instruction, and does NOT
fabricate a restore height. **No fake snapshot artefact was created
or used.**

### Smoke 4 — negative future-height fresh data dir

- Data dir: `/tmp/run058/data_smoke4_freshfuture` (created fresh,
  empty before smoke).
- Bundle: `/tmp/run058/seq1_actfuture/trust-bundle.json`, signed,
  `sequence=1`, `activation_height=Some(1_000_000)`,
  `fp=04e923cb…cd6c`.
- Exit code: `1`.
- Stderr FATAL (verbatim, in
  `docs/devnet/run_058_smoke_negative_future_fresh.stderr.log`):

  ```
  [binary] FATAL: --p2p-trust-bundle load/validate failed for path=/tmp/run058/seq1_actfuture/trust-bundle.json: trust bundle activation gating: pqc trust-bundle activation height not yet reached (scope=bundle, current_height=0, required_height=1000000); fail closed — bundle is structurally valid and properly signed but has not yet become effective at this committed height. No fallback to --p2p-trusted-root.. No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade). See docs/whitepaper/contradiction.md C4 (signed root distribution).
  ```

- Sequence persistence file: **does NOT exist** after Smoke 4
  (`ls -la /tmp/run058/data_smoke4_freshfuture/` shows the
  directory is empty). This is the central Run 057 invariant: a
  future-activation rejection runs BEFORE sequence persistence is
  touched, so no record is created.
- `[Run040] P2pNodeBuilder` line: **NOT** emitted. The binary exited
  before `P2pNodeBuilder::build()` was reached, so no `Dummy*`
  primitive could be installed even hypothetically and no live
  transport bound.
- `/metrics` excerpt: **not available** — the binary exited via
  `std::process::exit(1)` before the metrics HTTP server bound. This
  is the documented operator-honest tradeoff (the Run 057 metric
  counter movement is pinned by the metrics-render-once test
  `pqc_trust_bundle_activation_metrics_render_once_in_format_metrics`
  and the atomic-increment test
  `pqc_trust_bundle_activation_metrics_start_at_zero_and_increment_atomically`,
  exactly as the Run 057 evidence document states).

### Smoke 5 — negative future-height after persisted `sequence=1`

- Data dir: `/tmp/run058/data_main` (same dir used by Smoke 2; before
  Smoke 5 the persistence file held `highest_sequence=1
  bundle_fingerprint=1b804a67…f8b6
  updated_at_unix_secs=1778657986`).
- Bundle: `/tmp/run058/seq2_actfuture/trust-bundle.json`, signed,
  `sequence=2`, `activation_height=Some(1_000_000)`,
  `fp=427e5178…7a09`.
- Pre-state copy:
  `/tmp/run058/data_main/pqc_trust_bundle_sequence.json.before_smoke5`.
- Exit code: `1`.
- Stderr FATAL (verbatim, in
  `docs/devnet/run_058_smoke_negative_future_after_seq1.stderr.log`):

  ```
  [binary] FATAL: --p2p-trust-bundle load/validate failed for path=/tmp/run058/seq2_actfuture/trust-bundle.json: trust bundle activation gating: pqc trust-bundle activation height not yet reached (scope=bundle, current_height=0, required_height=1000000); fail closed — bundle is structurally valid and properly signed but has not yet become effective at this committed height. No fallback to --p2p-trusted-root.. No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade). See docs/whitepaper/contradiction.md C4 (signed root distribution).
  ```

- Sequence persistence record BEFORE smoke 5:

  ```json
  {"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":1,"bundle_fingerprint":"1b804a6737688def0cbf4e290beb9f11158228016d8c9578fcdc9148c94cf8b6","updated_at_unix_secs":1778657986}
  ```

- Sequence persistence record AFTER smoke 5: identical to BEFORE
  (verified by `diff /tmp/run058/data_main/pqc_trust_bundle_sequence.json.before_smoke5
  /tmp/run058/data_main/pqc_trust_bundle_sequence.json` printing no
  difference; `echo IDENTICAL` ran). `highest_sequence` stayed at
  `1`, `bundle_fingerprint` stayed at `1b804a67…f8b6`,
  `updated_at_unix_secs` stayed at `1778657986`. The activation gate
  rejection ran BEFORE Run 055's `check_and_update_sequence`, so the
  rejected `sequence=2` future-activation bundle did NOT burn the
  higher sequence.
- `[Run040] P2pNodeBuilder` line: **NOT** emitted (binary exited
  before transport bound). No bundle roots from the rejected
  `sequence=2` bundle were merged into the live trust set — the
  trust set on this restart would have been empty, since the
  rejection path never reaches the root-merge step.
- `/metrics` excerpt: **not available** (same operator-honest
  tradeoff as Smoke 4).

### Smoke 6 — positive normal upgrade after rejected future activation

- Data dir: `/tmp/run058/data_main` (same dir; persisted state
  before Smoke 6 is the same `highest_sequence=1
  bundle_fingerprint=1b804a67…f8b6` from Smoke 2, unchanged by
  Smoke 5).
- Bundle: `/tmp/run058/seq2_act0/trust-bundle.json`, signed,
  `sequence=2`, `activation_height=Some(0)`,
  `fp=db25777e…8559`, signing_key_id 8-char prefix `703285f1`.
- Pre-state copy:
  `/tmp/run058/data_main/pqc_trust_bundle_sequence.json.before_smoke6`.
- Exit: binary continued to run consensus and metrics scrape; the
  smoke ended by SIGTERM after the `/metrics` scrape completed.
- Stderr key lines (verbatim, in
  `docs/devnet/run_058_smoke_positive_upgrade_after_rejection.stderr.log`):

  ```
  [binary] Run 057: trust-bundle activation gate satisfied (required_height=Some(0) current_height=Some(0) required_epoch=None current_epoch=None)
  [binary] Run 055: trust-bundle sequence persistence env=devnet chain_id=51424e4444455600 path=/tmp/run058/data_main/pqc_trust_bundle_sequence.json upgraded previous_sequence=1 -> new_sequence=2 fp=db25777e
  [binary] Run 050/051: trust bundle loaded path=/tmp/run058/seq2_act0/trust-bundle.json env=devnet fp=db25777e3751675aef87c5080550ca9aa0b5d63aa854072b953cb6ba089e8559 active_roots=1 revoked_roots=0 sequence=2 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=703285f1..) signing_keys_configured=1. Bundle root IDs: [00f7ccc9..]
  [Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
  ```

- Sequence persistence record AFTER smoke 6 (`cat
  /tmp/run058/data_main/pqc_trust_bundle_sequence.json`):

  ```json
  {"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":2,"bundle_fingerprint":"db25777e3751675aef87c5080550ca9aa0b5d63aa854072b953cb6ba089e8559","updated_at_unix_secs":1778658025}
  ```

  → `highest_sequence` flipped from `1` to `2`, `bundle_fingerprint`
  flipped to `db25777e…8559`, `updated_at_unix_secs` advanced.

- `/metrics` excerpt
  (`docs/devnet/run_058_metrics_positive_upgrade_after_rejection.txt`):

  ```
  qbind_p2p_pqc_trust_bundle_loaded 1
  qbind_p2p_pqc_trust_bundle_active_roots 1
  qbind_p2p_pqc_trust_bundle_sequence 2
  qbind_p2p_pqc_trust_bundle_signature_verified_total 1
  qbind_p2p_pqc_trust_bundle_sequence_highest 2
  qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0
  qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0
  qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0
  qbind_p2p_pqc_trust_bundle_activation_height_required 0
  qbind_p2p_pqc_trust_bundle_activation_height_current 0
  qbind_p2p_pqc_trust_bundle_activation_epoch_required 0
  qbind_p2p_pqc_trust_bundle_activation_epoch_current 0
  qbind_p2p_pqc_trust_bundle_activation_rejected_total 0
  ```

This proves end-to-end that the failed future-activation rejection
in Smoke 5 did NOT poison the persisted sequence state. The
`pqc_trust_bundle_sequence.json` record advanced from `1 → 2`
cleanly under a later validly-signed satisfied-activation
`sequence=2` bundle.

### Smoke 7 — optional epoch declaration negative smoke — BOUNDARY (not run as live release-binary smoke)

The Run 058 helper does not currently expose an
`[activation_epoch_override]` argument (only the Run 057
`[activation_height_override]`). The task explicitly permits
skipping this case if unit / integration tests already prove the
fail-closed behaviour, which is the case:

- `pqc_trust_activation::tests::bundle_activation_epoch_future_rejected_when_epoch_source_present`
  — `current_epoch=10, required_epoch=20` → fail-closed.
- `pqc_trust_activation::tests::bundle_activation_epoch_requires_runtime_source_today`
  — `current_epoch=None, required_epoch=Some(0)` → fail-closed
  (`CurrentEpochUnavailable`). This is the exact path a real-binary
  smoke would exercise on this build, because Run 057 wires
  `current_epoch = None` unconditionally in
  `crates/qbind-node/src/main.rs`.
- `run_057_pqc_trust_bundle_activation_tests::activation_epoch_present_without_current_epoch_refuses`
  — full integration coverage of the same fail-closed path on a
  signed, full-shape DevNet bundle.

Recorded explicitly as remaining-open under the broader **C4 epoch
gating runtime source** boundary (no safe pre-consensus epoch
source exists today, exactly as the Run 057 evidence states).

## Proof rejected future activation did not create/update sequence state

For Smoke 4 (negative on fresh data dir):

- Pre-smoke: `/tmp/run058/data_smoke4_freshfuture/` was created
  empty (`mkdir -p`).
- Post-smoke: `ls -la /tmp/run058/data_smoke4_freshfuture/` shows
  the directory still contains zero files
  (`pqc_trust_bundle_sequence.json` does not exist; only the
  default `.` and `..` entries appear).

For Smoke 5 (negative on data dir already at `sequence=1`):

- Pre-smoke copy: `pqc_trust_bundle_sequence.json.before_smoke5`
  with `highest_sequence=1
  bundle_fingerprint=1b804a6737688def0cbf4e290beb9f11158228016d8c9578fcdc9148c94cf8b6
  updated_at_unix_secs=1778657986`.
- Post-smoke: identical bytes (`diff before vs after` exits 0 with
  no output). `highest_sequence` did NOT advance to `2`. The
  attempted `sequence=2 fp=427e5178…7a09 act=1_000_000` rejection
  did not leak into the persistence record.

## Proof roots were not merged for future activation

For both negative smokes (Smoke 4 and Smoke 5), the binary exited
via `std::process::exit(1)` immediately after the FATAL line, BEFORE
the `[Run040] P2pNodeBuilder` log line was emitted. The
`P2pNodeBuilder` log line is the source-of-truth that the live
transport stack was constructed with `configured_roots=N` and is
emitted by `crates/qbind-net/src/lib.rs::P2pNodeBuilder::build()`
during transport startup; it is gated downstream of bundle-root
merge into `trusted_roots`. Its absence on Smoke 4 and Smoke 5
proves the future-activation bundles' roots were never merged into
the live PQC trust set (this is the same operator-honest signal
Run 056 uses for its negative cases).

The Run 057 source surface in `crates/qbind-node/src/main.rs`
positions the activation gate inside
`TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
and **returns `Err(TrustBundleError::Activation(_))` BEFORE** any
mutation of `trusted_roots`. This is pinned end-to-end by the Run
057 integration `future_activation_does_not_advance_sequence_persistence`
(structurally valid + signed + Run-055-clean future-activation
bundle is rejected, no persistence record is written, and a
subsequent satisfied bundle at the same `sequence` advances the
record cleanly — which is exactly the Smoke 5 → Smoke 6 transition
on the live binary).

## /metrics excerpts where available — exact boundary where not

- **Smoke 2** — `/metrics` reachable, full activation series
  scraped (see Smoke 2 section above).
  `docs/devnet/run_058_metrics_positive_active_now.txt` (471
  lines).
- **Smoke 4** — `/metrics` **NOT reachable**. The binary
  fail-closed-exited (`exit_code=1`) BEFORE the metrics HTTP
  server bound. This is the documented Run 055/Run 056/Run 057
  operator-honest tradeoff (`/metrics` is unavailable on
  fail-closed startup paths; the
  `qbind_p2p_pqc_trust_bundle_activation_rejected_total +1`
  movement is pinned by the Run 057 metrics-render-once test
  `pqc_trust_bundle_activation_metrics_render_once_in_format_metrics`
  and the atomic-increment test
  `pqc_trust_bundle_activation_metrics_start_at_zero_and_increment_atomically`).
- **Smoke 5** — `/metrics` **NOT reachable** (same reason as
  Smoke 4).
- **Smoke 6** — `/metrics` reachable, full activation series
  scraped at the post-upgrade values.
  `docs/devnet/run_058_metrics_positive_upgrade_after_rejection.txt`
  (471 lines).

## No-fallback proof (Run 058)

- **No `--p2p-trusted-root` supplied on any Run 058 smoke.** The
  trust set on every positive smoke was sourced exclusively from
  the signed `--p2p-trust-bundle`; the trust set on every negative
  smoke was never populated at all because the binary exited
  before the transport stack was built.
- **No `Dummy*` primitive used.** Every positive smoke's `[Run040]
  P2pNodeBuilder` log line reports
  `dummy_kem_registered=false dummy_aead_registered=false
  sig_suite_id=100 transport_kem_suite_id=100
  transport_aead_suite_id=101`, proving real ML-DSA-44 + real
  ML-KEM-768 + real ChaCha20-Poly1305. Negative smokes exit
  BEFORE `P2pNodeBuilder::build()` is reached, so no `Dummy*`
  primitive can be installed even hypothetically.
- **No silent downgrade.** Each negative smoke's FATAL line ends
  with the verbatim `No fallback to --p2p-trusted-root on bundle
  failure (production-honest lifecycle must not silently
  downgrade). See docs/whitepaper/contradiction.md C4 (signed
  root distribution).` — and additionally the activation
  error's own `Display` impl ends with `No fallback to
  --p2p-trusted-root.`, so the assertion appears in the stderr
  TWICE per negative smoke (once from the embedded error
  display, once from the binary FATAL prologue).
- **No private-key material in logs.** Every artefact under
  `docs/devnet/run_058_*.{stdout,stderr}.log` and `.txt` was
  grep-audited for `root_sk`, `signing_sk`, `kem_sk`,
  `validator_sk`, `private_key`, `BEGIN PRIVATE KEY` — none
  appear. The helper's terminating line `[devnet_pqc_trust_bundle_helper]
  root_sk and bundle signing_sk were held in memory only; never
  written to disk.` is the only mention of any `_sk` substring
  and is an explicit guarantee statement, not a leak.

**No fabricated metrics**, **no silent regression**, **no protocol
behaviour change**, **no removed tests**, **no DummySig/DummyKem/
DummyAead fallback path introduced or strengthened**, **no
transport-root reuse as bundle-signing authority**, **no classical
signatures introduced** (suite 100 / ML-DSA-44 only on the bundle
layer), and **no leak of `root_sk` / `signing_sk` / `kem_sk` /
validator signer key bytes** were observed in the run.

## Explicit remaining boundaries (NOT done in Run 058)

- **`--restore-from-snapshot` satisfied-height live release-binary
  smoke (Case 3).** Documented as a boundary above and in
  `docs/whitepaper/contradiction.md` Run 058 update; underlying
  code path is pinned by Run 057 unit + integration tests
  (`bundle_activation_height_satisfied_accepted`,
  `bundle_activation_height_equal_accepted_inclusive`,
  `activation_height_satisfied_accepts_bundle`,
  `activation_height_inclusive_equal_accepts`). No fake snapshot
  was created or used.
- **Epoch declaration live release-binary negative smoke (Case
  7).** Documented as a boundary above; underlying code path is
  pinned by Run 057 unit (`bundle_activation_epoch_requires_runtime_source_today`,
  `bundle_activation_epoch_future_rejected_when_epoch_source_present`)
  and integration (`activation_epoch_present_without_current_epoch_refuses`).
- **Epoch gating runtime source.** No safe pre-consensus epoch
  source exists today; bundles that declare `activation_epoch`
  continue to fail closed with `CurrentEpochUnavailable`. This is
  the same item Run 057 carries; Run 058 does not change it.
- **Activation gates on revocation entries.**
  `TrustBundleRevocation` still carries only `effective_from`
  (UNIX seconds) at the validity-window layer; an equivalent
  activation-height / activation-epoch field on revocation
  entries is NOT introduced by Run 058.
- **Per-environment minimum-activation-height policy.** Not
  introduced; remains an open production-operability item under
  C4.
- **MainNet live signed-bundle release-binary smoke with
  production-grade signing key.** Run 058 ran DevNet only.
  Activation-gate semantics are environment-independent at the
  bundle envelope layer (the same `check_bundle_activation`
  function executes on every environment), but a real-binary
  MainNet smoke was deliberately not performed.
- **Operator-facing CA + certificate rotation + signing-key
  rotation playbook.** Helper still mints ephemeral DevNet
  bundle-signing keys in process; production signing remains an
  out-of-process KMS task. Same as Run 056/Run 057 boundary.
- **Production fast-sync / consensus-storage restore.** Out of
  scope for Run 058.
- **C5 remains NOT closed** by Run 058. Run 058 does not touch
  timeout/NewView wire formats, forged-traffic policy, KEMTLS
  wire formats, consensus message wire formats, or any signature/
  verification semantics outside the trust-bundle
  activation-height evidence surface.

**Full C4 remains OPEN.** Run 058 narrows only the live-binary
release-build smoke artifact set for Run 057's
**activation-height** gating path on DevNet.

## Exact immediate next action

Plumb a persisted "last committed epoch" source into the
pre-consensus startup context in `crates/qbind-node/src/main.rs` (in
the same way Run 057 plumbs `restore_baseline.snapshot_height`),
populate `ActivationContext.current_epoch` from it, and then close
the **epoch gating runtime source** remaining-open item under C4 the
same way Run 057+058 closed the height gating path. The bundle
layer's signature and canonical fingerprint already cover
`activation_epoch` (Run 057 invariant); no schema or signing change
is needed when that lands.