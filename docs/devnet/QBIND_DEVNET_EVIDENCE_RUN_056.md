# QBIND DevNet Evidence — Run 056: Release-Binary Live Artifacts for Run 055 Trust-Bundle Sequence-Number Monotonicity Persistence

## Exact objective

Run 056 is **evidence-only**. It produces the live release-binary
artifact set for the Run 055 trust-bundle sequence-number
monotonicity persistence layer on the real `qbind-node` release
binary in `pqc-static-root` + signed `--p2p-trust-bundle` mode. The
explicit artifact gap left open in Run 055
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_055.md`, "Explicit remaining
boundaries (NOT done in Run 055)" → "Live release-binary smoke
artefact set for the Run 055 anti-rollback path itself") is the only
target.

The scope is intentionally narrow:

- prove on the live release binary that a fresh-data-dir startup with
  a valid signed DevNet bundle at `sequence=1` is accepted and the
  persistence record is written;
- prove on the live release binary that a subsequent restart with a
  valid signed DevNet bundle at `sequence=2` on the same data dir is
  accepted as an upgrade and the persisted `highest_sequence` is
  updated from `1` to `2`;
- prove on the live release binary that a restart with the
  `sequence=1` bundle after `sequence=2` was accepted fails closed
  with a precise FATAL rollback message before any bundle root is
  merged, and that the persisted record stays at `sequence=2`;
- prove on the live release binary that a restart with the same
  `sequence=2` bundle is accepted as an equal-sequence
  same-fingerprint no-op restart (no record rewrite);
- prove on the live release binary that a restart with a *different*
  validly-signed `sequence=2` bundle (different canonical
  fingerprint) fails closed with a precise FATAL
  equal-sequence-equivocation message and the persisted record stays
  unchanged;
- prove on the live release binary that a restart with a corrupted
  persistence file fails closed with a precise FATAL malformed
  message and the corrupted file is NOT silently deleted, reset, or
  overwritten;
- prove no fallback to `--p2p-trusted-root`, `DummySig`, `DummyKem`,
  or `DummyAead` on any path;
- preserve Run 037 / Run 040 / Run 044 / Run 050 / Run 051 / Run 052 /
  Run 053 / Run 054 / Run 055 behaviour bit-for-bit.

Explicitly out of scope for Run 056 (and listed in
`docs/whitepaper/contradiction.md`):

- activation epoch / height gating for revocation entries and
  root-status windows (only `effective_from` UNIX seconds is honored);
- operator-facing CA + certificate rotation + signing-key rotation
  playbook;
- production fast-sync / consensus-storage restore;
- live MainNet signed-bundle release-binary smoke with a
  production-grade signing key;
- any redesign of KEMTLS, trust bundles, transport, or consensus.

## Exact verdict

**Strongest positive for the scoped Run 056 release-binary
anti-rollback evidence run.** On the live release `qbind-node` binary
(sha256 `69013d1eb30e9c9c5e7bbd5083f2fe8103c94118182002cf779f50b967ef4bce`,
ELF BuildID `9b27c3be718768bda7dcfa1e23c7446b264e105d`) driven from
the live release helper `devnet_pqc_trust_bundle_helper` (sha256
`e4359904c159aaae61bad9e38a17ba8d43a7fc5de12493702010801c412b4ab9`,
ELF BuildID `5e8eb5a99b12ba7efe740d2128af3ba5c818abdd`), every Run 055
sequence-persistence policy case behaved exactly as the Run 055
design promises:

- **Smoke 2 — positive first-load `sequence=1`.** Fresh `--data-dir`,
  signed DevNet bundle `fp=fddb8e40…1494` at `sequence=1`. The
  binary printed `[binary] Run 055: trust-bundle sequence persistence
  env=devnet chain_id=51424e4444455600
  path=/tmp/run056/data/pqc_trust_bundle_sequence.json first-load
  persisted_sequence=1 fp=fddb8e40`, the persistence file appeared
  under the data dir with `{"record_version":1,
  "environment":"devnet", "chain_id":"51424e4444455600",
  "highest_sequence":1, "bundle_fingerprint":"fddb8e40…1494",
  "updated_at_unix_secs":1778606996}`, and `/metrics` reported
  `qbind_p2p_pqc_trust_bundle_sequence_highest 1`,
  `qbind_p2p_pqc_trust_bundle_signature_verified_total 1`,
  `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0`,
  `qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0`,
  `qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0`.
- **Smoke 3 — positive upgrade `sequence=2`.** Same data dir; signed
  DevNet bundle `fp=951df85c…92a9` at `sequence=2`. The binary
  printed `[binary] Run 055: trust-bundle sequence persistence …
  upgraded previous_sequence=1 -> new_sequence=2 fp=951df85c`. The
  persistence file updated to `highest_sequence:2,
  bundle_fingerprint:951df85c…92a9`. `/metrics` reported
  `qbind_p2p_pqc_trust_bundle_sequence_highest 2`,
  `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0`,
  `qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0`,
  `qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0`.
- **Smoke 4 — negative rollback `sequence=1` after `sequence=2`.**
  Same data dir; re-loaded the original `sequence=1` bundle. The
  binary exited `1` with FATAL `pqc trust-bundle sequence rollback
  rejected: attempted_sequence=1 is lower than persisted
  highest_sequence=2 (fail closed; this node has already accepted a
  newer signed bundle for the same trust domain). No fallback to
  --p2p-trusted-root on bundle failure (production-honest lifecycle
  must not silently downgrade or silently reset persistence state).`
  The persistence file was byte-for-byte unchanged at
  `highest_sequence:2, bundle_fingerprint:951df85c…92a9`. `/metrics`
  was not reachable (fail-closed startup); the
  `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`
  counter is observed through the Run 055 unit + integration tests
  (21+12 covered earlier), exactly as Run 055 documented for this
  startup boundary.
- **Smoke 5 — positive equal-sequence same-fingerprint.** Same data
  dir; re-loaded the same `sequence=2` bundle. The binary printed
  `[binary] Run 055: trust-bundle sequence persistence … equal-sequence
  same-fingerprint (no write) sequence=2 fp=951df85c`. The persistence
  file was byte-for-byte unchanged (same JSON, same
  `updated_at_unix_secs=1778607009` — no rewrite). `/metrics`
  reported `qbind_p2p_pqc_trust_bundle_sequence_highest 2` and all
  failure counters at `0`.
- **Smoke 6 — negative equal-sequence different-fingerprint
  (equivocation).** Same data dir; loaded a *second* validly-signed
  DevNet bundle at `sequence=2` (independent ephemeral root +
  signing key + `generated_at`, thus a different canonical
  fingerprint `9a699845…f441`). The binary exited `1` with FATAL
  `pqc trust-bundle equal-sequence equivocation rejected:
  sequence=2 persisted_fingerprint=951df85c…92a9
  attempted_fingerprint=9a699845…f441 (fail closed; two distinct
  bundles cannot share the same sequence). No fallback to
  --p2p-trusted-root on bundle failure …`. The persistence file was
  byte-for-byte unchanged. `/metrics` was not reachable
  (fail-closed startup).
- **Smoke 7 — negative corrupted persistence file.** With the live
  persistence file overwritten by 35 bytes of garbage
  (`this is not valid json {{{\x00\xff broken`), the binary exited
  `1` with FATAL `pqc trust-bundle sequence malformed: expected ident
  at line 1 column 2. No fallback to --p2p-trusted-root on bundle
  failure (production-honest lifecycle must not silently downgrade or
  silently reset persistence state).`. The persistence file's byte
  contents were verified IDENTICAL to the corrupted bytes after the
  binary exited — Run 055's "never silently delete, truncate, or
  reset a corrupted file" guarantee is honoured on the live binary.

On every positive smoke, the Run 040 `[Run040] P2pNodeBuilder` log
line emitted verbatim
`pqc_root_mode=pqc-static-root sig_suite_id=100
transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768
dummy_kem_registered=false transport_aead_suite_id=101
transport_aead_suite_name=chacha20-poly1305
dummy_aead_registered=false configured_roots=1
leaf_credentials_present=true` — proving real ML-DSA-44 + real
ML-KEM-768 + real ChaCha20-Poly1305 on the active cert-verify path
and the absence of `DummySig` / `DummyKem` / `DummyAead`. Every Run
050/051 log line emitted
`signature=verified(signing_key_id=…)` — proving signed-bundle
verification (not unsigned fallback). No `--p2p-trusted-root` was
supplied on any smoke; the trust set was sourced exclusively from
the signed `--p2p-trust-bundle`.

All required regression suites stay green (numbers below). Full C4
remains OPEN for the items listed in the Run 055 evidence document
plus everything Run 056 was explicitly told not to do (activation
epoch / height gating, CA / rotation playbook, MainNet live signed
smoke with production-grade signing key, fast-sync /
consensus-storage restore).

## Exact files changed

| File | Change |
| --- | --- |
| `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` | **Evidence-tooling extension only.** Add an optional 4th positional CLI argument `[sequence_override]` (decimal `u64`). When supplied, the helper overrides the bundle's `sequence` field BEFORE signing (so the signed preimage covers the requested sequence) for the existing signed-bundle modes, and BEFORE returning for the unsigned modes. The bundle's `generated_at` continues to come from `SystemTime::now()`, so two helper invocations seconds apart at the same `sequence` naturally produce different canonical fingerprints (used by Run 056 smoke 6 to mint the equal-sequence different-fingerprint equivocation fixture). The eprintln summary now also reports `bundle_sequence=<N>`. No core library / protocol source touched; the helper is example code that exists explicitly to produce DevNet evidence fixtures, following the Run 051 / Run 054 precedent that extended the same helper for signed-bundle and leaf-revocation fixtures. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_056.md` | This evidence document (new). |
| `docs/devnet/run_056_smoke_*.{stdout,stderr}.log` and `run_056_metrics_*.txt` | Live release-binary smoke logs and `/metrics` excerpts for all six cases. |
| `docs/whitepaper/contradiction.md` | Append "C4 Run 056 evidence update" recording that the live-binary release-build smoke artifact set for Run 055's anti-rollback persistence path (the explicit remaining boundary called out in Run 055) is now closed/narrowed; the still-open C4 pieces are listed explicitly. |

No `crates/**/src/**` files outside the example helper were touched.
No tests were removed or weakened. No `Cargo.toml` changes. No
`--p2p-trusted-root` weakening. No KEMTLS / transport / consensus /
trust-bundle / sequence-persistence library source changes.

## Exact commands run

```bash
# 0) Baseline identity.
git rev-parse HEAD                # d5a6056bd8db8b27677495a4687be08563befaaf
git status --porcelain | wc -l    # 1 (the helper extension only; before evidence-doc edits)

# 1) Build release artefacts.
cargo build --release -p qbind-node \
  --bin qbind-node \
  --example devnet_pqc_trust_bundle_helper \
  --example devnet_pqc_root_helper

# 2) Confirm hidden flag stays hidden, required flags surface.
./target/release/qbind-node --help | grep -c devnet-forged-inject   # 0
./target/release/qbind-node --help | grep -E -- \
  '--p2p-trust-bundle|--p2p-trust-bundle-signing-key|--p2p-pqc-root-mode|\
--p2p-leaf-cert|--p2p-leaf-cert-key|--p2p-peer-leaf-cert|--p2p-mutual-auth|--data-dir'

# 3) Regression test rerun (release profile).
cargo test --release -p qbind-node --lib pqc_trust_sequence
cargo test --release -p qbind-node --lib pqc_trust_bundle
cargo test --release -p qbind-node --lib metrics
cargo test --release -p qbind-node --lib p2p
cargo test --release -p qbind-node --lib
cargo test --release -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests
cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests
cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests
cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests
cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests
cargo test --release -p qbind-net  --test run_052_leaf_revocation_handshake_tests
cargo test --release -p qbind-net  --lib
cargo test --release -p qbind-crypto --lib
cargo check --release -p qbind-node --bin qbind-node

# 4) Mint signed DevNet fixtures (sequence override is the new 4th arg).
./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run056/seq1     1 signed-devnet 1
sleep 2
./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run056/seq2     1 signed-devnet 2
sleep 2
./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run056/seq2_alt 1 signed-devnet 2

# 5) Live release-binary smokes (same --data-dir across smokes 2..7).
DATA_DIR=/tmp/run056/data && mkdir -p "$DATA_DIR"

# Smoke 2: positive first-load sequence=1 (fresh data dir).
SPEC=$(cat /tmp/run056/seq1/signing-key.spec)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9156 ./target/release/qbind-node \
  --env devnet --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle /tmp/run056/seq1/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert /tmp/run056/seq1/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run056/seq1/v0.kem.sk.bin \
  --data-dir "$DATA_DIR" &
sleep 4
curl -s http://127.0.0.1:9156/metrics > docs/devnet/run_056_metrics_seq1_first_load.txt
kill %1; wait

# Smoke 3: positive upgrade sequence=2.
SPEC=$(cat /tmp/run056/seq2/signing-key.spec)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9157 ./target/release/qbind-node \
  ... --p2p-trust-bundle /tmp/run056/seq2/... --data-dir "$DATA_DIR" &
sleep 4; curl -s http://127.0.0.1:9157/metrics > docs/devnet/run_056_metrics_seq2_upgrade.txt
kill %1; wait

# Smoke 4: negative rollback sequence=1 after sequence=2 (re-uses seq1 bundle).
./target/release/qbind-node \
  ... --p2p-trust-bundle /tmp/run056/seq1/trust-bundle.json --data-dir "$DATA_DIR"
# exit_code=1; persistence file byte-for-byte unchanged.

# Smoke 5: positive equal-sequence same-fingerprint (re-uses seq2 bundle).
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9158 ./target/release/qbind-node \
  ... --p2p-trust-bundle /tmp/run056/seq2/trust-bundle.json --data-dir "$DATA_DIR" &
sleep 4; curl -s http://127.0.0.1:9158/metrics > docs/devnet/run_056_metrics_equal_same_fp.txt
kill %1; wait

# Smoke 6: negative equal-sequence different-fingerprint (seq2_alt bundle).
./target/release/qbind-node \
  ... --p2p-trust-bundle /tmp/run056/seq2_alt/trust-bundle.json --data-dir "$DATA_DIR"
# exit_code=1; persistence file byte-for-byte unchanged.

# Smoke 7: negative corrupted persistence file.
cp "$DATA_DIR/pqc_trust_bundle_sequence.json" "$DATA_DIR/pqc_trust_bundle_sequence.json.bak"
printf 'this is not valid json {{{\x00\xff broken' > "$DATA_DIR/pqc_trust_bundle_sequence.json"
./target/release/qbind-node \
  ... --p2p-trust-bundle /tmp/run056/seq2/trust-bundle.json --data-dir "$DATA_DIR"
# exit_code=1; corrupted bytes verified IDENTICAL after exit (not reset).
mv "$DATA_DIR/pqc_trust_bundle_sequence.json.bak" "$DATA_DIR/pqc_trust_bundle_sequence.json"
```

## Tests run and pass/fail status

| Suite | Result |
| --- | --- |
| `cargo test --release -p qbind-node --lib pqc_trust_sequence` | **21 / 21 pass** |
| `cargo test --release -p qbind-node --lib pqc_trust_bundle` | **70 / 70 pass** |
| `cargo test --release -p qbind-node --lib metrics` | **106 / 106 pass** |
| `cargo test --release -p qbind-node --lib p2p` | **138 / 138 pass** |
| `cargo test --release -p qbind-node --lib` (full) | **882 / 882 pass** |
| `cargo test --release -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | **12 / 12 pass** |
| `cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests` | **14 / 14 pass** |
| `cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | **13 / 13 pass** |
| `cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests` | **12 / 12 pass** |
| `cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **12 / 12 pass** |
| `cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **14 / 14 pass** |
| `cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | **10 / 10 pass** |
| `cargo test --release -p qbind-net --test run_052_leaf_revocation_handshake_tests` | **9 / 9 pass** |
| `cargo test --release -p qbind-net --lib` | **17 / 17 pass** |
| `cargo test --release -p qbind-crypto --lib` | **68 / 68 pass** |
| `cargo build --release -p qbind-node --bin qbind-node` | Clean |
| `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper` | Clean |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | Clean |
| `cargo check --release -p qbind-node --bin qbind-node` | Clean (only pre-existing `bincode::config` deprecation warnings unrelated to Run 056) |

`binary_consensus`, `forged_injection`, `run030`, and
`qbind-consensus --lib timeout` were intentionally not rerun because
Run 056 did not modify any source on those paths (only an additive
DevNet example-helper extension was made). The integration test
`m16_epoch_transition_hardening_tests` has a pre-existing
`cargo build --tests` compile error (`set_inject_write_failure` /
`clear_epoch_transition_marker` methods missing on
`RocksDbConsensusStorage`) that is unrelated to Run 056 — Run 056
did not touch `crates/qbind-node/src/storage_rocksdb*` or that test;
the failing test was present on `d5a6056` before Run 056's edits.

## Binary identity

```
git rev-parse HEAD               d5a6056bd8db8b27677495a4687be08563befaaf
git status (during evidence)     1 modified file:
                                   crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs
                                 (additive evidence-tooling extension only)

target/release/qbind-node
  sha256                         69013d1eb30e9c9c5e7bbd5083f2fe8103c94118182002cf779f50b967ef4bce
  ELF Build ID                   9b27c3be718768bda7dcfa1e23c7446b264e105d

target/release/examples/devnet_pqc_trust_bundle_helper
  sha256                         e4359904c159aaae61bad9e38a17ba8d43a7fc5de12493702010801c412b4ab9
  ELF Build ID                   5e8eb5a99b12ba7efe740d2128af3ba5c818abdd

target/release/examples/devnet_pqc_root_helper
  sha256                         f4e6a5e87aeea114b08131651efc1c8f255a6719110a54c9c126248568c6b728
  ELF Build ID                   83b7a7c073c7b8238f8fcf3f53ad6f3ea8dcb7c8

qbind-node --help | grep -c devnet-forged-inject   0   (hidden flag stays hidden)

qbind-node --help surfaces the required flags:
  --p2p-mutual-auth, --p2p-pqc-root-mode, --p2p-leaf-cert,
  --p2p-leaf-cert-key, --p2p-trust-bundle,
  --p2p-trust-bundle-signing-key, --p2p-peer-leaf-cert, --data-dir
```

## Trust-bundle material procedure

All three bundles are minted by the live release helper
`./target/release/examples/devnet_pqc_trust_bundle_helper` using the
existing Run 051 `signed-devnet` mode plus the new Run 056
`[sequence_override]` 4th positional argument. Each invocation mints
a fresh ephemeral ML-DSA-44 root keypair and a fresh ephemeral
ML-DSA-44 bundle-signing keypair entirely in process; **the root
secret key and the bundle-signing secret key are NEVER written to
disk** (helper stderr: "`root_sk and bundle signing_sk were held in
memory only; never written to disk.`"). The KEM secret key for the
issued leaf cert is written `0o600`. No private key material appears
in any Run 056 log artefact.

```
fixture        sequence  root_id (8)  signing_key_id (8)  canonical fingerprint
/tmp/run056/seq1       1  00331027..   722e5f80..          fddb8e408cb793d52d949fec46d50e6ff4bc05d47ba98e2ef55abf6a08c91494
/tmp/run056/seq2       2  d8278773..   5d31257d..          951df85c7a615c615696322b6df54a438107b5fe6afa5eba8b8977c63c6c92a9
/tmp/run056/seq2_alt   2  d338c78e..   de6ba09f..          9a699845ddba237bd953a3b625c96debc08822fac52e2359b77ee8505f7fa441
```

All three bundles are environment = `devnet`, sig suite = `100`
(ML-DSA-44), kem suite = `100` (ML-KEM-768), and validity window
`[0, u64::MAX]`. `seq2` and `seq2_alt` share `sequence=2` but have
distinct ephemeral roots, signing keys, and `generated_at`, hence
distinct canonical fingerprints (required to surface the
equal-sequence equivocation policy).

## Signed-bundle verification proof

Every positive smoke's stderr contains exactly the Run 050/051 log
line `[binary] Run 050/051: trust bundle loaded path=… env=devnet
fp=… active_roots=1 revoked_roots=0 sequence=<N> valid_from=0
valid_until=18446744073709551615 signature=verified(signing_key_id=…)
signing_keys_configured=1.` proving ML-DSA-44 signature verification
on the live release binary, not unsigned fallback:

- seq1 first-load: `signature=verified(signing_key_id=722e5f80..)`
- seq2 upgrade:    `signature=verified(signing_key_id=5d31257d..)`
- equal-same-fp:   `signature=verified(signing_key_id=5d31257d..)`

The two negative paths that reach the sequence layer (rollback and
equivocation) BOTH passed the Run 051 signature verification step
first — the FATAL message they emit names the sequence-layer error
verbatim (`pqc trust-bundle sequence rollback rejected: …` /
`pqc trust-bundle equal-sequence equivocation rejected: …`), and the
corrupt-persistence smoke names the persistence-layer error verbatim
(`pqc trust-bundle sequence malformed: …`). None of the three
negative paths claim a signature-verification failure.

## chain_id compatibility/matching status for bundles used

All three bundles emit `chain_id: null` (the Run 053 legacy
compatibility window, preserved by `build_helper_bundle`). The Run
053 chain-id crosscheck accepts `chain_id: null` and the Run 055
sequence layer persists the record under the RUNTIME chain id, NOT
under `"none"` — exactly as the Run 055 integration test
`null_chain_id_bundle_persists_under_runtime_chain_id` pins. The
runtime chain id for `--env devnet` is `0x51424e4444455600`, and the
persistence file persists `"chain_id":"51424e4444455600"` verbatim
in all three positive cases, confirming end-to-end that the legacy
compatibility window is honoured by the live release binary.

## Sequence persistence file path

```
<data_dir>/pqc_trust_bundle_sequence.json
= /tmp/run056/data/pqc_trust_bundle_sequence.json
```

Matches `qbind_node::pqc_trust_sequence::TRUST_BUNDLE_SEQUENCE_FILENAME`
and `sequence_file_path(data_dir)`. The file is created on the
first-load smoke and never on any other path (negative rollback,
equivocation, and corrupt-persistence smokes all leave the existing
file byte-for-byte unchanged).

## Sequence record contents after first load (smoke 2)

```json
{"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":1,"bundle_fingerprint":"fddb8e408cb793d52d949fec46d50e6ff4bc05d47ba98e2ef55abf6a08c91494","updated_at_unix_secs":1778606996}
```

## Sequence record contents after upgrade (smoke 3)

```json
{"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":2,"bundle_fingerprint":"951df85c7a615c615696322b6df54a438107b5fe6afa5eba8b8977c63c6c92a9","updated_at_unix_secs":1778607009}
```

## Positive first-load sequence 1 smoke (smoke 2)

Files: `docs/devnet/run_056_smoke_seq1_first_load.{stdout,stderr}.log`
and `docs/devnet/run_056_metrics_seq1_first_load.txt`.

Key stderr line (verbatim):

```
[binary] Run 055: trust-bundle sequence persistence env=devnet chain_id=51424e4444455600 path=/tmp/run056/data/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=fddb8e40
[binary] Run 050/051: trust bundle loaded path=/tmp/run056/seq1/trust-bundle.json env=devnet fp=fddb8e408cb793d52d949fec46d50e6ff4bc05d47ba98e2ef55abf6a08c91494 active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=722e5f80..) signing_keys_configured=1. Bundle root IDs: [00331027..]
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
```

`/metrics` excerpt (verbatim, sorted):

```
qbind_p2p_pqc_trust_bundle_active_roots 1
qbind_p2p_pqc_trust_bundle_environment 0
qbind_p2p_pqc_trust_bundle_loaded 1
qbind_p2p_pqc_trust_bundle_sequence 1
qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0
qbind_p2p_pqc_trust_bundle_sequence_highest 1
qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0
qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0
qbind_p2p_pqc_trust_bundle_signature_verified_total 1
```

## Positive upgrade sequence 2 smoke (smoke 3)

Files: `docs/devnet/run_056_smoke_seq2_upgrade.{stdout,stderr}.log`
and `docs/devnet/run_056_metrics_seq2_upgrade.txt`.

Key stderr line (verbatim):

```
[binary] Run 055: trust-bundle sequence persistence env=devnet chain_id=51424e4444455600 path=/tmp/run056/data/pqc_trust_bundle_sequence.json upgraded previous_sequence=1 -> new_sequence=2 fp=951df85c
[binary] Run 050/051: trust bundle loaded path=/tmp/run056/seq2/trust-bundle.json env=devnet fp=951df85c7a615c615696322b6df54a438107b5fe6afa5eba8b8977c63c6c92a9 active_roots=1 revoked_roots=0 sequence=2 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=5d31257d..) signing_keys_configured=1. Bundle root IDs: [d8278773..]
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
```

`/metrics` excerpt (verbatim, sorted):

```
qbind_p2p_pqc_trust_bundle_active_roots 1
qbind_p2p_pqc_trust_bundle_environment 0
qbind_p2p_pqc_trust_bundle_loaded 1
qbind_p2p_pqc_trust_bundle_sequence 2
qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0
qbind_p2p_pqc_trust_bundle_sequence_highest 2
qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0
qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0
qbind_p2p_pqc_trust_bundle_signature_verified_total 1
```

## Negative rollback sequence 1 after sequence 2 smoke (smoke 4)

Files: `docs/devnet/run_056_smoke_rollback_seq1_after_seq2.{stdout,stderr}.log`.

`exit_code = 1` BEFORE any bundle root was merged into the live PQC
trust set, BEFORE the `[Run040] P2pNodeBuilder` line, BEFORE the
consensus loop started.

Verbatim FATAL line:

```
[binary] FATAL: --p2p-trust-bundle sequence anti-rollback check failed for path=/tmp/run056/seq1/trust-bundle.json (sequence persistence file=/tmp/run056/data/pqc_trust_bundle_sequence.json): pqc trust-bundle sequence rollback rejected: attempted_sequence=1 is lower than persisted highest_sequence=2 (fail closed; this node has already accepted a newer signed bundle for the same trust domain). No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade or silently reset persistence state). See docs/whitepaper/contradiction.md C4 (signed root distribution).
```

Persistence record after this smoke (byte-for-byte unchanged from
post-smoke-3):

```json
{"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":2,"bundle_fingerprint":"951df85c7a615c615696322b6df54a438107b5fe6afa5eba8b8977c63c6c92a9","updated_at_unix_secs":1778607009}
```

`/metrics` is not reachable on this smoke (fail-closed startup
before the metrics HTTP server is bound). Run 055 documents this
boundary honestly: the
`qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`
counter is exercised through the Run 055 unit + integration tests
(`pqc_trust_sequence::lower_sequence_is_rejected_as_rollback`,
`run_055_pqc_trust_bundle_sequence_tests::signed_devnet_seq1_rejected_after_seq2`).
Run 056 does not fabricate a `/metrics` excerpt for the rollback
smoke; we rely on the Run 055 test coverage for counter movement.

## Positive equal-sequence same-fingerprint smoke (smoke 5)

Files: `docs/devnet/run_056_smoke_equal_same_fp.{stdout,stderr}.log`
and `docs/devnet/run_056_metrics_equal_same_fp.txt`.

Key stderr line (verbatim):

```
[binary] Run 055: trust-bundle sequence persistence env=devnet chain_id=51424e4444455600 path=/tmp/run056/data/pqc_trust_bundle_sequence.json equal-sequence same-fingerprint (no write) sequence=2 fp=951df85c
```

Persistence record after this smoke (byte-for-byte unchanged
including `updated_at_unix_secs=1778607009`, proving no rewrite):

```json
{"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":2,"bundle_fingerprint":"951df85c7a615c615696322b6df54a438107b5fe6afa5eba8b8977c63c6c92a9","updated_at_unix_secs":1778607009}
```

`/metrics` excerpt (verbatim, sorted):

```
qbind_p2p_pqc_trust_bundle_active_roots 1
qbind_p2p_pqc_trust_bundle_environment 0
qbind_p2p_pqc_trust_bundle_loaded 1
qbind_p2p_pqc_trust_bundle_sequence 2
qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0
qbind_p2p_pqc_trust_bundle_sequence_highest 2
qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0
qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0
qbind_p2p_pqc_trust_bundle_signature_verified_total 1
```

## Negative equal-sequence different-fingerprint smoke (smoke 6)

Files: `docs/devnet/run_056_smoke_equivocation.{stdout,stderr}.log`.

`exit_code = 1` BEFORE any bundle root was merged into the live PQC
trust set.

Verbatim FATAL line:

```
[binary] FATAL: --p2p-trust-bundle sequence anti-rollback check failed for path=/tmp/run056/seq2_alt/trust-bundle.json (sequence persistence file=/tmp/run056/data/pqc_trust_bundle_sequence.json): pqc trust-bundle equal-sequence equivocation rejected: sequence=2 persisted_fingerprint=951df85c7a615c615696322b6df54a438107b5fe6afa5eba8b8977c63c6c92a9 attempted_fingerprint=9a699845ddba237bd953a3b625c96debc08822fac52e2359b77ee8505f7fa441 (fail closed; two distinct bundles cannot share the same sequence). No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade or silently reset persistence state). See docs/whitepaper/contradiction.md C4 (signed root distribution).
```

The FATAL message names BOTH the `persisted_fingerprint` and the
`attempted_fingerprint` (operator forensics), exactly as the Run 055
unit test
`equivocation_detail_carries_both_fingerprints` pins.

Persistence record after this smoke (byte-for-byte unchanged):

```json
{"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":2,"bundle_fingerprint":"951df85c7a615c615696322b6df54a438107b5fe6afa5eba8b8977c63c6c92a9","updated_at_unix_secs":1778607009}
```

`/metrics` is not reachable on this smoke (fail-closed startup
before the metrics HTTP server is bound). The
`qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total`
counter movement is observed through the Run 055 unit + integration
tests (`pqc_trust_sequence::equal_sequence_different_fingerprint_is_rejected`,
`run_055_pqc_trust_bundle_sequence_tests::equal_sequence_different_fingerprint_rejected_as_equivocation`).
Run 056 does not fabricate a `/metrics` excerpt for this smoke.

## Negative corrupted sequence-file smoke (smoke 7)

Files: `docs/devnet/run_056_smoke_corrupt_persistence.{stdout,stderr}.log`.

Corruption procedure: overwrote `<data_dir>/pqc_trust_bundle_sequence.json`
with 35 bytes of garbage (`this is not valid json {{{\x00\xff broken`)
after backing it up.

`exit_code = 1` BEFORE any bundle root was merged.

Verbatim FATAL line:

```
[binary] FATAL: --p2p-trust-bundle sequence anti-rollback check failed for path=/tmp/run056/seq2/trust-bundle.json (sequence persistence file=/tmp/run056/data/pqc_trust_bundle_sequence.json): pqc trust-bundle sequence malformed: expected ident at line 1 column 2. No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade or silently reset persistence state). See docs/whitepaper/contradiction.md C4 (signed root distribution).
```

File state after this smoke (`xxd | head -2`), verified
byte-for-byte IDENTICAL to the corrupted input — Run 055's
"never silently delete, truncate, or reset a corrupted file"
guarantee is honoured on the live release binary:

```
00000000: 7468 6973 2069 7320 6e6f 7420 7661 6c69  this is not vali
00000010: 6420 6a73 6f6e 207b 7b7b 00ff 2062 726f  d json {{{.. bro
```

After the smoke, the operator-restored backup was moved back into
place so the data dir is again at the post-smoke-3 state.

`/metrics` is not reachable on this smoke (fail-closed startup).
The
`qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total`
counter movement is observed through the Run 055 unit + integration
tests (`pqc_trust_sequence::load_record_rejects_malformed_json`,
`run_055_pqc_trust_bundle_sequence_tests::corrupt_persistence_file_fails_closed_no_silent_reset`).

## /metrics excerpts where available

`/metrics` was successfully scraped on the three positive smokes
(2, 3, 5) where the binary stayed alive long enough to bind the
metrics HTTP server. Excerpts are reproduced inline above and the
raw scrapes live in `docs/devnet/run_056_metrics_*.txt`.

## Exact boundary if fail-closed startup prevents metric scraping

Smokes 4 (rollback), 6 (equivocation), and 7 (corrupt persistence)
all fail closed BEFORE the metrics HTTP server is bound. This
matches the Run 055 "in the binary's fail-closed startup path the
process exits before `/metrics` is scraped, so the
rollback/equivocation/persist-failure counters are primarily
observed today through unit + integration tests" boundary, recorded
honestly in Run 055 rather than fabricated. Run 056 does not invent
a `/metrics` reading for these three smokes; the counter movement
remains pinned by the Run 055 unit + integration tests
(`cargo test -p qbind-node --lib pqc_trust_sequence` 21/21 +
`--test run_055_pqc_trust_bundle_sequence_tests` 12/12 +
`--lib metrics` 106/106).

## Proof no fallback to --p2p-trusted-root

- No `--p2p-trusted-root` was supplied on any Run 056 smoke (verifiable
  by inspecting any `run_056_smoke_*.stderr.log` — the stdout banner
  line lists `peer_kem_overrides=0` and there is no static-root parse
  log).
- The Run 055 wiring in `crates/qbind-node/src/main.rs` keys the
  sequence check off the LOADED TRUST BUNDLE's `sequence` and
  canonical `fingerprint`, NOT off `--p2p-trusted-root` (Run 055
  invariant, preserved by Run 056 — no `main.rs` edits).
- On all three negative paths (smokes 4, 6, 7), the FATAL line
  explicitly ends with `No fallback to --p2p-trusted-root on bundle
  failure (production-honest lifecycle must not silently downgrade or
  silently reset persistence state).` and `exit_code = 1` — the
  binary never installed `--p2p-trusted-root` as a substitute trust
  source.
- Smokes 4, 6, 7 all exit BEFORE the `[Run040] P2pNodeBuilder` line
  (no `configured_roots=…` line is printed); the live PQC trust set
  was never populated from any source on those paths.

## Proof no DummySig/DummyKem/DummyAead fallback

All three positive smokes' stderr contain exactly the verbatim line:

```
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
```

Verbatim `dummy_kem_registered=false` and
`dummy_aead_registered=false`. `sig_suite_id=100` is ML-DSA-44,
`transport_kem_suite_id=100` is ML-KEM-768,
`transport_aead_suite_id=101` is ChaCha20-Poly1305. The negative
smokes exit BEFORE this line is reached — they never reach
`P2pNodeBuilder` at all, so no `Dummy*` primitive can be installed
even if the wiring were to attempt to fall back (and Run 037 / Run
040 invariants prove the wiring does not).

## Remaining open items (NOT done in Run 056)

Run 056 inherits, unchanged, every Run 055 remaining-open item and
adds nothing new:

- Activation `epoch` / `height` gating for revocation entries and
  root-status windows (only `effective_from` UNIX seconds is
  honoured).
- Operator-facing CA + certificate rotation + signing-key rotation
  playbook (the helper still mints ephemeral DevNet bundle-signing
  keys in process; production signing remains an out-of-process KMS
  task).
- Production fast-sync / consensus-storage restore.
- Live MainNet signed-bundle release-binary smoke with a
  production-grade signing key. Run 056 ran DevNet only, exactly as
  the task said ("Do not implement MainNet live smoke unless trivial
  and non-distracting").
- A startup self-check in `qbind-node/src/main.rs` that fails the
  binary closed when `--p2p-leaf-cert` matches an active entry in
  the loaded bundle's `revoked_leaf_fingerprints` (Run 052 / Run 054
  boundary; still open).
- An optional "wrong-domain persistence" smoke that manually alters
  the persisted record's `environment` or `chain_id` and restarts.
  Run 056 deliberately did not perform this smoke — it is already
  pinned by two Run 055 tests
  (`pqc_trust_sequence::wrong_environment_in_record_fails_closed`,
  `pqc_trust_sequence::wrong_chain_id_in_record_fails_closed`,
  `run_055_pqc_trust_bundle_sequence_tests::stray_mainnet_record_blocks_devnet_load_fail_closed`)
  and the Run 056 task explicitly states "do not block Run 056 on
  this if unit/integration tests already prove it."

**C5 remains NOT closed** by Run 056; Run 056 does not touch
timeout/NewView wire formats, forged-traffic policy, KEMTLS wire
formats, consensus message wire formats, or any signature /
verification semantics outside the trust-bundle sequence-persistence
evidence surface. **Full C4 remains OPEN.**

## Exact immediate next action

Run 057 candidate (operator playbook / activation-gating):
introduce activation `epoch` / `height` gating for revocation
entries and root-status windows, narrowing the longest-standing
remaining-open C4 item that the current `effective_from` UNIX-seconds
shape does not cover. Strictly evidence-and-design first — no
broad redesign of the trust-bundle envelope.