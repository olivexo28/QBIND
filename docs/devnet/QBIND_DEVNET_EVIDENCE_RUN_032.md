# QBIND DevNet Evidence — Run 032

**Run:** 032
**Date:** 2026-05-09
**Branch:** `copilot/continue-qbind-l1-development`
**Predecessors:** Runs 028, 029, 030, 031 (binary timeout-verification API,
inbound verification, deterministic loop tests, activation bridge,
fail-closed gate, production probe).

---

## 1. Exact objective

Implement the smallest next production-safe step toward closing C5
(`TimeoutVerificationContext` activation in `run_p2p_node`):

> Wire `config.signer_keystore_path` into `main.rs::run_p2p_node` so the
> **signer half** of `TimeoutVerificationBridgeInputs` can be populated
> honestly.

This run is explicitly **not** about per-peer public-key distribution
(`NodeConfig.network.static_peers`) and is explicitly **not** about
production PQC KEMTLS root-key distribution (C4). It is also explicitly
**not** about activating full timeout verification — `verification_ctx`
remains `None` until the peer key-provider half also lands.

Strict scope as declared by the task framing:

- No HotStuff / B14 / networking / snapshot redesign.
- No classical-crypto assumptions, no bypass of existing PQC verification
  abstractions.
- No clone / log / expose / serialise of private key material.
- No hardcoded fake or test keys as production signer material.
- No silent activation with an incomplete key provider.
- No claim that C4 is closed.
- No claim of N=4 verified-timeout real-binary evidence.

---

## 2. Exact files changed

| File | Change |
|------|--------|
| `crates/qbind-node/src/lib.rs` | Register new `signer_loader` module. |
| `crates/qbind-node/src/signer_loader.rs` | **New module** — `LoadedValidatorSigner`, `SignerBackendKind`, `SignerLoadError`, `load_validator_signer_from_config`, `keystore_entry_for_validator`, `public_key_fingerprint`, `safe_keystore_path_log`. Reuses `FsValidatorKeystore` / `EncryptedFsValidatorKeystore`, `derive_validator_public_key`, `LocalKeySigner`. 11 focused unit tests. |
| `crates/qbind-node/src/timeout_verification_bridge.rs` | New `TimeoutVerificationDisabledReason::SignerPresentKeyProviderUnavailable { local_validator_id, signer_suite_id, detail }`. New `run_032_probe_with_signer(signer, local_validator_id)` — the signer-aware narrowing of the Run 031 probe. 5 new tests. |
| `crates/qbind-node/src/main.rs` (`run_p2p_node`) | Calls `load_validator_signer_from_config(config, local_validator_id)`. Logs safe metadata only. Sets `qbind_timeout_verification_signer_loaded` 0/1. Fails closed under `--require-timeout-verification` when signer load fails. Replaces Run 031 probe site with `run_032_probe_with_signer(...)`; on `OptionalActivate` falls back to `verification_ctx: None` with a precise log line distinguishing "signer half wired" from "signer absent". |
| `crates/qbind-node/src/metrics.rs` | New `qbind_timeout_verification_signer_loaded` 0/1 atomic gauge with `set_timeout_verification_signer_loaded(bool)` / `timeout_verification_signer_loaded() -> u8`. Exposed in `format_metrics`. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md` | This document. |
| `docs/whitepaper/contradiction.md` | C5 narrowed: signer half landed; per-peer key-provider distribution still missing. C4 remains open. |

No other files were modified. No new external dependencies added.

---

## 3. Exact commands run

```
cargo check -p qbind-node --bin qbind-node
cargo test  -p qbind-node --lib signer_loader
cargo test  -p qbind-node --lib timeout_verification_bridge
cargo test  -p qbind-node --lib run030
cargo test  -p qbind-node --lib vm_v0_runtime
cargo test  -p qbind-node --lib test_cli_help
cargo test  -p qbind-node --lib
cargo test  -p qbind-node --test t144_keystore_integration_tests \
                            --test t145_identity_self_check_tests \
                            --test t153_encrypted_keystore_integration_tests
```

---

## 4. Tests run and pass/fail status

| Suite | Pass / Fail | Notes |
|-------|-------------|-------|
| `cargo check -p qbind-node --bin qbind-node` | ✅ clean | Two pre-existing `bincode::config` deprecation warnings only. |
| `signer_loader::tests::*` (Run 032 unit tests) | ✅ **11 / 11** | New focused tests. |
| `timeout_verification_bridge::tests::*` | ✅ **20 / 20** | 15 Run 031 + 5 new Run 032 tests. |
| `binary_consensus_loop::tests::run030::*` | ✅ **20 / 20** | All 20 Run 030 deterministic tests. |
| `vm_v0_runtime::tests::*` | ✅ **9 / 9** | Snapshot-trigger surface (Runs 022/023/025–027) untouched. |
| `cli::tests::test_cli_help_exposes_snapshot_flags` | ✅ **1 / 1** | CLI help contract preserved. |
| `qbind-node` lib (full) | ✅ **693 / 693** | Up from 677 (16 new tests, no regressions). |
| `t144_keystore_integration_tests` | ✅ all green | Plain-FS keystore integration. |
| `t145_identity_self_check_tests` | ✅ **16 / 16** | Identity self-check wiring (we reuse its primitive). |
| `t153_encrypted_keystore_integration_tests` | ✅ **3 / 3** | Encrypted-FS keystore integration. |

No tests were removed, weakened, or skipped.

---

## 5. Investigation findings (file/function references)

### 5.1 Existing keystore loading path

- `crates/qbind-node/src/keystore.rs`:
  - `FsValidatorKeystore::load_signing_key` (`{root}/{entry}.json`,
    suite_id 100 only).
  - `EncryptedFsValidatorKeystore::load_signing_key` (`{root}/{entry}.enc`,
    ChaCha20-Poly1305 + PBKDF2, passphrase from env var).
  - `KeystoreError::{NotFound, Parse, InvalidKey, Config, Io}` — already
    precise, never carries key bytes.
- `crates/qbind-node/src/validator_config.rs`:
  - `make_local_validator_config_from_keystore` and
    `make_local_validator_config_with_identity_check` already exist.
    Run 032 does NOT call them — they require a `consensus_pk` we do
    not have in `NodeConfig` today, and they bundle in `listen_addr`
    which is not what the bridge needs. Instead Run 032 uses the same
    underlying primitives (`FsValidatorKeystore`,
    `EncryptedFsValidatorKeystore`, `derive_validator_public_key`)
    directly through the new `signer_loader` module to produce just
    an `Arc<dyn ValidatorSigner>` plus safe metadata.

### 5.2 Existing identity / suite self-check primitives

- `validator_config::verify_signing_key_matches_identity` —
  derives the public key, compares to the configured one, and pins
  `EXPECTED_SUITE_ID = ConsensusSigSuiteId(100)`.
- `validator_config::derive_validator_public_key` — wraps
  `ValidatorSigningKey::derive_public_key()`. **Used by Run 032** for
  the public-key fingerprint and for the suite cross-check.
- `validator_config::EXPECTED_SUITE_ID` (= 100, ML-DSA-44).

We do not yet have a configured peer pubkey to run the *full*
`verify_signing_key_matches_identity` cross-check against in
`NodeConfig` today (that is the exact peer-side blocker C5 still
calls out). Run 032 still validates the **suite**: if the loaded key
derives under any suite other than 100, the loader returns
`SignerLoadError::UnsupportedSuite`.

### 5.3 Existing signer / signer-mode plumbing

- `crates/qbind-node/src/validator_signer.rs`:
  - `trait ValidatorSigner` (Send + Sync; type-erasable via `Arc<dyn ...>`).
  - `LocalKeySigner` (in-process, `Arc<ValidatorSigningKey>`,
    Debug-redacted).
  - `make_local_validator_signer(identity, signing_key) -> LocalKeySigner`.
- `crates/qbind-node/src/node_config.rs`:
  - `enum SignerMode { LoopbackTesting, EncryptedFsV1, RemoteSigner, HsmPkcs11 }`.
  - `NodeConfig.signer_keystore_path: Option<PathBuf>`.
  - `parse_signer_mode`, `is_production_signer_mode`,
    `validate_signer_mode_for_mainnet/testnet/devnet` already gate
    operator config.
- `crates/qbind-node/src/cli.rs`:
  - `--signer-mode` and `--signer-keystore-path` already plumbed;
    `--require-timeout-verification` already plumbed (Run 031).

Run 032 wires **only** `LocalKeystorePlain` and
`LocalKeystoreEncrypted` paths. `RemoteSigner` and `HsmPkcs11` modes
explicitly return `SignerLoadError::SignerModeNotWiredYet { mode }`
in this run; they are unchanged. This is documented and tested.

### 5.4 Naming convention

The on-disk keystore entry id is derived from the local
`ValidatorId` as `validator-{N}`. This matches:
- the `qbind-remote-signer` example config
  (`keystore_entry_id = "validator42"` style),
- existing `t144_keystore_integration_tests.rs` /
  `t145_identity_self_check_tests.rs` (`"validator1"` style).

This is a binary-path naming convention, not a wire / protocol
change.

---

## 6. Whether signer is now loaded in `run_p2p_node`

**Yes.** `run_p2p_node` now:

1. Reads `config.signer_keystore_path`.
2. Calls `signer_loader::load_validator_signer_from_config(config, local_validator_id)`.
3. On success: holds an `Arc<dyn ValidatorSigner>` ready to feed into
   `TimeoutVerificationBridgeInputs::signer`.
4. On absence: emits a precise log line and continues with no signer.
5. On load failure: emits a precise error log (no key bytes).
6. Sets `qbind_timeout_verification_signer_loaded` to 0 or 1.

---

## 7. Whether `TimeoutVerificationContext` is activated

**No** — and this is intentional and correct.

`run_p2p_node` does **not** call `try_build_timeout_verification_context`
in this run. Instead it calls `run_032_probe_with_signer(signer, local_validator_id)`,
which deliberately returns `Disabled`:

- **Signer absent:** returns
  `ProductionPiecesUnavailable { detail: "...signer_keystore_path...static_peers...TrustedClientRoots...contradiction.md..." }`
  (same honest "no" as the Run 031 probe).
- **Signer present and consistent:** returns the new
  `SignerPresentKeyProviderUnavailable { local_validator_id, signer_suite_id, detail: "...static_peers...contradiction.md C5..." }`.
- **Signer present but `validator_id` or suite mismatched:** returns
  `SignerValidatorIdMismatch` / `SignerSuiteMismatch` (fail-closed
  identity self-check at the bridge layer).

`qbind_timeout_verification_active` therefore remains 0 in this run.

---

## 8. Exact remaining blockers

C5 is **narrower** after Run 032:

1. ~~`main.rs::run_p2p_node` does not load `Arc<dyn ValidatorSigner>`
   from `config.signer_keystore_path`.~~ ✅ **Landed in Run 032.**
2. `NodeConfig.network.static_peers` carries no per-peer
   `(suite_id, pk_bytes)` distribution. A
   `SuiteAwareValidatorKeyProvider` covering the active validator
   set therefore cannot be honestly constructed from current config.
3. Production PQC KEMTLS root-key distribution / per-validator cert
   lifecycle (C4) remains open.

Once (2) lands, the single-site flip remains: replace
`run_032_probe_with_signer(...)` with the real
`try_build_timeout_verification_context(TimeoutVerificationBridgeInputs { ... })`
call passing all five pieces — the signer half this run already wired.

---

## 9. Startup log examples

### 9.1 Default mode (no `--require-timeout-verification`), no keystore configured

```
[binary] Run 032: validator signer not loaded — config.signer_keystore_path is not set; Run 030 bit-equivalent path (no outbound timeout signing). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md.
[binary] Run 032: timeout-verification probe: active=false reason=production pieces unavailable in current qbind-node binary path: qbind-node main.rs does not yet load validator keystore (signer_keystore_path unread on startup), NodeConfig.network.static_peers carries no per-peer (suite_id, pk_bytes), and --p2p-mutual-auth runs on test-grade TrustedClientRoots/DummySig — see docs/whitepaper/contradiction.md C4/C5 policy=OptionalActivate validators=4 chain_id=ChainId(1) supported_suite_ids=[100] local_signer=absent(keystore_path_not_configured)
[binary] Run 032: timeout verification DISABLED — BinaryConsensusLoopIo::verification_ctx=None (Run 030 bit-equivalent path). Inbound timeout/new-view crypto verification and outbound timeout signing remain off until production pieces land. See docs/whitepaper/contradiction.md C5.
```

### 9.2 Default mode, valid keystore configured

```
[binary] Run 032: validator signer loaded — backend=local-keystore-plain validator_id=ValidatorId(0) suite_id=ConsensusSigSuiteId(100) pk_fingerprint=a1b2c3d4... keystore_path=/data/qbind/keystore
[binary] Run 032: timeout-verification probe: active=false reason=signer present (validator ValidatorId(0), suite ConsensusSigSuiteId(100)), peer key-provider unavailable: NodeConfig.network.static_peers carries no per-peer (suite_id, pk_bytes); a SuiteAwareValidatorKeyProvider over the active validator set cannot be honestly constructed from current config — see docs/whitepaper/contradiction.md C5 policy=OptionalActivate validators=4 chain_id=ChainId(1) supported_suite_ids=[100] local_signer=loaded(backend=local-keystore-plain,validator=ValidatorId(0),suite=ConsensusSigSuiteId(100))
[binary] Run 032: timeout verification DISABLED — signer half wired honestly, but BinaryConsensusLoopIo::verification_ctx=None because the peer-side SuiteAwareValidatorKeyProvider over NodeConfig.network.static_peers is still missing. See docs/whitepaper/contradiction.md C5.
```

### 9.3 `--require-timeout-verification` with no keystore configured

```
[binary] Run 032: validator signer not loaded — config.signer_keystore_path is not set; Run 030 bit-equivalent path (no outbound timeout signing). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md.
[binary] FATAL: --require-timeout-verification was set but the local validator signer could not be loaded: config.signer_keystore_path is not set; no local validator signer was loaded. qbind-node refuses to start. See docs/whitepaper/contradiction.md C5 and docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md.
```

(`std::process::exit(1)` follows.)

### 9.4 `--require-timeout-verification` with valid keystore but no peer key-provider

```
[binary] Run 032: validator signer loaded — backend=local-keystore-plain validator_id=ValidatorId(0) suite_id=ConsensusSigSuiteId(100) pk_fingerprint=a1b2c3d4... keystore_path=/data/qbind/keystore
[binary] Run 032: timeout-verification probe: active=false reason=signer present (validator ValidatorId(0), suite ConsensusSigSuiteId(100)), peer key-provider unavailable: NodeConfig.network.static_peers carries no per-peer (suite_id, pk_bytes); a SuiteAwareValidatorKeyProvider over the active validator set cannot be honestly constructed from current config — see docs/whitepaper/contradiction.md C5 policy=RequireOrFail validators=4 chain_id=ChainId(1) supported_suite_ids=[100] local_signer=loaded(...)
[binary] FATAL: --require-timeout-verification was set but timeout verification cannot be activated honestly: timeout verification policy 'RequireOrFail' refused activation: signer present (validator ValidatorId(0), suite ConsensusSigSuiteId(100)), peer key-provider unavailable: NodeConfig.network.static_peers carries no per-peer (suite_id, pk_bytes); a SuiteAwareValidatorKeyProvider over the active validator set cannot be honestly constructed from current config — see docs/whitepaper/contradiction.md C5
[binary] qbind-node refuses to start under RequireOrFail policy with no production-safe context. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_031.md, docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md, and docs/whitepaper/contradiction.md C5/C4.
```

(`std::process::exit(1)` follows.)

---

## 10. Metrics examples

```
# HELP qbind_timeout_verification_active Run 031: 1 = TimeoutVerificationContext threaded into binary loop, 0 = None.
qbind_timeout_verification_active 0

# Timeout verification signer loaded (Run 032, C5)
qbind_timeout_verification_signer_loaded 1
```

The two gauges are intentionally independent. After Run 032:

- A node started with no keystore configured exposes
  `qbind_timeout_verification_signer_loaded 0` and
  `qbind_timeout_verification_active 0`.
- A node started with a valid keystore but no per-peer pubkeys
  exposes `qbind_timeout_verification_signer_loaded 1` and
  `qbind_timeout_verification_active 0` — the precise observable
  signal that the signer half is wired and the peer-side half is the
  remaining blocker.

We deliberately do **not** add an "active=2 / partial" sentinel. An
active timeout verifier either is or is not threaded into the
binary loop.

---

## 11. Positive evidence

- New module `crates/qbind-node/src/signer_loader.rs` (≈700 lines) is
  the **only** call path the binary uses to materialise a signer.
  Every error variant carries operator-visible identifiers (validator
  id, suite id, backend kind, entry name) but **never** key bytes.
  Test `errors_never_carry_key_material` pins this assertion across
  every error variant.
- Test `loaded_signer_signs_correctly` round-trips: loader →
  `Arc<dyn ValidatorSigner>` → `sign_proposal` → `MlDsa44Backend::verify_proposal`.
  This proves the loaded `Arc<dyn ValidatorSigner>` is the same
  shape `TimeoutVerificationBridgeInputs::signer` expects.
- Test `run_032_probe_with_matching_signer_narrows_to_keyprovider_missing`
  pins that the new disabled reason is reachable and that the
  detail string mentions `static_peers` and `contradiction.md`.
- Test `run_032_required_mode_fails_closed_when_only_signer_present`
  pins that `--require-timeout-verification` still fails closed when
  the peer-side blocker remains. (No silent activation.)
- Test `run_032_probe_with_signer_id_mismatch_fails_closed` pins
  the bridge-side signer-identity self-check at the probe site —
  even before peer-side pieces land, a malformed signer is rejected.
- Test `loaded_signer_signs_correctly` also explicitly confirms
  `LocalKeySigner`'s `Debug` impl emits `<redacted>` and never the
  word `private_key`. The new `LoadedValidatorSigner` `Debug` impl
  does the same (only safe metadata, plus literal
  `"<Arc<dyn ValidatorSigner>>"` for the signer field).

## 12. Negative evidence

- We do **not** call `try_build_timeout_verification_context` with
  any fake / empty / placeholder key provider in the binary path.
  The Run 031 probe site (`run_031_probe_production_pieces_for_run_p2p_node`)
  is replaced by `run_032_probe_with_signer`, which is itself a
  pure factory of `TimeoutVerificationActivation::Disabled { ... }`
  outcomes today.
- We do **not** introduce `derive_test_kem_keypair_from_validator_id`,
  `DummySig`, or `TrustedClientRoots` into the production probe site.
- We do **not** clone, log, expose, or serialise private key bytes.
  - The `Arc<ValidatorSigningKey>` lives only inside `LocalKeySigner`.
  - `LoadedValidatorSigner.signer` is `Arc<dyn ValidatorSigner>` — the
    consumer can sign but cannot extract the key.
  - Logs show only: backend kind, validator id, suite id, public-key
    fingerprint, keystore path. The fingerprint is a 4-byte hex
    prefix of the **public** key (already public from the validator
    set).
- We do **not** add `--signer-keystore-entry` or any other new CLI
  surface in this run. The entry name is derived deterministically
  from the local validator id (`validator-{N}`) — matching the
  existing `t144_*` / `t145_*` integration tests and the
  `qbind-remote-signer` example config.
- We do **not** weaken or remove any pre-existing test. Full
  `qbind-node` lib tests grew from 677 → 693 (+16, no regressions).
- We do **not** mark C4 closed.

---

## 13. Remaining open items

1. `NodeConfig.network.static_peers` carries no per-peer
   `(suite_id, pk_bytes)`. Without this the bridge cannot construct a
   real `SuiteAwareValidatorKeyProvider`. **C5 stays open until this
   lands.**
2. Production PQC KEMTLS root-key distribution / per-validator
   cert lifecycle. **C4 stays open.**
3. Once (1) lands, the single site
   (`main.rs::run_p2p_node` Run 032 probe call) flips to a real
   `try_build_timeout_verification_context(...)` call passing the
   already-loaded signer, the new key provider, the existing
   backend registry, the existing validator set, and the existing
   chain id.
4. Once (1)+(2)+(3) all land, an N=4 Required-mode real-binary B14
   absent-leader recovery run can capture per-reason `/metrics`
   snapshots and rejection counters under negative injection. We
   explicitly **do not** claim that evidence today.

---

## 14. Exact verdict

> **Strongest positive (signer half).**
> `run_p2p_node` can load a production-safe validator signer from
> `config.signer_keystore_path`, feeds it into the activation bridge,
> fails closed under `--require-timeout-verification` both when the
> signer cannot be loaded and when the peer-side key-provider remains
> missing, and all targeted tests pass (693 / 693 in `qbind-node` lib
> alone, including 11 new signer_loader tests, 5 new Run 032 bridge
> tests, all 20 Run 030 deterministic tests, all 9 vm_v0_runtime
> snapshot-trigger tests, and the t144 / t145 / t153 keystore
> integration suites). Full timeout verification remains inactive
> only because per-peer public-key distribution
> (`NodeConfig.network.static_peers`) and production PQC KEMTLS
> root-key distribution are still missing — both are out of scope
> for Run 032 by explicit task framing. C5 is narrowed; C4 is
> unchanged.