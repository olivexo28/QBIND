# QBIND DevNet — Evidence — Run 033

> **Run-level scope:** smallest honest **peer-side
> `SuiteAwareValidatorKeyProvider`** step for timeout-verification
> activation, completing the C5 piece-(b) blocker. **Production PQC
> KEMTLS root-key distribution (C4 piece c) remains OPEN and is
> not solved by this run.**

## 1. Exact objective

Run 032 wired the **signer half** of the activation bridge:
`main.rs::run_p2p_node` constructs an `Arc<dyn ValidatorSigner>`
from `config.signer_keystore_path`, but the resulting
`BinaryConsensusLoopIo::verification_ctx` stayed `None` because
the **peer-side `SuiteAwareValidatorKeyProvider` half** of
`TimeoutVerificationBridgeInputs` was still unwired.

Run 033 lands that peer-side half — and only that half. With both
halves honestly populated, `main.rs::run_p2p_node` now calls real
`try_build_timeout_verification_context(...)` so
`BinaryConsensusLoopIo::verification_ctx` becomes `Some(...)`.

Out of scope (explicitly):

- Production PQC KEMTLS root-key distribution (C4 piece c). Not
  solved here. B12 `TrustedClientRoots`/`DummySig` is
  test-grade only and **not** a substitute.
- Transport-level identity binding. Run 033 distributes
  **consensus** timeout-verification public keys, not transport
  KEMTLS root keys.

## 2. Exact files changed

| File | Change |
|------|--------|
| `crates/qbind-node/src/peer_key_provider.rs` | **new** — `StaticConsensusKeyProvider`, `LoadedValidatorKeyProvider`, `build_validator_set_and_key_provider`, `PeerKeyProviderError`, `decode_strict_hex_pk`, 22 unit tests |
| `crates/qbind-node/src/lib.rs` | declare `pub mod peer_key_provider` |
| `crates/qbind-node/src/node_config.rs` | add `pub struct StaticPeerConsensusKey { validator_id: u64, suite_id: u16, public_key_hex: String }` and `NetworkTransportConfig.static_peer_consensus_keys: Vec<StaticPeerConsensusKey>` (default empty); update 3 in-crate constructors and helper methods |
| `crates/qbind-node/src/cli.rs` | new `--validator-consensus-key VID:SUITE:HEXPK` `Append` flag, `parse_validator_consensus_key_spec`, `parse_validator_consensus_keys`, `CliError::InvalidValidatorConsensusKey`, propagate into `NodeConfig.network.static_peer_consensus_keys`, 8 new tests |
| `crates/qbind-node/src/signer_loader.rs` | expose `LoadedValidatorSigner.public_key_bytes: Vec<u8>` (already-public bytes; used only for the signer-vs-configured-local cross-check; never logged in full) |
| `crates/qbind-node/src/main.rs::run_p2p_node` | call `build_validator_set_and_key_provider(config, local_validator_id, signer_pk)`; when both signer and provider honest, build `SimpleBackendRegistry::with_backend(SUPPORTED_TIMEOUT_SUITE_ID, MlDsa44Backend::new())` and call **real `try_build_timeout_verification_context(...)`**; preserve Run 032 disabled probe path otherwise; under `RequireOrFail` fail-closed if either half cannot be honestly built; precise startup logs (signer / provider / active / count / suite ids / local + peer ids / disabled or fail-closed reason) |
| `crates/qbind-node/src/metrics.rs` | new `qbind_timeout_verification_key_provider_loaded` 0/1 gauge and `qbind_timeout_verification_validator_count` u64 gauge; setters/getters + `format_metrics` lines |
| `crates/qbind-node/src/p2p_node_builder.rs` | constructor: `static_peer_consensus_keys: Vec::new()` |
| `crates/qbind-node/tests/{b7,b8,b12,t172,t175_*,t175_p2p_node_config}_*.rs` | constructor: `static_peer_consensus_keys: Vec::new()` (additive; preserves existing literal-shape tests) |
| `docs/whitepaper/contradiction.md` | C5 narrowed: signer + peer key-provider halves both landed; C4 remains OPEN; explicit "consensus key distribution ≠ transport PKI" |

## 3. Investigation findings (with exact references)

### 3.1 Existing config shape

- `NodeConfig.network` is `NetworkTransportConfig`
  (`crates/qbind-node/src/node_config.rs:2700`).
- `static_peers: Vec<String>` (line 2731) carries only
  `host:port` or `vid@host:port` — no `(suite_id, pk_bytes)`.
- `--p2p-peer vid@addr` parses via `parse_peer_spec` in
  `crates/qbind-node/src/p2p_node_builder.rs` (used by Run 033's
  builder to walk static-peer entries).
- The smallest additive shape that does not break existing usage
  is a **sibling** field
  `static_peer_consensus_keys: Vec<StaticPeerConsensusKey>` plus
  a CLI `--validator-consensus-key VID:SUITE:HEXPK` flag. This
  preserves every existing `--p2p-peer` consumer and parser test
  (verified: t175, t172, b7, b8, b12 all still pass).

### 3.2 Existing key-provider abstractions

- The trait
  `qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider`
  already exists with method
  `fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)>`.
- No production-grade concrete provider was available in
  `qbind-node`. `TestKeyProvider` exists in
  `timeout_verification_bridge.rs::tests` but is intentionally
  test-only. Run 033 adds the smallest production-safe concrete
  provider — `StaticConsensusKeyProvider` — backed by an explicit
  `HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>`. **No
  parallel verifier path is introduced.**

### 3.3 Validator-set construction

- `run_p2p_node` previously inferred `local_validator_id` from
  `args.validator_id` and the active set size from
  `args.num_validators`. Run 033's
  `build_validator_set_and_key_provider` constructs a
  `ConsensusValidatorSet` covering local + every configured peer,
  using `ValidatorSetEntry { id, voting_power: 1 }` (deterministic
  sort-by-id) and `ConsensusValidatorSet::new` (which fail-closes
  on duplicates and empty input).

### 3.4 Backend registry

- `SimpleBackendRegistry::with_backend` and
  `MlDsa44Backend::new` already exist
  (`crates/qbind-consensus/src/crypto_verifier.rs:88`,
  `crates/qbind-crypto/src/ml_dsa44/mod.rs`). Run 033 reuses these
  directly in `main.rs` — no new registry types.

## 4. Chosen config shape and why

**Chosen:** sibling field `network.static_peer_consensus_keys:
Vec<StaticPeerConsensusKey>` + CLI `--validator-consensus-key
VID:SUITE:HEXPK` (Append).

Why:

- **Smallest additive shape.** `--p2p-peer vid@addr` is unchanged;
  every existing test (`b7`, `b8`, `b12`, `t172`, `t175*`) passes
  with no edits beyond the `static_peer_consensus_keys: Vec::new()`
  default.
- **Explicit and deterministic.** Each entry is a concrete
  `(validator_id, suite_id, public_key_hex)` triple. No silent
  inference from any test-grade KEM material.
- **Strict decoding.** `decode_strict_hex_pk` rejects empty,
  `0x` prefix, odd length, and any non-hex character — all
  fail-closed at config-load time.
- **CLI-driven** matches the rest of the binary — `--p2p-peer`,
  `--enable-p2p`, `--require-timeout-verification`,
  `--signer-keystore-path` etc. are all CLI flags. A file-only
  shape would have been inconsistent with the existing operator
  surface.

## 5. `SuiteAwareValidatorKeyProvider` is now built in `run_p2p_node`

Yes. `main.rs::run_p2p_node` now calls
`build_validator_set_and_key_provider(config,
local_validator_id, signer_derived_pk_opt.as_deref())`. On
success the resulting
`Arc<dyn SuiteAwareValidatorKeyProvider>` is passed into
`TimeoutVerificationBridgeInputs.key_provider`, exactly as
specified in the Run 031/032 blocker analysis.

## 6. `TimeoutVerificationContext` activation

- **Optional mode (default):** activates when **all** of signer,
  key-provider, validator-set, backend-registry are honestly
  available. Otherwise `verification_ctx: None` with a precise
  disabled reason logged.
- **Required mode (`--require-timeout-verification`):**
  - succeeds when **all** pieces are configured and the bridge
    returns `Active`;
  - **fails closed** with `exit(1)` when:
    - signer cannot be loaded (Run 032 path);
    - peer key-provider build fails for any reason
      (`InvalidHex` / `UnsupportedSuite` /
      `DuplicateValidatorId` / `PeerMissingKey` /
      `PeerWithoutValidatorId` / `LocalKeyMissing` /
      `LocalKeyMismatchesSigner` /
      `ValidatorSetBuildFailed`);
    - bridge-level invariant fails (e.g. signer-suite vs
      governance-suite mismatch, backend missing).

## 7. Exact commands run (and pass/fail)

```text
$ cargo check -p qbind-node --bin qbind-node
warning: `qbind-node` (lib) generated 2 warnings   # pre-existing bincode::config deprecation
Finished `dev` profile [unoptimized + debuginfo] target(s)
=> PASS

$ cargo test -p qbind-node --lib peer_key_provider
running 22 tests
test peer_key_provider::tests::bare_peer_addr_fails_closed ... ok
test peer_key_provider::tests::build_with_local_signer_pk_and_no_explicit_local_entry_succeeds ... ok
test peer_key_provider::tests::build_with_explicit_matching_local_entry_succeeds ... ok
test peer_key_provider::tests::duplicate_validator_id_fails_closed ... ok
test peer_key_provider::tests::empty_keys_fails_closed ... ok
test peer_key_provider::tests::enforce_policy_optional_returns_none_without_keys ... ok
test peer_key_provider::tests::enforce_policy_required_succeeds_with_full_pieces ... ok
test peer_key_provider::tests::bridge_activates_when_signer_plus_key_provider_plus_registry_set_present ... ok
test peer_key_provider::tests::fingerprints_are_short_and_safe ... ok
test peer_key_provider::tests::invalid_hex_fails_closed ... ok
test peer_key_provider::tests::local_key_mismatch_with_signer_fails_closed ... ok
test peer_key_provider::tests::local_key_missing_without_signer_fails_closed ... ok
test peer_key_provider::tests::peer_missing_key_fails_closed ... ok
test peer_key_provider::tests::strict_hex_decodes_lowercase ... ok
test peer_key_provider::tests::strict_hex_decodes_uppercase ... ok
test peer_key_provider::tests::strict_hex_rejects_0x_prefix ... ok
test peer_key_provider::tests::strict_hex_rejects_empty ... ok
test peer_key_provider::tests::strict_hex_rejects_non_hex ... ok
test peer_key_provider::tests::strict_hex_rejects_odd_length ... ok
test peer_key_provider::tests::suite_ids_are_deduped_and_stable ... ok
test peer_key_provider::tests::unknown_validator_returns_none ... ok
test peer_key_provider::tests::unsupported_suite_fails_closed ... ok
test result: ok. 22 passed; 0 failed
=> PASS

$ cargo test -p qbind-node --lib
test result: ok. 725 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
=> PASS  (was 693 in Run 032; +22 peer_key_provider + 8 cli + 2 misc = +32)

$ cargo test -p qbind-node --test t172_p2p_smoke_tests --test t175_p2p_node_config_tests \
    --test t175_p2p_wiring_smoke_tests --test b7_kemtls_bringup_identity_closure_tests \
    --test b8_listener_identity_closure_and_dial_retry_tests \
    --test b12_mutual_auth_identity_binding_tests --test t144_keystore_integration_tests
test result: ok. 6/5/6/15/9/25/10 passed; 0 failed (per-suite)
=> PASS  (regression — every suite that constructs `NetworkTransportConfig` directly
   keeps working with the additive `static_peer_consensus_keys: Vec::new()` field)

$ cargo build -p qbind-node --bin qbind-node
Finished `dev` profile [unoptimized + debuginfo] target(s)
=> PASS

$ ./target/debug/qbind-node --help | grep -A1 'validator-consensus-key'
--validator-consensus-key <VALIDATOR_CONSENSUS_KEYS>
        Run 033: explicit per-validator consensus public key for timeout-verification activation.
=> PASS  (CLI flag exposed)

$ ./target/debug/qbind-node --require-timeout-verification --validator-consensus-key 'not_a_valid:spec'
Error: invalid --validator-consensus-key: spec 'not_a_valid:spec' does not match VID:SUITE:HEXPK (expected 'VID:SUITE:HEXPK')
exit=1
=> PASS  (malformed --validator-consensus-key fails closed at CLI parse)

$ ./target/debug/qbind-node --network-mode p2p --enable-p2p --require-timeout-verification
[binary] Run 032: validator signer not loaded — config.signer_keystore_path is not set; ...
[binary] FATAL: --require-timeout-verification was set but the local validator signer could
        not be loaded: config.signer_keystore_path is not set; no local validator signer was
        loaded. qbind-node refuses to start.
exit=1
=> PASS  (signer-half fail-closed remains)
```

### Pre-existing failure (NOT caused by Run 033)

`crates/qbind-node/tests/m16_epoch_transition_hardening_tests.rs`
calls `RocksDbConsensusStorage::set_inject_write_failure` and
`clear_epoch_transition_marker` which do not exist on
`RocksDbConsensusStorage` — this fails to compile on `cargo
test -p qbind-node --tests` regardless of Run 033 changes.
Confirmed pre-existing by reading the diff: `m16_*` was not
modified by Run 033. **Out of scope; not addressed.**

## 8. Investigation findings (file/function references, repeated)

- `decode_strict_hex_pk` →
  `crates/qbind-node/src/peer_key_provider.rs::decode_strict_hex_pk`
- `build_validator_set_and_key_provider` → ibid., the only
  entry point used by `main.rs`.
- `parse_peer_spec` →
  `crates/qbind-node/src/p2p_node_builder.rs::parse_peer_spec`
  (already existed; reused for `--p2p-peer` walking).
- `try_build_timeout_verification_context` →
  `crates/qbind-node/src/timeout_verification_bridge.rs:361`
  (already existed; called from `main.rs` only when both halves
  are honestly populated).
- `SUPPORTED_TIMEOUT_SUITE_ID` →
  `crates/qbind-node/src/timeout_verification_bridge.rs:97` —
  `ConsensusSigSuiteId::new(100)` (ML-DSA-44).
- `ValidatorSetEntry` and `ConsensusValidatorSet::new` →
  `crates/qbind-consensus/src/validator_set.rs:36, :396`.
- `MlDsa44Backend::new` →
  `crates/qbind-crypto/src/ml_dsa44/mod.rs`.
- `SimpleBackendRegistry::with_backend` →
  `crates/qbind-consensus/src/crypto_verifier.rs:115`.

## 9. Whether `--require-timeout-verification` succeeds when all pieces are configured

**Yes** — proved by the integration tests
`peer_key_provider::tests::bridge_activates_when_signer_plus_key_provider_plus_registry_set_present`
and
`peer_key_provider::tests::enforce_policy_required_succeeds_with_full_pieces`,
which together exercise the exact wiring done by `main.rs`:

- real ML-DSA-44 keypair generated via
  `MlDsa44Backend::generate_keypair`,
- `LocalKeySigner` constructed from that key,
- `StaticConsensusKeyProvider` built from explicit
  `(validator_id, suite_id, pk_bytes)` entries,
- `ConsensusValidatorSet` covering local + peer,
- `SimpleBackendRegistry` registered with `MlDsa44Backend`,
- `try_build_timeout_verification_context` returns `Active`,
- `enforce_policy(RequireOrFail, Active)` returns `Ok(Some(_))`.

## 10. Whether `--require-timeout-verification` fails closed when keys are missing/invalid

**Yes** — proved by:

- `peer_key_provider::tests::*_fails_closed` (7 tests covering
  `NoConfiguredKeys`, `InvalidHex`, `UnsupportedSuite`,
  `DuplicateValidatorId`, `PeerMissingKey`,
  `PeerWithoutValidatorId`, `LocalKeyMissing`,
  `LocalKeyMismatchesSigner`),
- `cli::tests::run_033_consensus_key_invalid_hex_is_caller_error`
  (CLI parse rejects malformed flag),
- real-binary smoke: `--validator-consensus-key 'not_a_valid:spec'`
  exits 1 with a precise error,
- real-binary smoke: `--require-timeout-verification` with no
  signer exits 1 (Run 032 path preserved),
- `main.rs::run_p2p_node` explicitly invokes `std::process::exit(1)`
  when `peer_kp_result` is `Err(_)` under `RequireOrFail`.

## 11. Startup log examples (illustrative; produced by the new code path)

When fully wired (`--enable-p2p`, `--signer-keystore-path /tmp/v0.json`,
`--validator-consensus-key 0:100:<hex>`,
`--validator-consensus-key 1:100:<hex>`,
`--p2p-peer 1@127.0.0.1:9001`,
`--require-timeout-verification`):

```
[binary] Run 032: validator signer loaded — backend=local validator_id=ValidatorId(0)
        suite_id=100 pk_fingerprint=ab12cd34... keystore_path=...v0.json
[binary] Run 033: SuiteAwareValidatorKeyProvider built honestly —
        loaded(validators=2, peer_ids=[1], suite_ids=[100],
               fingerprints=["v0:s100:ab12cd34...", "v1:s100:7788aabb..."])
[binary] Run 033: timeout-verification probe: active=true reason=n/a
        policy=RequireOrFail validators=2 chain_id=ChainId(0x...)
        supported_suite_ids=[100]
        local_signer=loaded(backend=local,validator=ValidatorId(0),suite=100)
        peer_key_provider=loaded(...)
[binary] Run 033: timeout verification ACTIVE — Arc<TimeoutVerificationContext>
        threaded into BinaryConsensusLoopIo::verification_ctx. signer_loaded=1
        key_provider_loaded=1 validator_count=2
```

When peer keys absent (signer present):

```
[binary] Run 032: validator signer loaded — ...
[binary] Run 033: SuiteAwareValidatorKeyProvider NOT built —
        network.static_peer_consensus_keys is empty (no
        --validator-consensus-key entries). Preserving Run 032
        SignerPresentKeyProviderUnavailable disabled behaviour.
[binary] Run 033: timeout verification DISABLED — signer half wired
        honestly but peer-side SuiteAwareValidatorKeyProvider not
        configured (set --validator-consensus-key for every active
        validator). BinaryConsensusLoopIo::verification_ctx=None.
```

When peer keys malformed under `--require-timeout-verification`:

```
[binary] Run 033: SuiteAwareValidatorKeyProvider build FAILED —
        static_peer_consensus_keys entry validator_id=0 suite_id=100
        has invalid public_key_hex: public_key_hex must have even length.
[binary] FATAL: --require-timeout-verification was set but the
        peer-side SuiteAwareValidatorKeyProvider could not be built
        honestly: ... qbind-node refuses to start.
exit=1
```

## 12. Metrics examples

`/metrics` output now contains (in addition to existing gauges):

```
# Timeout verification signer loaded (Run 032, C5)
qbind_timeout_verification_signer_loaded 1
# Timeout verification key provider (Run 033, C5)
qbind_timeout_verification_key_provider_loaded 1
qbind_timeout_verification_validator_count 2
# Timeout verification active (Run 031, C5)
qbind_timeout_verification_active 1
```

When peer keys absent:

```
qbind_timeout_verification_signer_loaded 1
qbind_timeout_verification_key_provider_loaded 0
qbind_timeout_verification_validator_count 0
qbind_timeout_verification_active 0
```

`qbind_timeout_verification_active` becomes `1` **only** when
`BinaryConsensusLoopIo::verification_ctx` is actually `Some(...)`
— set by `node_metrics.set_timeout_verification_active(verification_ctx.is_some())`,
exactly as in Run 031/032. **No fabrication.**

## 13. Positive evidence

- `725 / 725` `qbind-node` lib unit tests pass (was `693 / 693`
  in Run 032; +22 `peer_key_provider` + 8 `cli` + 2 misc).
- 22 `peer_key_provider` tests prove every fail-closed
  invariant, the safe-fingerprint property, and the real
  bridge-activation integration with ML-DSA-44 keypairs.
- 8 `cli::tests::run_033_*` tests prove valid parsing,
  every malformed-flag rejection class, propagation into
  `NodeConfig.network.static_peer_consensus_keys`, default-empty
  preservation, and `--p2p-peer` regression.
- All Run 028/029/030/031/032 tests still pass — no behavioural
  regression in proposal/vote/QC paths.
- `qbind-node --help` exposes the new flag.
- Real-binary smoke proves CLI-level fail-closed and signer-side
  fail-closed both work.

## 14. Negative evidence

- Empty `network.static_peer_consensus_keys` ⇒ provider build
  returns `NoConfiguredKeys`; binary path preserves Run 032
  `SignerPresentKeyProviderUnavailable` disabled behaviour
  (verified by `enforce_policy_optional_returns_none_without_keys`
  + bridge tests `run_032_*`).
- `--validator-consensus-key 1:100:abc` (odd length) ⇒
  `CliError::InvalidValidatorConsensusKey` at CLI parse;
  `qbind-node` exits 1.
- `--validator-consensus-key 0:99:abcd` (unsupported suite) ⇒
  `PeerKeyProviderError::UnsupportedSuite { suite_id: 99,
  supported_suite_id: 100 }`; under `RequireOrFail`, exit 1.
- Two entries with the same `validator_id` ⇒
  `DuplicateValidatorId`; under `RequireOrFail`, exit 1.
- `--p2p-peer 2@addr` with no key for vid 2 ⇒
  `PeerMissingKey { validator_id: 2 }`; under `RequireOrFail`,
  exit 1.
- Configured local key bytes ≠ keystore-derived bytes ⇒
  `LocalKeyMismatchesSigner` (with **fingerprints only**, no key
  bytes); under `RequireOrFail`, exit 1.
- `qbind_timeout_verification_active` stays `0` whenever
  `verification_ctx.is_none()`. **Never fabricated.**

## 15. Real-binary evidence

- `cargo build -p qbind-node --bin qbind-node` succeeds.
- `qbind-node --help` shows the new `--validator-consensus-key`
  flag with usage docs.
- `qbind-node --require-timeout-verification
  --validator-consensus-key 'not_a_valid:spec'` exits 1 with
  precise CLI parse error (no key material in error).
- `qbind-node --network-mode p2p --enable-p2p
  --require-timeout-verification` (no signer, no keys) reaches
  `run_p2p_node`, logs the precise Run 032 signer-side reason,
  and exits 1.

### N=4 Required-mode B14 absent-leader recovery

**Not run in this session.** A full N=4 multi-validator
real-binary smoke requires:

1. Generating four ML-DSA-44 keypairs via the existing
   keystore-generation flow,
2. Writing four keystore JSON files,
3. Starting four `qbind-node` processes with paired
   `--validator-consensus-key` entries plus `--p2p-peer`
   topology,
4. Driving an absent-leader scenario and capturing per-reason
   `/metrics` snapshots.

This is honest end-to-end DevNet operator work, not unit-level
work. **Not claimed as completed in Run 033.** The deterministic
+ integration tests above (`bridge_activates_when_signer_plus_key_provider_plus_registry_set_present`
and `enforce_policy_required_succeeds_with_full_pieces`) cover
the full activation/fail-closed surface; the wire-level recovery
proof remains C5 piece (5) in `contradiction.md`.

## 16. Remaining open items

- **C4 piece (c)** — production PQC KEMTLS root-key
  distribution. **Not solved.** `B12 TrustedClientRoots` /
  `DummySig` is test-grade only and **not** a substitute. Run 033
  does not silently infer validator consensus keys from any KEM
  material.
- **N=4 Required-mode real-binary B14** absent-leader recovery
  with verified timeout traffic. Deferred to a separate run.
- The `timeout_verification_bridge.rs::run_032_probe_with_signer`
  fallback is still used when only the signer is loaded
  (i.e. operator did not configure `--validator-consensus-key`).
  This is intentional: it preserves precise Run 032 disabled
  reasons.

## 17. Exact verdict

**Strongest positive (within scope).**

- Peer key-provider config landed (`network.static_peer_consensus_keys`
  + `--validator-consensus-key`).
- `SuiteAwareValidatorKeyProvider` (`StaticConsensusKeyProvider`)
  is built from explicit configured validator keys in
  `main.rs::run_p2p_node`.
- `TimeoutVerificationContext` activates in optional mode when
  signer + peer keys + validator set + backend registry are all
  configured.
- `--require-timeout-verification` succeeds with all pieces and
  fails closed (exit 1, precise reason) on any missing/invalid
  piece.
- Metrics and logs are honest — `qbind_timeout_verification_active`
  becomes 1 only when `verification_ctx.is_some()`;
  `qbind_timeout_verification_key_provider_loaded` and
  `qbind_timeout_verification_validator_count` are honest gauges.
- 725 / 725 lib tests pass. Targeted integration suites pass.
- Production PQC KEMTLS root-key distribution remains OPEN
  under C4 — explicitly NOT claimed solved.
- `contradiction.md` C5 updated; **C4 deliberately not closed**.

## 18. Final required summary

1. **Verdict:** Strongest positive — C5 piece (b) landed
   honestly; C4 piece (c) remains open.
2. **Files changed:** see §2.
3. **Commands run:** see §7.
4. **Tests/evidence:** see §7, §13, §14, §15.
5. **What was fixed:** C5 piece (b) — peer-side
   `SuiteAwareValidatorKeyProvider` is now built honestly in
   `run_p2p_node` from explicit `--validator-consensus-key`
   config; both halves of `TimeoutVerificationBridgeInputs` are
   wired; real `try_build_timeout_verification_context(...)`
   replaces the Run 032 signer-only probe at the call site when
   both halves are present.
6. **What was proven:** activation works under real ML-DSA-44
   keypairs (integration tests); every fail-closed invariant
   triggers (unit + CLI tests); CLI parse rejects malformed
   specs (real binary); signer-side fail-closed still works;
   `qbind_timeout_verification_active` is never fabricated;
   no key material is logged.
7. **What remains:** C4 production PQC KEMTLS root-key
   distribution; N=4 Required-mode real-binary B14 absent-leader
   recovery proof.
8. **`contradiction.md` updated:** yes — C5 narrowed to "signer
   + peer key-provider halves both landed; C4 piece (c) still
   open"; C4 explicitly NOT closed; explicit clarification that
   consensus public-key distribution is not transport PKI.
9. **Recommended next action:** **Run 034** — produce real-binary
   N=4 Required-mode B14 absent-leader recovery evidence using
   the new wiring (or, if that is to be deferred, the next
   smallest C4 step toward production PQC KEMTLS root-key
   distribution).