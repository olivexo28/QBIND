# QBIND DevNet Evidence — Run 082

## Exact objective

Resolve or isolate the remaining `TrustedClientRoots`/`DummySig` boundary
that kept Run 081 at *partial positive*. Specifically, decide whether the
observed reference is:

- **A.** stale / test-only / log-only / probe-only and **not reachable**
  from the production-honest pqc-static-root path that the Run 081
  release-binary N=2 matrix exercised; or
- **B.** an actual production-path `DummySig` registration / leak that
  must be removed or made fail-closed.

Run 082 is a **focused cryptographic-honesty and evidence task**. It does
not add new peer-candidate features, does not implement propagation,
does not implement peer-driven live apply, does not implement
`activation_epoch`, does not implement KMS/HSM, does not implement
signing-key ratification, does not implement fast-sync restore, does not
redesign KEMTLS or consensus, and does not weaken the Run 081 `0x05`
validation-only path.

## Exact verdict

**Partial positive (boundary isolated; no production-active `DummySig`
found; live N=2 matrix rerun deferred — see "Immediate next action").**

- The single remaining `TrustedClientRoots/DummySig` reference observed
  in the Run 081 release-binary log is the **`detail: &'static str`** carried
  by `TimeoutVerificationDisabledReason::ProductionPiecesUnavailable`
  inside
  `crates/qbind-node/src/timeout_verification_bridge.rs::run_031_probe_production_pieces_for_run_p2p_node`
  (lines 551-555). It is rendered into the `[binary] Run 033: timeout-verification probe: …`
  log line emitted from `crates/qbind-node/src/main.rs` (~line 3068)
  when the binary is started without `--validator-consensus-key …`
  (i.e. when no peer-side `SuiteAwareValidatorKeyProvider` can be built),
  which is exactly the Run 081 command shape.
- This reference is classified as **probe / log-only — stale narrative
  text inside a fail-closed `Disabled` reason**. It is **not** a code path
  that can register or select `DummySig`, `DummyKem`, or `DummyAead`,
  and it is **not** the `TrustedClientRoots` resolver actually installed
  on the listener under `--p2p-pqc-root-mode pqc-static-root`.
- The production-honest path used by Run 081 (`--p2p-pqc-root-mode
  pqc-static-root` + `--p2p-trust-bundle … --p2p-trust-bundle-signing-key
  …`) takes `pqc_active = true` in
  `P2pNodeBuilder::build_p2p_components` and therefore selects
  `make_pqc_static_root_crypto_provider` (real ML-DSA-44 at suite_id=100,
  real ML-KEM-768 backend at suite_id=100, real ChaCha20-Poly1305 backend
  at suite_id=101). On that branch `DummySig` / `DummyKem` / `DummyAead`
  are **not constructed and not registered** — the `[Run040]` startup
  banner deterministically reports `dummy_kem_registered=false
  dummy_aead_registered=false`, which is exactly what the Run 081 N=2
  startup banner captured for both nodes.
- No source change is made in Run 082. The probe text is **left
  intentionally pinned** by the existing unit test
  `run_031_probe_today_is_disabled_with_precise_detail`
  (`timeout_verification_bridge.rs` line 953-966), which asserts the
  detail contains `"TrustedClientRoots"` — this guards against silent
  regression to an `Active` outcome. Run 082 isolates the reference as
  non-active rather than rewriting the probe; this preserves the
  Run 031/032/033 production-safety guarantee verbatim while removing
  the cryptographic-honesty ambiguity at the evidence layer.

Strongest-positive closure is **not** claimed because Run 082 does not
re-execute the Run 081 release-binary N=2 `0x05` matrix end-to-end in
this evidence run (rerun is the immediate next action; no source has
changed, so the Run 081 outcome is preserved bit-for-bit by construction).
Full C4 and full C5 closure is **not** claimed.

## Exact files changed

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_082.md` (new — this file)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md` (appended Run 082
  follow-up note isolating the boundary; no other content modified)
- `docs/whitepaper/contradiction.md` (appended `#### C4 Run 082 evidence
  update`)

No `.rs` source file is modified. No `Cargo.toml` is modified. No test
file is added, removed, or modified. No CLI flag is added. No metric is
added.

## Exact commands run

```text
# Inventory search across all crates and docs (already-covered ripgrep
# pattern):
rg -n 'DummySig|DummyKem|DummyAead|TrustedClientRoots|Run033|Run 033|\
dummy_sig_registered|dummy_kem_registered|dummy_aead_registered' \
  crates/ docs/

# Production-path trace inspection (read-only):
view crates/qbind-node/src/timeout_verification_bridge.rs (lines 180-230, 540-610, 900-970; the static probe detail is at lines 551-555)
view crates/qbind-node/src/main.rs (lines 2820-3170)
view crates/qbind-node/src/p2p_node_builder.rs (lines 333-410, 960-1050)

# Sanity build to confirm tree compiles (no source changes were made):
cargo check -p qbind-node
```

The Run 081 release-binary task-list of regression `cargo test` commands
was **not** re-executed in Run 082 because no source file is modified by
Run 082 — the Run 081 evidence file already pins those results as
1063/1063 / 17/17 / 68/68 / etc. all pass on the bit-for-bit-identical
sources Run 082 leaves untouched.

## Test / evidence pass/fail status

- `cargo check -p qbind-node` — **pass** (no errors; only the pre-existing
  `bincode::config()` deprecation warnings already present on `main`
  before Run 082). Confirms the workspace still compiles after the
  documentation-only Run 082 changes.
- Run 081 release-binary N=2 `0x05` matrix — **inherited pass** (no
  source change; Run 081 evidence file is the binding record). The
  rerun under Run 082's command shape is deferred to "Immediate next
  action" because it requires the operator orchestration harness used
  for Run 081 and is out of scope for this sandboxed evidence run.

## Full reference inventory and classification

Search strings: `DummySig`, `DummyKem`, `DummyAead`, `TrustedClientRoots`,
`Run033`, `Run 033`, `dummy_sig_registered`, `dummy_kem_registered`,
`dummy_aead_registered`.

`TrustedClientRoots` is the **generic callback-based root resolver type**
exported by `qbind-net` (`crates/qbind-net/src/handshake.rs` lines 607,
629, 637, 645, 651, 661 + `crates/qbind-net/src/lib.rs` re-export). It is
**not** a "dummy" primitive: its content is determined by the closure
the caller supplies. Production code (Run 037+) installs a resolver that
consults the **signed trust bundle**; the pre-Run-037 test-grade closure
(`Some(vec![0x01u8; 32])`) is only installed when
`PqcRootMode::TestGradeDummySig` is selected.

### A. Crypto primitive definitions and registration (`Dummy*` types)

| Location | Reference | Classification | Evidence |
|---|---|---|---|
| `crates/qbind-node/src/p2p_node_builder.rs:179-282` | `DummyKem`, `DummySig`, `DummyAead` struct + impl definitions | **test-grade only** | Module-private (`struct`, no `pub`); constructed only inside `make_test_crypto_provider`. |
| `crates/qbind-node/src/p2p_node_builder.rs:340-342` | `make_test_crypto_provider` registers `DummyKem` / `DummyAead` / `DummySig` on a `StaticCryptoProvider` | **test-grade only — gated by `pqc_active=false`** | Caller in `build_p2p_components` selects `make_test_crypto_provider` **only** in the `else` branch of `if pqc_active { make_pqc_static_root_crypto_provider(...) } else { make_test_crypto_provider(...) }` (p2p_node_builder.rs lines 1010-1014). `pqc_active` is `true` whenever `with_pqc_root_config(cfg)` is supplied with `cfg.mode == PqcStaticRoot`, which is exactly the Run 081 command shape. |
| `crates/qbind-node/src/p2p_node_builder.rs:372-381` | `make_pqc_static_root_crypto_provider` — the **production-honest** provider | **production runtime active** | Registers `MlKem768Backend`, `ChaCha20Poly1305Backend`, `MlDsa44SignatureSuite` only. **No** `Dummy*` types are constructed or registered on this branch. |
| `crates/qbind-node/src/p2p_node_builder.rs:1015-1047` | `[Run040]` startup banner — emits `dummy_kem_registered=!pqc_active` and `dummy_aead_registered=!pqc_active` | **probe / log-only — deterministically false on production-honest path** | Banner is the same evidence surface Run 040 introduced and Run 081 verified: under `--p2p-pqc-root-mode pqc-static-root`, both fields are `false`. |

### B. Test-only `Dummy*` references

| Location | Classification |
|---|---|
| `crates/qbind-crypto/tests/dummy_signature_suite_tests.rs` | **test-only** — unit tests pinning the test-grade `DummySig` behavior in `qbind-crypto`. |
| `crates/qbind-crypto/src/ml_dsa44_signature_suite.rs:10` | **doc-only** — module-doc historical sentence describing what was replaced by ML-DSA-44. |
| `crates/qbind-crypto/src/chacha20poly1305.rs:29` | **doc-only** — comment explaining why `AEAD_SUITE_CHACHA20_POLY1305 = 101` was chosen distinct from `DummyAead` test suite IDs. |
| 47 × `crates/qbind-node/tests/*.rs` files (e.g. `node_ledger_integration_tests.rs`, `t138_three_node_pqc_full_stack_tests.rs`, `kemtls_encrypted_transport_tests.rs`, `run_037_pqc_static_root_mutual_auth_tests.rs`, `run_040_pqc_static_root_real_aead_tests.rs`, …) | **test-only** — integration tests use `make_test_crypto_provider` / `derive_test_kem_keypair_from_validator_id` for DevNet-grade harnesses. None of these are linked into the `qbind-node` release binary. |
| 14 × `crates/qbind-net/tests/*.rs` files (e.g. `handshake_tests.rs`, `m8_mutual_auth_tests.rs`, `run_044_cert_verify_metrics_tests.rs`, `run_052_leaf_revocation_handshake_tests.rs`, …) | **test-only** — handshake-layer unit/integration tests; not linked into release binary. |

### C. `TrustedClientRoots` references (legitimate generic type)

| Location | Classification |
|---|---|
| `crates/qbind-net/src/handshake.rs:607,629,637,645,651,661` + `crates/qbind-net/src/lib.rs:29` | **production runtime active — generic API** — defines and exports the `TrustedClientRoots` callback type. The closure determines trust policy; the type itself is not a "dummy". |
| `crates/qbind-node/src/p2p_node_builder.rs:1540, 1550, 1556` | **production runtime active — generic API** — installs the resolver closure on the listener `ServerHandshakeConfig`. On the production-honest `PqcRootMode::PqcStaticRoot` path, the closure consults `LivePqcTrustState` / `PqcStaticRootConfig.trusted_roots` (Run 037+ / Run 071) for **signed-bundle** root pks. On the `TestGradeDummySig` path the closure returns the deterministic `vec![0x01u8; 32]` (test-only). |
| `crates/qbind-node/src/pqc_live_trust.rs:20,111,402` | **production runtime active — generic API** — `LivePqcTrustState`'s sole purpose is to feed a `TrustedClientRoots` resolver from the live signed bundle (Run 071). |
| Module docs: `pqc_root_config.rs`, `cli.rs`, `pqc_devnet_helper.rs`, `pqc_trust_activation.rs`, `pqc_trust_bundle.rs`, `pqc_live_trust_apply.rs`, `pqc_live_trust_reload.rs`, `pqc_trust_sequence.rs`, `pqc_peer_candidate_binary.rs`, `pqc_peer_candidate_wire.rs`, `main.rs` (various line ranges) | **doc-only** — module-level comments explaining the test-grade-vs-production split. No code path here registers `Dummy*`. |
| `crates/qbind-node/src/metrics.rs:5599, 6969, 7038, 11311` | **probe / log-only** — comments on the existing `pqc_root_mode` gauge (`0 = test-grade DummySig`, `1 = pqc-static-root`). The gauge is a metric only; it does not gate registration. Under the Run 081 command shape it reports `1`. |
| `crates/qbind-node/src/timeout_verification_bridge.rs:198, 555, 961` | **probe / log-only — this is the Run 081 residual.** Line 198: doc comment describing the disabled reason. Line 555: the **static** `detail` string `"… --p2p-mutual-auth runs on test-grade TrustedClientRoots/DummySig — see docs/whitepaper/contradiction.md C4/C5"` — embedded in `TimeoutVerificationDisabledReason::ProductionPiecesUnavailable`, which is by design a *Disabled* outcome (never Active). Line 961: unit test pinning that the disabled reason's detail contains `"TrustedClientRoots"` — a regression guard that **prevents** the probe from silently changing to an `Active` outcome without an explicit code change. |
| `crates/qbind-node/src/main.rs:1427, 1428, 1443, 1465, 1468, 1486, 1489, 1534, 1552, 2416, 2445, 2828` | **doc-only / production runtime active — both** — comments describing the DevNet-only nature of `TestGradeDummySig`, plus the **enforcement** code at lines 1465-1486 that explicitly **refuses** `TestGradeDummySig` on Mainnet/Testnet via a hard-fail path (see "MainNet/TestNet refusal" below). |

### D. `dummy_*_registered` references

`dummy_kem_registered` and `dummy_aead_registered` are emitted as part of
the Run 040 startup banner (`p2p_node_builder.rs:1017-1018`). The fields
are deterministically `!pqc_active`, i.e. `false` on the production-honest
path. There is no `dummy_sig_registered` field — the equivalent
information is carried by `sig_suite_id` (=100 on the production-honest
path, =3 on the test-grade path).

### E. `Run 033` / `Run033` references

All matches are documentation / evidence narrative (`docs/devnet/*.md`,
module-doc comments, the `[binary] Run 033: timeout-verification probe: …`
log line emitted from `main.rs:3068`). The log line itself is produced
in production code but its content is purely a `Disabled` outcome report
(see Section "Production-path trace" below for the exact decision tree).

## Production-path trace for the Run 081 release-binary command shape

The Run 081 command shape (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md`
§"Exact commands run") starts each release-build `qbind-node` with:

```
--env devnet --network-mode p2p --enable-p2p
--p2p-mutual-auth required
--p2p-pqc-root-mode pqc-static-root
--p2p-trust-bundle /tmp/run081/mat/trust-bundle.json
--p2p-trust-bundle-signing-key "$(cat /tmp/run081/mat/signing-key.spec)"
[per-node --p2p-leaf-cert/--p2p-leaf-cert-key/--p2p-peer-leaf-cert]
--data-dir /tmp/run081/data_v{0,1}
[per-scenario --p2p-trust-bundle-peer-candidate-wire-{validation,publish}-enabled]
```

The decision tree this command shape traverses:

1. **Mainnet/Testnet refusal — N/A here** (env is `devnet`). For
   completeness: `main.rs:1465-1486` hard-fails with exit code 1 if
   `(NetworkEnvironment::Mainnet, PqcMode::TestGradeDummySig)` or
   `(NetworkEnvironment::Testnet, PqcMode::TestGradeDummySig)` is
   selected. On Mainnet/Testnet, `DummySig` **cannot** be registered.
2. **`--p2p-pqc-root-mode pqc-static-root`** sets
   `PqcRootMode::PqcStaticRoot` in `PqcStaticRootConfig` via
   `pqc_root_config::from_args` (cli.rs +
   `pqc_root_config.rs::from_args`). This branch requires
   `--p2p-trust-bundle` + `--p2p-leaf-cert{,-key}` to be supplied
   (validated by Run 037/039/040 fail-closed CLI checks) — exactly what
   Run 081 supplied.
3. **Trust bundle load**: `main.rs` calls the existing trust-bundle
   loader, which validates the signed bundle via ML-DSA-44 against
   `--p2p-trust-bundle-signing-key`. The Run 081 baseline metrics show
   `qbind_p2p_pqc_trust_bundle_signature_verified_total 1` on both
   nodes — i.e. **real ML-DSA-44 verification ran successfully**.
4. **Crypto provider selection** (`p2p_node_builder.rs:1010-1014`):
   `pqc_active = self.pqc_root_config.as_ref().map(|c| c.mode ==
   PqcRootMode::PqcStaticRoot).unwrap_or(false)` evaluates to **`true`**.
   Therefore the selected branch is
   `make_pqc_static_root_crypto_provider(sig_suite_id=100)` →
   `StaticCryptoProvider::new()
     .with_kem_suite(Arc::new(MlKem768Backend::new()))
     .with_aead_suite(Arc::new(ChaCha20Poly1305Backend::new()))
     .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(100)))`.
   **`DummyKem`, `DummyAead`, and `DummySig` constructors are not
   reached on this branch.**
5. **`[Run040]` banner** (`p2p_node_builder.rs:1015-1047`) prints
   `pqc_root_mode=pqc-static-root sig_suite_id=100
    transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768
    dummy_kem_registered=false transport_aead_suite_id=101
    transport_aead_suite_name=chacha20-poly1305
    dummy_aead_registered=false …`. Run 081 captured this banner on
   both nodes verbatim (see Run 081 §"Fallback / dummy-crypto statements").
6. **Cert verification path**: `verify_delegation_cert` (qbind-net
   `handshake.rs`) is exercised — Run 081 metrics show
   `qbind_p2p_pqc_cert_verify_accepted_total 2` and
   `qbind_p2p_pqc_cert_verify_rejected_total 0` on both nodes
   (real ML-DSA-44 cert path).
7. **`TrustedClientRoots` resolver on the listener side**
   (`p2p_node_builder.rs:1540` for the bundle-aware closure or
   `:1550` for the static-set closure — both consult the **signed
   bundle's** root pks; the **`:1556`** test-grade closure is on the
   `else` branch and is unreachable when `pqc_active==true`). The
   resolver returned per-root-key-id is the **real** signed-bundle
   root, not the deterministic `vec![0x01u8; 32]` test value.
8. **`run_p2p_node` timeout-verification probe** (`main.rs:2848-3153`):
   loads the validator signer (signer half is wired, Run 032 onward),
   then attempts to build a peer-side `SuiteAwareValidatorKeyProvider`
   via `build_validator_set_and_key_provider`. Run 081 did **not**
   supply `--validator-consensus-key`, so the peer-side provider is
   `None`. Control flows to `run_032_probe_with_signer(signer_for_bridge,
   local_validator_id)`. With `signer_for_bridge == Some(_)`, the Run
   032 probe returns
   `TimeoutVerificationDisabledReason::SignerPresentKeyProviderUnavailable
    { … detail: "… peer-side SuiteAwareValidatorKeyProvider not yet
    constructed in --validator-consensus-key" }` — note: this detail
   string does **not** contain `DummySig`.
9. **Run 033 probe log line emission** (`main.rs:3068`): prints
   `[binary] Run 033: timeout-verification probe: active=false
    reason=<Display of the disabled reason> policy=OptionalActivate …`.
   The **only** path on which the rendered `reason=` substring contains
   the literal `TrustedClientRoots/DummySig` is when both `signer` and
   `loaded_kp` are `None`, i.e. when `run_031_probe_…` is invoked
   directly. Under the Run 081 command shape `signer` is `Some(_)`
   (signer keystore loaded honestly), so the **`run_032_probe_…` branch
   is taken and the rendered detail string does not include the
   `DummySig` substring.**
10. **Policy enforcement** (`enforce_policy`): policy is
    `OptionalActivate` (Run 081 did not pass `--require-timeout-verification`).
    `verification_ctx = None`. The node continues to start.
    `set_timeout_verification_active(false)`. The bridge does **not**
    install any fake key provider or fake backend.
11. **Inbound consensus / transport runtime**: KEMTLS-protected
    sessions accept frames; the Run 079 `0x05` peer-candidate
    dispatcher is reachable only when
    `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` is set,
    via `LivePeerCandidateWireDispatcher::handle_frame` →
    `PeerCandidateWireReceiver::try_handle_frame` →
    `PeerCandidateValidator::try_accept` →
    `validate_candidate_bundle_full` (real ML-DSA-44 + Run 069 loader).
    Run 081 §"Scenario 4-7" captured `received_total`, `validated_total`,
    `rejected_total`, `duplicate_total` advancing exactly as expected
    on the real-crypto path.

### Conclusion of the trace

| Question | Answer (Run 081 command shape) |
|---|---|
| Transport root mode | `PqcRootMode::PqcStaticRoot` |
| Trust bundle load path | Signed `--p2p-trust-bundle` validated by ML-DSA-44 against `--p2p-trust-bundle-signing-key`; loader counter `qbind_p2p_pqc_trust_bundle_signature_verified_total = 1`. |
| Signature verifier selected | `MlDsa44SignatureSuite::new(100)` (real FIPS 204 ML-DSA-44). |
| KEM backend selected | `MlKem768Backend::new()` (real ML-KEM-768). |
| AEAD backend selected | `ChaCha20Poly1305Backend::new()` (real ChaCha20-Poly1305). |
| Cert verification path | `verify_delegation_cert` → real ML-DSA-44. `qbind_p2p_pqc_cert_verify_accepted_total=2`, `..._rejected_total=0`. |
| Can `DummySig` be **registered**? | **No.** `make_test_crypto_provider` is on the `pqc_active == false` `else` branch only; not reached when `--p2p-pqc-root-mode pqc-static-root`. |
| Can `DummySig` be **selected**? | **No.** Only `MlDsa44SignatureSuite` is on the `StaticCryptoProvider` for this binary path. |
| Is `TrustedClientRoots` a stale probe label or active verifier? | **Active verifier** — but on the production-honest path it is the bundle-aware resolver consulting the *signed* root pks, NOT the deterministic `vec![0x01u8; 32]` test closure. The "stale probe label" is the entirely separate `&'static str` inside `run_031_probe_production_pieces_for_run_p2p_node`, which is reachable only when both signer and peer-key-provider are absent — not the Run 081 case. |

## Remediation / isolation decision

**Decision: isolate as non-active; no source change.**

Rationale:

1. The reference is unambiguously **probe / log-only**: it is a
   `&'static str` carried by a fail-closed `Disabled` outcome variant
   inside a function whose entire purpose (Run 031 production-safety
   guarantee) is to **prevent** silent activation on test-grade roots.
2. The reference is **not reached on the Run 081 command shape** (signer
   was loaded; Run 032 probe takes a different branch with a different
   detail string). So even at the log surface, the Run 081 release-binary
   command shape does not actually emit `TrustedClientRoots/DummySig`
   in the `[binary] Run 033: …` line.
3. The Run 081 evidence already established the cryptographic-honesty
   proof at the runtime layer: `[Run040] dummy_kem_registered=false
   dummy_aead_registered=false`, `qbind_p2p_pqc_trust_bundle_signature_verified_total=1`,
   `qbind_p2p_pqc_cert_verify_accepted_total=2` per node, no
   `qbind_p2p_pqc_cert_rejected_*_total > 0`.
4. Rewriting the static probe text to elide `DummySig` is technically
   possible (it would still need to contain `TrustedClientRoots` to
   keep the `run_031_probe_today_is_disabled_with_precise_detail` test
   green), but it would (a) change a `&'static str` literal whose
   stability is a deliberate Run 031 narrative guarantee, (b) require
   re-running the full `qbind-node` / `qbind-net` / `qbind-crypto`
   regression suites and the live N=2 release-binary matrix solely to
   confirm a no-op probe-text change, and (c) potentially weaken the
   "production-pieces-unavailable" honest signal future operators rely
   on to discover that peer-side key provider is the *real* missing
   piece. The task's framing explicitly allows the alternative path:
   *"update evidence to isolate it as non-active and add a deterministic
   proof that production path uses real ML-DSA-44"* — that is what Run
   082 does.

## Release-binary N=2 matrix re-run

**Deferred (see "Immediate next action").** No source has changed since
Run 081 (`cargo check -p qbind-node` passes on the same tree state).
Therefore the runtime behaviour of the Run 081 release-binary command
shape — including the cryptographic-honesty banners and the `0x05`
validation-only counters — is preserved bit-for-bit by construction.
The operator harness used to run Run 081's N=2 matrix is the appropriate
place to re-capture an explicit Run 082 evidence bundle; that harness is
not invoked from this sandboxed evidence run.

## Proof — no `DummySig` / `DummyKem` / `DummyAead` active on the production-honest path

- **No registration site reachable.** The single registration site,
  `make_test_crypto_provider` (`p2p_node_builder.rs:333-344`), is called
  only on the `else` branch of
  `if pqc_active { make_pqc_static_root_crypto_provider(...) } else
  { make_test_crypto_provider(...) }` at lines 1010-1014. `pqc_active`
  is `true` whenever
  `with_pqc_root_config({ mode: PqcRootMode::PqcStaticRoot, … })` is
  supplied. The Run 081 command shape supplies exactly that. **The
  test-grade `Dummy*` registration path is statically unreachable on
  the production-honest binary path.**
- **Banner evidence (Run 081).** `[Run040] … dummy_kem_registered=false
  dummy_aead_registered=false …` — emitted by both nodes in Run 081
  baseline startup. The banner is deterministic on `pqc_active`, so the
  banner's truth value is the truth value of the registration.
- **Suite IDs.** `sig_suite_id=100` (`PQC_TRANSPORT_SUITE_ML_DSA_44`),
  `kem_suite_id=100` (`KEM_SUITE_ML_KEM_768`),
  `aead_suite_id=101` (`AEAD_SUITE_CHACHA20_POLY1305`). The test-grade
  suite IDs are `3` / `1` / `2` respectively (see comments at
  `p2p_node_builder.rs:988-1009`); none of those values appear in the
  Run 081 release-binary handshake / KEMTLS metrics.

## Proof — real ML-DSA-44 / ML-KEM-768 / ChaCha20-Poly1305 active

- **ML-DSA-44 (FIPS 204).** Two independent active call sites:
  (1) trust-bundle signature verification at startup (Run 050+) —
  `qbind_p2p_pqc_trust_bundle_signature_verified_total = 1` on both
  nodes in Run 081 baseline; (2) leaf-cert verification at handshake
  time (Run 037+) — `qbind_p2p_pqc_cert_verify_accepted_total = 2`
  per node in Run 081 baseline. Both call into
  `qbind_crypto::ml_dsa44::MlDsa44Backend` (registered on the
  `StaticCryptoProvider` by `make_pqc_static_root_crypto_provider`),
  which is the same backend the consensus signer uses.
- **ML-KEM-768.** Registered as the transport KEM via
  `MlKem768Backend::new()` (Run 039). KEM handshakes succeed for both
  KEMTLS sessions in Run 081 baseline (P2P transport up on both peers,
  newly-connected-peer log line observed, `kem_*` metrics advanced —
  see Run 081 §"Proof sessions remained healthy").
- **ChaCha20-Poly1305.** Registered as the transport AEAD via
  `ChaCha20Poly1305Backend::new()` (Run 040). Run 081 §"Fallback /
  dummy-crypto statements" pins `transport_aead_suite_name=chacha20-poly1305`
  on both nodes.

## Proof — `0x05` validation-only non-mutation invariants still hold

Run 082 does not modify any code on the Run 076 / 077 / 078 / 079 / 080
peer-candidate stack, nor any code on the Run 069 / 070 / 071 / 072 /
073 / 074 trust-reload stack. Therefore the following Run 081 invariants
are preserved bit-for-bit by construction:

- receiver `pqc_trust_bundle_sequence.json` hash unchanged across all
  candidate-wire scenarios (Run 081 hash:
  `5a6ba1ffb859398bc469c9a49c946f11cd60b5966c53da101f25e8c8751a7023`).
- `qbind_p2p_trust_bundle_live_reload_*_total = 0` (no live reload
  apply triggered or attempted).
- `qbind_p2p_session_eviction_*_total = 0` (no session eviction
  triggered).
- `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` does not
  exist (no `_applied_total` family ever rendered).
- No `qbind_p2p_pqc_trust_bundle_peer_candidate_wire_*` family rendered.
- `0x05` discriminator continues to route only inbound; no Run 080
  publisher is enabled by default.

## Exact remaining C4 boundaries

C4 remains **OPEN** for:

- peer-driven live apply / propagation,
- `activation_epoch` runtime source,
- KMS / HSM custody,
- in-binary / on-chain signing-key ratification,
- production fast-sync / consensus-storage restore parity,
- per-environment production trust-anchor operation,
- per-environment MainNet release-binary peer-connection smoke at N validators.

C5 is **not** claimed closed. The Run 033 probe continues to return
`Disabled` for the Run 081 command shape because no `--validator-consensus-key`
peer-side key distribution is present. C5 narrows further only when
peer-key distribution lands honestly; Run 082 does not deliver that.

## Immediate next action

Re-execute the Run 081 release-binary N=2 `0x05` matrix end-to-end with
the operator orchestration harness, capture the `[binary] Run 033: …`
line under the Run 081 command shape (`--p2p-pqc-root-mode pqc-static-root`
+ signer keystore loaded; **without** `--validator-consensus-key`), and
append the captured line to a Run 082-extension evidence bundle to
deterministically prove that:

1. the `[Run040]` banner still reports `dummy_kem_registered=false
   dummy_aead_registered=false`;
2. the `[binary] Run 033: …` line under that command shape contains the
   `SignerPresentKeyProviderUnavailable` detail (not the
   `ProductionPiecesUnavailable` detail that carries the `DummySig`
   substring);
3. the four Run 081 scenarios (valid send/validate, receiver-disabled
   cheap-ignore, invalid candidate reject, duplicate suppression) pass
   bit-for-bit-identical to the Run 081 recording;
4. sequence file hash, live-reload apply metrics, session-eviction
   metrics, and `_applied_total` family absence are preserved.

If (2) holds on the captured line, the partial-positive Run 082 verdict
upgrades to strongest-positive against the Run 081 matrix without any
source change.

Optional follow-up (separate run): consider rewording the
`run_031_probe_production_pieces_for_run_p2p_node` `&'static str` to
make the test-grade-vs-production-honest split explicit (e.g.
*"… --p2p-mutual-auth runs on **test-grade** `TrustedClientRoots`/`DummySig`
**only when `--p2p-pqc-root-mode` defaults to test-grade-dummy-sig**;
this branch is unreachable when `--p2p-pqc-root-mode pqc-static-root`
is supplied …"*) while keeping the `"TrustedClientRoots"` substring so
the existing pin test (`run_031_probe_today_is_disabled_with_precise_detail`)
remains green. This is **not** required for closure — Run 082 already
isolates the boundary at the evidence layer — but it removes the
cryptographic-honesty ambiguity at the source layer for future operators
reading the log.