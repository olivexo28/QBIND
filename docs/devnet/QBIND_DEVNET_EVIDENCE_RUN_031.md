# QBIND DevNet Evidence — Run 031

**Status:** PARTIAL POSITIVE  
**Run date:** 2026-05-09  
**Predecessor runs:** Run 028 (engine-level timeout verification primitives), Run 029 (signed-evidence-carrying `TimeoutCertificate`), Run 030 (binary-loop API + 20 deterministic positive/negative tests).

---

## 1. Exact objective

> Implement the smallest production-safe activation bridge for
> `TimeoutVerificationContext` in the real `qbind-node` binary path,
> or document the exact missing dependency if it cannot be wired
> honestly.

Strictly: do not redesign HotStuff / B14 / networking / snapshot,
do not introduce classical crypto assumptions, do not bypass PQC
verification abstractions, do not introduce a parallel crypto path,
do not hardcode fake production keys into `main.rs`, do not silently
activate verification with dummy roots or test-only key providers
in production mode, do not silently accept unsigned / malformed /
wrong-suite / unknown-validator / bad-signature timeout traffic.

## 2. Binary identity

No release binary was rebuilt for this run. The Run 031 changes are
purely a deterministic activation-bridge module + a single
fail-closed call site in `main.rs::run_p2p_node`, exercised under
`cargo test`. No N=4 real-binary verified-timeout evidence was
produced because the production probe honestly returns
`Disabled { ProductionPiecesUnavailable { ... } }` — see §6 and §10.

## 3. Exact files changed

| File | Purpose |
|---|---|
| `crates/qbind-node/src/timeout_verification_bridge.rs` | **New.** Smallest honest activation bridge: `TimeoutVerificationBridgeInputs`, `TimeoutVerificationActivation`, `TimeoutVerificationDisabledReason`, `TimeoutVerificationPolicy`, `try_build_timeout_verification_context`, `enforce_policy`, `run_031_probe_production_pieces_for_run_p2p_node`. 15 unit tests covering positive build (with and without signer), every fail-closed class, and every policy × outcome combination. |
| `crates/qbind-node/src/lib.rs` | Register `pub mod timeout_verification_bridge`. |
| `crates/qbind-node/src/cli.rs` | Add `--require-timeout-verification` (`bool`, default `false`). When set, drives `TimeoutVerificationPolicy::RequireOrFail` in `run_p2p_node`. |
| `crates/qbind-node/src/main.rs` (`run_p2p_node`) | Replace `verification_ctx: None` with: probe → policy → log → metric → fail-closed exit when required. No silent fallback to test-grade keys. |
| `crates/qbind-node/src/metrics.rs` | Add `qbind_timeout_verification_active` 0/1 gauge with `set_timeout_verification_active(bool)` setter and `/metrics` exposition. Mirrors the existing `qbind_mainnet_profile_invariants_ok` pattern. |
| `docs/whitepaper/contradiction.md` | C5 narrowed once more: confirm Run 031 inspected the binary path, confirm the precise blocker is keystore loading + per-peer pubkey distribution + production PQC PKI, confirm the safety story (no silent activation on test-grade roots). C5 remains **OPEN**. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_031.md` | This file. |

No code in `qbind-consensus`, `qbind-crypto`, `qbind-net`, `qbind-types`,
or `qbind-runtime` was touched. The bridge composes existing public
abstractions only.

## 4. Exact commands run

```
cargo check -p qbind-node --bin qbind-node --tests
cargo test  -p qbind-node --lib timeout_verification_bridge
cargo test  -p qbind-node --lib run030
cargo test  -p qbind-node --lib
cargo test  -p qbind-consensus --lib
cargo test  -p qbind-node --test b3_snapshot_restore_tests \
                          --test b5_restore_aware_consensus_start_tests \
                          --test b9_late_peer_connect_proposal_reemit_tests \
                          --test b10_engine_acceptance_qc_closure_tests \
                          --test b11_consensus_net_prometheus_coverage_tests \
                          --test t146_timeout_view_change_tests
```

`cargo check -p qbind-node --bin qbind-node` reports clean (only
the two pre-existing `bincode::config` deprecation warnings landed
before Run 031). The pre-existing test-only compilation errors in
`crates/qbind-node/tests/m16_epoch_transition_hardening_tests.rs`
(`set_inject_write_failure` / `clear_epoch_transition_marker`) are
**not** caused by Run 031 — they reference methods that do not
exist on `RocksDbConsensusStorage` independent of any bridge change,
and the failing test crate is unrelated to the timeout-verification
surface.

## 5. Tests run and pass/fail status

| Suite | Result |
|---|---|
| `qbind-node` lib (`timeout_verification_bridge::tests::*`) | **15 passed / 0 failed** (new) |
| `qbind-node` lib (`binary_consensus_loop::tests::run030::*`) | **20 passed / 0 failed** (Run 030 deterministic surface preserved) |
| `qbind-node` lib (full) | **677 passed / 0 failed** (was 662 before Run 031; +15 new bridge tests, all other tests unchanged) |
| `qbind-consensus` lib (full, includes Run 028/029 `timeout_verify::tests::*` and `timeout::tests::*`) | **150 passed / 0 failed** |
| `b3_snapshot_restore_tests` | 5/5 |
| `b5_restore_aware_consensus_start_tests` | 5/5 |
| `b9_late_peer_connect_proposal_reemit_tests` | 10/10 |
| `b10_engine_acceptance_qc_closure_tests` | 4/4 |
| `b11_consensus_net_prometheus_coverage_tests` | 6/6 |
| `t146_timeout_view_change_tests` | 15/15 |
| **Total Run 031 evidence** | **907 passed / 0 failed** |

## 6. Investigation findings (Required investigation §1–§5)

### §1 Validator key sources in `run_p2p_node`

`run_p2p_node` (`crates/qbind-node/src/main.rs:369-619`) currently obtains:

| Piece | Source today | Production-safe? |
|---|---|---|
| Active validator set | Inferred from `config.network.static_peers.len() + 1`; never built into a real `ConsensusValidatorSet` here | **No.** Test-grade `NodeValidatorConfig::build_consensus_validator_set_for_tests` (`crates/qbind-node/src/validator_config.rs:380-401`) is the only constructor, and `run_p2p_node` does not call it. |
| Validator IDs | Local: `args.validator_id.unwrap_or(0)`; remote: implicit from `static_peers` order in `P2pNodeBuilder::build` (`crates/qbind-node/src/p2p_node_builder.rs:643-665, 691-770`). Remote `ValidatorId`s for peers are derived deterministically through the **test-grade** `derive_test_kem_keypair_from_validator_id` / `parse_test_validator_id_from_cert_validator_id` path (`p2p_node_builder.rs:369-485`). | **No.** Explicitly test-grade by name. |
| Validator public keys | Not present in `NodeConfig`. `NodeConfig.network.static_peers: Vec<String>` (`crates/qbind-node/src/node_config.rs:2683`) carries only `host:port`. | **No source.** |
| Suite IDs | Not present in `NodeConfig`. The protocol's canonical suite is `qbind_crypto::SUITE_PQ_RESERVED_1` = `ConsensusSigSuiteId::new(100)` (`crates/qbind-crypto/src/suite_catalog.rs:39`), but no peer-suite distribution mechanism exists in the binary path. | **No source.** |
| Local validator signing key / signer | `config.signer_keystore_path: Option<PathBuf>` (`node_config.rs:3734`) flows through CLI (`cli.rs:377-378, 938-946`) but `main.rs` **never reads it** to produce an `Arc<ValidatorSigningKey>`. There is no call site to `make_local_validator_config_from_keystore` (`crates/qbind-node/src/validator_config.rs`) or `make_local_validator_signer` (`crates/qbind-node/src/validator_signer.rs:346-355`). | **No.** |
| Chain ID | `config.chain_id()` (`node_config.rs:5215`) returns the canonical `ChainId` for the configured environment (DevNet/TestNet/MainNet). | **Yes — chain ID alone is production-safe** to thread into `TimeoutVerificationContext`, but it is the only piece that is. |

### §2 Existing `SuiteAwareValidatorKeyProvider` constructions

`SuiteAwareValidatorKeyProvider` is defined at
`crates/qbind-consensus/src/key_registry.rs:57-63`. Two
implementations exist in the workspace:

* `GovernedValidatorKeyRegistry<G>` (`crates/qbind-consensus/src/governed_key_registry.rs:107-114`).  Implements
  `SuiteAwareValidatorKeyProvider` over any `G: ConsensusKeyGovernance`.
  No production governance source is reachable from
  `run_p2p_node`: `NodeConfig` does not hold a
  `ConsensusKeyGovernance` impl, and no governance state is loaded at
  binary startup.
* `ValidatorKeyRegistry` (`crates/qbind-consensus/src/key_registry.rs:120-124`)
  implements only the older `ValidatorKeyProvider`, **not** the
  suite-aware variant.

There is therefore **no smallest-adapter path** that produces a
`SuiteAwareValidatorKeyProvider` from `NodeConfig` today. Adding one
would require either:

1. extending `NodeConfig` to carry a per-peer `(suite_id, pk_bytes)`
   list (a new config-shape change), or
2. wiring a real on-chain governance registry into `run_p2p_node`
   (which is the production path and depends on PKI distribution).

Either of those is a non-trivial scope expansion and is the exact
substance of the C4 / C5 production blocker. Run 031 deliberately
refuses to fake it.

### §3 Existing `ConsensusSigBackendRegistry` constructions

`SimpleBackendRegistry` (`crates/qbind-consensus/src/crypto_verifier.rs:88-143`)
and `SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, Arc::new(MlDsa44Backend))`
are entirely production-safe and trivial to construct.

This is **the** piece Run 031 can build today. The bridge unit
tests build it as `Arc::new(SimpleBackendRegistry::with_backend(...))`
inside `#[cfg(test)]` to confirm the construction succeeds; the
production path simply does not have the other four pieces yet to
combine with it, so the registry alone cannot activate verification.

### §4 Local signer availability

No `Arc<dyn ValidatorSigner>` is constructed anywhere inside
`run_p2p_node`. `LocalKeySigner::new` (`crates/qbind-node/src/validator_signer.rs:205-222`),
`make_local_validator_signer` (`validator_signer.rs:346-355`),
`RemoteSignerClient` (`crates/qbind-node/src/remote_signer.rs`), and
`HsmPkcs11Signer` (`crates/qbind-node/src/hsm_pkcs11.rs`) are all
present and production-quality, but each requires either
`Arc<ValidatorSigningKey>` (loaded from keystore) or a configured
remote-signer / HSM endpoint. `main.rs` does not load any of these
in the P2P path. The `signer_mode` field defaults to
`SignerMode::LoopbackTesting` (`node_config.rs:734`) for the
`from_args` legacy path; this is explicitly testing-only and is not a
production signer.

Safe construction of a real signer **is** possible per-validator
once the keystore loading is wired into `main.rs`. That wiring is
the smallest next implementation step (see §10).

### §5 Activation policy

* `--p2p-mutual-auth required` multi-validator deployments → today
  fail closed *only* on MainNet (`main.rs:447-456`); on TestNet they
  warn and continue on the B12 test-grade `TrustedClientRoots`/`DummySig`
  stack. Run 031 introduces a **separate** opt-in
  `--require-timeout-verification` flag that maps to
  `TimeoutVerificationPolicy::RequireOrFail`. Activating verification
  in `--p2p-mutual-auth required` mode automatically would silently
  weaken the operator's intent against the existing B12 stub, which
  Run 031 explicitly refuses; instead, the operator declares the
  intent with `--require-timeout-verification`.
* LocalMesh / single-validator / legacy paths: `verification_ctx`
  remains `None` (bit-equivalent). The startup banner now says so
  precisely; Run 031 does not perturb the existing LocalMesh path.

## 7. Was `TimeoutVerificationContext` activated in `main.rs`?

**No.** The probe `run_031_probe_production_pieces_for_run_p2p_node`
(`crates/qbind-node/src/timeout_verification_bridge.rs`) returns
`Disabled { ProductionPiecesUnavailable { detail: "qbind-node main.rs does not yet load validator keystore (signer_keystore_path unread on startup), NodeConfig.network.static_peers carries no per-peer (suite_id, pk_bytes), and --p2p-mutual-auth runs on test-grade TrustedClientRoots/DummySig — see docs/whitepaper/contradiction.md C4/C5" } }`.

Under `OptionalActivate` (default), `enforce_policy` returns
`Ok(None)` and the loop proceeds with `verification_ctx: None`
identical to pre-Run-031 behaviour.

Under `RequireOrFail` (`--require-timeout-verification`),
`enforce_policy` returns
`Err(TimeoutVerificationPolicyError { policy: RequireOrFail, reason: ProductionPiecesUnavailable { ... } })`
and `main.rs` exits non-zero with a precise error pointing at the
contradiction doc — **fail-closed, no silent fallback**.

## 8. Activation policy

| CLI / config | Mapped policy | Behaviour today |
|---|---|---|
| (default, no flag) | `OptionalActivate` | Probe → `Disabled`; log precise reason; pass `verification_ctx: None`; metric `qbind_timeout_verification_active = 0`. |
| `--require-timeout-verification` | `RequireOrFail` | Probe → `Disabled`; **exit(1)** with precise error. |
| (LocalMesh) | not invoked | LocalMesh path has no Run-031 site; behaviour bit-equivalent. |

When the production blockers in §10 are resolved, a single edit
inside `run_p2p_node` (constructing `TimeoutVerificationBridgeInputs`
honestly and calling `try_build_timeout_verification_context` instead
of the probe) is sufficient to turn `OptionalActivate` /
`RequireOrFail` into real activation.

## 9. Logs / startup banners and metrics

### Expected startup logs (P2P mode, default)

```
[binary] Run 031: timeout-verification probe: active=false reason=production pieces unavailable in current qbind-node binary path: qbind-node main.rs does not yet load validator keystore (signer_keystore_path unread on startup), NodeConfig.network.static_peers carries no per-peer (suite_id, pk_bytes), and --p2p-mutual-auth runs on test-grade TrustedClientRoots/DummySig — see docs/whitepaper/contradiction.md C4/C5 policy=OptionalActivate validators=4 chain_id=chain_51424e4444455600 supported_suite_ids=[100] local_signer=<absent in main.rs — keystore not loaded>
[binary] Run 031: timeout verification DISABLED — BinaryConsensusLoopIo::verification_ctx=None (Run 030 bit-equivalent path). Inbound timeout/new-view crypto verification and outbound timeout signing remain off until production pieces land. See docs/whitepaper/contradiction.md C5.
```

### Expected startup logs (P2P mode, `--require-timeout-verification`)

```
[binary] Run 031: timeout-verification probe: active=false reason=production pieces unavailable ... policy=RequireOrFail ...
[binary] FATAL: --require-timeout-verification was set but timeout verification cannot be activated honestly: timeout verification policy RequireOrFail cannot be satisfied: production pieces unavailable in current qbind-node binary path: ...
[binary] qbind-node refuses to start under RequireOrFail policy with no production-safe context. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_031.md and docs/whitepaper/contradiction.md C5/C4.
```

### Metrics (`/metrics`)

New gauge:

```
# Timeout verification activation (Run 031, C5)
qbind_timeout_verification_active 0
```

Run 030 per-reason counters (`qbind_consensus_inbound_timeout_verify_*`,
`qbind_consensus_inbound_newview_verify_*`,
`qbind_consensus_outbound_timeout_signing_*`,
`qbind_consensus_view_advances_due_to_verified_tc_total`,
`qbind_consensus_timeout_crypto_verify_latency_*`) remain present on
`/metrics` and stay at 0 while `qbind_timeout_verification_active = 0`,
which is the honest signal that no verification is happening on the
binary path yet.

## 10. Remaining open items (gap section, per task spec)

The current `qbind-node` binary path cannot honestly construct an
`Arc<TimeoutVerificationContext>` for `run_p2p_node`. The exact
remaining dependencies, in increasing scope:

1. **Validator keystore load in `main.rs::run_p2p_node`.** `signer_keystore_path` flows into `NodeConfig` but is not read in `main.rs` to materialise an `Arc<ValidatorSigningKey>`. The consensus-side primitives (`LocalKeySigner`, `make_local_validator_signer`, `RemoteSignerClient`, `HsmPkcs11Signer`) are already production-quality. Smallest next step: call the existing keystore-load path under `signer_mode != LoopbackTesting` and stash the resulting `Arc<dyn ValidatorSigner>` so that `TimeoutVerificationBridgeInputs::signer` can be populated.
2. **Per-peer `(suite_id, pk_bytes)` distribution in `NodeConfig`.** Today `NodeConfig.network.static_peers: Vec<String>` is host:port only. Activating the bridge requires a `SuiteAwareValidatorKeyProvider` over the active validator set. This is the substantive missing config shape and is what `GovernedValidatorKeyRegistry<G>` is designed to bridge once a `ConsensusKeyGovernance` source is wired in.
3. **Production PQC KEMTLS root-key distribution and per-validator cert lifecycle (C4).** The `--p2p-mutual-auth` path itself runs on `TrustedClientRoots`/`DummySig` for B12 (`main.rs:427-472`). Until this lands, even an activated `TimeoutVerificationContext` would coexist with a transport that does not bind production-grade cryptographic identity at the channel layer; we explicitly refuse to call that "production verification".

Why activating with current pieces would be unsafe: every fallback
key source today (test-grade `derive_test_kem_keypair_from_validator_id`,
empty registry, default suite) would produce a key provider that
either (a) returns no `(suite, pk)` for the local validator,
producing a `KeyProviderMissingLocalKey` refusal, or (b) returns
deterministic test-grade keys whose secrets are public knowledge by
construction, which would let any node forge timeouts under any
identity. Either outcome makes "verification active" misleading.

Smallest next implementation step: **wire `signer_keystore_path` →
`Arc<ValidatorSigningKey>` → `Arc<dyn ValidatorSigner>` in
`main.rs::run_p2p_node`**, keeping `key_provider` / `backend_registry`
construction stubbed until §10.2 lands. That alone narrows C5 to
"key provider missing only" and closes the operator-side intent half
of the gap. The bridge already supports a context with
`signer = Some(...)` and a key provider that is non-empty but missing
peers — `try_build_timeout_verification_context` will surface the
exact peer that's missing, not silently weaken the check.

## 11. Positive evidence

* `try_build_timeout_verification_context` builds a real
  `Arc<TimeoutVerificationContext>` from honest pieces (real
  `ConsensusValidatorSet`, `SuiteAwareValidatorKeyProvider` returning
  `(SUITE_PQ_RESERVED_1, real ML-DSA-44 pk)`, `SimpleBackendRegistry`
  with `MlDsa44Backend`, real `LocalKeySigner` over a real
  `ValidatorSigningKey`). Test:
  `build_succeeds_with_real_pieces_and_signer`.
* Optional-signer path returns `Active` with `signer = None`, which
  is the honest "verify-only" mode the loop already supports for
  follower-style ingestion. Test:
  `build_succeeds_without_signer_means_no_local_emission`.
* Policy `OptionalActivate` returns `Some(ctx)` exactly when active,
  `None` otherwise. Tests: `policy_optional_returns_some_when_active`,
  `policy_optional_returns_none_when_disabled`.
* Policy `RequireOrFail` returns `Some(ctx)` exactly when active.
  Test: `policy_required_returns_some_when_active`.
* The binary's `run_p2p_node` activates the `qbind_timeout_verification_active`
  gauge to 1 only when `verification_ctx.is_some()`; otherwise it
  emits 0. The metric line is rendered next to `qbind_mainnet_profile_invariants_ok`
  on `/metrics`.

## 12. Negative evidence

* **Required mode never silently falls back to `None`.**
  `policy_required_fails_closed_when_disabled` pins this guarantee.
  In `main.rs::run_p2p_node`, `enforce_policy` returns `Err(...)` and
  the binary exits non-zero with a precise error.
* **Empty validator set is rejected.** `EmptyValidatorSet` /
  `LocalValidatorNotInSet` cover both directions: an empty set can
  never be supplied (the consensus crate's constructor refuses it)
  and a set without the local validator id is rejected before any
  crypto pieces are even consulted. Test:
  `empty_validator_set_fails_closed`.
* **Missing local key is rejected.** Test:
  `missing_local_key_fails_closed`.
* **Unsupported suite is rejected.** Test:
  `unsupported_local_suite_fails_closed`.
* **Missing backend for governed suite is rejected.** Test:
  `missing_backend_for_local_suite_fails_closed`.
* **Signer / local validator-id mismatch is rejected.** Test:
  `signer_validator_id_mismatch_fails_closed`.
* **Signer / supported-suite mismatch is rejected.** Test:
  `signer_suite_mismatch_fails_closed`.
* **Production probe today is `Disabled` with a precise, stable
  detail string.** Test: `run_031_probe_today_is_disabled_with_precise_detail`
  pins the substring set so that any future silent activation
  attempt will fail this test in CI.
* **Run 030 deterministic negative tests still pass.** All 20
  `binary_consensus_loop::tests::run030::*` tests pass under
  Run 031 (run name list in §5).

No real-binary negative injection was performed because no real
binary was activated.

## 13. Verdict

**PARTIAL POSITIVE.**

What landed:

* Honest, tested, production-safe **activation bridge** (`timeout_verification_bridge`) that is the single edit point a future production-PKI run needs to flip on real `TimeoutVerificationContext` activation.
* **Fail-closed** `--require-timeout-verification` flag wired through `enforce_policy` into `run_p2p_node`.
* Precise startup logs and a new `qbind_timeout_verification_active` `/metrics` gauge.
* No regressions in 907 tests across `qbind-node` lib + `qbind-consensus` lib + B3/B5/B9/B10/B11/T146 integration suites.

What did **not** land:

* Real activation in production `main.rs` — the production probe
  honestly returns `Disabled { ProductionPiecesUnavailable }` because
  the binary path still does not load a real keystore or a real
  per-peer key provider.
* N=4 real-binary verified-timeout B14 absent-leader recovery —
  cannot be run honestly until activation lands.
* Real-binary negative injection — same blocker.

C5 stays **OPEN — narrowed once more by Run 031** with the exact
remaining dependencies enumerated in §10.

## 14. Next action recommended

Wire `signer_keystore_path` → `Arc<ValidatorSigningKey>` →
`Arc<dyn ValidatorSigner>` inside `run_p2p_node` (the smallest of
the three §10 dependencies, and the one that can be done without
extending `NodeConfig` shape or shipping production PQC PKI). After
that lands, Run 032's scope is "extend `NodeConfig` with per-peer
`(suite_id, pk_bytes)` and construct a real
`SuiteAwareValidatorKeyProvider` from `static_peers + local`",
followed by the real activation flip in `try_build_timeout_verification_context`.