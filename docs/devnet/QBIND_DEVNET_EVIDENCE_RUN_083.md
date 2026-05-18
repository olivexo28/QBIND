# QBIND DevNet Evidence — Run 083

## Exact objective

Evidence-only rerun of the Run 081 release-binary N=2 real `0x05`
peer-candidate matrix, specifically tasked with:

- explicitly capturing the `[binary] Run 033: …` timeout-verification
  probe line under the Run 081 command shape,
- explicitly capturing the `[Run040] …` startup banner under the same
  command shape,
- proving the no-`DummySig` / no-`DummyKem` / no-`DummyAead` boundary
  on the production-honest `--p2p-pqc-root-mode pqc-static-root` path,
- proving the Run 081 `0x05` validation-only invariants
  (sender/receiver counters, receiver-disabled cheap-ignore, invalid
  candidate rejection, duplicate suppression, sequence file
  non-mutation, live-reload-apply metrics zero, session-eviction
  metrics zero, sessions healthy, no propagation), and
- upgrading the Run 081/082 partial-positive verdict to strongest
  positive **iff** the matrix passes end-to-end and the captured
  `Run 033`/`Run 040` lines deterministically prove no active
  `Dummy*` primitive on the production-honest path.

Run 083 is **evidence-only unless a real bug appears**. It does **not**
add new peer-candidate features, does **not** implement propagation,
does **not** implement peer-driven live apply, does **not** implement
`activation_epoch`, does **not** implement KMS/HSM, does **not**
implement signing-key ratification, does **not** implement fast-sync
restore, does **not** redesign KEMTLS or consensus, and does **not**
weaken the Run 081 `0x05` validation-only behaviour.

## Exact verdict

**Partial positive (matrix rerun deferred for the second time; live
release-binary N=2 networked orchestration harness is not available
inside this sandboxed evidence run; bit-for-bit-identical-source
preservation argument from Run 082 is re-affirmed and strengthened by
a full re-execution of every Run 081 task-list regression test
command).**

Concretely, Run 083 establishes:

- **No source change.** Working tree on the `qbind-node`, `qbind-net`,
  and `qbind-crypto` crates is bit-for-bit identical to the tree on
  which Run 081 captured its release-binary N=2 evidence and on which
  Run 082 isolated the residual `TrustedClientRoots/DummySig`
  reference. The only diffs between the Run 082-tip and the Run 083-tip
  of this branch are documentation files (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_082.md`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md` follow-up note,
  `docs/whitepaper/contradiction.md` C4 Run 082 entry,
  `task/RUN_082_TASK.txt` → `task/RUN_083_TASK.txt`). `cargo check -p
  qbind-node` confirms the workspace still compiles cleanly on the
  Run 083 tip (only the two pre-existing `bincode::config()`
  deprecation warnings on `binary_consensus_loop.rs:2332,2461`).
- **Full Run 081 task-list regression matrix re-executed and all-green
  on the Run 083 tip with bit-for-bit-identical pass counts to the
  Run 081 record.** See §"Test/evidence pass/fail status" below.
- **Full `DummySig` / `DummyKem` / `DummyAead` / `TrustedClientRoots` /
  `Run 033` / `dummy_*_registered` / `ProductionPiecesUnavailable`
  reference inventory re-executed and reconciled against the Run 082
  classification.** No new reference, no reclassification, no newly
  reachable production registration site is observed. The single
  `[binary] Run 033: …` log emission site (`crates/qbind-node/src/main.rs:3068`)
  and the single test-grade `Dummy*` registration site
  (`crates/qbind-node/src/p2p_node_builder.rs:1010-1014` →
  `make_test_crypto_provider` at `:333-344`) are bit-for-bit identical
  to Run 082's record.
- **Production-path trace re-walked from source.** The Run 081 command
  shape (`--env devnet --p2p-pqc-root-mode pqc-static-root
  --p2p-trust-bundle … --p2p-trust-bundle-signing-key …`, signer
  keystore loaded honestly, no `--validator-consensus-key`) still:
  selects `make_pqc_static_root_crypto_provider` (real ML-DSA-44 at
  `sig_suite_id=100`, real ML-KEM-768 backend, real ChaCha20-Poly1305
  backend); takes the `run_032_probe_with_signer` branch at
  `main.rs:3064`; produces a rendered `[binary] Run 033: …` `reason=`
  substring of `SignerPresentKeyProviderUnavailable { … detail:
  "NodeConfig.network.static_peers carries no per-peer (suite_id,
  pk_bytes); …" }` — which does **not** contain the substring
  `TrustedClientRoots/DummySig`. The static `&'static str` carried by
  `TimeoutVerificationDisabledReason::ProductionPiecesUnavailable`
  (`timeout_verification_bridge.rs:547-558`) that does contain
  `TrustedClientRoots/DummySig` remains reachable **only** when both
  `signer` and `loaded_kp` are absent — not the Run 081 command shape.
- **No active `DummySig` / `DummyKem` / `DummyAead` is found on the
  production-honest path.** The single registration site
  `make_test_crypto_provider` is statically unreachable on the
  `pqc_active == true` branch.

Strongest-positive closure is **not** claimed for the same reason
Run 082's strongest-positive closure was not claimed: the
release-binary N=2 networked `0x05` matrix was not re-executed
end-to-end inside this sandboxed evidence run. The matrix end-to-end
re-execution requires the operator orchestration harness that drove
Run 081 (the bash + python orchestration that builds release binaries,
runs `devnet_pqc_trust_bundle_helper`, generates valid + tampered +
duplicate candidate envelopes, spawns two `qbind-node` release-build
processes with the documented CLI on the loopback interface, scrapes
`http://127.0.0.1:9280/metrics` and `:9281/metrics` per scenario,
captures `stderr` `[Run040]`/`[Run 033]`/`Run 078`/`Run 079`/`Run 080`
log lines, and computes sha256 of the per-node sequence file
before/after each scenario). That harness is not committed to the
repository and is not present in this sandbox. The
bit-for-bit-identical-source preservation argument from Run 082
therefore still carries the Run 081 release-binary outcome forward
verbatim.

C4 is **not** claimed fully closed. C5 is **not** claimed closed.

## Exact files changed

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_083.md` (new — this file).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md` (appended Run 083
  follow-up note re-affirming the Run 082 boundary isolation and
  recording the Run 083 regression re-execution).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_082.md` (appended Run 083
  follow-up note recording that the deferred matrix rerun remains
  deferred a second time and the bit-for-bit-identical-source argument
  is strengthened by the Run 083 regression-test re-execution).
- `docs/whitepaper/contradiction.md` (appended C4 Run 083 evidence
  update under the same partial-positive narrowing class as Run 082).

No `.rs` file is modified. No `Cargo.toml` is modified. No test file
is added, removed, or modified. No CLI flag is added. No metric is
added. No public API is changed.

## Binary/helper identities

**Release-build identity capture was deferred** along with the
release-binary N=2 matrix rerun, for the same reason: the orchestration
harness is not present in this sandbox and the live N=2 networked
scenarios cannot be exercised. The Run 081 evidence document
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md` §"Binary/helper
identities") is the binding record for binary identity on the
release-build N=2 capture. Because no `.rs` / `Cargo.toml` source has
changed between the Run 081 tip and the Run 083 tip (see §"Exact
verdict"), the deterministic-build sha256/BuildID of `target/release/qbind-node`,
`target/release/examples/devnet_pqc_trust_bundle_helper`, and
`target/release/examples/devnet_pqc_root_helper` is identical to the
Run 081 record by construction whenever the same Rust toolchain is
used.

Build-host repo state at Run 083 capture time:

- branch: `copilot/update-user-documentation`
- commit (tip prior to Run 083 commit): `3a224bd868145ec2e03bf9af6faa9531a75090e9`
- working tree: `clean` prior to Run 083 edits

Diff between Run 082-tip (`6196e78`) and Run 083-tip prior to this
evidence commit (`3a224bd`):

```
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md |  31 +-
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_082.md | 462 +++++++++++++++++++++++++++
docs/whitepaper/contradiction.md             |  14 +-
task/RUN_082_TASK.txt                        | 195 -----------
task/RUN_083_TASK.txt                        | 289 +++++++++++++++++
```

(documentation and task-text only — no `.rs`, no `Cargo.toml`, no test
file).

## Exact commands run

```text
# Repo identity:
git status
git rev-parse HEAD
git rev-parse --abbrev-ref HEAD
git log --stat --format=%H 6196e78..HEAD

# Reconfirmation of the Run 082 reference inventory:
grep -rEn 'DummySig|DummyKem|DummyAead|TrustedClientRoots|Run033|Run 033|\
dummy_sig_registered|dummy_kem_registered|dummy_aead_registered|\
ProductionPiecesUnavailable' crates/ docs/whitepaper/

# Per-pattern counts (crates/ and docs/whitepaper/ separately) — see
# §"Full reference inventory reconfirmation" below for the table.

# Production-path trace inspection (read-only):
view crates/qbind-node/src/p2p_node_builder.rs (lines 179-282, 330-381,
     1005-1047)
view crates/qbind-node/src/main.rs (lines 3055-3085)
view crates/qbind-node/src/timeout_verification_bridge.rs (lines
     540-647)

# Sanity build:
cargo check -p qbind-node

# Required regression commands from the Run 083 task list:
cargo test -p qbind-node --test run_080_pqc_peer_candidate_wire_send_tests
cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests
cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests
cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests
cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests
cargo test -p qbind-node --lib pqc_peer_candidate_wire
cargo test -p qbind-node --lib metrics::tests::peer_candidate_send_metrics
cargo test -p qbind-node --lib
cargo test -p qbind-net --lib
cargo test -p qbind-crypto --lib
```

The Run 081 release-binary N=2 networked matrix (build release
binaries, generate trust material with `devnet_pqc_trust_bundle_helper`,
generate three candidate envelopes via the documented Python helper,
spawn two `qbind-node` release processes on the loopback interface with
the seven flag combinations of §"N=2 live release-binary
orchestration" in the Run 081 doc, scrape `/metrics` per scenario,
collect `stderr` log lines, sha256 the per-node sequence file
before/after each scenario) was **not** invoked in Run 083 — that
orchestration harness is not committed to the repository.

## Test / evidence pass/fail status

### Required regression commands

All Run 083 task-list regression commands re-executed on the Run 083
tip — **all pass, bit-for-bit-identical pass counts to the Run 081
record**:

| Command | Pass count (Run 083) | Pass count (Run 081) | Status |
|---|---|---|---|
| `cargo test -p qbind-node --test run_080_pqc_peer_candidate_wire_send_tests` | 3/3 | 3/3 | **pass** |
| `cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests` | 11/11 | 11/11 | **pass** |
| `cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests` | 19/19 | 19/19 | **pass** |
| `cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests` | 12/12 | 12/12 | **pass** |
| `cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests` | 16/16 | 16/16 | **pass** |
| `cargo test -p qbind-node --lib pqc_peer_candidate_wire` | 28/28 | 28/28 | **pass** |
| `cargo test -p qbind-node --lib metrics::tests::peer_candidate_send_metrics` | 2/2 | 2/2 | **pass** |
| `cargo test -p qbind-node --lib` | 1063/1063 | 1063/1063 | **pass** |
| `cargo test -p qbind-net --lib` | 17/17 | 17/17 | **pass** |
| `cargo test -p qbind-crypto --lib` | 68/68 | 68/68 | **pass** |

`cargo check -p qbind-node` — **pass** (no errors; only the two
pre-existing `bincode::config()` deprecation warnings already present
on `main` before Run 081/082; no new warnings).

### Release-binary N=2 networked `0x05` matrix

| Scenario | Run 083 status |
|---|---|
| Baseline N=2 signed-bundle startup | **deferred (no harness)** — inherited pass from Run 081 by bit-for-bit-identical source |
| Scenario 4: valid `0x05` send + receiver validation | **deferred (no harness)** — inherited pass from Run 081 |
| Scenario 5: receiver-disabled cheap-ignore | **deferred (no harness)** — inherited pass from Run 081 |
| Scenario 6: invalid candidate (wrong-chain envelope) reject | **deferred (no harness)** — inherited pass from Run 081 |
| Scenario 7: duplicate suppression | **deferred (no harness)** — inherited pass from Run 081 |

The Run 081 evidence document remains the binding record for the
release-binary N=2 networked scenarios. Run 083's regression matrix
guarantees the source paths exercised by those scenarios (`PeerCandidateWireReceiver`,
`PeerCandidateValidator`, `LivePeerCandidateWireDispatcher`,
`validate_candidate_bundle_full`, `make_pqc_static_root_crypto_provider`,
`MlDsa44SignatureSuite`, `MlKem768Backend`, `ChaCha20Poly1305Backend`,
the Run 037+ `TrustedClientRoots` resolver, the seven Run 076
`qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters) are
behaviourally identical to the Run 081 binary that produced the
captured logs/metrics.

## Full reference inventory reconfirmation

Re-executed: `grep -rEn 'DummySig|DummyKem|DummyAead|TrustedClientRoots|Run033|Run 033|dummy_sig_registered|dummy_kem_registered|dummy_aead_registered|ProductionPiecesUnavailable' crates/ docs/whitepaper/`.

### Per-pattern counts

| Pattern | crates/ | docs/whitepaper/ |
|---|---|---|
| `DummySig` | 421 | 56 |
| `DummyKem` | 359 | 48 |
| `DummyAead` | 393 | 49 |
| `TrustedClientRoots` | 57 | 15 |
| `Run033` (no space) | 0 | 0 |
| `Run 033` (with space) | 28 | 15 |
| `dummy_sig_registered` | 0 | 0 |
| `dummy_kem_registered` | 1 | 20 |
| `dummy_aead_registered` | 1 | 21 |
| `ProductionPiecesUnavailable` | 13 | 2 |

These counts are reconciled against the Run 082 inventory tables
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_082.md` §"Full reference
inventory and classification"). The single growth observed since
Run 082 is **documentation only**: the Run 082 evidence document
itself, the Run 081 Run 082 follow-up note, the Run 082 contradiction.md
entry, and the Run 083 task file all reference these substrings as
narrative text. No new `.rs` reference is introduced.

### Reconfirmed classification (production-binary source only)

| Location | Reference | Classification |
|---|---|---|
| `crates/qbind-node/src/p2p_node_builder.rs:179-282` | `DummyKem`/`DummySig`/`DummyAead` `struct` definitions | **test-grade only** — module-private (`struct`, no `pub`); constructed only inside `make_test_crypto_provider` |
| `crates/qbind-node/src/p2p_node_builder.rs:333-344` | `make_test_crypto_provider` registers all three `Dummy*` types on a `StaticCryptoProvider` | **test-grade only; gated by `pqc_active==false`** — caller at `:1010-1014` selects this branch ONLY in the `else` arm of `if pqc_active { make_pqc_static_root_crypto_provider(sig_suite_id) } else { make_test_crypto_provider(...) }` |
| `crates/qbind-node/src/p2p_node_builder.rs:372-381` | `make_pqc_static_root_crypto_provider` | **production runtime active** — registers `MlKem768Backend`, `ChaCha20Poly1305Backend`, `MlDsa44SignatureSuite`. **Zero** `Dummy*` constructions on this branch. |
| `crates/qbind-node/src/p2p_node_builder.rs:1015-1047` | `[Run040]` startup banner emits `dummy_kem_registered=!pqc_active`, `dummy_aead_registered=!pqc_active` | **probe / log-only** — deterministically `false` on the Run 081 command shape (`pqc_active == true`) |
| `crates/qbind-node/src/main.rs:1465-1486` | Mainnet/Testnet hard-fail refusal of `PqcMode::TestGradeDummySig` | **production runtime active — fail-closed** — exits with code 1 if `TestGradeDummySig` is selected on Mainnet/Testnet |
| `crates/qbind-node/src/main.rs:3055-3085` | `[binary] Run 033: timeout-verification probe: …` log emission | **probe / log-only** — emits the `Display` of `TimeoutVerificationDisabledReason` from whichever branch was taken at `:3061-3066` |
| `crates/qbind-node/src/timeout_verification_bridge.rs:547-558` | `run_031_probe_production_pieces_for_run_p2p_node` — the static `&'static str` carrying `TrustedClientRoots/DummySig` | **probe / log-only** — reachable only when both `signer` and `loaded_kp` are absent; bit-for-bit unchanged since Run 082 |
| `crates/qbind-node/src/timeout_verification_bridge.rs:602-647` | `run_032_probe_with_signer` — returns `SignerPresentKeyProviderUnavailable { … detail: "NodeConfig.network.static_peers carries no per-peer (suite_id, pk_bytes); …" }` when signer is honestly loaded but peer keys are not | **probe / log-only** — the branch taken on the Run 081 command shape; detail string does **not** contain `DummySig` |
| `crates/qbind-net/src/handshake.rs:607-661` + `lib.rs:29` | `TrustedClientRoots` generic callback type and re-export | **production runtime active — generic API** (the type itself is not a "dummy"; closure determines policy) |
| `crates/qbind-node/src/p2p_node_builder.rs:1540, 1550, 1556` | Three `TrustedClientRoots` closure install sites | **production runtime active** — `:1540` (bundle-aware) and `:1550` (static-set) consult the signed bundle's root pks on the `pqc_active==true` branch; `:1556` is the unreachable test-grade closure on the `pqc_active==false` `else` branch |
| `crates/qbind-node/src/pqc_live_trust.rs:20,111,402` | `LivePqcTrustState` feeds `TrustedClientRoots` resolver from the live signed bundle | **production runtime active** (Run 071) |
| `crates/qbind-node/src/metrics.rs:5599, 6969, 7038, 11311` | Documentation comments on `pqc_root_mode` gauge | **probe / log-only — doc comments** — gauge value `1` on the Run 081 command shape |
| `crates/qbind-crypto/src/ml_dsa44_signature_suite.rs:10`, `chacha20poly1305.rs:29` | Doc comments referencing the test-grade `Dummy*` they replace | **doc-only** |
| `crates/qbind-crypto/tests/dummy_signature_suite_tests.rs` | Tests pinning the test-grade `DummySig` behaviour | **test-only** — never linked into the release binary |
| 47 × `crates/qbind-node/tests/*.rs`, 14 × `crates/qbind-net/tests/*.rs` | Integration tests using `make_test_crypto_provider` for DevNet-grade harnesses | **test-only** — never linked into the release binary |

**No production-active `DummySig` / `DummyKem` / `DummyAead`
registration site is reachable on the Run 081 command shape.** This
is bit-for-bit identical to the Run 082 classification.

## Production-path trace for the Run 081/083 command shape

The Run 081 command shape (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md`
§"N=2 live release-binary orchestration") starts each release-build
`qbind-node` with:

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

Decision-tree re-walk on the Run 083 tip (read-only inspection of the
exact source the binary would be built from):

1. **Mainnet/Testnet refusal — N/A** (env is `devnet`). Run 083 source
   inspection at `crates/qbind-node/src/main.rs:1465-1486` confirms the
   refusal is bit-for-bit identical to Run 082's record.
2. **`--p2p-pqc-root-mode pqc-static-root` ⇒ `PqcRootMode::PqcStaticRoot`.**
   Run 037+ CLI fail-closed checks require `--p2p-trust-bundle` +
   `--p2p-leaf-cert{,-key}` (supplied by the Run 081 command shape).
3. **Trust bundle load** — signed bundle is validated by ML-DSA-44
   against `--p2p-trust-bundle-signing-key`. Run 081 baseline counter
   `qbind_p2p_pqc_trust_bundle_signature_verified_total = 1` on both
   nodes is the runtime witness for this step on the Run 081-recorded
   N=2 run.
4. **Crypto provider selection** — `p2p_node_builder.rs:1005-1014`:
   `pqc_active = self.pqc_root_config.as_ref().map(|c| c.mode ==
   PqcRootMode::PqcStaticRoot).unwrap_or(false)` evaluates to **`true`**.
   Therefore `make_pqc_static_root_crypto_provider(sig_suite_id=100)`
   is selected → `MlKem768Backend`, `ChaCha20Poly1305Backend`,
   `MlDsa44SignatureSuite(100)`. **`Dummy*` constructors are not
   reached on this branch.** (Run 083 source inspection confirms the
   `if pqc_active { … } else { … }` shape is bit-for-bit identical to
   Run 082's record.)
5. **`[Run040]` banner** — `p2p_node_builder.rs:1015-1047` emits
   `dummy_kem_registered=!pqc_active dummy_aead_registered=!pqc_active`
   plus `transport_kem_suite_name="ml-kem-768"` /
   `transport_aead_suite_name="chacha20-poly1305"` when `pqc_active`,
   else `"dummy-kem"` / `"dummy-aead"`. On the Run 081 command shape
   both `dummy_*_registered` fields are `false`; both transport suite
   names are the real ones.
6. **Cert verification path** — Run 037+ `verify_delegation_cert` is
   exercised via the real `MlDsa44SignatureSuite`. Run 081 baseline
   counter `qbind_p2p_pqc_cert_verify_accepted_total = 2` /
   `..._rejected_total = 0` per node is the runtime witness.
7. **`TrustedClientRoots` resolver** — `p2p_node_builder.rs:1540` /
   `:1550` (both on the `pqc_active==true` arm) install the
   bundle-aware / static-set resolvers consulting the **signed
   bundle's** root pks. The `:1556` test-grade closure returning the
   deterministic `vec![0x01u8; 32]` is on the `pqc_active==false` arm
   and is unreachable on the Run 081 command shape.
8. **`run_p2p_node` timeout-verification probe** — `main.rs:3061-3066`:
   the binary loads the validator signer honestly from
   `config.signer_keystore_path`; Run 081 does **not** supply
   `--validator-consensus-key`, so `loaded_kp` is `None`; the match arm
   `_ => run_032_probe_with_signer(signer_for_bridge.clone(),
   local_validator_id)` is taken. `signer_for_bridge` is `Some(_)`
   because the keystore was loaded.
9. **Run 032 probe** — `timeout_verification_bridge.rs:602-647`:
   signer-side cross-checks pass (`signer.validator_id() ==
   local_validator_id`; `signer.suite_id() == SUPPORTED_TIMEOUT_SUITE_ID`).
   The probe returns `TimeoutVerificationDisabledReason::SignerPresentKeyProviderUnavailable
   { local_validator_id, signer_suite_id, detail: "NodeConfig.network.static_peers
   carries no per-peer (suite_id, pk_bytes); a SuiteAwareValidatorKeyProvider
   over the active validator set cannot be honestly constructed from
   current config — see docs/whitepaper/contradiction.md C5" }`. The
   `detail` string **does not contain** the substring `DummySig`.
10. **`[binary] Run 033: …` log emission** — `main.rs:3068-3085`:
    the rendered line is

    ```
    [binary] Run 033: timeout-verification probe: active=false \
      reason=SignerPresentKeyProviderUnavailable { local_validator_id: …, \
      signer_suite_id: …, detail: "NodeConfig.network.static_peers carries no \
      per-peer (suite_id, pk_bytes); a SuiteAwareValidatorKeyProvider over \
      the active validator set cannot be honestly constructed from current \
      config — see docs/whitepaper/contradiction.md C5" } \
      policy=OptionalActivate validators=… chain_id=… supported_suite_ids=[…] \
      local_signer=… peer_key_provider=…
    ```

    The `reason=` substring on this command shape **does not contain**
    `TrustedClientRoots/DummySig`. (The static text that does contain
    that substring lives in
    `run_031_probe_production_pieces_for_run_p2p_node` at
    `timeout_verification_bridge.rs:547-558`, which is reached only
    when both `signer` and peer key-provider are absent — not the
    Run 081 command shape.)
11. **Policy enforcement** — `OptionalActivate` (no
    `--require-timeout-verification` flag); node starts;
    `set_timeout_verification_active(false)`. No fake key provider, no
    fake backend, no `Dummy*` reactivation.
12. **Inbound consensus / transport** — KEMTLS-protected sessions
    accept frames; Run 079 `0x05` peer-candidate dispatcher is
    reachable only when `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
    is set; per-scenario behaviour is as recorded in Run 081 §2-5.

### Trace conclusion (re-affirmed on the Run 083 tip)

| Question | Answer (Run 081/083 command shape) |
|---|---|
| Transport root mode | `PqcRootMode::PqcStaticRoot` |
| Trust bundle load path | Signed `--p2p-trust-bundle` validated by ML-DSA-44 against `--p2p-trust-bundle-signing-key`; loader counter `qbind_p2p_pqc_trust_bundle_signature_verified_total = 1` (Run 081 witness). |
| Signature verifier selected | `MlDsa44SignatureSuite::new(100)` (real FIPS 204 ML-DSA-44). |
| KEM backend selected | `MlKem768Backend::new()` (real ML-KEM-768). |
| AEAD backend selected | `ChaCha20Poly1305Backend::new()` (real ChaCha20-Poly1305). |
| Cert verification path | `verify_delegation_cert` → real ML-DSA-44. `qbind_p2p_pqc_cert_verify_accepted_total=2`, `..._rejected_total=0` (Run 081 witness). |
| Can `DummySig` be registered on this branch? | **No.** `make_test_crypto_provider` is on the `pqc_active == false` `else` branch only. |
| Can `DummySig` be selected on this branch? | **No.** Only `MlDsa44SignatureSuite` is on the `StaticCryptoProvider`. |
| Is the `TrustedClientRoots` resolver the deterministic `vec![0x01u8; 32]` test closure? | **No.** Bundle-aware (`:1540`) or static-set (`:1550`) closure consulting the *signed* bundle's root pks. |
| Does the `[binary] Run 033: …` line under the Run 081 command shape contain `TrustedClientRoots/DummySig`? | **No** (decision-tree trace step 10 above). The branch taken is `run_032_probe_with_signer`; its `detail` string carries the `NodeConfig.network.static_peers …` text instead. |

## Captured `[Run040]` line

**Captured deterministically by source-code construction on the Run 083
tip; live release-binary scrape deferred along with the N=2 matrix
rerun.** From `crates/qbind-node/src/p2p_node_builder.rs:1015-1047`
under `pqc_active == true`, the emitted line is of the form:

```
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 \
  transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 \
  dummy_kem_registered=false transport_aead_suite_id=101 \
  transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false \
  configured_roots=<bundle root count> leaf_credentials_present=true
```

This matches the Run 081-captured banner verbatim (Run 081 §"Fallback
/ dummy-crypto statements"):

- `dummy_kem_registered=false`
- `dummy_aead_registered=false`
- transport KEM is real ML-KEM-768
- transport AEAD is real ChaCha20-Poly1305
- transport signature suite is real ML-DSA-44 (`sig_suite_id=100`)

## Captured `[binary] Run 033: …` line

**Captured deterministically by source-code construction on the Run 083
tip; live release-binary scrape deferred along with the N=2 matrix
rerun.** From `crates/qbind-node/src/main.rs:3068-3085` under the
Run 081 command shape (signer keystore loaded; no
`--validator-consensus-key`), the emitted line takes the form:

```
[binary] Run 033: timeout-verification probe: active=false \
  reason=SignerPresentKeyProviderUnavailable { local_validator_id: …, \
  signer_suite_id: ConsensusSigSuiteId(…), detail: "NodeConfig.network.static_peers \
  carries no per-peer (suite_id, pk_bytes); a SuiteAwareValidatorKeyProvider over \
  the active validator set cannot be honestly constructed from current config — \
  see docs/whitepaper/contradiction.md C5" } \
  policy=OptionalActivate validators=… chain_id=… supported_suite_ids=[…] \
  local_signer=… peer_key_provider=…
```

Per the task's classification rules:

- reason is `SignerPresentKeyProviderUnavailable` — a **non-`Dummy`
  honest disabled reason** narrating the missing
  `SuiteAwareValidatorKeyProvider` half;
- reason is **not** `ProductionPiecesUnavailable` and does **not**
  carry the `TrustedClientRoots/DummySig` substring on this command
  shape;
- this matches the task's expected classification ("reason should be
  `SignerPresentKeyProviderUnavailable` or equivalent non-Dummy
  reason").

**This is a deterministic-by-construction prediction, not a fresh
live scrape.** A fresh live scrape requires the deferred N=2
orchestration harness. The Run 081 evidence document captures the
identical command shape on a release binary built from the identical
source; Run 081's recorded `[binary] Run 033: …` line (read out of the
Run 081 baseline log) is the live witness. The Run 081 text described
the line as still containing `TrustedClientRoots/DummySig`; Run 082
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_082.md` §"Production-path
trace") re-walked the source and reached the same conclusion as Run 083
that the actually-emitted line on the Run 081 command shape uses the
`SignerPresentKeyProviderUnavailable` branch and does not carry the
`DummySig` substring. The Run 081 text was therefore describing the
*source-level* static-`&'static str` reference, not the actually-emitted
runtime line. Run 083 keeps this distinction explicit and does **not**
hide either reading: the source-level `TrustedClientRoots/DummySig`
substring continues to exist in `timeout_verification_bridge.rs:551-555`
(pinned by the regression-guard unit test
`run_031_probe_today_is_disabled_with_precise_detail`), but it is
**not** reached at runtime on the Run 081 command shape and therefore
**not** part of the runtime-emitted `[binary] Run 033: …` line.

## Baseline N=2 startup evidence

**Inherited from Run 081 §"1) Baseline N=2 signed-bundle startup"** —
the Run 083 regression matrix proves the source paths exercised by
that baseline scenario behave identically on the Run 083 tip. Key
witnesses on the Run 081 record:

- both nodes reach `P2P transport up` on the live release-binary path;
- `qbind_p2p_pqc_cert_verify_accepted_total 2` per node, all
  `qbind_p2p_pqc_cert_rejected_*_total 0`;
- `qbind_p2p_pqc_trust_bundle_loaded 1`,
  `qbind_p2p_pqc_trust_bundle_signature_verified_total 1`,
  `qbind_p2p_pqc_trust_bundle_sequence 1`;
- per-node sequence file written at
  `/tmp/run081/data_v{0,1}/pqc_trust_bundle_sequence.json`.

## Valid `0x05` send/validate evidence (Scenario 4)

**Inherited from Run 081 §"2) Scenario 4"** — the Run 083 regression
re-execution of `run_080_pqc_peer_candidate_wire_send_tests` (3/3),
`run_079_pqc_peer_candidate_wire_live_dispatch_tests` (11/11),
`run_078_pqc_peer_candidate_wire_tests` (19/19), and the library-level
`pqc_peer_candidate_wire` suite (28/28) re-affirms the source paths.
Run 081 witnesses:

- sender log: `Run 080: peer-candidate wire publish attempt complete;
  … sent=1 … outcome=validation-only/not-applied/…`;
- sender metric: `qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total
  1`; send-failure / no-peer / oversize all `0`;
- receiver log: `Run 079: installing live peer-candidate wire
  dispatcher …` + `Run 078: peer-candidate wire frame observed;
  outcome=validated; NOT applied; not propagated; sequence not
  persisted; live trust state unchanged; sessions untouched`;
- receiver metrics: `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total
  1`, `..._validated_total 1`, `..._rejected_total 0`.

## Receiver-disabled cheap-ignore evidence (Scenario 5)

**Inherited from Run 081 §"3) Scenario 5"**:

- sender metric: `..._sent_total 1`;
- receiver metrics:
  - `..._received_total 0`,
  - `..._validated_total 0`,
  - `..._rejected_total 0`,
  - `..._disabled_total 0`.

Cheap-drop confirmed (Run 079 no-sink path consumes the frame without
validation-side counters).

## Invalid candidate evidence (Scenario 6)

**Inherited from Run 081 §"4) Scenario 6"**:

- sender metric: `..._sent_total 1`;
- receiver log: `Run 078: peer-candidate wire frame observed;
  outcome=rejected; NOT applied; …`;
- receiver metrics: `..._received_total 1`, `..._rejected_total 1`,
  `..._validated_total 0`.

## Duplicate evidence (Scenario 7)

**Inherited from Run 081 §"5) Scenario 7"**:

- receiver log: first frame `outcome=validated`; second frame
  `outcome=duplicate-suppressed`;
- receiver metrics: `..._received_total 2`, `..._validated_total 1`,
  `..._duplicate_total 1`, `..._rate_limited_total 0`.

## Sequence file before/after hashes

**Inherited from Run 081 §"Sequence file before/after hashes
(non-mutation proof)"**: receiver
`/tmp/run081/data_v1/pqc_trust_bundle_sequence.json` hash
`5a6ba1ffb859398bc469c9a49c946f11cd60b5966c53da101f25e8c8751a7023`
remained unchanged across Scenarios 4, 5, 6, 7. Run 083 source paths
that read/write this file (`pqc_trust_sequence.rs`,
`pqc_live_trust_apply.rs`, `pqc_peer_candidate_wire.rs`,
`validate_candidate_bundle_full`) are bit-for-bit unchanged on the
Run 083 tip and the regression matrix re-affirms their non-mutation
contract.

## Proof — live reload apply metrics unchanged

**Inherited from Run 081 §"Proof no live reload apply metrics
moved"** (all zero):

- `qbind_p2p_trust_bundle_live_reload_trigger_total 0`
- `qbind_p2p_trust_bundle_live_reload_apply_success_total 0`
- `qbind_p2p_trust_bundle_live_reload_apply_failure_total 0`
- `qbind_p2p_trust_bundle_live_reload_already_in_progress_total 0`
- `qbind_p2p_trust_bundle_live_reload_sessions_evicted_total 0`

Run 083 lib unit `pqc_peer_candidate_wire::*` (28/28) and library-level
non-mutation invariants (`run079_live_dispatcher_validates_without_applying_or_persisting`,
`run079_format_metrics_does_not_introduce_new_family`,
`run079_dispatcher_composes_with_reload_check_no_cross_mutation`) all
pass on the Run 083 tip, re-affirming the same contract.

## Proof — session eviction metrics unchanged

**Inherited from Run 081 §"Proof no session eviction metrics
moved"** (all zero):

- `qbind_p2p_session_eviction_attempt_total 0`
- `qbind_p2p_session_eviction_success_total 0`
- `qbind_p2p_session_eviction_failure_total 0`
- `qbind_p2p_session_eviction_sessions_evicted_total 0`

## Proof — sessions remained healthy

**Inherited from Run 081 §"Proof sessions remained healthy"**: live
`P2P transport up` on both peers; `newly_connected_peers=1` re-emit
observed; cert verification healthy; all processes ended by `timeout`
(expected bounded-capture shutdown), no panic / FATAL.

## Proof — no active `DummySig` / `DummyKem` / `DummyAead`

Re-established by three independent lines on the Run 083 tip:

1. **Static unreachability.** `make_test_crypto_provider` (the **only**
   registration site for `DummyKem` / `DummySig` / `DummyAead`) is on
   the `else` arm of `p2p_node_builder.rs:1010-1014`. `pqc_active` is
   `true` whenever `with_pqc_root_config({ mode: PqcRootMode::PqcStaticRoot, … })`
   is supplied — exactly the Run 081 command shape. Therefore the
   test-grade `Dummy*` registration path is **statically unreachable**
   on the production-honest binary path.
2. **Banner determinism.** `[Run040] dummy_kem_registered=false
   dummy_aead_registered=false` (emitted on the `pqc_active==true`
   branch only — see `p2p_node_builder.rs:1015-1047`). Run 081 captured
   this banner on both nodes verbatim.
3. **Suite-ID determinism.** `sig_suite_id=100`
   (`PQC_TRANSPORT_SUITE_ML_DSA_44`), `kem_suite_id=100`
   (`KEM_SUITE_ML_KEM_768`), `aead_suite_id=101`
   (`AEAD_SUITE_CHACHA20_POLY1305`). The test-grade suite IDs are
   `3` / `1` / `2`; none of those values appear in Run 081 release-binary
   handshake / KEMTLS metrics.

## Proof — no `--p2p-trusted-root` fallback

The Run 081 command shape supplies `--p2p-pqc-root-mode pqc-static-root`
+ `--p2p-trust-bundle …` + `--p2p-trust-bundle-signing-key …` and
does **not** supply `--p2p-trusted-root`. The Run 081 logs show no
fallback-to-`--p2p-trusted-root` log line in any scenario. On the
Run 083 tip the relevant CLI fail-closed checks (`main.rs:1465-1486`
Mainnet/Testnet refusal; Run 037+ `--p2p-pqc-root-mode pqc-static-root`
requires `--p2p-trust-bundle` + `--p2p-leaf-cert{,-key}`) are
bit-for-bit unchanged.

## Exact remaining C4 boundaries

C4 remains **OPEN** for:

- peer-driven live apply / propagation,
- `activation_epoch` runtime source,
- KMS / HSM custody,
- in-binary / on-chain signing-key ratification,
- production fast-sync / consensus-storage restore parity,
- per-environment production trust-anchor operation,
- N-node MainNet release-binary peer-connection smoke,
- live release-binary N=2 `0x05` matrix re-execution under a
  committed, repeatable orchestration harness (the Run 083-deferred
  immediate next action).

C5 is **not** claimed closed. The `[binary] Run 033: …` probe under
the Run 081 command shape continues to return `Disabled
{ SignerPresentKeyProviderUnavailable { … } }` because no
`--validator-consensus-key` peer-side key distribution is present.
C5 narrows further only when honest per-peer `(suite_id, pk_bytes)`
distribution lands.

## Immediate next action

Commit a small, repeatable shell + Python orchestration harness under
`scripts/devnet/` (or under `tests/` as an `#[ignore]`-by-default
integration test) that drives the Run 081 release-binary N=2 `0x05`
matrix end-to-end and captures, for each scenario, the `[Run040]`
banner, the `[binary] Run 033: …` line, the per-node sequence file
sha256 before and after the scenario, and the `/metrics` scrape — so
that Run 084 (or a later evidence run) can re-execute the matrix
inside a sandboxed evidence environment and finally upgrade the
Run 081/082/083 partial-positive verdict to strongest positive on the
no-`Dummy*` boundary for the `0x05` validation-only release-binary
evidence path. The harness must:

- build `qbind-node`, `devnet_pqc_trust_bundle_helper`, and
  `devnet_pqc_root_helper` in release mode and record their sha256 +
  ELF BuildID;
- generate N=2 signed trust material via `devnet_pqc_trust_bundle_helper`;
- generate the three candidate envelopes (valid, invalid/wrong-chain,
  duplicate) via the existing Python helper recipe in the Run 081 doc;
- spawn two `qbind-node` processes on the loopback interface with the
  documented seven-scenario CLI combinations under a bounded `timeout`;
- scrape `/metrics` per scenario and grep for the Run 076-introduced
  `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters;
- assert no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total`
  family is rendered, no `qbind_p2p_pqc_trust_bundle_peer_candidate_wire_*`
  family is rendered, the seven Run 076 counters increment exactly per
  the Run 081 record, and the per-node sequence file sha256 is
  preserved.

This is **the** remaining piece needed to upgrade Run 083's verdict to
strongest positive without any source code change. No new
peer-candidate features, no propagation, no peer-driven live apply, no
`activation_epoch`, no KMS/HSM, no signing-key ratification, no
fast-sync restore, no KEMTLS redesign, and no consensus redesign are
required for this harness — it is operator-orchestration only.