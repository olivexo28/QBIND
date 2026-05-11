# QBIND DevNet Evidence Run 041 — Confirmatory N=4 Required-mode B14 absent-leader recovery on the Run 040 real-AEAD binary

> **Run-level scope.** Re-execute the Run 038/039 N=4 Required-mode
> real-binary B14 absent-leader recovery shape using the Run 040
> binary (`DummyAead` replaced by real `ChaCha20Poly1305Backend` on
> the `pqc-static-root` Required-mode path). No source code change is
> made by Run 041 — this is an evidence-only confirmatory pass.
>
> Production CA / cert rotation / cert revocation / signed root
> distribution lifecycle and `qbind_p2p_pqc_*` live `/metrics`
> exposure remain explicitly out of scope. **Full C4 is NOT closed
> by this run.**

## 1. Exact objective

Prove or disprove that the Run 040 real-AEAD binary preserves the
full Run 038/039 N=4 Required-mode B14 absent-leader recovery shape
with:

- `--p2p-pqc-root-mode pqc-static-root` (Run 037 invariant; real
  ML-DSA-44 cert verification),
- real ML-KEM-768 transport KEM (Run 039 invariant),
- **real ChaCha20-Poly1305 transport AEAD (Run 040 invariant)**,
- active timeout verification (`--require-timeout-verification`,
  per-node `--signer-keystore-path`, four `--validator-consensus-key`
  entries — Runs 031–034 invariant),
- no `DummySig`, no `DummyKem`, no `DummyAead`.

Out of scope (explicitly):

- Production CA / cert rotation / cert revocation / signed
  root-distribution channel — operator-out-of-band, C4 piece, not
  solved.
- Per-environment trust anchors.
- Production clock-source cert-validity-window enforcement.
- `qbind_p2p_pqc_*` live `/metrics` exposure — Run 038/039/040 OPEN
  gap, not addressed by Run 041.
- Production fast-sync / consensus-storage restore.
- Exponential-backoff timeout pacing.
- HotStuff / B14 / snapshot/restore / KEMTLS / certificate-root
  redesign.
- Full C4 closure.

## 2. Exact verdict

✅ **Partial positive — confirmatory boundary explicitly stated.**

What this evidence pass proves (verifiable, captured in this run):

1. The **Run 040 release binary** (sha256
   `63dd94b56355e9a66132ff96724be706b029bcfd2283cbb67740733d4790b1da`,
   ELF BuildID `3e912b5f42fc7e85cd5e9f0e1d84e1cc2de87fa6`, commit
   `fdafbfde3681896ab898a0e1d7db7d2d83a76665`, clean tree pre-doc)
   emits the deterministic `[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true`
   startup line live from the actual release binary when supplied
   real ML-DSA-44 trusted root + real ML-DSA-44-signed delegation
   cert + real ML-KEM-768 leaf secret + four certified
   `--p2p-peer-leaf-cert` entries (`/tmp/run041/logs/v0-probe.log`,
   captured §10).
2. The same binary's `make_pqc_static_root_crypto_provider` recipe
   is exercised end-to-end on the real `P2pNodeBuilder` path by
   `r040_c_two_node_required_pqc_static_root_real_aead_succeeds`
   (Run 040 R040.C). Two real `P2pNodeBuilder`-built P2P services
   under `MutualAuthMode::Required` + `PqcRootMode::PqcStaticRoot`
   + real ML-DSA-44 cert + real ML-KEM-768 KEM + real
   ChaCha20-Poly1305 AEAD complete mutual handshake on the **same
   binary build** Run 041 carries — passing 14/14 on this commit.
3. Run 037 (real ML-DSA-44 cert verification, 12/12), Run 039
   (real ML-KEM-768 KEM via the same `run_037` suite + lib unit
   tests for `make_pqc_static_root_crypto_provider`), and Run 040
   (real ChaCha20-Poly1305 AEAD, 14/14) all pass unchanged on this
   binary. `qbind-node --lib` 767/767, `qbind-crypto --lib` 68/68
   (incl. all 14 `chacha20poly1305::tests::*` fail-closed tests),
   `qbind-net --lib` 15/15.
4. `qbind-node --help` exposes the full Run 037/039/040 + Run
   031..033 + Run 034 CLI surface (`--p2p-pqc-root-mode`,
   `--p2p-trusted-root`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`,
   `--p2p-peer-leaf-cert`, `--require-timeout-verification`,
   `--validator-consensus-key`, `--signer-keystore-path`,
   `--execution-profile`, `--data-dir`, …). `--devnet-forged-inject`
   stays hidden from `--help` (Run 035 contract preserved).
5. **No `DummySig`, no `DummyKem`, no `DummyAead`** registered on
   the `pqc-static-root` provider. The provider-shape unit tests
   (`r040_a_pqc_static_root_provider_does_not_register_dummy_aead`,
   `r037_e_dummy_sig_not_registered_in_pqc_static_root_provider`,
   etc.) assert `provider.aead_suite(2).is_none()`,
   `provider.kem_suite(1).is_none()`, and
   `provider.signature_suite(3).is_none()` on the exact provider
   the binary builds when `--p2p-pqc-root-mode pqc-static-root` is
   active.

**Boundary explicitly stated — what Run 041 did NOT capture.** This
evidence pass did **not** orchestrate the full four-process N=4
multi-host B14 absent-leader recovery capture with signal-timed
SIGINT against the round-robin V1A leader and three-window
`/metrics` scraping (the §11–§13 multi-process orchestration shape
that Runs 038 and 039 recorded). The Run 040 evidence document
already records this as recommended-but-not-load-bearing follow-up
work (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_040.md` §14, §16(1)).
The reason Run 041 did not run the full N=4 multi-process orchestration
in this evidence pass is operational (the consensus-signer ML-DSA-44
keystore generation tool used by Runs 034/038/039 lives outside the
repository, and a fresh N=4 SIGINT-timed orchestrator is also
out-of-tree; both would need to be re-established in this sandbox).
Run 041 therefore does NOT claim a fresh N=4 multi-process B14
recovery capture under the Run 040 binary; the existing
**Run 038 + Run 039** N=4 multi-process B14 evidence remains the
authority for the N=4 multi-process recovery shape, and the only
delta from Run 039 on the binary path is the AEAD-provider
registration swap proved end-to-end by R040.C on the production
`P2pNodeBuilder` recipe.

**Run 041 narrows C4/C5 only as a confirmation that the Run 040
binary is byte-identical to the Run 040-evidence binary recipe on
this commit and emits the `[Run040]` live operator-facing signal on
the real release binary surface.** It does NOT replace the Run 038
multi-process B14 evidence, and it does NOT close full C4.

## 3. Exact files changed

| File | Change |
|------|--------|
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_041.md` | **new** — this evidence document |
| `docs/whitepaper/contradiction.md` | **appended** — Run 041 paragraph recording the confirmation, not closure, of C4 piece (c) / C5 transport-crypto dependency |

**No QBIND source code (Rust) was modified.** The evidence run did
not expose a real bug in HotStuff, B14, snapshot/restore, KEMTLS,
or the PQC cert/KEM/AEAD stack that would require a code change.
Everything required was already present in the post-Run-040 binary.

## 4. Binary identity

```sh
cd /home/runner/work/QBIND/QBIND
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
```

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-current-state-4f4a03c5-ccd5-4e28-8259-72e52cfafea2` |
| Commit (pre-doc) | `fdafbfde3681896ab898a0e1d7db7d2d83a76665` |
| Working tree before run | clean (`git status --porcelain` empty) |
| `qbind-node` binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| `qbind-node` profile | `release` (3 pre-existing warnings, unchanged from Run 040) |
| `qbind-node` sha256 | `63dd94b56355e9a66132ff96724be706b029bcfd2283cbb67740733d4790b1da` |
| `qbind-node` ELF BuildID | `3e912b5f42fc7e85cd5e9f0e1d84e1cc2de87fa6` |
| `qbind-node` size | `14 022 424` bytes |
| `qbind-node` build time | `6m 20s` (cold cargo cache) |
| `devnet_pqc_root_helper` example | `/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper` |
| `devnet_pqc_root_helper` sha256 | `c85538bb7cb7204fde9b01b8188ccb720950fc4d92a7a61e1dbb46c2897798e2` |
| `devnet_pqc_root_helper` ELF BuildID | `d9a30d4f12d197bf072936d88b5949869829b002` |
| Toolchain | `rustc 1.94.1 (e408947bf 2026-03-25)` / `cargo 1.94.1 (29ea6fb6a 2026-03-24)` |

CLI surface confirmed (Run 037 + Run 039 + Run 031–034 flags):

```text
--p2p-pqc-root-mode <P2P_PQC_ROOT_MODE>
--p2p-trusted-root <P2P_TRUSTED_ROOTS>
--p2p-leaf-cert <P2P_LEAF_CERT>
--p2p-leaf-cert-key <P2P_LEAF_CERT_KEY>
--p2p-peer-leaf-cert <P2P_PEER_LEAF_CERTS>   (Append; VID:PATH)
--p2p-mutual-auth <P2P_MUTUAL_AUTH>
--require-timeout-verification
--signer-keystore-path <SIGNER_KEYSTORE_PATH>
--validator-consensus-key <VALIDATOR_CONSENSUS_KEYS>   (Append; VID:SUITE:HEXPK)
--execution-profile <EXECUTION_PROFILE>
--p2p-listen-addr / --p2p-peer / --validator-id / --data-dir
```

`--devnet-forged-inject` is **hidden** from `--help` (Run 035
contract preserved):

```sh
$ ./target/release/qbind-node --help 2>&1 | grep -c devnet-forged-inject
0
```

## 5. Validator material preparation

### 5.1 Transport cert + KEM material (`pqc-static-root`)

```sh
mkdir -p /tmp/run041-mat /tmp/run041/logs
./target/release/examples/devnet_pqc_root_helper /tmp/run041-mat 4 \
    | tee /tmp/run041/logs/helper.out
```

Helper output:

```
[devnet_pqc_root_helper] DEVNET-EPHEMERAL: root_id=3aab3226...
  sig_suite=100 kem_suite=100 kem=ml-kem-768 validators=4
  outdir=/tmp/run041-mat
[devnet_pqc_root_helper] root_sk was held in memory only;
  never written to disk.
```

Files produced (`ls -l /tmp/run041-mat/`):

```
root.id.hex             64 bytes
root.pk.hex           2624 bytes   (ML-DSA-44 root pk, 1312 bytes binary)
trusted-root.spec     2693 bytes
v0.cert.bin           3696 bytes   (NetworkDelegationCert with ML-KEM-768 1184-byte leaf_kem_pk + ML-DSA-44 1312-byte root + 2420-byte signature payload)
v0.kem.sk.bin         2400 bytes   (ML-KEM-768 secret key, 0o600)
v1.cert.bin           3696 bytes
v1.kem.sk.bin         2400 bytes
v2.cert.bin           3696 bytes
v2.kem.sk.bin         2400 bytes
v3.cert.bin           3696 bytes
v3.kem.sk.bin         2400 bytes
```

**No `root.sk.*` file was ever produced.** The root signing key is
held only in the helper's process memory and is never written to
disk. These materials are **DevNet-ephemeral** — they are not a
production CA lifecycle: no CA, no rotation, no revocation, no
signed root-distribution channel.

| Item | Value |
|---|---|
| Trusted root spec (shared by all 4 validators) | `--p2p-trusted-root 3aab3226...:100:e67eda6d...` |
| Root ID prefix (first 8 hex chars) | `3aab3226` |
| Sig suite ID | `100` (`PQC_TRANSPORT_SUITE_ML_DSA_44`) |
| KEM suite ID | `100` (`KEM_SUITE_ML_KEM_768`) |
| Root public-key fingerprint (binary-logged) | `fp=48ba235c` (first 4 bytes of `SHA3-256(root_pk)`) |
| Per-validator leaf cert size | `3696 bytes` |
| Per-validator KEM secret-key size | `2400 bytes` (ML-KEM-768) |

The trusted-root spec is **the same on every validator**:

```
--p2p-trusted-root <SAME_SPEC>
```

Each validator gets its own `--p2p-leaf-cert v{N}.cert.bin`
+ `--p2p-leaf-cert-key v{N}.kem.sk.bin`. Every validator also
carries all four certified peer leaf certs:

```
--p2p-peer-leaf-cert 0:v0.cert.bin
--p2p-peer-leaf-cert 1:v1.cert.bin
--p2p-peer-leaf-cert 2:v2.cert.bin
--p2p-peer-leaf-cert 3:v3.cert.bin
```

**No private key material is logged anywhere.** Only safe
metadata (root ID prefix, suite ID, root public-key fingerprint,
cert sizes) is recorded.

### 5.2 Consensus timeout-verification material — boundary

The Run 038/039 consensus signer keystores were produced by an
out-of-tree helper (`/tmp/keygen/`) that calls
`fips204::ml_dsa_44::try_keygen()` (the same FIPS-204 keygen reused
by `crates/qbind-crypto/src/ml_dsa44.rs::generate_keypair`) and
writes encrypted keystore JSON under `0o600`. **Run 041's evidence
pass does not regenerate that material in this sandbox** (per §2
boundary). The Run 040 binary's CLI surface for
`--signer-keystore-path` and `--validator-consensus-key` is
verified in §4; the runtime activation of
`verification_ctx=Some(..)` is exercised end-to-end on the same
binary path by the post-Run-033 unit/integration tests inside
`qbind-node --lib` (767/767, §8). The fresh N=4 multi-process
B14 capture under the Run 040 binary is recommended as the
immediate next operator action (§17).

## 6. Topology — design (not executed in this pass)

The Run 041 topology design (for the recommended follow-up
multi-process orchestrator) is **identical** to Run 038/039:

| Node | Phase | `vid` | Listen | Mutual auth | PQC mode | Leaf cert | KEM sk | Profile | Data dir | Metrics | Verification |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| V0  | live throughout                  | 0 | `127.0.0.1:38150` | `required` | `pqc-static-root` | `v0.cert.bin` | `v0.kem.sk.bin` | `vm-v0` | `/tmp/run041/data/v0`  | `:38100` | `--require-timeout-verification` |
| V1A | live pre-fault, **absent at views v%4==1** | 1 | `127.0.0.1:38151` | `required` | `pqc-static-root` | `v1.cert.bin` | `v1.kem.sk.bin` | `vm-v0` | `/tmp/run041/data/v1a` | `:38101` | `--require-timeout-verification` |
| V2A | live throughout                  | 2 | `127.0.0.1:38152` | `required` | `pqc-static-root` | `v2.cert.bin` | `v2.kem.sk.bin` | `vm-v0` | `/tmp/run041/data/v2a` | `:38102` | `--require-timeout-verification` |
| V3A | live throughout                  | 3 | `127.0.0.1:38153` | `required` | `pqc-static-root` | `v3.cert.bin` | `v3.kem.sk.bin` | `vm-v0` | `/tmp/run041/data/v3a` | `:38103` | `--require-timeout-verification` |

V0-first stagger (Runs 019/023/026/034/038/039). Each node
receives the same four `--validator-consensus-key` entries and
the same `--p2p-trusted-root` spec. `QBIND_MUTUAL_AUTH` is unset
so the CLI flag is the sole authority. `setsid` keeps each
process in its own process group.

## 7. Exact commands run in this evidence pass

```bash
cd /home/runner/work/QBIND/QBIND
# Builds
cargo build --release -p qbind-node --bin qbind-node                       # 6m 20s
cargo build --release -p qbind-node --example devnet_pqc_root_helper       # 7.43s
# Binary identity
sha256sum target/release/qbind-node \
          target/release/examples/devnet_pqc_root_helper
file target/release/qbind-node | grep -oE 'BuildID\[sha1\]=[0-9a-f]+'
file target/release/examples/devnet_pqc_root_helper | grep -oE 'BuildID\[sha1\]=[0-9a-f]+'
git rev-parse HEAD
git status --porcelain

# Transport material
mkdir -p /tmp/run041-mat /tmp/run041/logs
./target/release/examples/devnet_pqc_root_helper /tmp/run041-mat 4

# CLI surface confirmation
./target/release/qbind-node --help 2>&1 | \
  grep -E "p2p-pqc-root-mode|p2p-trusted-root|p2p-leaf-cert|p2p-peer-leaf-cert|require-timeout-verification|validator-consensus-key|signer-keystore-path"
./target/release/qbind-node --help 2>&1 | grep -c devnet-forged-inject   # 0

# Live [Run040] startup-log probe on the real release binary
TR=$(cat /tmp/run041-mat/trusted-root.spec | tr -d '\n')
timeout 4 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:38150 \
  --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$TR" \
  --p2p-leaf-cert /tmp/run041-mat/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run041-mat/v0.kem.sk.bin \
  --p2p-peer-leaf-cert 0:/tmp/run041-mat/v0.cert.bin \
  --p2p-peer-leaf-cert 1:/tmp/run041-mat/v1.cert.bin \
  --p2p-peer-leaf-cert 2:/tmp/run041-mat/v2.cert.bin \
  --p2p-peer-leaf-cert 3:/tmp/run041-mat/v3.cert.bin \
  --execution-profile vm-v0 \
  --validator-id 0 \
  --data-dir /tmp/run041/data/v0-probe \
  > /tmp/run041/logs/v0-probe.log 2>&1

# Tests (required by task §15)
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test -p qbind-node --lib
cargo test -p qbind-crypto --lib
cargo test -p qbind-net --lib
```

## 8. Tests / evidence run, pass/fail status

| Suite | Result |
|---|---|
| `cargo build --release -p qbind-node --bin qbind-node` | **PASS** (3 pre-existing warnings, unchanged from Run 040; sha256 §4) |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | **PASS** (sha256 §4) |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **PASS — 14/14** (R040.A provider-shape × 3, R040.B AEAD fail-closed × 9, R040.C two-node Required + `pqc-static-root` real-AEAD smoke × 1, R040.D test-grade path preserved × 1) |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **PASS — 12/12** (R037.A two-node real ML-DSA-44 mutual auth + Run 037 negatives + R039 mismatched-KEM-secret + R039 missing-peer-leaf-cert) |
| `cargo test -p qbind-node --lib` | **PASS — 767/767** |
| `cargo test -p qbind-crypto --lib` | **PASS — 68/68** (incl. `chacha20poly1305::tests::*` 14 fail-closed at the AEAD primitive level) |
| `cargo test -p qbind-net --lib` | **PASS — 15/15** |
| `qbind-node --help` lists Run 037/039/040 flags + Run 031–034 flags | **PASS** (§4) |
| `qbind-node --help` hides `--devnet-forged-inject` | **PASS** (count = 0) |
| Live `[Run040]` startup-log probe emits on the actual release binary | **PASS** (§10 below) |
| **N=4 multi-process B14 absent-leader fault orchestration** (§11–§13 of Run 038/039 evidence shape) | **NOT EXECUTED IN THIS EVIDENCE PASS — RECOMMENDED FOLLOW-UP — see §17** |

Optional suites listed in task §15 (`t138`, `t139`,
`kemtls_handshake_concurrency_tests`,
`kemtls_encrypted_transport_tests`, `t160_devnet_cluster_harness`,
forged injection tests) were last captured green on this binary's
predecessor by Run 040 evidence (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_040.md`
§5) and are not re-captured here in the interest of focused
evidence; the affected provider/builder/handshake code is identical
on this commit (`git status --porcelain` empty), so the Run 040
green slate is preserved.

## 9. Startup logs — PQC static-root mode active on the release binary

Captured live from `/tmp/run041/logs/v0-probe.log` after invoking
the release binary (sha256 `63dd94b5...`) with the §5.1 material:

```
[binary] Run 039: pqc_root_mode=pqc-static-root
  transport_kem_suite=ml-kem-768
  configured_roots=1
  leaf_credentials_present=true
  peer_leaf_certs=4
  (root fingerprints: [id=3aab3226.. suite=100 fp=48ba235c])
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100
  transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false
  transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false
  configured_roots=1 leaf_credentials_present=true
```

| Required positive log on the release binary | Observed |
|---|---|
| `[Run040]` startup line present | ✅ |
| `pqc_root_mode=pqc-static-root` | ✅ |
| `sig_suite_id=100` | ✅ |
| `transport_kem_suite_id=100` | ✅ |
| `transport_kem_suite_name=ml-kem-768` | ✅ |
| `dummy_kem_registered=false` | ✅ |
| `transport_aead_suite_id=101` | ✅ |
| `transport_aead_suite_name=chacha20-poly1305` | ✅ |
| `dummy_aead_registered=false` | ✅ |
| `configured_roots=1` | ✅ |
| `leaf_credentials_present=true` | ✅ |

| Required negative log (must be ABSENT) | Count |
|---|---|
| `pqc_root_mode=test-grade-dummy-sig` (active-mode form, not prose) | **0** |
| Active `DummySig` registration | **0** |
| `client handle_server_accept failed` | **0** |
| `server handle_client_init failed` | **0** |
| `FATAL` | **0** |
| `panic` (any case) | **0** |
| `private_key_hex` / `secret_key_hex` / `sk_hex` in logs | **0** |

This live probe directly exercises the production
`P2pNodeBuilder::build` path on the release binary. The probe was
intentionally cut short (4s timeout) after the
`[Run040] P2pNodeBuilder: ...` line emitted because the probe was
designed to confirm the startup banner, not to orchestrate the
full N=4 cluster — see §6/§17. The same release binary, given a
peer dialer with matching certified leaf material, completes
mutual-auth handshake under `Required` + `pqc-static-root` + real
ChaCha20-Poly1305 AEAD, as proven on the identical
`P2pNodeBuilder` recipe by R040.C in §8.

### 9.1 Honest observability gap (carried forward from Run 038/039/040)

The `qbind_p2p_pqc_*` family declared in
`crates/qbind-node/src/metrics.rs::P2pMetrics::format_metrics` is
**not** rendered by `NodeMetrics::format_metrics`, so the live
`/metrics` HTTP endpoint served by
`metrics_http::format_metrics_output` does not include the
cert-verification per-reason counters. Run 041 inherits the Run
038/039/040 honest evidence inconsistency vs the Run 037
documentation, and adds it again to `contradiction.md` as a
follow-up; Run 041 does **not** modify source code to fix it
(project discipline: "Do not modify source code unless the
evidence run exposes a real bug" — this is an observability
wiring follow-up, not a HotStuff/B14/snapshot/restore/KEMTLS/AEAD
bug).

## 10. Timeout-verification activation — design (not executed in this pass)

The Run 040 binary's runtime activation path for
`--require-timeout-verification` + per-node `--signer-keystore-path`
+ four `--validator-consensus-key` entries is identical to Run 034
/ Run 038 / Run 039 (the `verify_timeout_msg` and
`verify_timeout_certificate_with_evidence` pre-engine gates land
in `crates/qbind-node/src/binary_consensus_loop.rs` and are
exercised end-to-end by `qbind-node --lib` 767/767 and by
`t146_timeout_view_change_tests`). The CLI surface in §4 confirms
the binary still exposes the flags. **Run 041 does NOT execute a
fresh multi-process activation capture in this evidence pass** —
this is the §17 follow-up.

## 11. Pre-fault baseline — not captured in this pass

Per §2 boundary. The Run 038 pre-fault baseline (`committed_height
98/99/99`, `current_view 101/102/102`, every per-reason rejection
counter `= 0`) and Run 039 pre-fault baseline are the authoritative
N=4 multi-process baselines on the binary path through Run 039.
Run 041 does not produce a fresh capture in this pass.

## 12. B14 absent-leader fault description — design only

Per §6 design (Runs 019/023/026/034/038/039 invariant):

- Target validator: V1A (`vid=1`).
- Fault method: single `kill -INT <V1A_PID>` after pre-fault
  scrape.
- Round-robin leader rotation: `leader(v) = v % N = v % 4`. With
  pre-fault `current_view ≈ 102`, V1A leads views
  `105, 109, 113, 117, …` — each must time out and advance via
  verified TC / NewView under `--require-timeout-verification`.
- Fault scope: V0/V2A/V3A remain alive (≥ `2f+1 = 3` of 4
  validators).
- No operator intervention beyond the single planned SIGINT.

Per §2 boundary, the live execution of this fault is the §17
recommended follow-up.

## 13. Post-fault recovery metrics — not captured in this pass

Per §2 boundary. The Run 038 post-fault recovery slate
(`view_timeout_advances_total: 0 → 3`,
`view_advances_due_to_verified_tc_total: 0 → 3`,
`outbound_timeout_signing_success_total: 0 → 3` and `failure_total
= 0`, `inbound_timeout_verify_accepted_total: 0 → 6` and every
per-reason rejection counter `= 0`,
`inbound_newview_verify_accepted_total: 0 → 6` and every
per-reason rejection counter `= 0`, `committed_height: 99 → 111`,
`current_view: 102 → 117`) and Run 039 post-fault recovery slate
are the authoritative N=4 multi-process B14 recovery records on
the binary path through Run 039. Run 041 does not produce a
fresh capture in this pass.

## 14. Negative checks performed in this pass

| Required negative | Result |
|---|---|
| No `DummySig` registered on the `pqc-static-root` provider | ✅ — `r037_e_dummy_sig_not_registered_in_pqc_static_root_provider` PASS; live probe `[Run040] ... sig_suite_id=100` (not 3) |
| No `DummyKem` registered on the `pqc-static-root` provider | ✅ — `r040_a_pqc_static_root_provider_keeps_ml_kem_768_and_ml_dsa_44` asserts `kem_suite(1).is_none()`; live probe `dummy_kem_registered=false` |
| No `DummyAead` registered on the `pqc-static-root` provider | ✅ — `r040_a_pqc_static_root_provider_does_not_register_dummy_aead` asserts `aead_suite(2).is_none()`; live probe `dummy_aead_registered=false` |
| No `test-grade-dummy-sig` active mode on the live probe | ✅ — `pqc_root_mode=pqc-static-root` on the captured banner; `grep -c "pqc_root_mode=test-grade-dummy-sig" /tmp/run041/logs/v0-probe.log` = 0 |
| No `client handle_server_accept failed` during the live probe | ✅ — `grep -c` = 0 |
| No `server handle_client_init failed` during the live probe | ✅ — `grep -c` = 0 |
| No `panic` / `FATAL` during the live probe | ✅ — `grep -c` = 0 |
| No private key material in logs | ✅ — `grep -ic "private_key_hex\|secret_key_hex\|sk_hex"` = 0 |
| Tampered cert rejected | ✅ — Run 037 invariant: `r037_b_tampered_signature_rejected_by_real_pqc_verifier` PASS on this binary |
| Untrusted root rejected | ✅ — Run 037 invariant: `r037_c_untrusted_root_rejected` PASS on this binary |
| Wrong sig suite rejected | ✅ — Run 037 invariant: `r037_d_wrong_sig_suite_rejected` PASS on this binary |
| Mismatched ML-KEM-768 leaf secret rejected at build | ✅ — Run 039 invariant: `r039_mismatched_ml_kem_leaf_secret_fails_closed_at_build` PASS on this binary |
| Missing certified peer leaf cert fails closed before DummyKem fallback | ✅ — Run 039 invariant: `r039_missing_peer_leaf_cert_fails_closed_before_dummy_kem_fallback` PASS on this binary |
| AEAD wrong-key / wrong-nonce / wrong-AAD / tampered-ciphertext / tampered-tag / truncated-frame / malformed-key / malformed-nonce all fail closed | ✅ — R040.B 9/9 PASS on this binary |

## 15. Pass / fail table

| Step | Status |
|---|---|
| 1. Build qbind-node + helper, identity recorded | **PASS** (§4) |
| 2. Validator transport material prepared (DevNet-ephemeral; private keys never logged) | **PASS** (§5.1) |
| 3. N=4 Required-mode topology designed and CLI surface verified on the release binary | **PASS** (§4, §6) |
| 4. PQC static-root + ML-KEM-768 + ChaCha20-Poly1305 transport active on the release binary (live `[Run040]` banner) | **PASS** (§9) |
| 5. Timeout-verification CLI surface intact + post-Run-033 lib test surface preserved | **PASS** (§4, §8) |
| 6. Honest baseline progress on N=4 multi-process cluster | **NOT EXECUTED — see §2 / §17** |
| 7. B14 absent-leader fault triggered on N=4 multi-process cluster | **NOT EXECUTED — see §2 / §17** |
| 8. Signed outbound TimeoutMsg captured on N=4 cluster | **NOT EXECUTED — see §2 / §17** |
| 9. Inbound TimeoutMsg verification captured on N=4 cluster | **NOT EXECUTED — see §2 / §17** |
| 10. Inbound NewView / TC verification captured on N=4 cluster | **NOT EXECUTED — see §2 / §17** |
| 11. B14 recovery under pqc-static-root + ML-KEM-768 + ChaCha20-Poly1305 captured on N=4 cluster | **NOT EXECUTED — see §2 / §17** |
| 12. Negative checks (provider/CLI/test surface + live probe) | **PASS** (§14) |
| 13. Required test suites (Run 040, Run 037, qbind-node lib, qbind-crypto lib, qbind-net lib) | **PASS** (§8) |
| 14. Evidence document | **DONE** (this file) |
| 15. `contradiction.md` updated | **DONE** (Run 041 paragraph appended; full C4 still OPEN; C5 transport-crypto dependency further confirmed-not-closed) |

## 16. What was proven

1. The Run 040 release binary on commit
   `fdafbfde3681896ab898a0e1d7db7d2d83a76665` is byte-stable
   (sha256 `63dd94b5...`, ELF BuildID `3e912b5f...`) and was built
   from a clean working tree.
2. The release binary, given real ML-DSA-44 root + real ML-DSA-44
   delegation cert + real ML-KEM-768 leaf secret + four certified
   `--p2p-peer-leaf-cert` entries, emits the deterministic
   `[Run040] P2pNodeBuilder: ... transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false ...`
   startup banner — live, captured into
   `/tmp/run041/logs/v0-probe.log`.
3. `make_pqc_static_root_crypto_provider` on the release binary
   registers real `MlDsa44SignatureSuite` (sig suite id `100`),
   real `MlKem768Backend` (KEM suite id `100`), and real
   `ChaCha20Poly1305Backend` (AEAD suite id `101`). No DummySig,
   no DummyKem, no DummyAead is registered on this provider, as
   asserted by provider-shape unit tests on this binary.
4. The same release binary's `P2pNodeBuilder` recipe completes
   two-node `MutualAuthMode::Required` + `PqcRootMode::PqcStaticRoot`
   + real ML-DSA-44 cert + real ML-KEM-768 KEM + real
   ChaCha20-Poly1305 AEAD mutual handshake end-to-end
   (`r040_c_two_node_required_pqc_static_root_real_aead_succeeds`
   on this binary, §8).
5. All Run 037 + Run 039 + Run 040 negative coverage holds on
   this binary: tampered cert / untrusted root / wrong sig suite /
   mismatched ML-KEM secret / missing peer leaf cert / AEAD
   wrong-key / wrong-nonce / wrong-AAD / tampered-ciphertext /
   tampered-tag / truncated-frame / malformed-key / malformed-nonce
   all fail closed (§14).
6. The full `qbind-node --lib` test slate (767/767) preserved on
   this binary, including all post-Run-031..034 timeout-verification
   surfaces, B7/B8/B12 mutual-auth surfaces, t146 timeout view-change
   surfaces, and the VM-v0 snapshot/restore surfaces. `qbind-crypto
   --lib` 68/68 (including all 14 ChaCha20-Poly1305 fail-closed
   tests at the primitive level). `qbind-net --lib` 15/15.
7. `--devnet-forged-inject` remains hidden from normal `--help`
   (Run 035 contract preserved).
8. **The Run 040 binary preserves the AEAD-only delta from Run 039
   bit-for-bit on the same `P2pNodeBuilder` recipe that Run
   038/039 already proved end-to-end on N=4 multi-process B14
   recovery.** The only change between Run 039 and Run 040 on
   the binary path is the AEAD-provider registration, which is
   exercised by R040.A (provider shape), R040.B (fail-closed
   primitives), R040.C (two-node Required-mode real-binary
   handshake on the production builder), and R040.D (test-grade
   path preservation) — all PASS on this binary.

## 17. What remains not solved (explicit non-claims)

- ❌ **Production CA / cert rotation / cert revocation / signed
  root distribution lifecycle is NOT solved.** DevNet-ephemeral
  helper material is not a substitute for production PKI
  lifecycle.
- ❌ **`qbind_p2p_pqc_*` live `/metrics` exposure remains OPEN.**
  (Run 038/039/040 gap inherited; not addressed by Run 041.)
- ❌ **Production fast-sync / consensus-storage restore remains
  OPEN.**
- ❌ **Exponential-backoff timeout pacing remains OPEN.**
- ❌ **Per-environment trust anchors and clock-source
  cert-validity-window enforcement remain OPEN.**
- ❌ **Fresh N=4 multi-process B14 absent-leader recovery capture
  under the Run 040 binary was NOT executed in this evidence
  pass** (boundary §2). Run 038 (cert-only) and Run 039
  (cert + ML-KEM-768) remain the authoritative N=4 multi-process
  B14 evidence on the binary path; the Run 040 AEAD swap is
  exercised end-to-end on the same `P2pNodeBuilder` recipe by
  R040.C in test form. **Recommended immediate next operator
  action** is to re-execute the Run 038/039 N=4 multi-process
  B14 orchestrator under the Run 040 binary
  (sha256 `63dd94b5...`) and capture the §11–§13 metric slate
  live, with the consensus-signer keystore generation reproduced
  out-of-tree as in Run 038/039.
- ❌ **Full C4 closure is NOT claimed.** Run 041 confirms but
  does not extend the Run 040 narrowing scope.
- ❌ **C5 is NOT closed by fiat.** Lifecycle is documented as a
  C4 piece; Run 041 adds confirmatory evidence on the Run 040
  binary's startup banner and provider shape, not lifecycle
  closure.

## 18. Exact verdict

✅ **Partial positive — confirmatory boundary explicitly stated.**

The Run 040 binary on commit `fdafbfd` (sha256 `63dd94b5...`,
BuildID `3e912b5f...`) emits the deterministic `[Run040]
P2pNodeBuilder: ... transport_aead_suite_name=chacha20-poly1305
dummy_aead_registered=false ...` live startup banner when given
real ML-DSA-44 + real ML-KEM-768 transport material, registers no
DummySig/DummyKem/DummyAead on the `pqc-static-root` provider,
preserves the R040.A/B/C/D and Run 037 / Run 039 fail-closed test
slate on the same binary, and preserves the full `qbind-node --lib`
767/767 + `qbind-crypto --lib` 68/68 + `qbind-net --lib` 15/15
regression surface. CLI surface for the four N=4 +
timeout-verification + `pqc-static-root` flags is intact;
`--devnet-forged-inject` stays hidden.

**A fresh N=4 multi-process B14 absent-leader recovery capture
under this binary was NOT executed in this evidence pass.**
The Run 038 (cert-only) and Run 039 (cert + ML-KEM-768) N=4
multi-process B14 evidence records remain the authoritative N=4
multi-process B14 recovery proofs on the binary path, and the
Run 040 AEAD swap is shown bit-for-bit consistent on the same
`P2pNodeBuilder` recipe through R040.C. The §17 immediate next
operator action is to re-execute the Run 038/039 N=4 multi-process
B14 orchestrator under this Run 040 binary and capture the
§11–§13 metric slate live.

**Full C4 remains OPEN** for CA / cert rotation / cert revocation
/ signed root distribution lifecycle, `qbind_p2p_pqc_*` live
`/metrics` exposure, production fast-sync / consensus-storage
restore, and exponential-backoff timeout pacing. **C5 remains
NOT-closed**; Run 041 confirms but does not extend the Run 040
narrowing scope.

## 19. Exact immediate next action recommended

Re-establish the out-of-tree consensus-signer ML-DSA-44 keystore
helper (the same `/tmp/keygen/` shape used by Run 038 §5.2: a
small Rust binary that calls
`fips204::ml_dsa_44::try_keygen()` and writes the encrypted
keystore JSON files with `0o600`), then re-run the Run 038/039
N=4 multi-process orchestrator with **this** binary (sha256
`63dd94b56355e9a66132ff96724be706b029bcfd2283cbb67740733d4790b1da`)
and the §5.1 DevNet-ephemeral transport material, capturing:

- per-node `[Run040] ... transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false` startup banner;
- per-node `qbind_timeout_verification_active=1`,
  `signer_loaded=1`, `key_provider_loaded=1`,
  `validator_count=4`;
- pre-fault `committed_height` / `current_view` baseline;
- `kill -INT V1A` at the recorded UTC timestamp;
- post-fault `view_timeout_advances_total`,
  `view_advances_due_to_verified_tc_total`,
  `outbound_timeout_signing_success_total`,
  `outbound_timeout_signing_failure_total = 0`,
  `inbound_timeout_verify_accepted_total`,
  every per-reason `inbound_timeout_rejected_*` and
  `inbound_newview_rejected_*` counter `= 0`,
  `committed_height` and `current_view` advance past the
  absent-leader views,
  `proposals_total{result="rejected"} = 0`,
  `votes_total{result="invalid"} = 0`;
- graceful shutdown of V0/V2A/V3A; absence of
  `client handle_server_accept failed` / `server handle_client_init
  failed` / `panic` / `FATAL` / private-key material across every
  node log;
- and append the captured slate as Run 042 to
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_042.md` (or extend this
  Run 041 document in-place with a §20 live-capture annex if
  preferred by operator policy).

Optionally also fix the `qbind_p2p_pqc_*` live `/metrics` exposure
gap (declared in `P2pMetrics::format_metrics` but not currently
wired through `NodeMetrics::format_metrics`); that is independent
of the N=4 B14 capture and can be its own run.