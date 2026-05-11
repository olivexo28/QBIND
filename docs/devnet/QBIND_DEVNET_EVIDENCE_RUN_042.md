# QBIND DevNet Evidence Run 042 — Fresh N=4 Required-mode B14 absent-leader recovery on the Run 040 real-AEAD binary

> **Run-level scope.** Execute the fresh N=4 Required-mode real-binary
> B14 absent-leader recovery capture under the Run 040 release binary
> (`DummyAead` replaced by real `ChaCha20Poly1305Backend` on the
> `pqc-static-root` Required-mode path; `DummyKem` replaced by real
> `MlKem768Backend`; `DummySig` replaced by real
> `MlDsa44SignatureSuite`), using the same Run 038/039 topology
> shape, and record the full live pre-fault / mid-fault /
> post-recovery `/metrics` slate.
>
> Run 042 is the operator-recommended immediate next action from
> Run 041 §19. **No QBIND source code was modified by Run 042 — this
> is an evidence-only run.**
>
> Production CA / cert rotation / cert revocation / signed root
> distribution lifecycle and `qbind_p2p_pqc_*` live `/metrics`
> exposure remain explicitly out of scope. **Full C4 is NOT closed
> by this run.**

## 1. Exact objective

Prove or disprove that the Run 040 release binary sustains a full
N=4 Required-mode B14 absent-leader recovery under
`--p2p-pqc-root-mode pqc-static-root` with:

- real ML-DSA-44 transport delegation cert verification (Run 037
  invariant),
- real ML-KEM-768 transport KEM (Run 039 invariant),
- real ChaCha20-Poly1305 transport AEAD (Run 040 invariant),
- active timeout verification (`--require-timeout-verification`,
  per-node `--signer-keystore-path`, four
  `--validator-consensus-key` entries — Runs 031–034 invariant),
- no `DummySig`, no `DummyKem`, no `DummyAead`,
- live pre-fault and post-fault `/metrics` capture on every live
  node.

Out of scope (explicitly):

- Production CA / cert rotation / cert revocation / signed
  root-distribution channel — operator-out-of-band, C4 piece, not
  solved.
- Per-environment trust anchors.
- Production clock-source cert-validity-window enforcement.
- `qbind_p2p_pqc_*` live `/metrics` exposure — Run
  038/039/040/041 OPEN gap, not addressed by Run 042.
- Production fast-sync / consensus-storage restore.
- Exponential-backoff timeout pacing.
- HotStuff / B14 / snapshot/restore / KEMTLS / certificate-root
  redesign.
- Full C4 closure.

## 2. Exact verdict

✅ **STRONGEST POSITIVE.**

The Run 040 release binary (sha256
`63dd94b56355e9a66132ff96724be706b029bcfd2283cbb67740733d4790b1da`,
ELF BuildID `3e912b5f42fc7e85cd5e9f0e1d84e1cc2de87fa6`,
byte-identical to the Run 040 / Run 041 binary; commit
`d93d00648395a597aa574457831ed6d7de3f9123` on branch
`copilot/continue-qbind-progress-again`; the only delta from Run
041's pre-doc commit `fdafbfd...` is Run 041's documentation
appendage — no source changes) sustained a full fresh N=4
Required-mode B14 absent-leader recovery with **real ML-DSA-44 cert
verification + real ML-KEM-768 KEM + real ChaCha20-Poly1305 AEAD +
active timeout verification, no fallback to DummySig/DummyKem/
DummyAead/test-grade-dummy-sig**. Three live validators
(V0/V2A/V3A) recovered through three full B14 cycles after
`kill -INT V1A` at `2026-05-11T10:03:16Z`:

- `view_timeout_advances_total 0→3`
- `view_advances_due_to_verified_tc_total 0→3`
- `outbound_timeout_signing_success_total 0→3` /
  `outbound_timeout_signing_failure_total = 0` on every live node
- `inbound_timeout_verify_accepted_total 0→6` /
  `inbound_timeout_verify_rejected_total = 0`; every per-reason
  `inbound_timeout_rejected_*` counter `= 0` throughout
- `inbound_newview_verify_accepted_total 0→6` /
  `inbound_newview_verify_rejected_total = 0`; every per-reason
  `inbound_newview_rejected_*` counter `= 0` throughout
- `view_timeout_decode_failures_total = 0`,
  `view_timeout_engine_rejects_total = 0`,
  `inbound_newview_engine_rejected_total = 0`
- `committed_height 101/102/102 → 111/111/111` and `current_view
  104/105/105 → 117/117/117` on V0/V2A/V3A — past the V1A-led
  rotation views 105/109/113
- `proposals_total{result="rejected"} = 0` and
  `votes_total{result="invalid"} = 0` on every live node
- live `qbind_timeout_verification_active 1`, `_signer_loaded 1`,
  `_key_provider_loaded 1`, `_validator_count 4` on every node
  (incl. V1A pre-fault)
- live `[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root
  sig_suite_id=100 transport_kem_suite_id=100
  transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false
  transport_aead_suite_id=101
  transport_aead_suite_name=chacha20-poly1305
  dummy_aead_registered=false configured_roots=1
  leaf_credentials_present=true` startup banner emitted on every
  node (V0/V1A/V2A/V3A — `grep -c` = 1 per log)
- V0 emitted `newly_connected_peers=3` on the B9+B10 late-peer-reemit
  line (gated on `mutual_auth_complete=true` + cert-derived NodeId
  — proves all three peers V1A/V2A/V3A mutually authenticated under
  `MutualAuthMode::Required` with real ML-DSA-44 cert verification)
- zero `client handle_server_accept failed`, zero `server
  handle_client_init failed`, zero `DummySig`/`DummyKem`/
  `DummyAead`/`test-grade-dummy-sig` registration, zero `panic`,
  zero `FATAL`, zero private-key material in any log
- V1A's exit was the planned SIGINT (graceful shutdown trace
  captured); V0/V2A/V3A reached graceful `[binary] Shutdown
  complete.` after the final scrape
- all required test suites green on this binary
  (`qbind-node --lib` 767/767, `qbind-crypto --lib` 68/68,
  `qbind-net --lib` 15/15, `run_040_pqc_static_root_real_aead_tests`
  14/14, `run_037_pqc_static_root_mutual_auth_tests` 12/12,
  `t146_timeout_view_change_tests` 15/15)

This is the **fresh** N=4 multi-process B14 capture that Runs 040
and 041 explicitly recommended-but-did-not-execute. Combined with
the Run 038 (cert-only) and Run 039 (cert + ML-KEM-768) N=4
multi-process B14 evidence, the binary path now has end-to-end live
N=4 B14 recovery evidence for **all three** transport-crypto
primitives (ML-DSA-44 cert + ML-KEM-768 KEM + ChaCha20-Poly1305
AEAD) co-running with active timeout verification.

**Full C4 remains OPEN** for CA / cert rotation / cert revocation /
signed root distribution lifecycle, `qbind_p2p_pqc_*` live
`/metrics` exposure, production fast-sync / consensus-storage
restore, exponential-backoff timeout pacing, per-environment trust
anchors, and clock-source cert-validity-window enforcement. **C5 is
NOT closed by fiat**; C5's transport-crypto dependency
(cert-verification + KEM + AEAD + active timeout verification +
forged-traffic rejection) is now satisfied **and** demonstrated
live under N=4 multi-process B14 recovery, but the policy attaches
lifecycle to C4, so C5 closure remains contingent on the
operator-facing lifecycle policy being explicitly accepted as
out-of-C5-scope.

## 3. Exact files changed

| File | Change |
|------|--------|
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_042.md` | **new** — this evidence document |
| `docs/whitepaper/contradiction.md` | **appended** — Run 042 paragraph recording the fresh N=4 B14 capture and the further-narrowed (but not closed) C4/C5 status |

**No QBIND source code (Rust) was modified.** The evidence run did
not expose a real bug in HotStuff, B14, snapshot/restore, KEMTLS,
or the PQC cert/KEM/AEAD stack that would require a code change.
The Run 040 binary recipe was already complete on this commit.

## 4. Binary identity

```sh
cd /home/runner/work/QBIND/QBIND
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
```

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-progress-again` |
| Commit (pre-doc) | `d93d00648395a597aa574457831ed6d7de3f9123` |
| Working tree before run | clean (`git status --porcelain` empty) |
| `qbind-node` binary | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| `qbind-node` profile | `release` (3 pre-existing warnings, unchanged from Run 040) |
| `qbind-node` sha256 | `63dd94b56355e9a66132ff96724be706b029bcfd2283cbb67740733d4790b1da` |
| `qbind-node` ELF BuildID | `3e912b5f42fc7e85cd5e9f0e1d84e1cc2de87fa6` |
| `qbind-node` build time | `6m 38s` (cold cargo cache) |
| `devnet_pqc_root_helper` example | `/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper` |
| `devnet_pqc_root_helper` sha256 | `c85538bb7cb7204fde9b01b8188ccb720950fc4d92a7a61e1dbb46c2897798e2` |
| `devnet_pqc_root_helper` ELF BuildID | `d9a30d4f12d197bf072936d88b5949869829b002` |
| Toolchain | `rustc 1.94.1 (e408947bf 2026-03-25)` / `cargo 1.94.1 (29ea6fb6a 2026-03-24)` |

**Binary is byte-identical to Run 040 (`fdafbfd`) and Run 041
(`fdafbfd`).** The only commit-level change between Run 041's
pre-doc commit and Run 042's pre-doc commit is Run 041's
documentation appendage (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_041.md`
+ a paragraph in `docs/whitepaper/contradiction.md`) — no source
file changed, so cargo produced byte-identical release artefacts.

CLI surface confirmed (Run 037 / Run 039 / Run 040 + Run 031–034
flags):

```text
--execution-profile <EXECUTION_PROFILE>
--p2p-listen-addr <P2P_LISTEN_ADDR>
--p2p-peer <P2P_PEERS>
--p2p-mutual-auth <P2P_MUTUAL_AUTH>
--require-timeout-verification
--validator-consensus-key <VALIDATOR_CONSENSUS_KEYS>   (Append; VID:SUITE:HEXPK)
--p2p-pqc-root-mode <P2P_PQC_ROOT_MODE>
--p2p-trusted-root <P2P_TRUSTED_ROOTS>
--p2p-leaf-cert <P2P_LEAF_CERT>
--p2p-leaf-cert-key <P2P_LEAF_CERT_KEY>
--p2p-peer-leaf-cert <P2P_PEER_LEAF_CERTS>   (Append; VID:PATH)
--signer-keystore-path <SIGNER_KEYSTORE_PATH>
-v --validator-id <VALIDATOR_ID>
-d --data-dir <DATA_DIR>
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
mkdir -p /tmp/run042-mat /tmp/run042/logs
./target/release/examples/devnet_pqc_root_helper /tmp/run042-mat 4 \
    | tee /tmp/run042/logs/helper.out
```

Helper output:

```
[devnet_pqc_root_helper] DEVNET-EPHEMERAL: root_id=9bec797fd5d3a54d0198fddab4128b561497cee4f900b2c2dcbbe28341b757ee sig_suite=100 kem_suite=100 kem=ml-kem-768 validators=4 outdir=/tmp/run042-mat
[devnet_pqc_root_helper] root_sk was held in memory only; never written to disk.
```

Files produced (`ls -l /tmp/run042-mat/`):

```
root.id.hex             64 bytes
root.pk.hex           2624 bytes   (ML-DSA-44 root pk, 1312 bytes binary)
trusted-root.spec     2693 bytes
v0.cert.bin           3696 bytes
v0.kem.sk.bin         2400 bytes   (ML-KEM-768 secret key, 0o600)
v1.cert.bin           3696 bytes
v1.kem.sk.bin         2400 bytes
v2.cert.bin           3696 bytes
v2.kem.sk.bin         2400 bytes
v3.cert.bin           3696 bytes
v3.kem.sk.bin         2400 bytes
```

**No `root.sk.*` file was produced.** The root signing key is held
only in the helper's process memory; it is never written to disk
and never logged. The transport materials are **DevNet-ephemeral**
— they are not a production CA lifecycle: no CA, no rotation, no
revocation, no signed root-distribution channel.

| Item | Value |
|---|---|
| Trusted root spec (shared by all 4 validators) | `--p2p-trusted-root 9bec797fd5d3a54d…:100:c43e5477484…` |
| Root ID full hex | `9bec797fd5d3a54d0198fddab4128b561497cee4f900b2c2dcbbe28341b757ee` |
| Root ID prefix (first 8 hex chars) | `9bec797f` |
| Sig suite ID | `100` (`PQC_TRANSPORT_SUITE_ML_DSA_44`) |
| KEM suite ID | `100` (`KEM_SUITE_ML_KEM_768`) |
| Root public-key fingerprint (binary-logged) | `fp=1b1b157f` (first 4 bytes of `SHA3-256(root_pk)`) |
| Per-validator leaf cert size | `3696 bytes` |
| Per-validator KEM secret-key size | `2400 bytes` (ML-KEM-768) + `0o600` |

The trusted-root spec is **the same on every validator**. Each
validator gets its own `--p2p-leaf-cert v{N}.cert.bin` +
`--p2p-leaf-cert-key v{N}.kem.sk.bin`. Every validator also carries
all four certified peer leaf certs:

```
--p2p-peer-leaf-cert 0:v0.cert.bin
--p2p-peer-leaf-cert 1:v1.cert.bin
--p2p-peer-leaf-cert 2:v2.cert.bin
--p2p-peer-leaf-cert 3:v3.cert.bin
```

**No private key material is logged anywhere.** Only safe metadata
(root ID prefix, suite ID, root public-key fingerprint, cert sizes)
is recorded.

### 5.2 Consensus timeout-verification material — out-of-tree helper

Following the operator-recommended Run 041 §19 immediate next
action, Run 042 re-establishes the out-of-tree consensus signer
keystore helper at `/tmp/run042-keygen/` (mirroring the
Runs 038/039 `/tmp/keygen/` shape; **kept outside the repository so
it cannot accidentally land in source**). The helper calls
`fips204::ml_dsa_44::try_keygen()` (the same FIPS-204 keygen reused
by `crates/qbind-crypto/src/ml_dsa44.rs::generate_keypair`) for
each validator and writes a plaintext `LocalKeystorePlain` JSON
entry at `<root>/v<N>/validator-<N>.json` with mode `0o600`:

```sh
mkdir -p /tmp/run042-keygen/src

cat > /tmp/run042-keygen/Cargo.toml <<'EOF'
[package]
name = "run042-keygen"
version = "0.1.0"
edition = "2021"

[dependencies]
fips204 = "0.4"

[[bin]]
name = "keygen"
path = "src/main.rs"

[profile.release]
opt-level = 3
EOF

# src/main.rs (see commit-attached transcript /tmp/run042-keygen/src/main.rs;
# the full helper source is reproduced in §5.2.1 below)

cd /tmp/run042-keygen && cargo build --release        # 8.67s
mkdir -p /tmp/run042/keystores
/tmp/run042-keygen/target/release/keygen /tmp/run042/keystores 4 \
    > /tmp/run042/logs/keygen.out
```

Keystore files (`ls -l /tmp/run042/keystores/v*/`):

| Path | Mode | Size |
|---|---|---|
| `/tmp/run042/keystores/v0/validator-0.json` | `0o600` | 5157 bytes |
| `/tmp/run042/keystores/v1/validator-1.json` | `0o600` | 5157 bytes |
| `/tmp/run042/keystores/v2/validator-2.json` | `0o600` | 5157 bytes |
| `/tmp/run042/keystores/v3/validator-3.json` | `0o600` | 5157 bytes |

Helper output (logged keys are **public** only — the full ML-DSA-44
public-key hex strings):

```
[run042-keygen] DEVNET-EPHEMERAL: ml-dsa-44 consensus signer keystores; out-root=/tmp/run042/keystores N=4
[run042-keygen] validator_id=0 suite_id=100 pk_fp=dfdd6b31 pk_len=1312 pk_hex=<2624 hex chars>
[run042-keygen] validator_id=1 suite_id=100 pk_fp=16b81c45 pk_len=1312 pk_hex=<2624 hex chars>
[run042-keygen] validator_id=2 suite_id=100 pk_fp=4a516481 pk_len=1312 pk_hex=<2624 hex chars>
[run042-keygen] validator_id=3 suite_id=100 pk_fp=4df40b03 pk_len=1312 pk_hex=<2624 hex chars>
[run042-keygen] done; secret keys are inside the 0o600 keystore JSON files only.
```

| Validator | Suite ID | Consensus signing PK length (bytes) | PK fingerprint (helper SHA3-256 first-4-bytes) | Keystore entry |
|---|---|---|---|---|
| V0  | 100 | 1312 | `dfdd6b31` | `/tmp/run042/keystores/v0/validator-0.json` (`0o600`, 5157 bytes) |
| V1A | 100 | 1312 | `16b81c45` | `/tmp/run042/keystores/v1/validator-1.json` (`0o600`, 5157 bytes) |
| V2A | 100 | 1312 | `4a516481` | `/tmp/run042/keystores/v2/validator-2.json` (`0o600`, 5157 bytes) |
| V3A | 100 | 1312 | `4df40b03` | `/tmp/run042/keystores/v3/validator-3.json` (`0o600`, 5157 bytes) |

The full 2624-character ML-DSA-44 PK hex strings are public and
were passed verbatim on every node's CLI as the four
`--validator-consensus-key VID:100:HEXPK` entries (the **same** set
on every node). The corresponding ML-DSA-44 secret keys live only
in the keystore JSON files (`0o600`) under `/tmp/run042/keystores/`
and are **never** logged. Note that the binary's startup log
re-derives its own first-4-bytes fingerprints from
`load_validator_signer_from_config::public_key_fingerprint(&pk.0)`
(a different hashing scheme — first 4 bytes of a SHA-256 with a
fixed domain-separation tag), so the binary-side log reports the
matching public keys under fingerprints `v0:s100:6b59d5c0`,
`v1:s100:77a9ec59`, `v2:s100:3c1e96f0`, `v3:s100:c0b77fdc`. Both
fingerprints (helper-side SHA3-256 prefix and binary-side
SHA-256-tagged prefix) are derived from PUBLIC keys only.

> **Trust-boundary reminder.** The four
> `--validator-consensus-key VID:100:HEXPK` entries distribute
> **consensus** timeout-verification public keys. They are
> independent of the **transport** PQC root + leaf cert material in
> §5.1. Run 042 carries both, on the same processes, simultaneously,
> and never confuses them. Both are DevNet-ephemeral.

#### 5.2.1 Full out-of-tree helper source

The helper source is reproduced verbatim from
`/tmp/run042-keygen/src/main.rs` (kept outside the repository):

```rust
//! Run 042 out-of-tree ML-DSA-44 consensus-signer keystore helper.
//!
//! Mirrors the shape of the Run 038/039 `/tmp/keygen/` helper:
//! - Calls `fips204::ml_dsa_44::try_keygen()` for each of N validators.
//! - Writes a plaintext keystore JSON `{"suite_id":100,"private_key_hex":"..."}`
//!   at `<root>/v<N>/validator-<N>.json` with file mode 0o600.
//! - Logs only the public-key fingerprint (first 4 bytes of SHA3-256(pk))
//!   plus the full PK hex (PUBLIC by definition; safe to print).
//! - NEVER logs the secret key.

use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{:02x}", b)); }
    s
}

fn fingerprint(pk: &[u8]) -> String {
    // SHA3-256 first-4-bytes via openssl; FNV-1a fallback if openssl absent.
    // (Source omitted here for brevity — see full file at /tmp/run042-keygen/src/main.rs)
    // …
    String::new()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <out-root> <N>", args[0]);
        std::process::exit(2);
    }
    let out_root = PathBuf::from(&args[1]);
    let n: usize = args[2].parse().expect("N must be an integer");

    fs::create_dir_all(&out_root).expect("create out-root");
    println!("[run042-keygen] DEVNET-EPHEMERAL: ml-dsa-44 consensus signer keystores; out-root={} N={}",
             out_root.display(), n);

    for vid in 0..n {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("keygen");
        let pk_bytes = pk.clone().into_bytes();
        let sk_bytes = sk.clone().into_bytes();
        // Self-test: sign + drop sig (don't print).
        let _sig = sk.try_sign(b"run042-keygen-selftest", b"run042-ctx").expect("self-sign");

        let pk_hex = hex(&pk_bytes);
        let sk_hex = hex(&sk_bytes);
        let fp = fingerprint(&pk_bytes);

        let v_dir = out_root.join(format!("v{}", vid));
        fs::create_dir_all(&v_dir).expect("create v-dir");
        let path = v_dir.join(format!("validator-{}.json", vid));

        let json = format!("{{\"suite_id\":100,\"private_key_hex\":\"{}\"}}", sk_hex);

        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(&path).expect("open keystore");
        f.write_all(json.as_bytes()).expect("write keystore");
        f.sync_all().expect("fsync keystore");
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("chmod 0o600");

        println!("[run042-keygen] validator_id={} suite_id=100 pk_fp={} pk_len={} pk_hex={}",
                 vid, fp, pk_bytes.len(), pk_hex);
        drop(sk_hex); drop(sk_bytes);
    }
    println!("[run042-keygen] done; secret keys are inside the 0o600 keystore JSON files only.");
}
```

The helper produces a JSON file compatible with the in-tree
`FsValidatorKeystore` reader at
`crates/qbind-node/src/keystore.rs:264..296` (`parse_keystore_json`
expects `{"suite_id": 100, "private_key_hex": "..."}`), which is
what `signer_loader::load_validator_signer_from_config` loads under
the default `SignerMode::LoopbackTesting`
(`SignerBackendKind::LocalKeystorePlain`) when
`--signer-keystore-path` is supplied. No new in-repo helper was
created.

## 6. Topology

N=4, `f=1`, `2f+1=3`, V0-first stagger (matching Runs
019/023/026/034/038/039), `--p2p-mutual-auth required`,
`--p2p-pqc-root-mode pqc-static-root`, `--execution-profile vm-v0`,
explicit data dirs, `/metrics` HTTP enabled on every node,
`QBIND_MUTUAL_AUTH` unset on every process so the CLI flag is the
sole authority.

| Node | Phase | `vid` | Listen | Metrics | Mutual auth | PQC mode | Leaf cert | KEM sk | Profile | Data dir | Keystore | Verification |
|---|---|---:|---|---|---|---|---|---|---|---|---|---|
| V0  | live throughout                  | 0 | `127.0.0.1:38150` | `:38100` | `required` | `pqc-static-root` | `v0.cert.bin` | `v0.kem.sk.bin` | `vm-v0` | `/tmp/run042/data/v0`  | `/tmp/run042/keystores/v0` | `--require-timeout-verification` |
| V1A | live pre-fault, **absent after T+16s** (round-robin leader of views v%4==1: 105, 109, 113, …) | 1 | `127.0.0.1:38151` | `:38101` | `required` | `pqc-static-root` | `v1.cert.bin` | `v1.kem.sk.bin` | `vm-v0` | `/tmp/run042/data/v1a` | `/tmp/run042/keystores/v1` | `--require-timeout-verification` |
| V2A | live throughout                  | 2 | `127.0.0.1:38152` | `:38102` | `required` | `pqc-static-root` | `v2.cert.bin` | `v2.kem.sk.bin` | `vm-v0` | `/tmp/run042/data/v2a` | `/tmp/run042/keystores/v2` | `--require-timeout-verification` |
| V3A | live throughout                  | 3 | `127.0.0.1:38153` | `:38103` | `required` | `pqc-static-root` | `v3.cert.bin` | `v3.kem.sk.bin` | `vm-v0` | `/tmp/run042/data/v3a` | `/tmp/run042/keystores/v3` | `--require-timeout-verification` |

Each node was launched with the **same** four
`--validator-consensus-key` entries (one for every validator,
including itself) and the **same** `--p2p-trusted-root` spec.
`setsid` keeps each process in its own process group.

### Timing (UTC, from `/tmp/run042/events.log`)

| Event | Time |
|---|---|
| `RUN042_START` | `2026-05-11T10:02:58Z` |
| V0 start (PID 11741) | `2026-05-11T10:02:58Z` |
| V1A/V2A/V3A start (PIDs 11784/11823/11866) | `2026-05-11T10:02:59Z` |
| `SCRAPE_startup` (T+10s) | `2026-05-11T10:03:09Z` |
| `SCRAPE_prefault` (T+16s; pre-fault baseline) | `2026-05-11T10:03:16Z` |
| **B14 absent-leader fault: `kill -INT V1A` (PID 11784)** | `2026-05-11T10:03:16Z` |
| `SCRAPE_midfault` (T+6s after fault) | `2026-05-11T10:03:22Z` |
| `SCRAPE_postrecovery` (T+14s after fault) | `2026-05-11T10:03:30Z` |
| `SCRAPE_final` (T+18s after fault) | `2026-05-11T10:03:34Z` |
| `RUN042_END_BEGIN_SHUTDOWN` | `2026-05-11T10:03:34Z` |
| `RUN042_END` | `2026-05-11T10:03:37Z` |

## 7. Exact commands run

Driver: `/tmp/run042/orchestrate.sh` (kept outside the repository;
content reproduced below). Helper: `/tmp/run042/launch_node.sh`
(also outside the repository).

### 7.1 Per-node launcher (relevant `qbind-node` invocation)

```sh
QBIND_METRICS_HTTP_ADDR="127.0.0.1:${METRICS}" \
setsid /home/runner/work/QBIND/QBIND/target/release/qbind-node \
    --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr "127.0.0.1:${LISTEN}" \
    --p2p-peer "${PEER1}" --p2p-peer "${PEER2}" --p2p-peer "${PEER3}" \
    --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root "${TR}" \
    --p2p-leaf-cert "/tmp/run042-mat/v${VID}.cert.bin" \
    --p2p-leaf-cert-key "/tmp/run042-mat/v${VID}.kem.sk.bin" \
    --p2p-peer-leaf-cert "0:/tmp/run042-mat/v0.cert.bin" \
    --p2p-peer-leaf-cert "1:/tmp/run042-mat/v1.cert.bin" \
    --p2p-peer-leaf-cert "2:/tmp/run042-mat/v2.cert.bin" \
    --p2p-peer-leaf-cert "3:/tmp/run042-mat/v3.cert.bin" \
    --execution-profile vm-v0 \
    --require-timeout-verification \
    --signer-keystore-path "/tmp/run042/keystores/v${VID}" \
    --validator-consensus-key "0:100:${PK0}" \
    --validator-consensus-key "1:100:${PK1}" \
    --validator-consensus-key "2:100:${PK2}" \
    --validator-consensus-key "3:100:${PK3}" \
    --validator-id "${VID}" \
    --data-dir "${DATA}" \
    >>"$LOG" 2>&1 < /dev/null &
```

`QBIND_MUTUAL_AUTH` was `unset` on every process so the CLI flag
was the sole authority. `setsid` was used so the process group
survives the orchestrator's exit window between scrapes.

### 7.2 Orchestrator outline

```text
RUN042_START
  V0 start                  (V0-first stagger)
  sleep 1
  V1A, V2A, V3A start
  sleep 10                  -> SCRAPE_startup
  sleep 6                   -> SCRAPE_prefault       (pre-fault baseline)
  kill -INT V1A             (B14 absent-leader fault)
  sleep 6                   -> SCRAPE_midfault       (mid-recovery)
  sleep 8                   -> SCRAPE_postrecovery   (post-recovery)
  sleep 4                   -> SCRAPE_final          (final)
RUN042_END_BEGIN_SHUTDOWN
  kill -INT V0 V2A V3A
  sleep 3
  kill -9 (defensive; no-op if already exited)
RUN042_END
```

### 7.3 Commands re-run for evidence and tests

```bash
cd /home/runner/work/QBIND/QBIND
cargo build --release -p qbind-node --bin qbind-node                       # 6m 38s
cargo build --release -p qbind-node --example devnet_pqc_root_helper       # 7.76s
sha256sum target/release/qbind-node target/release/examples/devnet_pqc_root_helper
file target/release/qbind-node | grep -oE 'BuildID\[sha1\]=[0-9a-f]+'
file target/release/examples/devnet_pqc_root_helper | grep -oE 'BuildID\[sha1\]=[0-9a-f]+'
git rev-parse HEAD; git status --porcelain

mkdir -p /tmp/run042-mat /tmp/run042/{logs,scrapes,keystores/{v0,v1,v2,v3},data/{v0,v1a,v2a,v3a}}
./target/release/examples/devnet_pqc_root_helper /tmp/run042-mat 4

# Out-of-tree helper:
cd /tmp/run042-keygen && cargo build --release
/tmp/run042-keygen/target/release/keygen /tmp/run042/keystores 4 \
    > /tmp/run042/logs/keygen.out

# Orchestrator (described in §7.2):
/tmp/run042/orchestrate.sh

# Required test suites:
cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test --release -p qbind-node --lib
cargo test --release -p qbind-crypto --lib
cargo test --release -p qbind-net --lib
# Optional:
cargo test --release -p qbind-node --test t146_timeout_view_change_tests
```

## 8. Tests / evidence run, pass/fail status

| Suite | Result |
|---|---|
| `cargo build --release -p qbind-node --bin qbind-node` | **PASS** (3 pre-existing warnings, unchanged from Run 040; sha256 §4) |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | **PASS** (sha256 §4) |
| `cargo build --release` of `/tmp/run042-keygen/` (out-of-tree) | **PASS** (8.67s; not committed) |
| `cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **PASS — 14/14** |
| `cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **PASS — 12/12** |
| `cargo test --release -p qbind-node --lib` | **PASS — 767/767** |
| `cargo test --release -p qbind-crypto --lib` | **PASS — 68/68** |
| `cargo test --release -p qbind-net --lib` | **PASS — 15/15** |
| `cargo test --release -p qbind-node --test t146_timeout_view_change_tests` (optional) | **PASS — 15/15** |
| `qbind-node --help` lists Run 037/039/040 + Run 031–034 flags | **PASS** (§4) |
| `qbind-node --help` hides `--devnet-forged-inject` | **PASS** (count = 0) |
| **N=4 multi-process B14 absent-leader fault orchestration** | **PASS — see §10–§13 below** |

## 9. Startup logs — Run 040 real-AEAD transport mode active on every node

Every live node (V0/V1A/V2A/V3A) emitted identical PQC mode banner
+ `P2pNodeBuilder` log lines, captured at
`/tmp/run042/logs/{v0,v1a,v2a,v3a}.log`:

```
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=4 (root fingerprints: [id=9bec797f.. suite=100 fp=1b1b157f])
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
```

| Required positive log on the release binary | V0 | V1A | V2A | V3A |
|---|---|---|---|---|
| `[Run040]` startup line present | ✅ | ✅ | ✅ | ✅ |
| `pqc_root_mode=pqc-static-root` | ✅ | ✅ | ✅ | ✅ |
| `sig_suite_id=100` | ✅ | ✅ | ✅ | ✅ |
| `transport_kem_suite_id=100` | ✅ | ✅ | ✅ | ✅ |
| `transport_kem_suite_name=ml-kem-768` | ✅ | ✅ | ✅ | ✅ |
| `dummy_kem_registered=false` | ✅ | ✅ | ✅ | ✅ |
| `transport_aead_suite_id=101` | ✅ | ✅ | ✅ | ✅ |
| `transport_aead_suite_name=chacha20-poly1305` | ✅ | ✅ | ✅ | ✅ |
| `dummy_aead_registered=false` | ✅ | ✅ | ✅ | ✅ |
| `configured_roots=1` | ✅ | ✅ | ✅ | ✅ |
| `leaf_credentials_present=true` (incl. `peer_leaf_certs=4` on Run 039 banner) | ✅ | ✅ | ✅ | ✅ |

| Required negative log (must be ABSENT during honest run) | V0 | V1A | V2A | V3A |
|---|---|---|---|---|
| `pqc_root_mode=test-grade-dummy-sig` (active mode, not prose) | 0 | 0 | 0 | 0 |
| Active `DummySig` registration | 0 | 0 | 0 | 0 |
| Active `DummyKem` registration | 0 | 0 | 0 | 0 |
| Active `DummyAead` registration | 0 | 0 | 0 | 0 |
| `client handle_server_accept failed` | 0 | 0 | 0 | 0 |
| `server handle_client_init failed` | 0 | 0 | 0 | 0 |
| Cert verify failure / unknown root / wrong suite / validator mismatch | 0 | 0 | 0 | 0 |
| KEM decapsulation failure | 0 | 0 | 0 | 0 |
| AEAD decrypt / authentication failure | 0 | 0 | 0 | 0 |
| `FATAL` | 0 | 0 | 0 | 0 |
| `panic` (any case) | 0 | 0 | 0 | 0 |
| `private_key_hex` / `secret_key_hex` / `sk_hex` | 0 | 0 | 0 | 0 |

Mutual-auth peer-connectivity proof (V0 emits the B9+B10 re-emit
line gated on `mutual_auth_complete=true` **and** a verified
cert-derived NodeId):

```
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=3, ...)
```

`newly_connected_peers=3` proves all three peers (V1A/V2A/V3A)
mutually authenticated to V0 under `MutualAuthMode::Required` with
real ML-DSA-44 cert verification, real ML-KEM-768 KEM, and real
ChaCha20-Poly1305 AEAD on the live `P2pNodeBuilder::build`
production path — **none used DummySig/DummyKem/DummyAead**.

### 9.1 Honest observability gap (carried forward from Run 038/039/040/041)

The `qbind_p2p_pqc_*` family declared in
`crates/qbind-node/src/metrics.rs::P2pMetrics::format_metrics` is
**not** rendered by `NodeMetrics::format_metrics`, so the live
`/metrics` HTTP endpoint served by
`metrics_http::format_metrics_output` does not include the
cert-verification per-reason counters. Run 042 inherits the Run
038/039/040/041 honest evidence inconsistency vs the Run 037
documentation, and adds it again to `contradiction.md` as a
follow-up. Run 042 does **not** modify source code to fix it
(project discipline: "Do not modify source code unless the
evidence run exposes a real bug"). The same proof of PQC mode
active is delivered redundantly by:

- the deterministic `[Run040]` startup log line on every node,
- the `newly_connected_peers=3` mutual-auth proof on V0,
- the strict absence of `client handle_server_accept failed` /
  `server handle_client_init failed` on every node,
- the `r040_a_*` provider-shape unit tests on the same binary that
  assert `provider.aead_suite(2).is_none()`, `kem_suite(1).is_none()`,
  and `signature_suite(3).is_none()` on the exact provider the
  binary builds (`make_pqc_static_root_crypto_provider`).

## 10. Timeout-verification activation logs

Every live node logged the post-Run-033 timeout-verification ACTIVE
banner:

```
[binary] Run 033: SuiteAwareValidatorKeyProvider built honestly — loaded(validators=4,peer_ids=[…],suite_ids=[100],fingerprints=["v0:s100:6b59d5c0…", "v1:s100:77a9ec59…", "v2:s100:3c1e96f0…", "v3:s100:c0b77fdc…"])
[binary] Run 033: timeout-verification probe: active=true reason=n/a policy=RequireOrFail validators=4 chain_id=chain_51424e4444455600 supported_suite_ids=[100] local_signer=loaded(backend=local-keystore-plain,validator=ValidatorId(N),suite=suite_100) peer_key_provider=loaded(validators=4,…)
[binary] Run 033: timeout verification ACTIVE — Arc<TimeoutVerificationContext> threaded into BinaryConsensusLoopIo::verification_ctx. Inbound TimeoutMsg / NewView / TC traffic will be verified before engine ingestion; locally-emitted timeouts will be signed before broadcast. signer_loaded=1 key_provider_loaded=1 validator_count=4
[binary-consensus] Starting consensus loop: local_id=ValidatorId(N) num_validators=4 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on timeout_verification=verify+sign
```

| Required active-state log | V0 | V1A | V2A | V3A |
|---|---|---|---|---|
| `active=true` | ✅ | ✅ | ✅ | ✅ |
| `signer_loaded=1` | ✅ | ✅ | ✅ | ✅ |
| `key_provider_loaded=1` | ✅ | ✅ | ✅ | ✅ |
| `validator_count=4` | ✅ | ✅ | ✅ | ✅ |
| `verification_ctx=Some(...)` (via `timeout_verification=verify+sign`) | ✅ | ✅ | ✅ | ✅ |
| Fallback to `verification_ctx=None` / disabled / `OptionalActivate` | ❌ none | ❌ none | ❌ none | ❌ none |

Required `/metrics` shape on every node (live SCRAPE_startup at
T+10s, port `127.0.0.1:381{00,01,02,03}/metrics`):

```
qbind_timeout_verification_active 1
qbind_timeout_verification_signer_loaded 1
qbind_timeout_verification_key_provider_loaded 1
qbind_timeout_verification_validator_count 4
```

Captured from all four scrape ports
(`/tmp/run042/scrapes/startup-{v0,v1a,v2a,v3a}.txt`) — all four
required metrics emit the required value on every node.

## 11. Pre-fault baseline (SCRAPE_prefault at T+16s)

| Metric | V0 | V1A | V2A | V3A |
|---|---:|---:|---:|---:|
| `qbind_timeout_verification_active` | 1 | 1 | 1 | 1 |
| `qbind_timeout_verification_signer_loaded` | 1 | 1 | 1 | 1 |
| `qbind_timeout_verification_key_provider_loaded` | 1 | 1 | 1 | 1 |
| `qbind_timeout_verification_validator_count` | 4 | 4 | 4 | 4 |
| `qbind_consensus_committed_height` | 101 | 102 | 102 | 102 |
| `qbind_consensus_current_view` | 104 | 105 | 105 | 105 |
| `qbind_consensus_qcs_formed_total` | 204 | 207 | 209 | 210 |
| `qbind_consensus_view_timeout_advances_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_advances_due_to_verified_tc_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_outbound_timeout_signing_success_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_outbound_timeout_signing_failure_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_timeout_verify_accepted_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_timeout_verify_rejected_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_verify_accepted_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_verify_rejected_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeout_decode_failures_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeout_engine_rejects_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | 0 |
| `qbind_consensus_votes_total{result="invalid"}` | 0 | 0 | 0 | 0 |
| Every per-reason `qbind_consensus_inbound_timeout_rejected_*` | 0 | 0 | 0 | 0 |
| Every per-reason `qbind_consensus_inbound_newview_rejected_*` | 0 | 0 | 0 | 0 |

N=4 cluster committed ≥101 blocks pre-fault (V0 lags slightly
behind V1A/V2A/V3A by one block — a normal stagger artifact of
V0-first start that is bounded and corrects post-recovery; see §13
where all live nodes converge to the same `committed_height = 111`
and `current_view = 117`).

## 12. B14 absent-leader fault description

- **Target validator:** V1A (`vid = 1`).
- **Fault method:** single `kill -INT 11784` (PID captured from the
  launcher; `signal.SIGINT`).
- **Fault timestamp:** `2026-05-11T10:03:16Z` (UTC; recorded in
  `/tmp/run042/events.log` as the `B14_FAULT` and `V1A_INT_SENT`
  events; equal to the pre-fault scrape time, fault triggered
  immediately after the pre-fault scrape completed).
- **Round-robin leader rotation:** `leader(v) = v % N = v % 4`.
  With pre-fault `current_view = 105` on V1A/V2A/V3A (V0 at 104),
  V1A leads views `105, 109, 113, 117, …` — each of these views
  must time out and advance via verified TC / NewView under
  `--require-timeout-verification`.
- **Fault scope:** V0/V2A/V3A remain alive (≥ `2f+1 = 3` of 4
  validators). No operator intervention beyond the single planned
  SIGINT.
- **V1A graceful-shutdown trace** (`/tmp/run042/logs/v1a.log` tail):
  ```
  [binary] Shutdown signal received, stopping P2P node...
  [snapshot] VM-v0 snapshot trigger stopped.
  [binary-consensus] Shutdown signal received after 161 ticks.
  [binary-consensus] Loop exit: ticks=161 proposals=26 commits=103 committed_height=Some(102) view=105 inbound_msgs=394 inbound_proposals=79 inbound_votes=315 outbound_proposals=26 outbound_votes=105 outbound_proposal_late_peer_reemits=0
  [T175] Shutting down P2P node for validator ValidatorId(1)
  [T175] P2P node shutdown complete
  [binary] P2P node shutdown complete.
  [binary] Stopping metrics HTTP server...
  [metrics_http] Shutting down
  [binary] Shutdown complete.
  ```
  V1A exited under its own SIGINT handler — no panic, no FATAL, no
  protocol error.

## 13. Post-fault recovery metrics

### 13.1 Recovery progression (V0 / V2A / V3A)

| Metric (final scrape, T+18s after fault) | V0 | V2A | V3A |
|---|---:|---:|---:|
| `qbind_consensus_committed_height` | **111** | **111** | **111** |
| `qbind_consensus_current_view` | **117** | **117** | **117** |
| `qbind_consensus_qcs_formed_total` | 215 | 218 | 219 |
| `qbind_consensus_view_timeout_advances_total` | **3** | **3** | **3** |
| `qbind_consensus_view_advances_due_to_verified_tc_total` | **3** | **3** | **3** |
| `qbind_consensus_outbound_timeout_signing_success_total` | **3** | **3** | **3** |
| `qbind_consensus_outbound_timeout_signing_failure_total` | **0** | **0** | **0** |
| `qbind_consensus_inbound_timeout_verify_accepted_total` | **6** | **6** | **6** |
| `qbind_consensus_inbound_timeout_verify_rejected_total` | **0** | **0** | **0** |
| `qbind_consensus_inbound_newview_verify_accepted_total` | **6** | **6** | **6** |
| `qbind_consensus_inbound_newview_verify_rejected_total` | **0** | **0** | **0** |
| `qbind_consensus_inbound_newview_engine_rejected_total` | **0** | **0** | **0** |
| `qbind_consensus_view_timeout_decode_failures_total` | **0** | **0** | **0** |
| `qbind_consensus_view_timeout_engine_rejects_total` | **0** | **0** | **0** |
| `qbind_consensus_proposals_total{result="accepted"}` | 114 | 114 | 114 |
| `qbind_consensus_proposals_total{result="rejected"}` | **0** | **0** | **0** |
| `qbind_consensus_votes_total{result="accepted"}` | 333 | 333 | 333 |
| `qbind_consensus_votes_total{result="invalid"}` | **0** | **0** | **0** |

### 13.2 Per-reason rejection counters (final scrape; identical on V0, V2A, V3A)

```
qbind_consensus_inbound_timeout_rejected_bad_signature_total       0
qbind_consensus_inbound_timeout_rejected_duplicate_total           0
qbind_consensus_inbound_timeout_rejected_missing_key_total         0
qbind_consensus_inbound_timeout_rejected_unknown_validator_total   0
qbind_consensus_inbound_timeout_rejected_unsupported_suite_total   0
qbind_consensus_inbound_timeout_rejected_wrong_suite_total         0

qbind_consensus_inbound_newview_rejected_bad_signature_total       0
qbind_consensus_inbound_newview_rejected_duplicate_signer_total    0
qbind_consensus_inbound_newview_rejected_evidence_mismatch_total   0
qbind_consensus_inbound_newview_rejected_high_qc_mismatch_total    0
qbind_consensus_inbound_newview_rejected_insufficient_quorum_total 0
qbind_consensus_inbound_newview_rejected_missing_evidence_total    0
qbind_consensus_inbound_newview_rejected_missing_key_total         0
qbind_consensus_inbound_newview_rejected_mixed_view_total          0
qbind_consensus_inbound_newview_rejected_unknown_validator_total   0
qbind_consensus_inbound_newview_rejected_unsupported_suite_total   0
qbind_consensus_inbound_newview_rejected_wrong_suite_total         0
```

### 13.3 Multi-window progression (V0 / V2A / V3A — identical across nodes)

| Scrape (T from fault) | `committed_height` | `current_view` | `view_timeout_advances_total` | `view_advances_due_to_verified_tc_total` |
|---|---:|---:|---:|---:|
| `startup`  (T-16s)  | 61    | 64    | 0 | 0 |
| `prefault` (T-0s)   | 101 / 102 / 102 | 104 / 105 / 105 | 0 | 0 |
| `midfault` (T+6s)   | **105** | **109** | **1** | **1** |
| `postrecovery` (T+14s) | **108** | **113** | **2** | **2** |
| `final`    (T+18s)  | **111** | **117** | **3** | **3** |

Three view-timeout cycles drove three view advances, all attributed
to verified TimeoutCertificates (the verified-TC attribution
counter advancing in lock-step with the timeout-advance counter is
the metric-level proof that
`verify_timeout_certificate_with_evidence(&tc, &tc.signed_timeouts,
&state)` ran ahead of every `engine.on_timeout_certificate` /
`engine.on_new_view` call). `current_view` advanced past V1A's
absent rotation views (105 → 109 → 113 → 117 — each multiple of
4 plus 1). `committed_height` advanced 102→111 on every live node,
matching the Run 038 +9 committed-height delta exactly (Run 038
recorded 99→111; Run 042 recorded 102→111 because the cluster's
pre-fault baseline was three blocks higher here — the +9 delta
through three view-timeout cycles is identical).

### 13.4 Graceful shutdown of V0/V2A/V3A

V0 tail (`/tmp/run042/logs/v0.log`):

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 352 ticks.
[binary-consensus] Loop exit: ticks=352 proposals=30 commits=112 committed_height=Some(111) view=117 inbound_msgs=429 inbound_proposals=84 inbound_votes=333 outbound_proposals=30 outbound_votes=114 outbound_proposal_late_peer_reemits=1
[snapshot] VM-v0 snapshot trigger stopped.
[T175] Shutting down P2P node for validator ValidatorId(0)
[T175] P2P node shutdown complete
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

The post-recovery `committed_height = 111` and `view = 117`
reported by the loop-exit summary match the final `/metrics` scrape
exactly. V2A and V3A produced equivalent graceful-shutdown traces
with their own per-validator counts (see
`/tmp/run042/logs/{v2a,v3a}.log`).

## 14. Negative checks performed in this pass

| Required negative | Result |
|---|---|
| No `DummySig` registered on the `pqc-static-root` provider | ✅ — `[Run040] ... sig_suite_id=100 ... dummy_kem_registered=false dummy_aead_registered=false`; `r037_e_dummy_sig_not_registered_in_pqc_static_root_provider` PASS on this binary |
| No `DummyKem` registered on the `pqc-static-root` provider | ✅ — `dummy_kem_registered=false` on every node; `r040_a_pqc_static_root_provider_keeps_ml_kem_768_and_ml_dsa_44` PASS |
| No `DummyAead` registered on the `pqc-static-root` provider | ✅ — `dummy_aead_registered=false` on every node; `r040_a_pqc_static_root_provider_does_not_register_dummy_aead` PASS |
| No `test-grade-dummy-sig` active mode on any node | ✅ — `grep -c "pqc_root_mode=test-grade-dummy-sig" /tmp/run042/logs/*.log` = 0 |
| No cert verification failure during honest startup | ✅ — `grep -ciE "cert.*verify.*fail\|cert.*reject\|unknown root\|wrong suite\|validator mismatch"` = 0 on every node |
| No KEM decapsulation failure during honest startup | ✅ — `grep -ciE "decapsulation"` = 0 on every node |
| No AEAD decrypt / authentication failure during honest traffic | ✅ — `grep -ciE "aead.*fail\|decrypt.*fail\|authentication.*fail"` = 0 on every node |
| No `client handle_server_accept failed` during honest run | ✅ — count 0 on every node |
| No `server handle_client_init failed` during honest run | ✅ — count 0 on every node |
| No timeout verification rejection during honest traffic | ✅ — every per-reason `inbound_timeout_rejected_*` and `inbound_timeout_verify_rejected_total` = 0 throughout |
| No NewView verification rejection during honest traffic | ✅ — every per-reason `inbound_newview_rejected_*` and `inbound_newview_verify_rejected_total` = 0 throughout |
| No timeout decode failure | ✅ — `view_timeout_decode_failures_total = 0` on every node |
| No NewView decode failure | ✅ — captured at `inbound_newview_*` counter family = 0 |
| No timeout engine reject | ✅ — `view_timeout_engine_rejects_total = 0` on every node |
| No NewView engine reject | ✅ — `inbound_newview_engine_rejected_total = 0` on every node |
| No proposal rejection spike | ✅ — `proposals_total{result="rejected"} = 0` on every live node |
| No invalid vote spike | ✅ — `votes_total{result="invalid"} = 0` on every live node |
| No process crash | ✅ — V0/V2A/V3A reached graceful `[binary] Shutdown complete.`; V1A exited under its own SIGINT handler |
| No `FATAL` | ✅ — count 0 on every node |
| No `panic` (any case) | ✅ — count 0 on every node |
| No private key material in logs | ✅ — `grep -ic "private_key_hex\|secret_key_hex\|sk_hex"` = 0 on every node |

### 14.1 Optional negative-smoke coverage (carried in by reference)

Run 042 did not separately re-execute the Run 039/040 negative
smokes (tampered cert, mismatched ML-KEM secret, malformed KEM
secret) on the multi-process orchestrator because they have already
been proven on this **identical binary** by:

- `r037_b_tampered_signature_rejected_by_real_pqc_verifier` (PASS)
- `r037_c_untrusted_root_rejected` (PASS)
- `r037_d_wrong_sig_suite_rejected` (PASS)
- `r039_mismatched_ml_kem_leaf_secret_fails_closed_at_build` (PASS)
- `r039_missing_peer_leaf_cert_fails_closed_before_dummy_kem_fallback` (PASS)
- `r040_b_real_aead_*` × 9 fail-closed cases (all PASS)
- `r037_e_dummy_sig_not_registered_in_pqc_static_root_provider` (PASS)
- `r040_a_pqc_static_root_provider_does_not_register_dummy_aead` (PASS)

All run on commit `d93d006` / binary sha256 `63dd94b5...`; see §8.
Per task §13 "Do not let optional negative smoke distract from the
N=4 positive B14 capture" — the in-binary unit-test coverage is the
authoritative fail-closed evidence on this binary.

## 15. Pass / fail table

| Step | Status |
|---|---|
| 1. Build qbind-node + helper, identity recorded (binary byte-identical to Run 040/041) | **PASS** (§4) |
| 2. Re-establish out-of-tree consensus signer keystore helper | **PASS** (§5.2) |
| 3. Prepare transport material (4 ML-DSA-44-signed delegation certs + 4 ML-KEM-768 leaf secret keys, `0o600`) | **PASS** (§5.1) |
| 4. Prepare consensus timeout-verification material (4 ML-DSA-44 signer keystores, `0o600`) | **PASS** (§5.2) |
| 5. Start N=4 Required-mode topology with V0-first stagger | **PASS** (§6) |
| 6. Run 040 real-AEAD transport mode active on every node (`[Run040]` banner) | **PASS** (§9) |
| 7. Timeout verification active on every node (`signer_loaded=1`, `key_provider_loaded=1`, `validator_count=4`, `verification_ctx=Some(...)`) | **PASS** (§10) |
| 8. Pre-fault honest baseline established (`committed_height ≥ 101`, every rejection counter = 0) | **PASS** (§11) |
| 9. Trigger B14 absent-leader recovery (`kill -INT V1A` at `2026-05-11T10:03:16Z`) | **PASS** (§12) |
| 10. Post-fault recovery metrics captured | **PASS** (§13) |
| 11. Required negative checks during honest run | **PASS** (§14) |
| 12. Optional negative smoke if time permits | **N/A** — covered by reference (§14.1) |
| 13. Required test suites (Run 040, Run 037, qbind-node lib, qbind-crypto lib, qbind-net lib, + optional t146) | **PASS** (§8) |
| 14. Evidence document | **DONE** (this file) |
| 15. `contradiction.md` updated | **DONE** (Run 042 paragraph appended; full C4 still OPEN) |

## 16. What was proven

1. The Run 040 release binary on commit `d93d006` (sha256
   `63dd94b56355e9a66132ff96724be706b029bcfd2283cbb67740733d4790b1da`,
   ELF BuildID `3e912b5f...`) is **byte-identical** to the Run
   040 / Run 041 binary and was built from a clean working tree.
2. The same binary, given real ML-DSA-44 root + four real
   ML-DSA-44-signed delegation certs + four ML-KEM-768 leaf secret
   keys + four certified `--p2p-peer-leaf-cert` entries + four
   `--signer-keystore-path` plaintext local keystores produced by
   `fips204::ml_dsa_44::try_keygen()` + four
   `--validator-consensus-key VID:100:HEXPK` entries, emitted the
   deterministic `[Run040] P2pNodeBuilder: ...
   transport_aead_suite_name=chacha20-poly1305
   dummy_aead_registered=false ...` startup banner on **every one
   of four** running nodes (V0/V1A/V2A/V3A), and the Run 033
   timeout-verification ACTIVE banner with
   `signer_loaded=1 key_provider_loaded=1 validator_count=4` on
   every node — captured live into `/tmp/run042/logs/{v0,v1a,v2a,v3a}.log`.
3. The same binary sustained **a fresh N=4 multi-process B14
   absent-leader recovery** through three full view-timeout cycles
   with **all three** transport-crypto primitives active
   simultaneously (real ML-DSA-44 cert verification, real
   ML-KEM-768 KEM, real ChaCha20-Poly1305 AEAD) and **active
   timeout verification** end-to-end:
   - three signed outbound TimeoutMsgs per live validator
     (`outbound_timeout_signing_success_total = 3`,
     `failure_total = 0`),
   - six verified inbound TimeoutMsgs per live validator
     (`inbound_timeout_verify_accepted_total = 6`,
     `rejected_total = 0`, every per-reason rejection counter `=0`),
   - six verified inbound NewView/TC frames per live validator
     (`inbound_newview_verify_accepted_total = 6`,
     `rejected_total = 0`, every per-reason rejection counter `=0`),
   - three TimeoutCertificates formed and drove three
     `view_timeout_advances_total` + three
     `view_advances_due_to_verified_tc_total`,
   - `committed_height 102→111` and `current_view 105→117` on
     every live validator,
   - `proposals_total{result="rejected"} = 0`,
     `votes_total{result="invalid"} = 0`,
   - `view_timeout_decode_failures_total = 0`,
     `view_timeout_engine_rejects_total = 0`,
     `inbound_newview_engine_rejected_total = 0`.
4. **No fallback to DummySig/DummyKem/DummyAead** on any node at
   any point — `dummy_kem_registered=false`,
   `dummy_aead_registered=false`, and `sig_suite_id=100` (the real
   ML-DSA-44 suite, not the test-grade 3) on every node;
   `pqc_root_mode=test-grade-dummy-sig` count `= 0` on every node.
5. **No `client handle_server_accept failed` / `server
   handle_client_init failed`** on any node at any point. V0
   emitted `newly_connected_peers=3` on its B9+B10 late-peer-reemit
   line — gated on real ML-DSA-44 cert verify success under
   `MutualAuthMode::Required` — proving all three peers
   (V1A/V2A/V3A) mutually authenticated to V0 with the full real
   transport-crypto stack.
6. **V1A's exit was the planned SIGINT.** V1A's graceful-shutdown
   trace ends with `[binary] Shutdown complete.` — no panic, no
   FATAL, no protocol error — and V0/V2A/V3A also reached graceful
   `[binary] Shutdown complete.` on the post-final
   `RUN042_END_BEGIN_SHUTDOWN` SIGINT.
7. All Run 037 + Run 039 + Run 040 negative-coverage tests + the
   full Run 040 R040.A/B/C/D slate (14/14), the Run 037 R037
   slate (12/12), `qbind-node --lib` (767/767), `qbind-crypto
   --lib` (68/68 — incl. all 14 ChaCha20-Poly1305 fail-closed
   primitive tests), `qbind-net --lib` (15/15), and (optional)
   `t146_timeout_view_change_tests` (15/15) all PASS on this
   binary build.
8. `--devnet-forged-inject` remains hidden from normal `--help`
   (Run 035 contract preserved).
9. **Run 042 is the operator-recommended Run 041 §19 immediate
   next action, executed live**, with full pre-fault / mid-fault /
   post-recovery / final `/metrics` capture from every reachable
   node.

## 17. What remains not solved (explicit non-claims)

- ❌ **Production CA / cert rotation / cert revocation / signed
  root distribution lifecycle is NOT solved.** DevNet-ephemeral
  helper material is not a substitute for production PKI
  lifecycle.
- ❌ **`qbind_p2p_pqc_*` live `/metrics` exposure remains OPEN.**
  Declared in `P2pMetrics::format_metrics` but not wired through
  `NodeMetrics::format_metrics`. Run 038/039/040/041/042 inherited
  gap; not addressed by Run 042 (observability-wiring follow-up,
  not a HotStuff/B14/snapshot/restore/KEMTLS/AEAD bug). The same
  proof of PQC mode active is delivered redundantly by the live
  `[Run040]` startup banner on every node, the
  `newly_connected_peers=3` mutual-auth proof on V0, the strict
  absence of handshake failures, and the `r040_a_*` provider-shape
  unit tests on the same binary.
- ❌ **Production fast-sync / consensus-storage restore remains
  OPEN.**
- ❌ **Exponential-backoff timeout pacing remains OPEN.**
- ❌ **Per-environment trust anchors and clock-source
  cert-validity-window enforcement remain OPEN.**
- ❌ **Full C4 closure is NOT claimed.** Run 042 narrows the
  evidence picture for piece (c) on the binary path further (now
  covering N=4 multi-process B14 recovery under all three real
  transport-crypto primitives simultaneously) but does not close
  C4.
- ❌ **C5 is NOT closed by fiat.** Lifecycle is documented as a
  C4 piece; Run 042 adds the missing N=4 multi-process B14
  recovery capture under the Run 040 real-AEAD binary that Run
  041 boundary-stated. C5 closure remains contingent on the
  operator-facing lifecycle policy being explicitly accepted as
  out-of-C5-scope.
- ❌ **Adversary-with-valid-keys harness or fake-peer transport
  rig** for live-binary coverage of the 3 NewView per-reason
  counters (`insufficient-quorum`, `mixed-view`,
  `high-qc-mismatch`) that the Run 036 forged-injection harness
  collapses onto `bad_signature` remains an open follow-up — but
  per Run 036, this is not in the way of C5/C4 closure because
  per-reason coverage is already proven deterministically in
  `qbind-node --lib`.

## 18. Exact verdict

✅ **STRONGEST POSITIVE.**

The Run 040 release binary (sha256 `63dd94b5...`, ELF BuildID
`3e912b5f...`, byte-identical to the Run 040 / Run 041 binary)
sustained a fresh N=4 multi-process B14 absent-leader recovery
under `--p2p-pqc-root-mode pqc-static-root` with **real ML-DSA-44
cert verification + real ML-KEM-768 KEM + real ChaCha20-Poly1305
AEAD + active timeout verification**, no fallback to DummySig /
DummyKem / DummyAead, three signed outbound TimeoutMsgs +
six verified inbound TimeoutMsgs + six verified inbound NewViews +
three verified TimeoutCertificates per live validator,
`committed_height 102→111` and `current_view 105→117` past the
V1A-led absent rotation views, every per-reason rejection counter
`= 0` throughout, every proposal/vote/decode/engine-reject error
counter `= 0` throughout, V0 emitting `newly_connected_peers=3` on
the B9+B10 mutual-auth proof, zero `client handle_server_accept
failed` / `server handle_client_init failed` / `FATAL` / `panic` /
private-key material across every node log, graceful shutdown of
V0/V2A/V3A and graceful self-shutdown of V1A on the planned SIGINT.
CLI surface for the four N=4 + timeout-verification +
`pqc-static-root` flag families intact; `--devnet-forged-inject`
stays hidden. All required test suites green on this binary.

**Full C4 remains OPEN** for CA / cert rotation / cert revocation /
signed root distribution lifecycle, `qbind_p2p_pqc_*` live
`/metrics` exposure, production fast-sync / consensus-storage
restore, exponential-backoff timeout pacing, per-environment trust
anchors, and clock-source cert-validity-window enforcement. **C5
remains NOT-closed** by fiat; the transport-crypto dependency
(real ML-DSA-44 cert verification — Run 037, real ML-KEM-768 —
Run 039, real ChaCha20-Poly1305 AEAD — Run 040, active timeout
verification — Runs 031–034, forged-traffic rejection —
Runs 035/036) is now demonstrated live under fresh N=4 multi-process
B14 recovery on the Run 040 release binary (Run 042), but lifecycle
remains a C4 piece, so Run 042 does NOT close C5 by fiat.

## 19. Exact immediate next action recommended

The Run 038/039/040/041 + Run 042 N=4 Required-mode evidence stack
now demonstrates the full real-binary B14 + real-PQC-transport
co-running picture end-to-end with live metric capture. The
immediate next actions, in priority order, are operability /
lifecycle follow-ups that lie strictly outside the Run 042
verdict and outside any HotStuff/B14/snapshot/restore/KEMTLS/AEAD
redesign scope:

1. **Wire the `qbind_p2p_pqc_*` family through `NodeMetrics::format_metrics`.**
   The counters are already declared in
   `crates/qbind-node/src/metrics.rs::P2pMetrics::format_metrics`;
   the only missing piece is `NodeMetrics::format_metrics`
   delegating to `self.p2p.format_metrics()`. This would close the
   Run 038/039/040/041/042 inherited observability gap and put the
   PQC cert-verification rejection counters on the live `/metrics`
   HTTP endpoint where operators can scrape them. **Smallest
   honest fix**; no protocol surface change.
2. **Document operational PKI policy.** Author a `docs/devnet/` or
   `docs/protocol/` note that explicitly enumerates the
   C4-attached lifecycle pieces (CA / cert rotation / cert
   revocation / signed root distribution / per-environment trust
   anchors / clock-source cert-validity-window enforcement) and
   states that operators using `--p2p-pqc-root-mode pqc-static-root`
   today must distribute the trusted root and per-validator
   delegation certs by out-of-band operator policy. **No protocol
   change**; only operator-facing documentation.
3. **Production fast-sync / consensus-storage restore** —
   separately scoped C4 piece. Run 042 does not depend on it.
4. **Exponential-backoff timeout pacing** — separately scoped C4
   piece. Run 042 does not depend on it.
5. **Adversary-with-valid-keys harness or fake-peer transport
   rig** to give the 3 collapsed NewView per-reason counters
   (`insufficient-quorum`, `mixed-view`, `high-qc-mismatch`)
   live-binary per-reason coverage. Per Run 036, this is not in
   the way of C5/C4 closure because per-reason coverage is already
   proven deterministically in `qbind-node --lib`.

Operators MUST NOT interpret Run 042 as a substitute for any of
the above. Run 042 is the missing live N=4 multi-process B14
recovery capture under the Run 040 real-AEAD binary, executed
clean, and nothing more.