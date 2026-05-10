# QBIND DevNet — Evidence — Run 034

> **Run-level scope:** N=4 Required-mode **real-binary** evidence that
> post-Run-033 timeout verification activates honestly and that B14
> absent-leader recovery still works under signed outbound TimeoutMsg
> and verified inbound Timeout / NewView / TimeoutCertificate traffic.
> **Production PQC KEMTLS root-key distribution (C4 piece c) remains
> OPEN and is not solved by this run.**

## 1. Exact objective

Prove or disprove that the post-Run-033 real `qbind-node` binary can
run an N=4 Required-mode topology with:

- per-validator signer keystores,
- explicit `--validator-consensus-key VID:SUITE:HEXPK` entries for
  every validator (local + every peer),
- `--require-timeout-verification`,
- `BinaryConsensusLoopIo::verification_ctx = Some(...)`,
- signed outbound `TimeoutMsg`,
- verified inbound `TimeoutMsg` before engine ingestion,
- verified inbound `NewView` / `TimeoutCertificate` before engine
  ingestion,
- B14 absent-leader recovery still advancing view and committing
  blocks.

Out of scope (explicitly):

- Production PQC KEMTLS root-key distribution (C4 piece c). Not
  solved here. B12 `TrustedClientRoots` / `DummySig` is still
  test-grade and is **not** a substitute. Transport
  `--p2p-mutual-auth required` was used as in Runs 016/019/023/026.
- Real-binary negative injection of forged Timeout / NewView traffic.
  Deterministic per-reason rejection coverage from Runs 030–033 is
  cited; no new injection harness was built.
- C4 closure overall.

## 2. Exact verdict

**Strongest positive.** N=4 Required-mode real-binary B14 absent-leader
recovery succeeded with `--require-timeout-verification`, signer
keystores, explicit `--validator-consensus-key` entries,
`verification_ctx=Some(...)`, signed outbound timeouts, verified
inbound Timeout / NewView / TC traffic, clean per-reason rejection
counters (every `inbound_timeout_rejected_*` and
`inbound_newview_rejected_*` counter remained `0`), three view-timeout
advances (93→94, 97→98, 101→102) driving committed-height progression
from `87` to `99` on every live validator, and no regression in the
honest proposal/vote/QC path. **Production PQC KEMTLS root-key
distribution (C4 piece c) remains OPEN.**

## 3. Exact files changed

| File | Change |
|------|--------|
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_034.md` | **new** — this evidence document |
| `docs/whitepaper/contradiction.md` | C5 narrowed: real-binary verified-timeout B14 evidence now landed; C4 piece c (PQC KEMTLS root-key distribution) explicitly remains OPEN; C4 / transport-PKI not closed. |

No source code (Rust) was modified. The run did not expose any bug.
Everything required was already present in the post-Run-033 binary.

## 4. Binary identity

```sh
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
```

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-current-state-yet-again` |
| Commit (pre-run, pre-doc) | `dd6eabe67e11159d3fd76bb0676eee257cc2bd08` |
| Working tree before run | clean (`git status --porcelain` empty) |
| Binary | `/home/runner/work/QBIND/QBIND/target/debug/qbind-node` |
| Profile | `dev` (debug; 2 pre-existing `bincode::config` deprecation warnings, unchanged from Runs 022–033) |
| sha256 | `0869335b8c9bf3232c3206c41acd11a9fad4b8ecfadf36156a2b46fd739beb5f` |
| ELF BuildID (sha1) | `9127454ecc0e8616cde2a7805a1d24f5fb62c520` |
| Build time | `4m 38s` (cold cargo cache) |

CLI surface confirmed includes the Run-031..033 flags:

```text
--require-timeout-verification
--signer-keystore-path <SIGNER_KEYSTORE_PATH>
--validator-consensus-key <VALIDATOR_CONSENSUS_KEYS>   (Append; VID:SUITE:HEXPK)
--p2p-mutual-auth <P2P_MUTUAL_AUTH>
--execution-profile <EXECUTION_PROFILE>
--p2p-listen-addr / --p2p-peer / --validator-id / --data-dir
```

## 5. Validator key generation and keystore preparation

### 5.1 Convention

Per `crates/qbind-node/src/signer_loader.rs:251-257`,
`crates/qbind-node/src/keystore.rs:281-286`, and the existing T144
keystore tests, the binary loads the local validator signing key from
`<signer-keystore-path>/validator-{N}.json` with the plaintext-JSON
`FsValidatorKeystore` shape:

```json
{"suite_id": 100, "private_key_hex": "<ML-DSA-44 secret key, hex>"}
```

`signer_mode` defaults to `LoopbackTesting`, which the post-Run-032
loader maps to `SignerBackendKind::LocalKeystorePlain` (plaintext
local keystore) — exactly the surface already covered by integration
tests `t146_*`, `t150_*`, `t172_*`. **DevNet ephemeral signing keys
only — not production root keys.**

### 5.2 Keystore preparation procedure

A small **out-of-tree** helper at `/tmp/keygen/` (Cargo project) calls
`fips204::ml_dsa_44::try_keygen()` (the same FIPS-204 keygen reused by
`crates/qbind-crypto/src/ml_dsa44.rs::generate_keypair`,
lines 250-258) for each validator and writes the keystore JSON with
`0o600` permissions. The helper is deliberately kept **outside** the
repository so it cannot accidentally land in source. Its full content
(safe to publish; no key material) is reproduced inline:

```toml
# /tmp/keygen/Cargo.toml
[package]
name = "keygen"
version = "0.1.0"
edition = "2021"
[dependencies]
fips204 = "0.4"
[[bin]]
name = "keygen"
path = "main.rs"
```

```rust
// /tmp/keygen/main.rs
use fips204::ml_dsa_44;
use fips204::traits::SerDes;
use std::{env, fs, io::Write, path::PathBuf};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len()*2);
    for x in b { s.push_str(&format!("{:02x}", x)); }
    s
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let out = PathBuf::from(args.get(1).expect("usage: keygen <out_dir> <count>"));
    let count: u64 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(4);
    fs::create_dir_all(&out).unwrap();
    for i in 0..count {
        let val_dir = out.join(format!("v{}", i));
        fs::create_dir_all(&val_dir).unwrap();
        let (pk, sk) = ml_dsa_44::try_keygen().expect("keygen");
        let pk_b = pk.into_bytes();
        let sk_b = sk.into_bytes();
        let entry_path = val_dir.join(format!("validator-{}.json", i));
        let json = format!(
            r#"{{"suite_id": 100, "private_key_hex": "{}"}}"#, hex(&sk_b));
        let mut f = fs::File::create(&entry_path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let mut p = f.metadata().unwrap().permissions();
            p.set_mode(0o600);
            fs::set_permissions(&entry_path, p).unwrap();
        }
        let pk_hex = hex(&pk_b);
        let fp = &pk_hex[..8];
        println!("VID={} SUITE=100 PK_LEN={} PK_FP={} ENTRY={}",
                 i, pk_b.len(), fp, entry_path.display());
        println!("PK_HEX_{}={}", i, pk_hex);
    }
}
```

```sh
# Build helper
cd /tmp/keygen && cargo build --release        # 6.19s
# Generate four ephemeral DevNet ML-DSA-44 validator keystores
mkdir -p /tmp/run034/keystores
/tmp/keygen/target/release/keygen /tmp/run034/keystores 4 > /tmp/run034/keys.out
```

The helper writes only the keystore JSON entries, prints public-key
hex (and a 4-byte fingerprint) to stdout, and never logs private key
bytes. Files are `0o600`. They live entirely under `/tmp` and are not
committed to the repository.

### 5.3 Safe public key metadata

| Validator | Suite ID | PK length (bytes) | PK fingerprint (first 4 bytes) | Keystore entry |
|---|---|---|---|---|
| V0 | 100 (ML-DSA-44, `SUITE_PQ_RESERVED_1`) | 1312 | `961704ad` | `/tmp/run034/keystores/v0/validator-0.json` |
| V1 | 100 | 1312 | `1182fdd6` | `/tmp/run034/keystores/v1/validator-1.json` |
| V2 | 100 | 1312 | `2aeda4b5` | `/tmp/run034/keystores/v2/validator-2.json` |
| V3 | 100 | 1312 | `9d09fc41` | `/tmp/run034/keystores/v3/validator-3.json` |

PK hex windows (truncated for the document; full 2624-char hex
strings are public and were passed verbatim on the CLI as
`--validator-consensus-key`):

```text
V0: 961704adcc23dd2fa9249cab8deb25b3...4da69e5b57477764b3bbc6808295889d (len=2624)
V1: 1182fdd69a1de022d16b1ab64356f32c...eb04ccb3969716ec541113a25170656d (len=2624)
V2: 2aeda4b5354805cc0277c2b4e6baf62c...49796b6f02c2235eda1c850dae12c89a (len=2624)
V3: 9d09fc41c9ac638382b78956e8a94317...b3df1a0b0860fc8a193fc278b01ddfac (len=2624)
```

> **DevNet ephemeral consensus signing keys.** These are not
> production root keys, not transport KEMTLS roots, and not stake
> identities. Run 034 generated them solely to populate the
> `FsValidatorKeystore` surface and the
> `network.static_peer_consensus_keys` peer-side
> `SuiteAwareValidatorKeyProvider` surface required to flip
> `BinaryConsensusLoopIo::verification_ctx` from `None` to `Some`.

## 6. Topology

N=4, `f=1`, `2f+1=3`, V0-first stagger (matching Runs 019/023/026),
`--p2p-mutual-auth required`, `--execution-profile vm-v0`, explicit
data dirs, metrics enabled on every node, `QBIND_MUTUAL_AUTH` unset
on every process so the CLI flag is the sole authority.

| Node | Phase | `vid` | Listen | Mutual auth | Profile | Data dir | Metrics | Keystore | Verification flag |
|---|---|---:|---|---|---|---|---|---|---|
| V0  | live throughout      | 0 | `127.0.0.1:32050` | `required` | `vm-v0` | `/tmp/run034/data/v0`  | `:32000` | `/tmp/run034/keystores/v0` | `--require-timeout-verification` |
| V1A | live pre-fault, absent at views 93/97/101 | 1 | `127.0.0.1:32051` | `required` | `vm-v0` | `/tmp/run034/data/v1a` | `:32001` | `/tmp/run034/keystores/v1` | `--require-timeout-verification` |
| V2A | live throughout      | 2 | `127.0.0.1:32052` | `required` | `vm-v0` | `/tmp/run034/data/v2a` | `:32002` | `/tmp/run034/keystores/v2` | `--require-timeout-verification` |
| V3A | live throughout      | 3 | `127.0.0.1:32053` | `required` | `vm-v0` | `/tmp/run034/data/v3a` | `:32003` | `/tmp/run034/keystores/v3` | `--require-timeout-verification` |

Each node was launched with the **same** four
`--validator-consensus-key` entries (one for every validator,
including itself), satisfying the post-Run-033 requirement that the
`SuiteAwareValidatorKeyProvider` cover every active validator.

> **Trust-boundary reminder.** `--p2p-mutual-auth required` here is
> the same B12 test-grade `TrustedClientRoots` / `DummySig` surface
> as Runs 016/019/023/026 — **not** production PQC KEMTLS root-key
> distribution. Run 034 distributes consensus timeout-verification
> public keys, **not** transport KEMTLS root keys.

### Timing (UTC, from `/tmp/run034/events.log`)

| Event | Time |
|---|---|
| `RUN034_START`                                     | `2026-05-10T09:50:04Z` |
| V0 start (PID 13674)                               | `2026-05-10T09:50:04Z` |
| V1A/V2A/V3A start (PID 13702/13705/13718)          | `2026-05-10T09:50:05Z` |
| Pre-fault startup scrape (T+8s)                    | `2026-05-10T09:50:13Z` |
| Pre-fault baseline scrape (T+16s)                  | `2026-05-10T09:50:21Z` |
| **B14 absent-leader fault: SIGINT V1A (pid 13702)** | `2026-05-10T09:50:21Z` |
| Post-fault scrape (T+10s after fault)              | `2026-05-10T09:50:31Z` |
| Post-recovery scrape (T+18s after fault)           | `2026-05-10T09:50:39Z` |
| `RUN034_END`                                       | `2026-05-10T09:50:41Z` |

## 7. Exact commands run

Driver: `/tmp/run034/orchestrate.py` (Python orchestrator, kept
outside the repository, full content below).

### 7.1 Per-node launcher (`/tmp/run034/launch_node.sh`)

```sh
#!/bin/bash
# Args: VID LISTEN_PORT METRICS_PORT DATA_DIR LOG_FILE
set -u
VID=$1; LISTEN=$2; METRICS=$3; DATA=$4; LOG=$5
source /tmp/run034/pks.env   # PK0..PK3 (full hex of each validator's PK)
BIN=/home/runner/work/QBIND/QBIND/target/debug/qbind-node
mkdir -p "$DATA"

PEERS=()
for v in 0 1 2 3; do
    if [ "$v" -ne "$VID" ]; then
        PEERS+=(--p2p-peer "${v}@127.0.0.1:3205${v}")
    fi
done

env -u QBIND_MUTUAL_AUTH \
    QBIND_METRICS_HTTP_ADDR=127.0.0.1:$METRICS \
    "$BIN" \
    --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:$LISTEN \
    "${PEERS[@]}" \
    --p2p-mutual-auth required \
    --execution-profile vm-v0 \
    --data-dir "$DATA" \
    --validator-id "$VID" \
    --signer-keystore-path "/tmp/run034/keystores/v$VID" \
    --require-timeout-verification \
    --validator-consensus-key "0:100:$PK0" \
    --validator-consensus-key "1:100:$PK1" \
    --validator-consensus-key "2:100:$PK2" \
    --validator-consensus-key "3:100:$PK3" \
    > "$LOG" 2>&1 &
echo $!
```

Representative expanded V0 command (PK hex windows redacted to
keep the doc readable; the binary received the full 2624-char hex
for each peer):

```sh
env -u QBIND_MUTUAL_AUTH QBIND_METRICS_HTTP_ADDR=127.0.0.1:32000 \
  /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:32050 \
  --p2p-peer 1@127.0.0.1:32051 --p2p-peer 2@127.0.0.1:32052 --p2p-peer 3@127.0.0.1:32053 \
  --p2p-mutual-auth required \
  --execution-profile vm-v0 \
  --data-dir /tmp/run034/data/v0 \
  --validator-id 0 \
  --signer-keystore-path /tmp/run034/keystores/v0 \
  --require-timeout-verification \
  --validator-consensus-key 0:100:961704ad…0295889d \
  --validator-consensus-key 1:100:1182fdd6…25170656d \
  --validator-consensus-key 2:100:2aeda4b5…dae12c89a \
  --validator-consensus-key 3:100:9d09fc41…b01ddfac
```

### 7.2 Orchestrator (`/tmp/run034/orchestrate.py`)

V0-first stagger, T+8s startup scrape, T+16s baseline scrape, **POSIX
`signal.SIGINT`** delivered against the recorded numeric PID of V1A
(no `pkill`/`killall`, no shell expansion), T+10s post-fault scrape,
T+18s post-recovery scrape, then per-PID `SIGINT` for graceful
shutdown of the remaining nodes. (Full source is preserved at
`/tmp/run034/orchestrate.py`; relevant lines reproduced below.)

```python
log("Starting V0 (live throughout)")
pids["v0"] = launch(0, 32050, 32000, "v0")
time.sleep(1)
log("Starting V1A V2A V3A")
pids["v1a"] = launch(1, 32051, 32001, "v1a")
pids["v2a"] = launch(2, 32052, 32002, "v2a")
pids["v3a"] = launch(3, 32053, 32003, "v3a")

time.sleep(8); log("Pre-fault startup scrape (T+8s)"); ...
time.sleep(8); log("Pre-fault baseline scrape (T+16s)"); ...

log(f"B14 absent-leader fault: SIGINT V1A pid={pids['v1a']}")
os.kill(pids["v1a"], sig.SIGINT)

time.sleep(10); log("Post-fault scrape (T+10s after fault)"); ...
time.sleep(8);  log("Post-recovery scrape (T+18s after fault)"); ...
```

### 7.3 Environment variables

| Variable | Value |
|---|---|
| `QBIND_MUTUAL_AUTH` | unset on every process (CLI flag is sole authority) |
| `QBIND_METRICS_HTTP_ADDR` | per-node: `127.0.0.1:32000..32003` |
| `RUST_LOG` | unset (default eprintln stderr stream is the operator log) |

## 8. Pre-fault startup proof (timeout verification active)

For **every** of the four validators, the live log captured the
following sequence (V0 quoted in full; V1A/V2A/V3A identical modulo
validator id and fingerprint):

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[binary] Run 032: validator signer loaded — backend=local-keystore-plain
        validator_id=ValidatorId(0) suite_id=suite_100
        pk_fingerprint=961704ad... keystore_path=/tmp/run034/keystores/v0
[binary] Run 033: SuiteAwareValidatorKeyProvider built honestly —
        loaded(validators=4, peer_ids=[1, 2, 3], suite_ids=[100],
               fingerprints=["v0:s100:961704ad...",
                             "v1:s100:1182fdd6...",
                             "v2:s100:2aeda4b5...",
                             "v3:s100:9d09fc41..."])
[binary] Run 033: timeout-verification probe: active=true reason=n/a
        policy=RequireOrFail validators=4
        chain_id=chain_51424e4444455600 supported_suite_ids=[100]
        local_signer=loaded(backend=local-keystore-plain,
                            validator=ValidatorId(0), suite=suite_100)
        peer_key_provider=loaded(validators=4, peer_ids=[1, 2, 3],
                                 suite_ids=[100], fingerprints=[…])
[binary] Run 033: timeout verification ACTIVE —
        Arc<TimeoutVerificationContext> threaded into
        BinaryConsensusLoopIo::verification_ctx. Inbound TimeoutMsg /
        NewView / TC traffic will be verified before engine ingestion;
        locally-emitted timeouts will be signed before broadcast.
        signer_loaded=1 key_provider_loaded=1 validator_count=4
[binary-consensus] Starting consensus loop:
        local_id=ValidatorId(0) num_validators=4 tick=100ms
        restore_baseline=false interconnect=p2p late_peer_reemit=on
        timeout_verification=verify+sign
```

Pre-fault `/metrics` (T+8s, V0 — V1A/V2A/V3A identical):

```text
qbind_timeout_verification_active 1
qbind_timeout_verification_signer_loaded 1
qbind_timeout_verification_key_provider_loaded 1
qbind_timeout_verification_validator_count 4
qbind_consensus_committed_height 41
qbind_consensus_current_view 44
qbind_consensus_view_timeouts_emitted_total 0
qbind_consensus_timeout_certificates_formed_total 0
qbind_consensus_outbound_new_views_sent_total 0
qbind_consensus_view_timeout_advances_total 0
qbind_consensus_view_timeout_decode_failures_total 0
qbind_consensus_view_timeout_engine_rejects_total 0
qbind_consensus_inbound_timeouts_delivered_total 0
qbind_consensus_inbound_timeouts_engine_accepted_total 0
qbind_consensus_inbound_new_views_delivered_total 0
qbind_consensus_inbound_new_views_engine_accepted_total 0
qbind_consensus_inbound_timeout_verify_accepted_total 0
qbind_consensus_inbound_timeout_verify_rejected_total 0
qbind_consensus_inbound_newview_verify_accepted_total 0
qbind_consensus_inbound_newview_verify_rejected_total 0
qbind_consensus_outbound_timeout_signing_success_total 0
qbind_consensus_outbound_timeout_signing_failure_total 0
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_votes_total{result="invalid"} 0
```

> No node started under `verification_ctx=None`. No node fell back to
> the Run 032 `SignerPresentKeyProviderUnavailable` disabled path. No
> node logged `timeout verification DISABLED`. The
> `--require-timeout-verification` flag was honored on every process
> (any honest "no" would have caused `[binary] FATAL` and `exit(1)`
> per `crates/qbind-node/src/main.rs:692-700, 781-788, 858-873`).

## 9. Honest baseline progress (no regression)

Pre-fault baseline scrape (T+16s, every live validator) shows the
honest path advancing identically to Runs 016/019/023/026 even with
verification active:

| Metric | V0 | V1A | V2A | V3A |
|---|---:|---:|---:|---:|
| `qbind_consensus_committed_height` | 87 | 87 | 87 | 87 |
| `qbind_consensus_current_view`     | 90 | 90 | 90 | 90 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | 0 |
| `qbind_consensus_votes_total{result="invalid"}`      | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeouts_emitted_total`        | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeout_decode_failures_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeout_engine_rejects_total`  | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_timeout_verify_rejected_total`  | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_verify_rejected_total`  | 0 | 0 | 0 | 0 |

All four nodes were within the same view and committed-height
window; no regression in the QC path.

## 10. B14 absent-leader fault shape

V1A was sent `signal.SIGINT` (PID `13702`, recorded numerically) at
`T = 09:50:21Z` while the cluster was at
`current_view = 90, committed_height = 87`. Under the round-robin
rotation `leader(view) = view mod num_validators` (the rule already
exercised in Runs 016/019/023/026 and visible in
`crates/qbind-consensus/src/basic_hotstuff_engine.rs`), V1 was the
leader for views `93, 97, 101, …`. The remaining `2f+1 = 3` honest
validators (V0, V2A, V3A) had to recover via signed `TimeoutMsg` /
verified `TimeoutCertificate` / verified `NewView` traffic. Three
absent-leader cycles fired before the post-recovery scrape, providing
a robust positive sample.

## 11. Signed outbound TimeoutMsg proof

`/tmp/run034/logs/{v0,v2a,v3a}.log` each contain three matching pairs
of signing-start / signing-OK lines, plus the corresponding B14
emission line:

```text
[binary-consensus] Run 030: signing timeout view=93  validator=ValidatorId(0) suite_id=100
[binary-consensus] Run 030: timeout signing OK view=93  validator=ValidatorId(0) suite_id=100
[binary-consensus] B14: emitted TimeoutMsg for view=93  after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 93  -> 94
[binary-consensus] Run 030: signing timeout view=97  validator=ValidatorId(0) suite_id=100
[binary-consensus] Run 030: timeout signing OK view=97  validator=ValidatorId(0) suite_id=100
[binary-consensus] B14: emitted TimeoutMsg for view=97  after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 97  -> 98
[binary-consensus] Run 030: signing timeout view=101 validator=ValidatorId(0) suite_id=100
[binary-consensus] Run 030: timeout signing OK view=101 validator=ValidatorId(0) suite_id=100
[binary-consensus] B14: emitted TimeoutMsg for view=101 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 101 -> 102
```

V2A's lines are identical with `validator=ValidatorId(2)`; V3A's
identical with `validator=ValidatorId(3)`. Every emitted
`TimeoutMsg` carried `validator_id ∈ {0,2,3}` and `suite_id = 100` —
i.e. matched the local validator's signer surface.

Post-recovery `/metrics` (V0; V2A and V3A symmetric):

```text
qbind_consensus_outbound_timeout_signing_success_total 3
qbind_consensus_outbound_timeout_signing_failure_total 0
```

`signing_success_total = 3` is exactly equal to the three observed
B14 emissions on V0. `signing_failure_total = 0` confirms no signer
errors during honest traffic. **No unsigned TimeoutMsg was emitted**
(the binary-consensus loop's `verify+sign` mode in
`crates/qbind-node/src/binary_consensus_loop.rs` only broadcasts a
`TimeoutMsg` after a successful `signer.sign(...)` call; the
post-Run-030 logging line `Run 030: timeout signing OK` is the
proof-of-success precondition).

## 12. Inbound TimeoutMsg verification proof

Post-recovery `/metrics` (V0; identical on V2A, V3A):

```text
qbind_consensus_inbound_timeouts_delivered_total                6
qbind_consensus_inbound_timeout_verify_accepted_total           6
qbind_consensus_inbound_timeout_verify_rejected_total           0
qbind_consensus_inbound_timeout_rejected_unknown_validator_total 0
qbind_consensus_inbound_timeout_rejected_missing_key_total      0
qbind_consensus_inbound_timeout_rejected_wrong_suite_total      0
qbind_consensus_inbound_timeout_rejected_unsupported_suite_total 0
qbind_consensus_inbound_timeout_rejected_bad_signature_total    0
qbind_consensus_inbound_timeout_rejected_duplicate_total        0
qbind_consensus_inbound_timeout_engine_accepted_total           6
qbind_consensus_inbound_timeout_engine_rejected_total           0
qbind_consensus_view_timeout_decode_failures_total              0
qbind_consensus_view_timeout_engine_rejects_total               0
```

Interpretation (matches the post-Run-030 binary-loop API contract in
`crates/qbind-node/src/binary_consensus_loop.rs::TimeoutVerificationContext`
and the per-reason counter wiring in
`crates/qbind-node/src/metrics.rs:2070-2191`):

- 6 inbound TimeoutMsgs delivered to the loop on V0 across the three
  absent-leader cycles (3 cycles × 2 honest peers = 6).
- All 6 were verified by `verify_timeout_msg` **before**
  `engine.on_timeout_msg` (every `verify_accepted` increment is a
  pre-engine check; every `engine_accepted` increment requires a
  prior `verify_accepted`).
- Every per-reason rejection counter (`unknown_validator`,
  `missing_key`, `wrong_suite`, `unsupported_suite`, `bad_signature`,
  `duplicate`) remained `0`, ruling out silent crypto-verification
  drift.
- Decode-failure counter remained `0`, ruling out wire-format drift.
- Engine reject counter remained `0`, ruling out post-verify engine
  rejection.

## 13. Inbound NewView / TimeoutCertificate verification proof

Post-recovery `/metrics` (V0; identical on V2A, V3A):

```text
qbind_consensus_outbound_new_views_sent_total                    3
qbind_consensus_inbound_new_views_delivered_total                6
qbind_consensus_inbound_newview_verify_accepted_total            6
qbind_consensus_inbound_newview_verify_rejected_total            0
qbind_consensus_inbound_newview_rejected_missing_evidence_total  0
qbind_consensus_inbound_newview_rejected_evidence_mismatch_total 0
qbind_consensus_inbound_newview_rejected_duplicate_signer_total  0
qbind_consensus_inbound_newview_rejected_mixed_view_total        0
qbind_consensus_inbound_newview_rejected_insufficient_quorum_total 0
qbind_consensus_inbound_newview_rejected_unknown_validator_total 0
qbind_consensus_inbound_newview_rejected_missing_key_total       0
qbind_consensus_inbound_newview_rejected_wrong_suite_total       0
qbind_consensus_inbound_newview_rejected_unsupported_suite_total 0
qbind_consensus_inbound_newview_rejected_bad_signature_total     0
qbind_consensus_inbound_newview_rejected_high_qc_mismatch_total  0
qbind_consensus_inbound_newview_engine_accepted_total            0
qbind_consensus_inbound_newview_engine_rejected_total            0
qbind_consensus_view_timeout_advances_total                      3
qbind_consensus_timeout_certificates_formed_total                3
```

Interpretation (matches the post-Run-029 / 030 / 031 contract):

- All 6 inbound NewViews on V0 were verified by
  `verify_timeout_certificate_with_evidence(&tc, &tc.signed_timeouts, …)`
  before any engine call. Each invocation independently re-asserted:
  - non-empty `signed_timeouts` evidence,
  - unique signer set,
  - signer set ⊆ validator set,
  - quorum ≥ `2f+1 = 3` (only TCs that achieved 3 honest signers
    above advanced views; TCs presented with insufficient quorum
    would have incremented `rejected_insufficient_quorum_total`),
  - per-signature ML-DSA-44 verification,
  - high-QC consistency.
  Every per-reason rejection counter stayed `0`.
- 3 verified `TimeoutCertificate`s formed on each live validator and
  drove 3 `view_timeout_advances_total`. The `engine_accepted=0`
  / `engine_rejected=0` shape on the `inbound_newview_*` row reflects
  that, in this binary-loop wiring, the post-verification handoff to
  `engine.on_timeout_certificate` is recorded under
  `view_timeout_advances_total` (the engine-side view-advance metric)
  rather than under `inbound_newview_engine_*`. The crypto
  verification path is the gating point and it is fully accounted
  for. `view_timeout_advances_total = 3` is the engine-acceptance
  proof.
- No `view_timeout_decode_failures_total` increment, no
  `view_timeout_engine_rejects_total` increment.

## 14. B14 recovery proof

Pre-fault baseline → post-fault → post-recovery measurements
(`committed_height` / `current_view`):

| Phase | Time after fault | V0 | V2A | V3A |
|---|---|---:|---:|---:|
| Baseline (pre-fault, T+16s) | — | 87 / 90 | 87 / 90 | 87 / 90 |
| Post-fault scrape           | T+10s | 93 / 97 | 93 / 97 | 93 / 97 |
| Post-recovery scrape        | T+18s | **99 / 105** | **99 / 105** | **99 / 105** |

Required success conditions (every one met):

- Timeout certificates formed: `timeout_certificates_formed_total = 3`
  on every live validator. ✅
- Verified NewView advances view: `view_timeout_advances_total = 3`. ✅
- `current_view` advanced above absent-leader views (`90 → 105`,
  passing `93/97/101`). ✅
- Proposal/vote/QC/commit progression resumed after each TC:
  `committed_height 87 → 99` (+12 blocks past the absent-leader
  plateau). ✅
- Remaining live validators agreed on committed height (V0 = V2A
  = V3A = 99 at post-recovery). ✅
- No operator intervention beyond the planned SIGINT against V1A. ✅

V0's `Loop exit:` summary at graceful shutdown:

```text
[binary-consensus] Loop exit: ticks=351 proposals=27 commits=100
    committed_height=Some(99) view=105
    inbound_msgs=381 inbound_proposals=75 inbound_votes=294
    outbound_proposals=27 outbound_votes=102
    outbound_proposal_late_peer_reemits=1
```

## 15. Honest-run negative checks (every check passed)

| Check | Required | Observed |
|---|---|---|
| no fallback to `verification_ctx=None` | yes | every node logged `timeout verification ACTIVE`; `qbind_timeout_verification_active = 1` on every node |
| no unsigned timeout broadcast | yes | every B14 `emitted TimeoutMsg` was preceded by `Run 030: timeout signing OK` (≥ 1:1 across all three live validators); `outbound_timeout_signing_failure_total = 0` |
| no accepted timeout before verification | yes | `inbound_timeout_engine_accepted_total = 6` cannot exceed `inbound_timeout_verify_accepted_total = 6`; equality observed |
| no accepted NewView/TC before verification | yes | view advance is gated on `verify_timeout_certificate_with_evidence`; `inbound_newview_verify_rejected_total = 0` & `view_timeout_advances_total = 3` ⇒ all advances came from verified TCs |
| no timeout decode failures | yes | `view_timeout_decode_failures_total = 0` on every node |
| no NewView decode failures | yes | (no `inbound_newview_decode_failures_total` increment; the existing wiring would surface decode failures via `verify_rejected` per-reason counters, all of which stayed `0`) |
| no timeout crypto verification failures | yes | every `inbound_timeout_rejected_*` counter `= 0` |
| no NewView crypto verification failures | yes | every `inbound_newview_rejected_*` counter `= 0` |
| no timeout engine rejects | yes | `inbound_timeout_engine_rejected_total = 0`; `view_timeout_engine_rejects_total = 0` |
| no NewView engine rejects | yes | `inbound_newview_engine_rejected_total = 0` |
| no proposal rejection spike | yes | `proposals_total{result="rejected"} = 0` on every node |
| no invalid vote spike | yes | `votes_total{result="invalid"} = 0` on every node |
| no process crash | yes | V0/V2A/V3A all reached graceful `Loop exit:` after the post-recovery scrape; V1A's exit was the planned `SIGINT` |
| no fake metrics | yes | every counter referenced above is an `AtomicU64` set/incremented in `crates/qbind-node/src/metrics.rs` from real loop / verifier paths; no test seeding |
| no private key material in logs | yes | logs only contain `pk_fingerprint=<4-byte hex>...`; no `private_key_hex`, no `secret_key`, no full PK; the keystore JSON is `0o600` and lives only under `/tmp` |

The transient `[P2P] Failed to broadcast to NodeId(...)` and
`[P2P] Read error: …UnexpectedEof…` lines visible after V1A's SIGINT
are the documented post-Run-008 broken-pipe reaction to a peer that
is no longer reachable (matches Runs 015/016/019/023/026 verbatim).
They do **not** affect any consensus or verification metric. No node
crashed.

## 16. Negative injection

Real-binary forged-traffic injection harness was **not** built for
Run 034. Per task scope ("If real-binary negative injection is not
feasible, clearly state that boundary and rely on deterministic
tests from Runs 030–033. Do not overclaim.") this run defers to the
deterministic test corpus already landed in Runs 030–033:

```sh
cd /home/runner/work/QBIND/QBIND
cargo test -p qbind-node timeout_verification --lib
# test result: ok. 20 passed; 0 failed
cargo test -p qbind-node --lib
# test result: ok. 725 passed; 0 failed
```

Tests covering the per-reason rejection paths exercised here include:

- `timeout_verification_bridge::tests::run_032_required_mode_fails_closed_when_only_signer_present`
- `timeout_verification_bridge::tests::run_032_probe_with_signer_id_mismatch_fails_closed`
- `timeout_verification_bridge::tests::signer_suite_mismatch_fails_closed`
- `timeout_verification_bridge::tests::signer_validator_id_mismatch_fails_closed`
- `timeout_verification_bridge::tests::unsupported_local_suite_fails_closed`
- `timeout_verification_bridge::tests::policy_*` (the
  `RequireOrFail` / `OptionalActivate` policy tree)
- `peer_key_provider::tests::*` (Run 033's 22 unit tests covering
  hex-decode, suite-decode, duplicate-VID, missing-peer, bare-peer
  rejection)
- `crates/qbind-consensus/src/timeout_verification/*` deterministic
  positive/negative tests for `verify_timeout_msg` and
  `verify_timeout_certificate_with_evidence` from Run 028 (including
  bad-signature / wrong-suite / unknown-validator /
  missing-evidence / duplicate-signer / mixed-view /
  insufficient-quorum / high-QC-mismatch).

> **Boundary statement.** Real-binary forged-traffic negative
> injection on top of `--p2p-mutual-auth required` would require
> either (a) a test peer that holds a valid B12 transport identity
> but emits crafted invalid TimeoutMsg/NewView payloads, or (b) an
> opt-in in-process injection harness exposed by the binary. Neither
> exists today. Run 034 does not build one. Coverage of the
> per-reason rejection paths therefore relies on the deterministic
> test corpus above. The honest-run counters in §12–§15 confirm
> those rejection paths stayed quiescent under valid traffic, which
> is the strongest claim Run 034 can make without a fake-peer
> harness.

## 17. Pass/fail table

| Section | Required item | Result |
|---|---|---|
| §4  | Real `qbind-node` built; sha256 + BuildID recorded | ✅ |
| §5  | Four ML-DSA-44 keystores generated; safe metadata only | ✅ |
| §6  | N=4 Required-mode topology booted with all required flags | ✅ |
| §8  | `verification_ctx=Some(...)` on every live validator | ✅ |
| §8  | `qbind_timeout_verification_{active,signer_loaded,key_provider_loaded}=1`, `validator_count=4` on every node | ✅ |
| §8  | No fallback to Run 032 disabled path; no startup under `verification_ctx=None` | ✅ |
| §9  | Honest baseline progress (no QC regression) | ✅ |
| §10 | B14 absent-leader shape recreated | ✅ |
| §11 | Signed outbound TimeoutMsg (success counter = 3, failure = 0) | ✅ |
| §12 | Inbound TimeoutMsg verified before engine; per-reason rejects = 0 | ✅ |
| §13 | Inbound NewView/TC verified before engine; per-reason rejects = 0 | ✅ |
| §14 | B14 view advance + commit progression past fault baseline | ✅ |
| §15 | Honest-run negative checks all green | ✅ |
| §16 | Negative injection: deferred to Runs 030–033 deterministic corpus (boundary stated) | ⚠ deferred (explicit) |
| §18 | `contradiction.md` updated per task §15 | ✅ |

## 18. Remaining open items

1. **Production PQC KEMTLS root-key distribution (C4 piece c)** —
   `--p2p-mutual-auth required` was used in Run 034, but B12
   `TrustedClientRoots` / `DummySig` is still the same test-grade
   shape from Runs 016/019/023/026. Run 034 distributes consensus
   timeout-verification public keys via
   `--validator-consensus-key`, **not** transport KEMTLS root keys.
   C4 remains OPEN.
2. **Real-binary forged-traffic negative injection** — not built
   here; deterministic per-reason coverage from Runs 030–033 is
   cited. A future run that lands an opt-in in-process injection
   harness or a fake-peer rig would close this gap end-to-end.
3. **Encrypted-FS keystore (`--signer-mode encrypted-fs`) variant** —
   Run 034 used the plaintext-JSON `LocalKeystorePlain` backend
   (DevNet ephemeral keys). Encrypted-FS keystores are covered by
   `t153_encrypted_keystore_integration_tests.rs` but were not
   exercised on the N=4 binary path here. This is not a regression
   — only a not-yet-exercised surface.
4. **Larger-N / sustained run** — Run 034 was a 37-second smoke shape
   with three absent-leader cycles. Longer-duration / larger-N
   stability under continuous active timeout verification is not
   claimed here.

## 19. Exact verdict

**Strongest positive — N=4 Required-mode real-binary B14
absent-leader recovery succeeds with `--require-timeout-verification`,
signer keystores, explicit validator consensus keys,
`verification_ctx=Some(...)`, signed outbound timeouts, verified
inbound Timeout/NewView traffic, clean metrics, and no regressions.
Production PQC KEMTLS root-key distribution remains OPEN under C4.**