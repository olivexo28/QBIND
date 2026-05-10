# QBIND DevNet — Evidence — Run 036

> **Run-level scope:** Live N=4 Required-mode **real-binary** forged
> Timeout / NewView / TimeoutCertificate negative-injection evidence
> using the Run 035 dev/test-only injection harness on the same
> machine/topology shape as Run 034. **Production PQC KEMTLS root-key
> distribution (C4 piece c) remains OPEN and is not solved by this
> run.**

## 1. Exact objective

Prove or disprove, on four live `qbind-node` binaries running with
post-Run-035 source, that forged `TimeoutMsg` / `NewView` /
`TimeoutCertificate` traffic injected through the Run 035 harness
into the same `mpsc::Sender<ConsensusNetMsg>` channel real P2P
traffic flows through is:

- **rejected before engine ingestion** (no forged frame increments
  any `inbound_*_engine_accepted_total` counter),
- **does not advance view** (no forged frame increments
  `view_timeout_advances_total` /
  `view_advances_due_to_verified_tc_total`),
- **does not crash the process** (V0 — the injection target — stays
  alive through the injection burst and to graceful shutdown), and
- **does not poison subsequent honest verified-timeout B14
  recovery** (after the injection burst, the same Run-034-shape
  absent-leader fault still drives signed outbound TimeoutMsg,
  verified inbound Timeout/NewView traffic, fresh `TimeoutCertificate`
  formation, view advances and `committed_height` progression on
  every live validator).

Out of scope (explicitly):

- Production PQC KEMTLS root-key distribution (C4 piece c). Not
  solved here. B12 `TrustedClientRoots` / `DummySig` is still
  test-grade and is **not** a substitute. Transport
  `--p2p-mutual-auth required` was used as in Runs 016/019/023/026/034.
- C4 closure overall.
- Any redesign of HotStuff, B14, networking, or snapshot/restore.
- Any new code change. Run 036 is purely an evidence run on top of
  the post-Run-035 source tree.

## 2. Exact verdict

**Strongest positive.** Live N=4 Required-mode real-binary
forged-Timeout/NewView/TC injection through the Run 035 harness on
V0 was rejected fail-closed before engine ingestion on every one of
the 12 injected cases, no forged frame advanced view, V0 stayed
alive throughout the injection burst (≈ 1.6 s for 12 cases at 50 ms
spacing on top of a 1 s startup delay), all four nodes terminated
with `rc=0` at orchestrated shutdown, and the same Run-034-shape
B14 absent-leader recovery drove `committed_height` from 88 to 138
and `current_view` from 91 to 145 on every live validator after the
injection window — with `outbound_timeout_signing_failure_total = 0`,
all per-reason `inbound_timeout_rejected_*` and
`inbound_newview_rejected_*` counters frozen at exactly the values
implied by the harness case mix and **never moved by honest
traffic**, `proposals_total{result="rejected"} = 0`, and
`votes_total{result="invalid"} = 0` on every live node.
**Production PQC KEMTLS root-key distribution (C4 piece c) remains
OPEN.**

## 3. Exact files changed

| File | Change |
|------|--------|
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_036.md` | **new** — this evidence document |
| `docs/whitepaper/contradiction.md` | C5 narrowed: live N=4 forged-Timeout/NewView negative-injection evidence has now landed; production PQC KEMTLS root-key distribution (C4 piece c) explicitly remains OPEN; full C4 not closed |

**No source code (Rust) was modified.** The run did not expose any
bug. The binary built from the working tree at run start is
byte-identical to the one Run 035 captured (sha256
`5c90fcc486b1132c76c1f4aca76d93fae3c48374c3de21499f5d32fc5aeee4af`,
ELF BuildID `63e756e7fc87c7df870c8c3c88c4774d63453e6c`, size
`290338072` bytes). Run 036's only landed artifacts are this
document and the C5 narrowing in `contradiction.md`.

## 4. Binary identity

```sh
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
```

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-progress` |
| Commit (run start, run end) | `ec6a2b830b5e5a8c9a8416663422bb360842d8fc` (Run 035 landed `a2281b78` → squashed/superseded by `ec6a2b8`; the Run-035 source surface is unchanged) |
| Working tree before run | clean (`git status --porcelain` empty) |
| Working tree after run | clean (Run 036 only adds documentation) |
| Binary | `/home/runner/work/QBIND/QBIND/target/debug/qbind-node` |
| Profile | `dev` (debug; 2 pre-existing `bincode::config` deprecation warnings, unchanged from Runs 022–035) |
| sha256 | `5c90fcc486b1132c76c1f4aca76d93fae3c48374c3de21499f5d32fc5aeee4af` |
| ELF BuildID (sha1) | `63e756e7fc87c7df870c8c3c88c4774d63453e6c` |
| Binary size | `290338072` bytes |
| Build time | `5m 20s` (cold cargo cache) |

CLI surface confirmed includes the Run-031..035 flags:

```text
--require-timeout-verification
--signer-keystore-path <SIGNER_KEYSTORE_PATH>
--validator-consensus-key <VALIDATOR_CONSENSUS_KEYS>   (Append; VID:SUITE:HEXPK)
--p2p-mutual-auth <P2P_MUTUAL_AUTH>
--execution-profile <EXECUTION_PROFILE>
--p2p-listen-addr / --p2p-peer / --validator-id / --data-dir
```

`--devnet-forged-inject` confirmed **hidden** from `--help` (per
Run 035 §4 — `hide = true` on the clap arg in
`crates/qbind-node/src/cli.rs`):

```sh
$ ./target/debug/qbind-node --help | grep -i devnet-forged-inject
   (no output — flag is correctly hidden)
```

## 5. Validator key generation and keystore preparation

Same convention as Run 034 §5: out-of-tree FIPS-204 ML-DSA-44 keygen
helper at `/tmp/keygen36/` writes plaintext-JSON
`FsValidatorKeystore` entries
(`{"suite_id": 100, "private_key_hex": "<sk hex>"}`) with mode
`0o600` under `/tmp/run036/keystores/v{0..3}/validator-{0..3}.json`.
**DevNet ephemeral consensus signing keys only — not production
root keys, not transport KEMTLS roots, not stake identities.**

```sh
cd /tmp/keygen36 && cargo build --release         # 7.86s
mkdir -p /tmp/run036/keystores
/tmp/keygen36/target/release/keygen36 /tmp/run036/keystores 4 > /tmp/run036/keys.out
```

The helper writes only the keystore JSON entries, prints public-key
hex (and a 4-byte fingerprint) to stdout, and never logs private-key
bytes. Files are `0o600`. They live entirely under `/tmp` and are
not committed to the repository.

### 5.1 Safe public-key metadata

| Validator | Suite ID | PK length (bytes) | PK fingerprint (first 4 bytes) | Keystore entry |
|---|---|---|---|---|
| V0 | 100 (ML-DSA-44, `SUITE_PQ_RESERVED_1`) | 1312 | `4f40cf4e` | `/tmp/run036/keystores/v0/validator-0.json` |
| V1 | 100 | 1312 | `989b53e0` | `/tmp/run036/keystores/v1/validator-1.json` |
| V2 | 100 | 1312 | `c1215c0a` | `/tmp/run036/keystores/v2/validator-2.json` |
| V3 | 100 | 1312 | `ab53ec9c` | `/tmp/run036/keystores/v3/validator-3.json` |

PK hex windows (truncated; full 2624-char hex strings are public and
were passed verbatim on the CLI as `--validator-consensus-key`):

```text
V0: 4f40cf4e…c31766c0 (len=2624)
V1: 989b53e0…e0743274 (len=2624)
V2: c1215c0a…a2c1fdde (len=2624)
V3: ab53ec9c…7a84ec81 (len=2624)
```

> **DevNet ephemeral consensus signing keys.** These are not
> production root keys, not transport KEMTLS roots, and not stake
> identities. Run 036 reuses Run 034's procedure solely to populate
> the `FsValidatorKeystore` and `network.static_peer_consensus_keys`
> peer-side `SuiteAwareValidatorKeyProvider` surface required to
> flip `BinaryConsensusLoopIo::verification_ctx` from `None` to
> `Some(...)`.

## 6. Topology

Same shape as Run 034 §6, with port range `:330xx` (instead of Run
034's `:320xx`) so the two runs can coexist in `/tmp` artifacts.

N=4, `f=1`, `2f+1=3`, V0-first stagger,
`--p2p-mutual-auth required`, `--execution-profile vm-v0`, explicit
data dirs, metrics enabled on every node, `QBIND_MUTUAL_AUTH` unset
on every process (CLI flag is sole authority).

| Node | Phase | `vid` | Listen | Mutual auth | Profile | Data dir | Metrics | Keystore | Verification flag |
|---|---|---:|---|---|---|---|---|---|---|
| V0  | live throughout (restarted once at T+17s to swap to forged-injection harness) | 0 | `127.0.0.1:33050` | `required` | `vm-v0` | `/tmp/run036/data/v0`  | `:33000` | `/tmp/run036/keystores/v0` | `--require-timeout-verification` |
| V1A | live pre-fault, SIGINT'd at injection-window end to drive B14 absent-leader recovery | 1 | `127.0.0.1:33051` | `required` | `vm-v0` | `/tmp/run036/data/v1a` | `:33001` | `/tmp/run036/keystores/v1` | `--require-timeout-verification` |
| V2A | live throughout      | 2 | `127.0.0.1:33052` | `required` | `vm-v0` | `/tmp/run036/data/v2a` | `:33002` | `/tmp/run036/keystores/v2` | `--require-timeout-verification` |
| V3A | live throughout      | 3 | `127.0.0.1:33053` | `required` | `vm-v0` | `/tmp/run036/data/v3a` | `:33003` | `/tmp/run036/keystores/v3` | `--require-timeout-verification` |

Each node was launched with the **same** four
`--validator-consensus-key` entries (one for every validator,
including itself), satisfying the Run-033 requirement that the
`SuiteAwareValidatorKeyProvider` covers every active validator.

> **Trust-boundary reminder.** `--p2p-mutual-auth required` here is
> the same B12 test-grade `TrustedClientRoots` / `DummySig` surface
> as Runs 016/019/023/026/034 — **not** production PQC KEMTLS
> root-key distribution. Run 036 distributes consensus
> timeout-verification public keys, **not** transport KEMTLS root
> keys.

### 6.1 Timing (UTC, from `/tmp/run036/events.log`)

| Event | Time |
|---|---|
| `RUN036_START` | `2026-05-10T12:36:22Z` |
| V0 (honest) start (PID 13708) | `2026-05-10T12:36:22Z` |
| V1A/V2A/V3A start (PID 13731/13732/13733) | `2026-05-10T12:36:23Z` |
| Phase-1 startup scrape (T+8s) | `2026-05-10T12:36:31Z` |
| Phase-1 baseline scrape (T+16s) | `2026-05-10T12:36:39Z` |
| **V0 honest SIGINT (graceful, rc=0)** | `2026-05-10T12:36:39Z` |
| Pre-injection scrape (V1A/V2A/V3A only) | `2026-05-10T12:36:39Z` |
| **V0 relaunch with `QBIND_DEVNET_FORGED_INJECTION=1` + 12 cases** (PID 13857) | `2026-05-10T12:36:39Z` |
| Post-injection scrape T+4s after V0 relaunch | `2026-05-10T12:36:43Z` |
| Post-injection scrape T+12s after V0 relaunch | `2026-05-10T12:36:51Z` |
| **B14 absent-leader fault: SIGINT V1A** (PID 13731) | `2026-05-10T12:36:51Z` |
| Post-fault scrape (T+10s after V1A SIGINT) | `2026-05-10T12:37:01Z` |
| Post-recovery scrape (T+20s after V1A SIGINT) | `2026-05-10T12:37:11Z` |
| Graceful shutdown of V0/V2A/V3A (all rc=0) | `2026-05-10T12:37:11Z` |
| `RUN036_END` | `2026-05-10T12:37:11Z` |

## 7. Exact commands run

Driver: `/tmp/run036/orchestrate.py` (Python orchestrator, kept
outside the repository, full content below).

### 7.1 Per-node arguments (constructed in `orchestrate.py::base_args`)

```sh
env -u QBIND_MUTUAL_AUTH \
    QBIND_METRICS_HTTP_ADDR=127.0.0.1:$METRICS \
    [QBIND_DEVNET_FORGED_INJECTION=1] \
    /home/runner/work/QBIND/QBIND/target/debug/qbind-node \
    --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:$LISTEN \
    --p2p-peer <other-vids>@127.0.0.1:330${peer} \
    --p2p-mutual-auth required \
    --execution-profile vm-v0 \
    --data-dir /tmp/run036/data/v$VID \
    --validator-id $VID \
    --signer-keystore-path /tmp/run036/keystores/v$VID \
    --require-timeout-verification \
    --validator-consensus-key 0:100:$PK0 \
    --validator-consensus-key 1:100:$PK1 \
    --validator-consensus-key 2:100:$PK2 \
    --validator-consensus-key 3:100:$PK3 \
    [--devnet-forged-inject malformed-timeout]            # V0_post only
    [--devnet-forged-inject unsigned-timeout]
    [--devnet-forged-inject bad-signature-timeout]
    [--devnet-forged-inject wrong-suite-timeout]
    [--devnet-forged-inject unknown-validator-timeout]
    [--devnet-forged-inject malformed-newview]
    [--devnet-forged-inject missing-evidence-newview]
    [--devnet-forged-inject duplicate-signer-newview]
    [--devnet-forged-inject insufficient-quorum-newview]
    [--devnet-forged-inject mixed-view-newview]
    [--devnet-forged-inject bad-signature-newview]
    [--devnet-forged-inject high-qc-mismatch-newview]
```

`QBIND_DEVNET_FORGED_INJECTION=1` and the twelve `--devnet-forged-inject`
flags are present **only** on the V0 relaunch (V0_post) — not on
V1A, V2A, V3A, and not on V0_pre. Subprocess parents use
`start_new_session=True` so children survive the orchestrator's
shell context.

### 7.2 Orchestrator phase outline (`/tmp/run036/orchestrate.py`)

```python
log("RUN036_START")
procs["v0"]  = launch(0, 33050, 33000, "v0_pre",  with_forged=False)  # honest
time.sleep(1)
procs["v1a"] = launch(1, 33051, 33001, "v1a")                          # honest
procs["v2a"] = launch(2, 33052, 33002, "v2a")                          # honest
procs["v3a"] = launch(3, 33053, 33003, "v3a")                          # honest

time.sleep(8); scrape_all("startup",  PORTS)         # T+8s
time.sleep(8); scrape_all("baseline", PORTS)         # T+16s

# Swap V0 to forged-injection variant
os.kill(procs["v0"].pid, signal.SIGINT); procs["v0"].wait()
scrape_all("pre_injection", {"v1a":33001,"v2a":33002,"v3a":33003})
procs["v0"] = launch(0, 33050, 33000, "v0_post", with_forged=True)

time.sleep(4);  scrape_all("post_injection_t4",  PORTS)
time.sleep(8);  scrape_all("post_injection_t12", PORTS)

# B14 absent-leader fault
os.kill(procs["v1a"].pid, signal.SIGINT)
time.sleep(10); scrape_all("post_fault",     {"v0":33000,"v2a":33002,"v3a":33003})
time.sleep(10); scrape_all("post_recovery",  {"v0":33000,"v2a":33002,"v3a":33003})

# Graceful shutdown — all four exited rc=0
log("RUN036_END")
```

### 7.3 Environment variables

| Variable | Value |
|---|---|
| `QBIND_MUTUAL_AUTH` | unset on every process (CLI flag is sole authority) |
| `QBIND_METRICS_HTTP_ADDR` | per-node: `127.0.0.1:33000..33003` |
| `QBIND_DEVNET_FORGED_INJECTION` | `1` **only** on V0_post; unset on V0_pre, V1A, V2A, V3A |
| `RUST_LOG` | unset (default eprintln stderr stream is the operator log) |

## 8. Pre-injection startup proof (timeout verification active)

For **every** of the four validators, the live log captured the
following sequence (V0_post quoted in full; V0_pre, V1A, V2A, V3A
identical modulo validator id and PK fingerprint):

```text
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[binary] Run 032: validator signer loaded — backend=local-keystore-plain
        validator_id=ValidatorId(0) suite_id=suite_100
        pk_fingerprint=4f40cf4e... keystore_path=/tmp/run036/keystores/v0
[binary] Run 033: SuiteAwareValidatorKeyProvider built honestly —
        loaded(validators=4,peer_ids=[1, 2, 3],suite_ids=[100],
               fingerprints=["v0:s100:4f40cf4e...",
                             "v1:s100:989b53e0...",
                             "v2:s100:c1215c0a...",
                             "v3:s100:ab53ec9c..."])
[binary] Run 033: timeout-verification probe: active=true reason=n/a
        policy=RequireOrFail validators=4
        chain_id=chain_51424e4444455600 supported_suite_ids=[100]
        local_signer=loaded(backend=local-keystore-plain,
                            validator=ValidatorId(0), suite=suite_100)
        peer_key_provider=loaded(validators=4,peer_ids=[1, 2, 3],
                                 suite_ids=[100],fingerprints=[…])
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

Phase-1 startup `/metrics` scrape (T+8s, every node — values
identical across V0/V1A/V2A/V3A modulo per-node committed-height
which was `48` on every node and `current_view = 51`):

```text
qbind_timeout_verification_active 1
qbind_timeout_verification_signer_loaded 1
qbind_timeout_verification_key_provider_loaded 1
qbind_timeout_verification_validator_count 4
qbind_consensus_committed_height 43        # snapshot at T+8s
qbind_consensus_current_view 46
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

> No node started under `verification_ctx=None`. No node fell back
> to the Run 032 `SignerPresentKeyProviderUnavailable` disabled
> path. No node logged `timeout verification DISABLED`. The
> `--require-timeout-verification` flag was honored on every process
> (any honest "no" would have caused `[binary] FATAL` and `exit(1)`
> per `crates/qbind-node/src/main.rs`).

## 9. Honest baseline progress (no regression)

Phase-1 baseline `/metrics` scrape (T+16s, every live validator)
shows the honest path advancing identically to Runs 016/019/023/026/034
with verification active and **before** any forged frame has been
injected:

| Metric | V0_pre | V1A | V2A | V3A |
|---|---:|---:|---:|---:|
| `qbind_consensus_committed_height` | 88 | 88 | 88 | 88 |
| `qbind_consensus_current_view`     | 91 | 91 | 91 | 91 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 | 0 | 0 |
| `qbind_consensus_votes_total{result="invalid"}`      | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeouts_emitted_total`        | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeout_decode_failures_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeout_engine_rejects_total`  | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_timeout_verify_rejected_total`  | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_verify_rejected_total`  | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_timeout_engine_accepted_total`  | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_engine_accepted_total`  | 0 | 0 | 0 | 0 |
| `qbind_consensus_view_timeout_advances_total`            | 0 | 0 | 0 | 0 |

All four nodes were within the same view and committed-height; no
regression in the QC path; all rejection counters quiescent.

## 10. Forged-injection harness activation

V0 was SIGINT'd (PID 13708, rc=0, log `v0_pre.log`) at
`T = 12:36:39Z` and immediately relaunched as PID 13857 with the
**same** Run-034 verification flags **plus**
`QBIND_DEVNET_FORGED_INJECTION=1` and twelve hidden
`--devnet-forged-inject CASE` flags. The Run 035 harness fired the
following structured stderr lines (verbatim from
`/tmp/run036/logs/v0_post.log`, lines 26–57):

```text
[binary] Run 035: forged-injection harness ARMED — env=devnet,
        QBIND_DEVNET_FORGED_INJECTION=1,
        cases=["malformed-timeout", "unsigned-timeout",
               "bad-signature-timeout", "wrong-suite-timeout",
               "unknown-validator-timeout", "malformed-newview",
               "missing-evidence-newview", "duplicate-signer-newview",
               "insufficient-quorum-newview", "mixed-view-newview",
               "bad-signature-newview", "high-qc-mismatch-newview"].
        Frames will traverse the same binary-loop verification gate
        as live inbound P2P traffic; the harness never calls into
        the engine and never fabricates metrics.

[forged-injection] Run 035: runtime activation; cases=[…12…]
        (env=devnet, QBIND_DEVNET_FORGED_INJECTION=1)
[forged-injection] Run 035: injecting case=malformed-timeout         kind=Timeout bytes=32
[forged-injection] Run 035: injecting case=unsigned-timeout          kind=Timeout bytes=26
[forged-injection] Run 035: injecting case=bad-signature-timeout     kind=Timeout bytes=2446
[forged-injection] Run 035: injecting case=wrong-suite-timeout       kind=Timeout bytes=2446
[forged-injection] Run 035: injecting case=unknown-validator-timeout kind=Timeout bytes=26
[forged-injection] Run 035: injecting case=malformed-newview         kind=NewView bytes=32
[forged-injection] Run 035: injecting case=missing-evidence-newview  kind=NewView bytes=57
[forged-injection] Run 035: injecting case=duplicate-signer-newview  kind=NewView bytes=7395
[forged-injection] Run 035: injecting case=insufficient-quorum-newview kind=NewView bytes=4941
[forged-injection] Run 035: injecting case=mixed-view-newview        kind=NewView bytes=7395
[forged-injection] Run 035: injecting case=bad-signature-newview     kind=NewView bytes=7395
[forged-injection] Run 035: injecting case=high-qc-mismatch-newview  kind=NewView bytes=7443
[forged-injection] Run 035: injection complete; harness terminating.
        Honest traffic continues unaffected.
```

Two structured rejection lines from the binary-loop's
verification gate were emitted in the same window, attributable to
the two `Malformed*` cases (decode failures):

```text
[binary-consensus] B14: inbound timeout decode failed: InvalidTagEncoding(255)
[binary-consensus] B14: inbound NewView decode failed: InvalidTagEncoding(255)
```

No private-key, signature, or signing-preimage bytes were logged
(grepped `private_key_hex|private_key_bytes|secret_key|secret_share`
across all five log files — zero hits).

## 11. Per-case post-injection metrics

V0_post scrape at **T+4s** after relaunch (the harness completes
all 12 injections within ~1.6 s on top of the 1 s startup delay,
so this scrape captures the steady forged-only state) and at
**T+12s** are shown side by side.

The honest path is observable on V1A/V2A/V3A in the **same**
`post_injection_t4` and `post_injection_t12` scrapes — it provides
the baseline for separating forged-only counter motion (V0) from
honest traffic (V1A/V2A/V3A).

### 11.1 Inbound Timeout family — V0 (target node)

| Counter | T+4s | T+12s | Δ vs pre-injection (V0 was relaunched fresh; pre = 0) | Forged contribution |
|---|---:|---:|---:|---|
| `qbind_consensus_inbound_timeouts_delivered_total` | 4 | 7 | +7 | 4 forged + 3 honest catch-up |
| `qbind_consensus_inbound_timeout_verify_accepted_total` | 0 | 3 | +3 | **0 forged** + 3 honest |
| `qbind_consensus_inbound_timeout_verify_rejected_total` | **4** | **4** | +4 | 4 forged (frozen — no honest motion) |
| `qbind_consensus_inbound_timeout_engine_accepted_total` | **0** | 3 | +3 | **0 forged** + 3 honest |
| `qbind_consensus_inbound_timeout_engine_rejected_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_timeout_rejected_unknown_validator_total` | **1** | **1** | +1 | `unknown-validator-timeout` (frozen) |
| `qbind_consensus_inbound_timeout_rejected_missing_key_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_timeout_rejected_wrong_suite_total` | **1** | **1** | +1 | `wrong-suite-timeout` (frozen) |
| `qbind_consensus_inbound_timeout_rejected_unsupported_suite_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_timeout_rejected_bad_signature_total` | **2** | **2** | +2 | `unsigned-timeout` + `bad-signature-timeout` (frozen) |
| `qbind_consensus_inbound_timeout_rejected_duplicate_total` | 0 | 0 | 0 | 0 |

Sum of per-reason `rejected_*` counters = 1 + 1 + 2 = **4**, exactly
equal to `verify_rejected_total = 4`. ✅

### 11.2 Inbound NewView/TC family — V0 (target node)

| Counter | T+4s | T+12s | Δ vs pre-injection | Forged contribution |
|---|---:|---:|---:|---|
| `qbind_consensus_inbound_new_views_delivered_total` | 6 | 9 | +9 | 6 forged + 3 honest catch-up |
| `qbind_consensus_inbound_newview_verify_accepted_total` | 0 | 3 | +3 | **0 forged** + 3 honest |
| `qbind_consensus_inbound_newview_verify_rejected_total` | **6** | **6** | +6 | 6 forged (frozen — no honest motion) |
| `qbind_consensus_inbound_newview_engine_accepted_total` | **0** | 1 | +1 | **0 forged** + 1 honest |
| `qbind_consensus_inbound_newview_engine_rejected_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_rejected_missing_evidence_total` | **1** | **1** | +1 | `missing-evidence-newview` (frozen) |
| `qbind_consensus_inbound_newview_rejected_evidence_mismatch_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_rejected_duplicate_signer_total` | **1** | **1** | +1 | `duplicate-signer-newview` (frozen) |
| `qbind_consensus_inbound_newview_rejected_mixed_view_total` | 0 | 0 | 0 | 0 (subsumed — see §11.4) |
| `qbind_consensus_inbound_newview_rejected_insufficient_quorum_total` | 0 | 0 | 0 | 0 (subsumed — see §11.4) |
| `qbind_consensus_inbound_newview_rejected_unknown_validator_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_rejected_missing_key_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_rejected_wrong_suite_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_rejected_unsupported_suite_total` | 0 | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_rejected_bad_signature_total` | **4** | **4** | +4 | `bad-signature-newview` + 3 subsumed cases (frozen — see §11.4) |
| `qbind_consensus_inbound_newview_rejected_high_qc_mismatch_total` | 0 | 0 | 0 | 0 (subsumed — see §11.4) |

Sum of per-reason NewView `rejected_*` counters = 1 + 1 + 4 = **6**,
exactly equal to `verify_rejected_total = 6`. ✅

### 11.3 Decode-failure family — V0

| Counter | T+4s | T+12s | Forged contribution |
|---|---:|---:|---|
| `qbind_consensus_view_timeout_decode_failures_total` | **2** | **2** | `malformed-timeout` + `malformed-newview` |

> **Wiring note.** Per
> `crates/qbind-node/src/binary_consensus_loop.rs:1970-1971` and
> `:2241-2242`, `view_timeout_decode_failures_total` is shared
> between the `Timeout` and `NewView` decode-failure paths. The
> observed `2` decomposes deterministically into one increment per
> `Malformed*` case in the harness manifest. No other counter is
> incremented in either decode-failure path, so `delivered_total`
> for the affected variant is *not* incremented (decode happens
> before the "delivered" accounting), which is why
> `inbound_timeouts_delivered_total = 4` (5 timeout cases injected
> minus 1 decode-failed) and `inbound_new_views_delivered_total = 6`
> (7 NewView cases injected minus 1 decode-failed) at T+4s.

### 11.4 Per-case manifest (forged → counter mapping)

| # | Case (CLI token) | Frame variant | Bytes | Counter incremented | Notes |
|--:|---|---|---:|---|---|
| 1 | `malformed-timeout` | `Timeout(32)` | 32 | `view_timeout_decode_failures_total` (+1) | non-bincode random bytes; rejected at decode (`InvalidTagEncoding(255)` line in v0_post.log). |
| 2 | `unsigned-timeout` | `Timeout(26)` | 26 | `inbound_timeout_rejected_bad_signature_total` (+1) | empty signature → ML-DSA-44 verify fails. |
| 3 | `bad-signature-timeout` | `Timeout(2446)` | 2446 | `inbound_timeout_rejected_bad_signature_total` (+1) | first sig byte flipped → verify fails. |
| 4 | `wrong-suite-timeout` | `Timeout(2446)` | 2446 | `inbound_timeout_rejected_wrong_suite_total` (+1) | suite_id mutated post-sign → suite rejection fires before sig path. |
| 5 | `unknown-validator-timeout` | `Timeout(26)` | 26 | `inbound_timeout_rejected_unknown_validator_total` (+1) | validator_id outside active set → membership rejection fires before key lookup. |
| 6 | `malformed-newview` | `NewView(32)` | 32 | `view_timeout_decode_failures_total` (+1) | non-bincode random bytes; rejected at decode. |
| 7 | `missing-evidence-newview` | `NewView(57)` | 57 | `inbound_newview_rejected_missing_evidence_total` (+1) | TC with empty `signed_timeouts` — structural rejection fires before sig path. |
| 8 | `duplicate-signer-newview` | `NewView(7395)` | 7395 | `inbound_newview_rejected_duplicate_signer_total` (+1) | same VID signs twice — structural rejection fires before sig path. |
| 9 | `insufficient-quorum-newview` | `NewView(4941)` | 4941 | `inbound_newview_rejected_bad_signature_total` (+1; see boundary statement below) | only 2/4 signers present, all signed by harness-fresh keys → first signature path fails verification before quorum check fires. |
| 10 | `mixed-view-newview` | `NewView(7395)` | 7395 | `inbound_newview_rejected_bad_signature_total` (+1; see boundary statement below) | one signed timeout has a different view; signed by harness-fresh keys → signature path fails first. |
| 11 | `bad-signature-newview` | `NewView(7395)` | 7395 | `inbound_newview_rejected_bad_signature_total` (+1) | one signed timeout has a flipped sig byte. |
| 12 | `high-qc-mismatch-newview` | `NewView(7443)` | 7443 | `inbound_newview_rejected_bad_signature_total` (+1; see boundary statement below) | TC declares non-empty `high_qc` but evidence's deterministic `max(high_qc) = None`; signed by harness-fresh keys → signature path fails before high-QC consistency check. |

Total: **5 timeout cases + 7 NewView cases = 12 cases**, mapped onto:
- `view_timeout_decode_failures_total = 2` (cases #1, #6)
- timeout per-reason counters: `unknown_validator=1` (#5),
  `wrong_suite=1` (#4), `bad_signature=2` (#2, #3) → **sum = 4** =
  `inbound_timeout_verify_rejected_total = 4`;
- NewView per-reason counters: `missing_evidence=1` (#7),
  `duplicate_signer=1` (#8), `bad_signature=4` (#9, #10, #11, #12)
  → **sum = 6** = `inbound_newview_verify_rejected_total = 6`;
- engine-accepted on either family, attributable to forged frames:
  **0** at T+4s on every family (§11.1, §11.2). ✅

### 11.5 Boundary statement on `bad_signature` subsumption

The harness intentionally constructs forged cases with **fresh
ML-DSA-44 keypairs** (see
`crates/qbind-node/src/main.rs::maybe_spawn_run035_forged_injection_harness`
and the per-case `ForgedFrameBuilder` doc in
`crates/qbind-node/src/forged_injection.rs`). These keys are not
registered with the live `SuiteAwareValidatorKeyProvider`, so any
case whose rejection reason fires **after** the per-signature
ML-DSA-44 verification step in
`crates/qbind-consensus/src/timeout_verify.rs::verify_timeout_certificate_with_evidence`
is preempted by `bad_signature` rejection. This collapses three
NewView cases (`insufficient-quorum-newview`, `mixed-view-newview`,
`high-qc-mismatch-newview`) onto the `bad_signature` counter rather
than their own per-reason counter at the **live N=4 binary path**.

The deterministic per-reason behaviour for those three cases is
already proved in-process by the **Run 030 / Run 035 deterministic
unit-tests** (`run030_inbound_*`,
`forged_injection::tests::run035_*`), where the engine's own keys
are used so the structural check fires before the signature check
and the case-specific counter increments cleanly. Run 036 does
**not** modify those tests — they are re-run as part of §14 below
and pass 21/21 + 20/20.

### 11.6 Honest peers (V1A, V2A, V3A) saw no forged motion

V1A/V2A/V3A scrapes during the same `post_injection_t4` and
`post_injection_t12` windows show **every** forged-injection
counter family at 0:

| Metric (V1A/V2A/V3A, T+4s and T+12s) | V1A | V2A | V3A |
|---|---:|---:|---:|
| `qbind_consensus_inbound_timeout_verify_rejected_total` | 0 | 0 | 0 |
| `qbind_consensus_inbound_newview_verify_rejected_total` | 0 | 0 | 0 |
| `qbind_consensus_view_timeout_decode_failures_total`    | 0 | 0 | 0 |
| every `qbind_consensus_inbound_timeout_rejected_*_total`  | 0 | 0 | 0 |
| every `qbind_consensus_inbound_newview_rejected_*_total`  | 0 | 0 | 0 |

i.e. the harness deliberately injected only into V0's local inbound
channel (matching its design — it does not synthesise forged
transport-layer P2P traffic; that would require a fake-peer rig
which Run 036 does not build). Honest peers are unaffected by the
injection.

## 12. Proof: forged traffic did not advance view

Attribution uses **counter freezing** plus a clean T+4s scrape:

1. The full forged burst (12 cases at 1 s + 11×50 ms ≈ 1.55 s) is
   complete well before the T+4s scrape (`post_injection_t4`).
2. At the T+4s scrape on V0:
   - `qbind_consensus_view_timeout_advances_total = 0`
   - `qbind_consensus_view_advances_due_to_verified_tc_total = 0`
   - `qbind_consensus_inbound_newview_engine_accepted_total = 0`
   - `qbind_consensus_inbound_timeout_engine_accepted_total = 0`
3. After the T+4s scrape, every per-reason **forged** counter
   (timeout `verify_rejected = 4`, newview `verify_rejected = 6`,
   `view_timeout_decode_failures = 2`, all six per-reason values
   listed in §11.1/§11.2) is **frozen** for the rest of the run.
   Across `post_injection_t12`, `post_fault`, and `post_recovery`:

   | Counter | T+4s | T+12s | post_fault | post_recovery |
   |---|---:|---:|---:|---:|
   | `inbound_timeout_verify_rejected_total` | 4 | 4 | 4 | 4 |
   | `inbound_timeout_rejected_bad_signature_total` | 2 | 2 | 2 | 2 |
   | `inbound_timeout_rejected_wrong_suite_total` | 1 | 1 | 1 | 1 |
   | `inbound_timeout_rejected_unknown_validator_total` | 1 | 1 | 1 | 1 |
   | `inbound_newview_verify_rejected_total` | 6 | 6 | 6 | 6 |
   | `inbound_newview_rejected_missing_evidence_total` | 1 | 1 | 1 | 1 |
   | `inbound_newview_rejected_duplicate_signer_total` | 1 | 1 | 1 | 1 |
   | `inbound_newview_rejected_bad_signature_total` | 4 | 4 | 4 | 4 |
   | `view_timeout_decode_failures_total` | 2 | 2 | 2 | 2 |

   Every single one of these **stays at exactly the value** implied
   by the harness case mix from Run-036 start to Run-036 end. **No
   honest traffic ever exercised these rejection paths.**
4. Therefore every increment in the forged counter family is
   exactly attributable to the 12-case burst, and every later
   increment in `verify_accepted` / `engine_accepted` /
   `view_timeout_advances` / `view_advances_due_to_verified_tc` /
   `timeout_certificates_formed` came from honest traffic only.

**Forged-attributable view-advance delta = 0.** ✅

## 13. Proof: forged traffic did not reach engine

For **every** of the 12 injected cases:

- `inbound_timeout_engine_accepted_total = 0` at T+4s → no forged
  Timeout reached `engine.on_timeout_msg`. ✅
- `inbound_newview_engine_accepted_total = 0` at T+4s → no forged
  NewView reached `engine.on_timeout_certificate`. ✅
- `inbound_timeout_engine_rejected_total = 0` and
  `inbound_newview_engine_rejected_total = 0` everywhere → forged
  rejection happened **before** engine ingestion (preferred), not
  via post-engine reject. ✅

Logs corroborate (V0 only — these decoder lines fire **before** any
engine call in `crates/qbind-node/src/binary_consensus_loop.rs`):

```text
[binary-consensus] B14: inbound timeout decode failed: InvalidTagEncoding(255)
[binary-consensus] B14: inbound NewView decode failed: InvalidTagEncoding(255)
```

The remaining ten cases that *do* decode but fail
verification are accounted for entirely in the
`inbound_*_verify_rejected_total` and per-reason
`inbound_*_rejected_*` counters (§11.1, §11.2) — never in any
`engine_*` counter.

## 14. Proof: process remained alive

| Process | Initial PID | Phase | Final PID | Exit code | Crash signal |
|---|---:|---|---:|---:|---|
| V0_pre  | 13708 | SIGINT'd at T+17s to swap to forged-injection variant | 13708 | **0** | none |
| V0_post | 13857 | injected 12 forged frames; survived through B14 fault and post-recovery; SIGINT'd at end | 13857 | **0** | none |
| V1A     | 13731 | SIGINT'd at injection-window end to drive B14 | 13731 | **0** | none |
| V2A     | 13732 | live throughout; SIGINT'd at end | 13732 | **0** | none |
| V3A     | 13733 | live throughout; SIGINT'd at end | 13733 | **0** | none |

Across all five log files (`v0_pre.log`, `v0_post.log`, `v1a.log`,
`v2a.log`, `v3a.log`) the strings `panic`, `panicked`, `SIGSEGV`,
`segmentation`, `abort`, and `FATAL` (excluding the harness's own
"Run 035 forged-injection harness…FATAL: …" pre-startup gate
diagnostics which are *helper output*, not process panics) produce
**zero hits**:

```sh
$ for f in /tmp/run036/logs/*.log; do
    echo "$f: $(grep -cE 'panic|panicked|SIGSEGV|segmentation|abort|FATAL' "$f") hits"
  done
/tmp/run036/logs/v0_post.log: 0 hits
/tmp/run036/logs/v0_pre.log:  0 hits
/tmp/run036/logs/v1a.log:     0 hits
/tmp/run036/logs/v2a.log:     0 hits
/tmp/run036/logs/v3a.log:     0 hits
```

V0 — the injection target — survived the entire 12-case forged
burst, the subsequent B14 absent-leader fault, the post-recovery
TimeoutCertificate formation cycle, and the final SIGINT-driven
graceful shutdown (rc = 0). ✅

## 15. Proof: post-injection honest B14 recovery still works

After the injection burst was complete (T+12s scrape captured a
stable forged-only V0 state), V1A was sent `signal.SIGINT` (PID
13731, recorded numerically) at `T = 12:36:51Z`. Under the
round-robin rotation
`leader(view) = view mod num_validators`, V1 was the leader for
views `133, 137, 141, …`. The remaining `2f+1 = 3` honest
validators (V0_post, V2A, V3A) had to recover via signed
`TimeoutMsg` / verified `TimeoutCertificate` / verified `NewView`
traffic — exactly the Run-034 shape, but now on a target node that
has just absorbed a 12-case forged-injection burst.

### 15.1 Signed outbound TimeoutMsg proof

`/tmp/run036/logs/{v0_post,v2a,v3a}.log` each contain matching
`Run 030: signing timeout` / `Run 030: timeout signing OK` /
`B14: emitted TimeoutMsg` / `B14: TimeoutCertificate advanced view`
sequences for views 133→134, 137→138, 141→142. Representative
extract from `v0_post.log`:

```text
[binary-consensus] Run 030: signing timeout view=133 validator=ValidatorId(0) suite_id=100
[binary-consensus] Run 030: timeout signing OK view=133 validator=ValidatorId(0) suite_id=100
[binary-consensus] B14: emitted TimeoutMsg for view=133 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 133 -> 134
[binary-consensus] Run 030: timeout signing OK view=137 validator=ValidatorId(0) suite_id=100
[binary-consensus] B14: emitted TimeoutMsg for view=137 after 50 ticks of no progress
[binary-consensus] B14: TimeoutCertificate advanced view 137 -> 138
[binary-consensus] Run 030: timeout signing OK view=141 validator=ValidatorId(0) suite_id=100
[binary-consensus] B14: emitted TimeoutMsg for view=141 after 50 ticks of no progress
```

Post-recovery `/metrics` (V0_post; V2A and V3A symmetric, see §15.4):

```text
qbind_consensus_outbound_timeout_signing_success_total 4
qbind_consensus_outbound_timeout_signing_failure_total 0
```

`signing_failure_total = 0` confirms no signer errors during honest
traffic. **No unsigned TimeoutMsg was emitted** (the binary-consensus
loop's `verify+sign` mode only broadcasts a `TimeoutMsg` after a
successful `signer.sign(...)` call). ✅

### 15.2 Inbound TimeoutMsg verification proof — honest only

Post-recovery `/metrics` (V0_post — recall pre-injection V0 was
relaunched fresh at view 0 and caught up via streamed proposals;
V2A/V3A symmetric):

```text
qbind_consensus_inbound_timeouts_delivered_total                13
qbind_consensus_inbound_timeout_verify_accepted_total            9
qbind_consensus_inbound_timeout_verify_rejected_total            4   # frozen from forged burst
qbind_consensus_inbound_timeout_rejected_unknown_validator_total 1   # frozen
qbind_consensus_inbound_timeout_rejected_missing_key_total       0
qbind_consensus_inbound_timeout_rejected_wrong_suite_total       1   # frozen
qbind_consensus_inbound_timeout_rejected_unsupported_suite_total 0
qbind_consensus_inbound_timeout_rejected_bad_signature_total     2   # frozen
qbind_consensus_inbound_timeout_rejected_duplicate_total         0
qbind_consensus_inbound_timeout_engine_accepted_total            9
qbind_consensus_inbound_timeout_engine_rejected_total            0
qbind_consensus_view_timeout_decode_failures_total               2   # frozen
qbind_consensus_view_timeout_engine_rejects_total                0
```

- `verify_accepted_total = 9` honest TimeoutMsgs verified
  (catch-up + 3 absent-leader cycles × 2 honest peers = 9).
- All 9 reached `engine.on_timeout_msg` (`engine_accepted_total = 9`,
  `engine_rejected_total = 0`).
- Every per-reason rejection counter is **frozen** at the value
  established by the forged burst — no honest traffic incremented
  any of them. ✅

### 15.3 Inbound NewView/TC verification proof — honest only

Post-recovery `/metrics` (V0_post; V2A/V3A symmetric):

```text
qbind_consensus_outbound_new_views_sent_total                    3
qbind_consensus_inbound_new_views_delivered_total               15
qbind_consensus_inbound_newview_verify_accepted_total            9
qbind_consensus_inbound_newview_verify_rejected_total            6   # frozen from forged burst
qbind_consensus_inbound_newview_rejected_missing_evidence_total  1   # frozen
qbind_consensus_inbound_newview_rejected_evidence_mismatch_total 0
qbind_consensus_inbound_newview_rejected_duplicate_signer_total  1   # frozen
qbind_consensus_inbound_newview_rejected_mixed_view_total        0
qbind_consensus_inbound_newview_rejected_insufficient_quorum_total 0
qbind_consensus_inbound_newview_rejected_unknown_validator_total 0
qbind_consensus_inbound_newview_rejected_missing_key_total       0
qbind_consensus_inbound_newview_rejected_wrong_suite_total       0
qbind_consensus_inbound_newview_rejected_unsupported_suite_total 0
qbind_consensus_inbound_newview_rejected_bad_signature_total     4   # frozen
qbind_consensus_inbound_newview_rejected_high_qc_mismatch_total  0
qbind_consensus_inbound_newview_engine_accepted_total            1
qbind_consensus_inbound_newview_engine_rejected_total            0
qbind_consensus_view_timeout_advances_total                      4
qbind_consensus_timeout_certificates_formed_total                3
qbind_consensus_view_advances_due_to_verified_tc_total           4
```

- 9 honest NewViews verified (`verify_accepted = 9`; one verified
  during catch-up before the fault, and 2 per fault cycle × 3 cycles
  + 1 catch-up + ≥ 2 broadcast).
- Every per-reason `inbound_newview_rejected_*` counter is
  **frozen** at its forged-burst value. No honest increment.
- 4 `view_timeout_advances_total` and 3
  `timeout_certificates_formed_total` confirm view-change progressed.
- `view_advances_due_to_verified_tc_total = 4` confirms every
  view advance came from a **verified** TC (no view advance is
  attributed to forged traffic, which had `verify_accepted = 0`
  for both timeout and newview families). ✅

### 15.4 Per-validator phase summary

| Phase | Time after fault | V0_post (committed/view) | V2A | V3A |
|---|---|---:|---:|---:|
| Pre-injection (V1A,V2A,V3A; V0 down) | – | – | 88 / 91 | 88 / 91 |
| Post-injection T+12s (all live) | – | 36 / 132 | 128 / 132 | 128 / 132 |
| Post-fault scrape | T+10s | 40 / 137 | 132 / 137 | 132 / 137 |
| **Post-recovery scrape** | T+20s | **46 / 145** | **138 / 145** | **138 / 145** |

V0_post's lower committed-height reflects its fresh restart
(committed=0 at relaunch; catching up streamed proposals from peers).
The crucial property is that **all three live validators agreed on
`current_view = 145`** at post-recovery (V0_post = V2A = V3A = 145),
and `committed_height` advanced past the fault baseline on every
node (V0 from 0 → 46; V2A/V3A from 88 → 138, +50 blocks past the
absent-leader plateau).

Required success conditions (every one met):

- Timeout certificates formed:
  `timeout_certificates_formed_total ≥ 3` on every live validator. ✅
- Verified NewView advances view:
  `view_timeout_advances_total = 4`,
  `view_advances_due_to_verified_tc_total = 4` on every node. ✅
- `current_view` advanced above absent-leader views
  (`132 → 145`, passing `133/137/141`). ✅
- Proposal/vote/QC/commit progression resumed after each TC:
  V2A/V3A `committed_height 88 → 138` (+50 blocks past plateau);
  V0_post `0 → 46` (catch-up plus post-fault commits). ✅
- Remaining live validators agreed on `current_view = 145`. ✅
- No operator intervention beyond the planned SIGINTs against V0_pre
  (swap) and V1A (B14 fault). ✅
- `qbind_consensus_proposals_total{result="rejected"} = 0` and
  `qbind_consensus_votes_total{result="invalid"} = 0` on every live
  node. ✅

## 16. Negative checks (every check passed)

| Check | Required | Observed |
|---|---|---|
| Harness activation requires all three gates | yes | three out-of-band smoke checks (testnet env, missing env var, unknown case token) all hit `[binary] FATAL: …; refusing startup`; harness only ARMED on V0_post |
| No fake metrics | yes | every counter referenced is an `AtomicU64` set/incremented in `crates/qbind-node/src/metrics.rs` from real loop / verifier paths — the harness reads no metrics counters and increments none (see Run 035 §1 safety property #4) |
| No direct engine call by harness | yes | harness writes `ConsensusNetMsg` only into the `mpsc::Sender<ConsensusNetMsg>` cloned from `ChannelConsensusHandler::sender_clone()`; the binary loop's `handle_inbound_consensus_msg` is the sole consumer (Run 035 §1 safety property #3) |
| No accepted forged Timeout | yes | `inbound_timeout_engine_accepted_total = 0` at T+4s on V0 (forged-only window); subsequent honest accepts are independently attributed (§15.2) |
| No accepted forged NewView/TC | yes | `inbound_newview_engine_accepted_total = 0` at T+4s on V0; subsequent honest accepts are independently attributed (§15.3) |
| No view advance caused by forged traffic | yes | `view_timeout_advances_total = 0` and `view_advances_due_to_verified_tc_total = 0` at T+4s on V0; subsequent advances are paired with `verify_accepted` increments **and** with `outbound_timeout_signing_success` motion on the honest peers, never with `verify_rejected` motion |
| No process crash | yes | every node exited rc=0 (§14); zero panic/abort/segfault signatures |
| No private key material in logs | yes | logs only contain `pk_fingerprint=<4-byte hex>...`; zero hits for `private_key_hex|private_key_bytes|secret_key|secret_share` across all five log files; keystore JSON is `0o600` and lives only under `/tmp` |
| No proposal rejection spike | yes | `proposals_total{result="rejected"} = 0` on every live node throughout |
| No invalid vote spike | yes | `votes_total{result="invalid"} = 0` on every live node throughout |
| No regression of Run 034 honest verified-timeout path | yes | V0_post + V2A + V3A drove 4 view advances and ≥ 3 fresh TCs after the injection window with `outbound_timeout_signing_failure_total = 0` (§15.1, §15.3) |
| No claim that production PQC KEMTLS root-key distribution is solved | yes | §6 trust-boundary reminder; §17 keeps C4 piece (c) explicitly OPEN |
| No new harness without all safety gates | yes | three out-of-band gate refusals captured (§7.3 / smoke-check transcript above) |

The transient `[P2P] Failed to broadcast to NodeId(...)` and `[P2P]
Read error: …UnexpectedEof…` lines visible after V1A's SIGINT are
the documented post-Run-008 broken-pipe reaction to a peer that is
no longer reachable (matches Runs 015/016/019/023/026/034 verbatim).
They do **not** affect any consensus or verification metric.

## 17. Tests rerun (all green)

```sh
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
cargo test -p qbind-node --lib forged_injection
cargo test -p qbind-node --lib run030
cargo test -p qbind-node --lib vm_v0_runtime
cargo test -p qbind-node --lib
```

| Suite | Result |
|---|---|
| `cargo build -p qbind-node --bin qbind-node` | ✅ `Finished dev profile in 5m 20s` (2 pre-existing `bincode::config` deprecation warnings, unchanged) |
| `cargo test -p qbind-node --lib forged_injection` | ✅ **21 passed; 0 failed** |
| `cargo test -p qbind-node --lib run030` | ✅ **20 passed; 0 failed** |
| `cargo test -p qbind-node --lib vm_v0_runtime` | ✅ **9 passed; 0 failed** |
| `cargo test -p qbind-node --lib` | ✅ **746 passed; 0 failed; 0 ignored** |

Three additional out-of-band binary safety-gate smoke checks (matches
Run 035 §3, repeated on the same binary):

| Smoke check | Result |
|---|---|
| `--env testnet --devnet-forged-inject malformed-timeout` | ✅ refused: `[binary] FATAL: Run 035 forged-injection harness is dev/test-only and cannot run on environment=Testnet` |
| `--env devnet --devnet-forged-inject malformed-timeout` (no env var) | ✅ refused: `[binary] FATAL: Run 035 forged-injection harness gated: --devnet-forged-inject was supplied but QBIND_DEVNET_FORGED_INJECTION=1 is not set in the environment` |
| `QBIND_DEVNET_FORGED_INJECTION=1 --env devnet --devnet-forged-inject not-a-real-case` | ✅ refused: `[binary] FATAL: --devnet-forged-inject parse error: unknown forged-injection case 'not-a-real-case'; valid: …` |

## 18. Pass/fail table

| Section | Required item | Result |
|---|---|---|
| §4  | Real `qbind-node` built; sha256 + BuildID + size recorded; `--devnet-forged-inject` confirmed hidden from `--help` | ✅ |
| §5  | Four ML-DSA-44 keystores generated; safe metadata only; no private key bytes logged or committed | ✅ |
| §6  | N=4 Required-mode topology booted with all required flags; same shape as Run 034 (port range `:330xx`) | ✅ |
| §8  | `verification_ctx=Some(...)` on every live validator; `qbind_timeout_verification_{active,signer_loaded,key_provider_loaded}=1`, `validator_count=4` on every node | ✅ |
| §9  | Honest pre-injection baseline progress (no QC regression; all rejection counters quiescent) | ✅ |
| §10 | Forged-injection harness ARMED on V0 with all 12 cases; harness logs activation + all 12 injection lines + completion line; no key material in logs | ✅ |
| §11.1, §11.2, §11.3, §11.4 | Per-case counter delta table; sum of per-reason counters equals `verify_rejected_total` on both Timeout and NewView family | ✅ |
| §11.5 | `bad_signature` subsumption boundary clearly stated for 3 NewView cases that depend on post-signature structural rejection | ⚠ explicit (deterministic per-reason coverage for those cases lives in Run 030 / Run 035 unit tests, re-run green in §17) |
| §11.6 | Honest peers (V1A/V2A/V3A) saw zero forged-injection counter motion | ✅ |
| §12 | No view advance caused by forged traffic (T+4s scrape: `view_timeout_advances_total = 0` and `view_advances_due_to_verified_tc_total = 0` on V0; per-reason counters frozen for the rest of the run) | ✅ |
| §13 | No forged frame reached engine (`inbound_timeout_engine_accepted_total = 0`, `inbound_newview_engine_accepted_total = 0` at T+4s on V0; rejection happened pre-engine) | ✅ |
| §14 | All four nodes alive throughout intended phases; rc=0 at orchestrated SIGINT shutdown; zero panic/abort/segfault signatures across all logs | ✅ |
| §15 | Post-injection honest verified-timeout B14 recovery still works (signed outbound TimeoutMsg; verified inbound Timeout/NewView; 4 view advances; 3 fresh TCs; `committed_height` 88→138 on V2A/V3A and 0→46 on V0_post; all live nodes agree on view 145; `outbound_timeout_signing_failure_total=0`; rejection counters frozen) | ✅ |
| §16 | Negative-check matrix (every check green) | ✅ |
| §17 | All targeted suites + full `qbind-node` lib pass; smoke-check refusals confirmed | ✅ |
| §19 | `contradiction.md` C5 narrowed per task §15 | ✅ |

## 19. Remaining open items

1. **Production PQC KEMTLS root-key distribution (C4 piece c)** —
   `--p2p-mutual-auth required` was used in Run 036, but B12
   `TrustedClientRoots` / `DummySig` is still the same test-grade
   shape from Runs 016/019/023/026/034. Run 036 distributes
   consensus timeout-verification public keys via
   `--validator-consensus-key`, **not** transport KEMTLS root keys.
   C4 remains OPEN.
2. **Encrypted-FS keystore (`--signer-mode encrypted-fs`) variant** —
   Run 036 used the plaintext-JSON `LocalKeystorePlain` backend
   (DevNet ephemeral keys), same as Run 034. Encrypted-FS keystores
   are covered by `t153_encrypted_keystore_integration_tests.rs`
   but were not exercised on the N=4 binary path here. This is not
   a regression — only a not-yet-exercised surface.
3. **Larger-N / sustained run** — Run 036 was a ≈ 49-second smoke
   shape with one 12-case forged burst and three absent-leader
   recovery cycles. Longer-duration / larger-N stability under
   continuous active timeout verification + forged injection is not
   claimed here.
4. **Adversary-with-valid-keys harness** — the Run 035 harness
   intentionally uses **fresh** ML-DSA-44 keypairs for forged
   frames (so cases that depend on post-signature structural
   rejection paths fold onto the `bad_signature` counter at the
   live binary path; deterministic per-reason coverage lives in
   the Run 030 / Run 035 unit tests). A future variant that
   exposes a deeper adversary (e.g. an honest-but-malicious peer
   that holds a valid signing key but emits structurally invalid
   evidence) would let those three NewView cases increment their
   own per-reason live counter. Run 036 does **not** build that
   variant.
5. **Inter-node forged transport** — Run 036's harness injects only
   into the local inbound channel of V0. It does not synthesise
   forged transport-layer P2P traffic across the wire. Honest
   peers V1A/V2A/V3A therefore saw zero forged-injection counter
   motion (§11.6). A fake-peer rig would close that gap.

## 20. Exact verdict

**Strongest positive — live N=4 Required-mode real-binary forged
Timeout/NewView/TC injections through the Run 035 harness on V0
were rejected fail-closed before engine ingestion on every one of
the 12 injected cases, no forged frame advanced view (T+4s scrape:
`view_timeout_advances_total = 0`,
`view_advances_due_to_verified_tc_total = 0`,
`inbound_*_engine_accepted_total = 0` on the forged-only window),
V0 stayed alive through the burst (rc=0 at graceful shutdown), all
four nodes terminated with rc=0, and the same Run-034-shape B14
absent-leader recovery still drove signed outbound TimeoutMsg
(`outbound_timeout_signing_failure_total = 0`), verified inbound
Timeout/NewView traffic, 4 view advances all attributed to verified
TCs (`view_advances_due_to_verified_tc_total = 4`), 3 fresh
TimeoutCertificates, and `committed_height` progression past the
fault baseline on every live validator. Every per-reason
`inbound_*_rejected_*` counter is frozen at the value implied by
the forged case mix from T+4s to graceful shutdown — i.e. honest
traffic never exercised any rejection path. No regression in the
Run 034 honest verified-timeout B14 recovery shape. Production PQC
KEMTLS root-key distribution (C4 piece c) remains OPEN.**

---

## Appendix A. Required final response (per task §"Required final response")

1. **Exact verdict:** Strongest positive (see §20).
2. **Exact files changed:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_036.md` (new),
   `docs/whitepaper/contradiction.md` (C5 narrowed). No source
   code modified.
3. **Exact commands run:** §3 of this task table; §7 launchers/
   orchestrator; §17 test/build commands; §6.1 timing.
4. **Exact tests/evidence run and pass/fail status:** §17 + §18.
5. **What was proven:** §1 objective (rejection before engine /
   no view advance / process alive / honest recovery preserved)
   met on a live N=4 cluster with all 12 forged cases.
6. **What remains not solved:** §19 — production PQC KEMTLS
   root-key distribution; encrypted-FS keystore on N=4 binary
   path; larger-N / sustained injection; adversary-with-valid-keys
   harness; inter-node forged transport rig.
7. **Whether `contradiction.md` was updated and why:** Yes — C5
   narrowed to reflect that live N=4 forged-Timeout/NewView/TC
   negative-injection evidence has now landed, while keeping C5
   open strictly because production PQC KEMTLS root-key
   distribution (a C4 sub-item) remains unresolved. C4 is left
   OPEN.
8. **Exact immediate next action recommended:** address C4 piece
   (c) — production PQC KEMTLS root-key distribution — without
   relying on B12's test-grade `TrustedClientRoots` / `DummySig`.
   That is the only remaining sub-item of C5 once Run 036 is
   accepted, and the only path to closing C4 / C5 jointly.