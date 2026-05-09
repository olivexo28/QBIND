# QBIND DevNet Evidence Run 021

## 1. Objective

Run 021 tested the latest claimed code-level closure for C4: a real `qbind-node` binary should, when started with `--execution-profile vm-v0`, open `<data_dir>/state_vm_v0` at runtime and, when `--snapshot-dir` is configured, install a bounded SIGUSR1 in-process snapshot trigger that invokes the existing `StateSnapshotter::create_snapshot` path on the opened VM-v0 RocksDB handle.

This run was intentionally evidence-first and did not redesign consensus, snapshot format, restore format, or snapshot creation.

## 2. Verdict

**Negative.** The built real binary does not accept `--snapshot-dir` or `--snapshot-max-snapshots`, so the required live validator shape cannot start. A secondary live run without snapshot flags showed no `<data_dir>/state_vm_v0` creation/open log during startup/progress, and SIGUSR1 terminated the process (`wait_status=-10`) instead of being handled by an in-process snapshot trigger.

Therefore Run 021 disproves the claimed operational closure on the tested binary. No SIGUSR1-created snapshot exists, so restore from that snapshot and B3/B5/B13/B14 preservation from that snapshot are not proven.

## 3. Binary Identity

Built command:

```bash
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
```

Result: build completed successfully in dev profile with two pre-existing deprecation warnings in `binary_consensus_loop.rs`.

Identity collected at `2026-05-09T06:03:18Z`:

| Field | Value |
|---|---|
| Repository path | `/home/runner/work/QBIND/QBIND` |
| Branch | `copilot/continue-qbind-development` |
| Commit | `950ce2b5e925b2162b1df3da840fa0b35e05dd36` |
| Git status before run | clean (`status_dirty_lines=0`) |
| Binary | `/home/runner/work/QBIND/QBIND/target/debug/qbind-node` |
| sha256 | `69223f70ff05ebc0030633c84d0a2c77e8d4052cee2325a7a62262f13c18199f` |
| ELF BuildID | `97fd927c08c5a3eb64ac01f93e20b318f00f30ea` |

`file` excerpt:

```text
/home/runner/work/QBIND/QBIND/target/debug/qbind-node: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=97fd927c08c5a3eb64ac01f93e20b318f00f30ea, with debug_info, not stripped
```

## 4. Topology and Environment

Primary required attempt:

| Validator | Mode | Metrics | Data dir | Snapshot dir |
|---|---|---|---|---|
| V0 | LocalMesh single validator, `--execution-profile vm-v0` | `QBIND_METRICS_HTTP_ADDR=127.0.0.1:9210` | `/tmp/qbind-run-021/data0` | `/tmp/qbind-run-021/snapshots` |

Secondary negative characterization run:

| Validator | Mode | Metrics | Data dir | Snapshot dir |
|---|---|---|---|---|
| V0 | LocalMesh single validator, `--execution-profile vm-v0` | `QBIND_METRICS_HTTP_ADDR=127.0.0.1:9211` | `/tmp/qbind-run-021/data-no-snapshot` | absent |

Run artifact root: `/tmp/qbind-run-021`.

## 5. Commands Run

```bash
cd /home/runner/work/QBIND/QBIND
cargo build -p qbind-node --bin qbind-node
```

```bash
sha256sum /home/runner/work/QBIND/QBIND/target/debug/qbind-node
file /home/runner/work/QBIND/QBIND/target/debug/qbind-node
readelf -n /home/runner/work/QBIND/QBIND/target/debug/qbind-node | grep -A4 'Build ID'
/home/runner/work/QBIND/QBIND/target/debug/qbind-node --help | grep -E 'snapshot|data-dir|execution-profile|metrics'
```

```bash
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9210 \
/home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet \
  --validator-id 0 \
  --execution-profile vm-v0 \
  --data-dir /tmp/qbind-run-021/data0 \
  --snapshot-dir /tmp/qbind-run-021/snapshots \
  --snapshot-max-snapshots 2
```

A Python process-control wrapper then started the same binary without snapshot flags, waited 6 seconds, scraped `/metrics`, sent SIGUSR1 to the numeric child PID, and recorded process liveness.

```bash
/home/runner/work/QBIND/QBIND/target/debug/qbind-node \
  --env devnet \
  --validator-id 1 \
  --execution-profile vm-v0 \
  --data-dir /tmp/qbind-run-021/restore-data \
  --restore-from-snapshot /tmp/qbind-run-021/snapshots/nonexistent
```

## 6. CLI Surface Evidence

`--help` contains restore support but no configured snapshot trigger flags:

```text
--execution-profile <EXECUTION_PROFILE>
-d, --data-dir <DATA_DIR>
--restore-from-snapshot <RESTORE_FROM_SNAPSHOT>
```

Required configured startup failed before validator launch:

```text
error: unexpected argument '--snapshot-dir' found

  tip: a similar argument exists: '--data-dir'

Usage: qbind-node --env <ENVIRONMENT> --validator-id <VALIDATOR_ID> --execution-profile <EXECUTION_PROFILE> --data-dir <DATA_DIR>
```

Exit code: `2`.

## 7. VM-v0 Runtime Open Evidence

Required configured run: **not reached** because `--snapshot-dir` is rejected by clap before startup.

Secondary no-snapshot run startup excerpt:

```text
[restore] no --restore-from-snapshot requested; normal startup.
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=vm-v0 network=local-mesh p2p=disabled gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9211 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9211 (set via QBIND_METRICS_HTTP_ADDR)
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=vm-v0
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=1 restore_baseline=false
[binary] Single-validator LocalMesh: leader self-quorum will commit a block per tick.
[binary] Consensus loop running. Press Ctrl+C to exit.
[metrics_http] Listening on 127.0.0.1:9211
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=1 tick=100ms restore_baseline=false interconnect=none late_peer_reemit=off
```

The run progressed (`committed_anchor height=1` through at least `height=58`) but did **not** log an open of `/tmp/qbind-run-021/data-no-snapshot/state_vm_v0` and the directory did not exist after 6 seconds:

```text
alive_before_sigusr1=True
state_dir_exists_before_sigusr1=False
```

Filesystem before SIGUSR1 contained only the configured data directory, not `state_vm_v0`.

## 8. SIGUSR1 Trigger Evidence

Required configured run: **not reached** because snapshot flags are unsupported.

Secondary no-snapshot run:

```text
sending_sigusr1_to=11441
alive_after_sigusr1=False
wait_status=-10
```

No logs showed signal receipt, bounded serialization, or `StateSnapshotter::create_snapshot` invocation. The process terminated on SIGUSR1.

## 9. Metrics Snapshot

Metrics before SIGUSR1 in the secondary run:

```text
qbind_restore_catchup_requests_sent_total 0
qbind_restore_catchup_requests_received_total 0
qbind_restore_catchup_responses_sent_total 0
qbind_restore_catchup_responses_received_total 0
qbind_restore_catchup_blocks_applied_total 0
qbind_restore_catchup_responses_rejected_total 0
qbind_restore_catchup_proposals_deferred_total 0
qbind_restore_catchup_mode_active 0
qbind_restore_catchup_mode_exited_at_height 0
qbind_snapshot_last_height 0
qbind_snapshot_last_duration_ms 0
qbind_snapshot_last_size_bytes 0
qbind_snapshot_last_created_at_ms 0
qbind_snapshot_success_total 0
qbind_snapshot_failure_total 0
qbind_snapshot_in_progress 0
```

No fabricated positive snapshot metrics were observed.

## 10. Filesystem and Snapshot Directory Evidence

Run artifact listing:

```text
<RUN>
<RUN>/data-no-snapshot
<RUN>/data0
<RUN>/filesystem.txt
<RUN>/identity.txt
<RUN>/live-no-snapshot-combined.txt
<RUN>/live-no-snapshot.log
<RUN>/restore-combined.txt
<RUN>/restore-data
<RUN>/restore.stderr
<RUN>/restore.stdout
<RUN>/snapshots
<RUN>/start-with-snapshot-combined.txt
<RUN>/start-with-snapshot.stderr
<RUN>/start-with-snapshot.stdout
```

`/tmp/qbind-run-021/snapshots` stayed empty. There was no numeric snapshot directory and no real RocksDB checkpoint substrate (`CURRENT`, `MANIFEST-*`, `*.sst`, `OPTIONS-*`) to inspect. This run did not create placeholder snapshot files either.

## 11. Restore Evidence

Because no SIGUSR1 snapshot was created, restore from a SIGUSR1-created snapshot could not be performed. A negative restore attempt against the expected absent path failed closed:

```text
[restore] requested: snapshot_dir=/tmp/qbind-run-021/snapshots/nonexistent data_dir=/tmp/qbind-run-021/restore-data expected_chain_id=0x51424e4444455600
[restore] ERROR: restore-from-snapshot path does not exist: /tmp/qbind-run-021/snapshots/nonexistent
[restore] qbind-node refuses to start because the requested snapshot restore could not be honestly applied. See docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md and docs/whitepaper/contradiction.md C4 (B3).
```

Exit code: `1`.

B3 fail-closed behavior for a missing snapshot remains intact, but B3 restore copy, B5 baseline, B13 catchup exit, and B14 timeout/new-view behavior from a SIGUSR1-created snapshot were not exercised because the trigger did not exist on this binary.

## 12. Required Checks

| Check | Result | Evidence |
|---|---:|---|
| Build `qbind-node` | Pass | `cargo build -p qbind-node --bin qbind-node` completed |
| Record binary sha256 / BuildID / branch / commit | Pass | §3 |
| Start validator with `--snapshot-dir` and `--snapshot-max-snapshots` | Fail | clap rejected `--snapshot-dir`, exit `2` |
| Prove `<data_dir>/state_vm_v0` opened on startup | Fail | configured run did not start; secondary run had no open log and `state_dir_exists_before_sigusr1=False` |
| Prove no silent fallback to in-memory under required vm-v0 snapshot shape | Fail / not reached | required shape rejected before startup |
| Prove SIGUSR1 received by running validator | Fail | secondary SIGUSR1 killed process; no receipt log |
| Prove `StateSnapshotter::create_snapshot` invoked in-process | Fail | no invocation log and no snapshot output |
| Prove process remains alive after SIGUSR1 | Fail | `alive_after_sigusr1=False`, `wait_status=-10` |
| Prove repeated SIGUSR1 bounded/serialized | Not reached | first SIGUSR1 terminated process |
| Prove real RocksDB checkpoint files | Fail | snapshot dir empty |
| Prove valid snapshot metadata | Fail | no snapshot created |
| Prove restore from SIGUSR1 snapshot | Fail / not reached | no SIGUSR1 snapshot exists |
| Prove B3 restore copy into `<data_dir>/state_vm_v0` | Not reached | no SIGUSR1 snapshot exists |
| Prove B5 restore-aware baseline from SIGUSR1 snapshot | Not reached | no SIGUSR1 snapshot exists |
| Prove B13/B14 behavior after SIGUSR1 restore | Not reached | no SIGUSR1 snapshot exists |
| No crash on SIGUSR1 | Fail in secondary characterization | SIGUSR1 terminated the process |
| No fabricated metrics | Pass | snapshot metrics stayed zero |

## 13. Remaining Open Items

1. Add and verify an actual supported CLI/config surface for snapshot trigger configuration if that remains the intended design.
2. Wire a bounded SIGUSR1 handler only when snapshot configuration is present, and prove it does not terminate the process.
3. Ensure the trigger invokes the existing `StateSnapshotter::create_snapshot` path on the same opened VM-v0 RocksDB handle.
4. Ensure `--execution-profile vm-v0` fail-closed opens `<data_dir>/state_vm_v0` at runtime and does not silently continue in-memory when a data dir is provided.
5. Re-run the full N=4 Required-mode evidence shape only after a real binary can create a SIGUSR1 snapshot.

## 14. Exact Verdict

**Negative:** VM-v0 runtime open + SIGUSR1 in-process snapshot trigger are **not** operationally proven on the tested real `qbind-node` binary. The required snapshot flags are not accepted; a live no-snapshot characterization run did not create/open `state_vm_v0`; SIGUSR1 terminated the process; and no real snapshot or restore from such a snapshot exists.