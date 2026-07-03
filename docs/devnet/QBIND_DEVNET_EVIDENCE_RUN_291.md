# QBIND DevNet Evidence — Run 291

**Run 291 — Production durable replay RocksDB backend (source/test
implementation).**

## 1. Exact verdict

**PASS / source-test production durable replay backend implementation,
release-binary evidence deferred to Run 292.**

Run 291 lands the first *real* production durable replay backend for the
governance durable replay layer: a RocksDB-backed backend that persists typed
replay records to disk, recovers them across reopen, enforces domain binding,
enforces idempotency / equivocation, verifies record digests on read, enforces
`Observed → Consumed` stage ordering, and fails closed on corrupt / wrong-domain
/ partial-write state — with **no** silent in-memory fallback and a
**default-Disabled** production policy. This is source/test only: the production
binary is not wired to open the backend, no CLI flag is added, and MainNet is
refused at open. **Full C4 remains OPEN; C5 remains OPEN.**

## 2. Files changed

* `crates/qbind-node/src/pqc_governance_production_durable_replay_rocksdb.rs`
  (new source module — the real RocksDB backend).
* `crates/qbind-node/src/lib.rs` (registers the module).
* `crates/qbind-node/tests/run_291_production_durable_replay_rocksdb_tests.rs`
  (new test file, ≥40 tests).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_291.md` (this report).
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` (matrix + status update).
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
  (Run 291 note).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 291 note).
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` (Run 291 note).
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 291 note).
* `docs/whitepaper/contradiction.md` (Run 291 entry).

## 3. Backend design summary

The new module defines a narrow, mockable trait
`GovernanceProductionDurableReplayBackend`
(`record_replay_event` / `read_replay_record` / `scan_replay_records` /
`recover_replay_window` / `close_or_flush`) implemented by:

* `ProductionDurableReplayRocksDbBackend` — the real backend over
  `rocksdb::DB`. Single default column family, prefixed keys
  (`qbind.run291.meta.schema`, `qbind.run291.meta.domain`,
  `qbind.run291.rec.<stage>.<record_id>`,
  `qbind.run291.partial.<record_id>`). Records and metadata are `bincode`
  encoded; digests use SHA3-256 canonical length-prefixed field hashing (never
  debug formatting, never wall-clock time).
* `MockDurableReplayBackend` — an in-memory `BTreeMap` implementation of the
  same trait, proving the surface is mockable and used for composition tests.

Policy selection is via `DurableReplayRocksDbPolicy` whose `Default` is
`Disabled`. `DurableReplayRocksDbConfig::source_test(...)` is the only
source/test path that permits opening; `disabled(...)` fails closed. Record ids
and payload digests are derived deterministically from the Run 238
`DurableBackendDecisionInput` (`durable_backend_key_digest` /
`durable_record_digest`), so the RocksDB backend accepts the same valid
replay-record shape as the existing fixture backend.

## 4. Schema / domain binding

* **Schema version** `DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION = 1`, stored as a
  little-endian `u32` under `meta:schema`.
* **Domain identity** (`DurableReplayRocksDbIdentity`) binds: environment,
  chain_id, genesis_hash (genesis/domain), replay namespace (domain separator),
  authority-domain sequence (replay epoch), and schema version. It is persisted
  as `bincode` metadata plus a self-`domain_digest`.
* **On open:** empty DB initializes metadata exactly once
  (`InitializedEmpty`); a matching non-empty DB opens (`OpenedExisting`); a
  wrong environment / chain / genesis / namespace / authority-domain-sequence
  fails closed (`DomainMismatch`); an unsupported schema version fails closed
  (`SchemaUnsupported`); a malformed schema marker fails closed
  (`SchemaMarkerMalformed`); missing schema/metadata in a non-empty DB fails
  closed (`SchemaMarkerMissing` / `MetadataMissing`); corrupted metadata fails
  closed (`MetadataMalformed`); partial-write residue fails closed
  (`PartialResidueDetected`).
* Every record digest binds the domain separator, schema version, environment,
  chain_id, genesis, namespace, authority-domain sequence, record id,
  stage/kind, prior-stage digest, payload digest, and replay sequence.

## 5. Durability / reopen evidence

Tests B01–B08 / D05 prove: write then read-back; write survives close/reopen;
multiple records survive reopen in deterministic (key-sorted) scan order; a
missing record returns typed `NotFound` without mutation; empty scan returns
empty; flush + reopen preserves committed data; `Observed` + `Consumed` stages
both persist and recover.

## 6. Idempotency / equivocation evidence

Tests C01–C09 prove: a duplicate identical record is idempotent (pre- and
post-reopen), producing exactly one logical record; the same record id with a
different digest (via changed replay sequence) or different payload fails closed
as `Equivocation` and does not overwrite the original; the original record
survives reopen after an equivocation attempt; a `Consumed` write without a
prior `Observed` record — or with a wrong prior-stage digest — fails closed as
`OrderingViolation`; a repeated `Consumed` write is idempotent after reopen.

## 7. Corruption / wrong-domain fail-closed evidence

Tests A03–A12, D06–D09 prove: wrong environment / chain / genesis / namespace /
authority-domain-sequence reopen fails closed; unsupported / malformed schema
fails closed; missing / corrupted metadata fails closed; a corrupted record
payload, a stale/mismatched record digest, and a truncated record all fail
closed on read/scan; a corrupt record does not affect reading a healthy sibling
record. A13 proves lock contention (second open of a live path) fails closed;
A14 proves an unwritable path fails closed; A15 proves the default-Disabled
policy fails closed; A16 proves a MainNet identity is refused.

## 8. Regression results

Run locally with `cargo test -p qbind-node`:

* `cargo build -p qbind-node --lib` — **PASS**.
* `cargo test -p qbind-node --test run_291_production_durable_replay_rocksdb_tests`
  — **PASS** (see final response for exact count).
* The Run 224–290 governance/durable-completion regression targets listed in the
  task, `--lib pqc_authority`, and `--lib` — **PASS** (see final response). No
  pre-existing regression was introduced by Run 291.

## 9. Secret scan result

Secret scanning was run over the changed files; **no secrets** were found. The
module contains only deterministic domain-separation tag string constants and
test fixture digests — no keys, tokens, or credentials.

## 10. CodeQL result or honest limitation

See final response for the exact CodeQL status. Because Run 291 adds a real
RocksDB-backed backend, CodeQL was requested; any skip / timeout / tooling
limitation is reported honestly there and is **not** claimed as coverage.

## 11. C4 / C5 taxonomy status

The modeled durable-completion / settlement / external-publication stack remains
**🟡 Yellow**, release-binary-evidenced only through **Run 289** and source/test
through **Run 290**. Run 291 adds a new capability row — **production durable
replay RocksDB backend** — at **🟡 Yellow / source-test implementation landed,
release-binary evidence pending**. It is **not** Green: Green requires
release-binary evidence on a real `target/release/qbind-node` and/or a
release-built helper with restart / corruption / negative-invariant evidence
(Run 292). Real production-backend rows for custody / RemoteSigner / KMS/HSM /
on-chain proof verifier / governance execution engine / validator-set rotation
remain **🔴 Red**.

## 12. Why Run 291 is not release-binary evidence / does not close C4/C5

Run 291 is source/test implementation only: it exercises the backend under
`cargo test` temp-dir databases, not a release-built binary, and it does not
enable the backend in the production node. It performs no Run 070 call, no
`LivePqcTrustState` mutation, no trust swap, no session eviction, no
sequence/marker write, no settlement, no external publication, no
custody/RemoteSigner/KMS/HSM signing, and no validator-set rotation. It
therefore cannot and does not claim C4 closure, C5 closure, production
readiness, MainNet evidence, or release-binary evidence. **Full C4 remains OPEN;
C5 remains OPEN.**

## 13. Suggested Run 292 next step

**Run 292 — release-binary evidence for the production durable replay RocksDB
backend.** Build a real `target/release/qbind-node` plus a release-built helper,
exercise the RocksDB backend in release mode, prove
write / reopen / replay / idempotency / equivocation / corruption / wrong-domain
behavior, prove the default production binary surfaces remain disabled/silent,
and preserve **Full C4 OPEN / C5 OPEN** unless all required production gates are
actually satisfied.
