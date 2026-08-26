# QBIND DevNet Evidence — Run 376

Public DevNet **identity registration / admission-check boundary** evidence. Run
376 adds a bounded, **non-mutating** `qbind-node identity register-check`
admission verifier that takes a `qbind-node identity seed-candidate` /
`public-identity.json` output and decides whether it is admissible as a future
live seed-list entry — **without** launching a public DevNet and **without**
opening any socket, mutating any runtime state, or making any live / reachability
/ M4 claim.

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready · **Route B**
> (minimal first-class CLI addition; DevNet-gated; default-safe — `register-check`
> is only reached when `identity` is the first CLI token, so normal
> `qbind-node …` startup is unaffected; no live deployment; no
> seed/faucet/RPC/explorer/status page; no P2P wire-format change; no
> peer-admission weakening; no trust/validator/epoch/sequence/marker mutation).

## 1. Exact verdict

**PASS / public-DevNet identity registration/admission-check positive — M6
registration/admission-check half Green-for-scope; M6 as a whole remains
Yellow / Partial.**

A stable, first-class, **non-mutating** `qbind-node identity register-check`
command now exists. It validates a `public-identity.json` against the
operator-identity schema rules, maps it into a `devnet-seed-list.schema.json`
`seed_node` candidate, enforces the seed-list status/reachability admission
rules, verifies the NodeId deterministically from a supplied leaf cert, and
fail-closes on every abuse case (status=live without reachability,
planned+reachability, embedded private material, malformed
NodeId/peer_id/trusted_root_spec, wrong environment, MainNet/TestNet material,
mismatched cert, unknown role). M6 as a whole is kept **Yellow / Partial**
because **no live public DevNet seed infrastructure exists to register an
identity into** (that live path is gated on M4). M4 stays Yellow/launch-blocking;
public DevNet remains NOT launch-ready; C4/C5 remain OPEN.

## 2. Files changed

- `crates/qbind-node/src/identity_cli.rs` — add the non-mutating
  `register-check` subcommand + admission validators (public-identity schema
  rules, seed-list schema rules, seed_node status/reachability rules, cert
  verification). No change to `generate`/`verify`/`print-public`/`seed-candidate`
  behavior.
- `crates/qbind-node/tests/run_376_public_devnet_identity_registration_tests.rs`
  — **new** integration coverage (14 tests).
- `scripts/devnet/run_376_public_devnet_identity_registration.sh` — **new**
  release harness.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md` — this evidence record.
- `docs/devnet/run_376_public_devnet_identity_registration/` — archive
  (README, summary, `.gitignore`).
- Documentation updates (see §5).

## 3. Decision gate route

**Route B** — a minimal, first-class, non-mutating `register-check` subcommand.
Route A (docs/harness only over existing surfaces) was rejected because the
existing `identity` surface generates and verifies material but provides **no**
admission decision (no schema-driven "is this admissible as a seed entry?"
verdict). Route C (live registration requires M4) still applies to the *live*
registration half and is documented as the remaining blocker: `register-check`
deliberately stops at admission validation and makes no reachability claim.

## 4. Registration / admission-check surface

```text
qbind-node identity register-check <public-identity.json> --seed-list <path> \
    [--role full-node|seed|validator-candidate] \
    [--cert <leaf.cert.bin>] \
    [--status planned|live] \
    [--reachability-evidence <ref>]
```

- **Input:** a public `public-identity.json` and a seed-list document (for
  genesis context + schema target). Optional leaf cert for deterministic NodeId
  verification, optional expected role, optional status/reachability.
- **Output:** a machine-readable JSON verdict on stdout with `admissible`,
  `role`, `node_id`, `expected_genesis_hash`, `candidate_status`, the derived
  seed-list `candidate`, and explicit non-claim flags (`socket_opened=false`,
  `runtime_state_mutated=false`, `live_reachability_claim=false`,
  `m4_green_claim=false`, `c4_c5_closure_claim=false`).
- **Exit codes:** `0` admissible, `3` refused (fail-closed), `2` usage,
  `1` I/O. Never panics on operator-controlled input.

## 5. Identity package / docs updates

- `docs/release/public-devnet/identity/README.md`
- `docs/release/public-devnet/identity/IDENTITY_GENERATION.md`
- `docs/release/public-devnet/identity/IDENTITY_VERIFY.md`
- `docs/release/public-devnet/identity/SAFETY.md`
- `docs/release/public-devnet/identity/VERIFY.md`
- `docs/release/public-devnet/operator/IDENTITY.md`
- `docs/release/public-devnet/operator/QUICKSTART.md`
- `docs/release/public-devnet/network/README.md`
- `docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

## 6. Identity types covered

`full-node`, `seed`, `validator-candidate` — all three pass `register-check` as a
`planned` candidate with deterministic cert verification. Only a
`validator-candidate` may carry a non-null `validator_address`; the schema rule
is enforced.

## 7. Register-check input / output

- **Reads:** `public-identity.json` (public material only) + the seed-list
  document. Optionally decodes `leaf.cert.bin` to re-derive the NodeId, leaf
  fingerprint, and root id.
- **Emits:** an `admissible: true` verdict + derived `seed_node` candidate
  (`status=planned`, `last_reachability_evidence=null`,
  `expected_genesis_hash` pulled from the seed-list) on success; an
  `admissible: false` verdict + reason on any fail-closed refusal.

## 8. Public vs private material enforcement

`register-check` reads only public material. The public-identity validator
rejects any embedded secret indicator (`secret_key`, `private_key`, `mnemonic`,
`seed_phrase`, PEM `-----begin`, …) and rejects any unknown top-level or
`private_material` field (`additionalProperties: false` behavior), so a private
key smuggled into the public JSON fails closed. It never reads the KEM secret
key.

## 9. Operator commands

```bash
# 1. generate DevNet identity material (Run 375)
qbind-node identity generate devnet seed ./id-seed

# 2. (optional) emit a seed-list candidate object
qbind-node identity seed-candidate ./id-seed

# 3. admission-check the identity against a seed list (Run 376)
qbind-node identity register-check ./id-seed/public-identity.json \
    --seed-list docs/release/public-devnet/network/devnet-seeds.placeholder.json \
    --role seed --cert ./id-seed/leaf.cert.bin
```

## 10. Schema / seed-list mapping

The derived candidate carries exactly the `devnet-seed-list.schema.json`
`seed_node` fields, with `expected_genesis_hash` taken from the target
seed-list's `genesis_hash`, `status=planned`, and
`last_reachability_evidence=null`. The Run 376 harness inserts the candidate into
the placeholder seed list and validates the whole document against the seed-list
JSON-Schema with Python `jsonschema`.

## 11. KEMTLS / static-root verification evidence

When `--cert <leaf.cert.bin>` is supplied, `register-check` decodes the leaf
`NetworkDelegationCert`, re-derives the NodeId
(`sha3_256('QBIND:nodeid:v1' || leaf_kem_pk)`), the leaf-cert fingerprint, and
the root id, and confirms they match the public identity. For a
`validator-candidate` it also confirms the cert's `validator_id` matches the
identity's `validator_address` index (`qbind-val-<index>`). Any mismatch fails
closed. This is the exact deterministic NodeId a deployed `PqcStaticRoot`
listener would register an admitted peer under — but `register-check` opens **no
socket** and performs the check locally.

## 12. Rejection / fail-closed evidence

| Case | Result |
| --- | --- |
| status=live without `--reachability-evidence` | REFUSED (exit 3) |
| status=planned with `--reachability-evidence` | REFUSED (schema forbids) |
| embedded private material in public JSON | REFUSED |
| malformed `node_id` / `peer_id` | REFUSED |
| malformed `trusted_root_spec` | REFUSED |
| wrong `environment` (staging, …) | REFUSED |
| MainNet / TestNet identity material | REFUSED (DevNet-only) |
| mismatched leaf cert vs identity | REFUSED |
| mismatched validator material | REFUSED |
| unknown / mismatched `--role` | REFUSED |
| missing `--seed-list` | usage error (exit 2), no panic |

## 13. Default compatibility / no runtime behavior change

`register-check` is only reached when `identity` is the first CLI token,
dispatched before `CliArgs::parse_args()`. A normal `qbind-node …` invocation is
completely unaffected. No new flag is added to the node's `CliArgs`. The command
opens no socket, registers no peer, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState`.

## 14. Readiness matrix delta for M6

- **M6:** generation + verification half remains Green-for-scope; the
  **registration / admission-check half is now Green-for-scope** (a stable
  first-class generate → verify → register-check workflow exists for external
  operators). **M6 overall stays Yellow / Partial** because *live* registration
  is inseparable from M4 live seed reachability, which has not landed.
- **M4:** remains **Yellow / launch-blocking** — no live seed/bootnode
  reachability evidence lands in this run.
- **M12:** remains **Green** (unchanged; no runtime/socket behavior changed).

## 15. Current public DevNet readiness status

**NOT launch-ready.** The registration/admission-check boundary is a validation
tool only. No live seed, faucet, RPC gateway, explorer, or status page exists.

## 16. Remaining public DevNet blockers

- **M4:** real externally reachable seed/bootnode infrastructure + reachability
  evidence (the live half of registration depends on this).
- Live registration/admission into a running DevNet (this run validates
  admissibility offline only).

## 17. Public TestNet blockers

TestNet identity material is explicitly refused. No TestNet readiness is claimed
or approached: TestNet requires the full C4/C5 trust-anchor lifecycle, validator
set governance, and value-bearing safety review — all out of scope.

## 18. MainNet blockers

MainNet identity material is explicitly refused. MainNet authority
rotation/revocation remains **Red**; no custody, no value, no MainNet readiness.

## 19. C4 / C5 status

**C4 OPEN, C5 OPEN.** No authority-lifecycle runtime wiring, no trust-bundle live
apply, no peer-driven apply, no validator-set mutation, no epoch transition. The
verdict explicitly sets `c4_c5_closure_claim=false`.

## 20. Tests run

- `cargo test -p qbind-node --test run_376_public_devnet_identity_registration_tests`
  — **14 passed**.
- `cargo test -p qbind-node --test run_375_public_devnet_identity_cli_tests`
  — **13 passed** (no regression).
- `cargo test -p qbind-node --lib identity_cli` — **4 passed**.
- `scripts/devnet/run_376_public_devnet_identity_registration.sh` — **RESULT=PASS**.

## 21. Security scans

- `runtime-tools-secret_scanning` over all changed files — no secrets.
- No generated private key, root signing key, KEM secret key, data dir, log, or
  metrics dump is committed. Harness material is temporary and removed on exit;
  the archive `.gitignore` is a backstop.

## 22. CodeQL

CodeQL was invoked over the Rust source change to `identity_cli.rs`. Exact
result: **analysis skipped — "Analysis was skipped because the database size is
too large" (0 alerts returned).** This is **not** a clean bill of health; the
tool did not analyze the change. Mitigating factors for this specific change:
`register-check` is read-only, opens no socket, spawns no process, and performs
only local file reads + JSON parsing (`serde_json`) + wire-cert decoding through
the same pre-existing `NetworkDelegationCert::decode` path used elsewhere; all
operator-controlled input is validated and fails closed without `unsafe`, shell
execution, or dynamic path traversal beyond the operator-supplied file arguments.

## 23. Provenance

From `scripts/devnet/run_376_public_devnet_identity_registration.sh`:

```
release_binary sha256 = ae1e699b0d6f1cbafb2913719e111877c8b90a67c0bbfac09fb23afe8acbfa96
build_id              = 8d34c1b1c5c5f8209060a2a63a939d45c7f9667e
toolchain             = rustc 1.97.1 (8bab26f4f 2026-07-14) / cargo 1.97.1 (c980f4866 2026-06-30)
```

(SHA-256 / BuildID are host-specific and reproduced locally by re-running the
harness; only publish-safe values are archived.)

## 24. Honest limitations

- `register-check` validates **admissibility only**. It proves an identity would
  be a schema-valid, cert-consistent, non-live seed-list candidate; it does
  **not** prove any live seed exists or is reachable.
- The Rust command implements a **targeted structural subset** of the two
  JSON-Schemas (the fields and rules that matter for admission). Full JSON-Schema
  validation is performed by the Python `jsonschema` harness, not the binary.
- No loopback boot admission was added in this run; the Run 375 loopback
  strict-auth boot evidence remains the standing end-to-end proof. `register-check`
  intentionally opens no socket.
- M4 live reachability is untouched; M6 cannot move fully Green here.

## 25. Suggested Run 377 next step

Land the **live** half: stand up a real externally reachable DevNet seed under
strict KEMTLS static-root, capture timestamped reachability evidence, and have
`register-check --status live --reachability-evidence <ref>` accept a *live*
seed-list entry backed by that evidence — the step that can finally move **M4**
toward Green and close the M6 registration half.
