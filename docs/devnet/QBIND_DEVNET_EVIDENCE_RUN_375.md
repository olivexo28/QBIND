# QBIND DevNet Evidence — Run 375

Public DevNet **first-class `qbind-node identity` command** evidence. Run 375
promotes the Run 374 operator identity-generation and verification workflow into
a stable, first-class `qbind-node identity` subcommand
(`generate` / `verify` / `print-public` / `seed-candidate`) while preserving the
Run 374 schema, safety rules, deterministic identity derivation, seed-list
mapping, and strict-auth verification evidence.

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready · **Route B**
> (minimal first-class CLI addition; DevNet-gated; default-safe — the `identity`
> command is only reached when `identity` is the first CLI token, so normal
> `qbind-node …` startup is unaffected; no live deployment; no
> seed/faucet/RPC/explorer/status page; no P2P wire-format change; no
> peer-admission weakening — strict mutual-auth only TIGHTENS admission; no
> trust/validator/epoch/sequence/marker mutation).

## 1. Exact verdict

**PASS / public-DevNet first-class identity command positive — M6 first-class
generation + verification half Green-for-scope; M6 as a whole remains
Yellow / Partial.**

A stable, first-class `qbind-node identity` command now exists, reusing the exact
Run 374 primitives. Every required proof lands, including a **real loopback
strict-auth boot** of `target/release/qbind-node` on the generated static-root
material. M6 as a whole is kept **Yellow / Partial** because **no live public
DevNet exists to register an identity into** (that registration path is gated on
M4) and operator-supplied root reuse/rotation/revocation remains C4/C5-OPEN. M4
stays Yellow/launch-blocking; public DevNet remains NOT launch-ready; C4/C5
remain OPEN.

## 2. Decision gate route

**Route B** — a minimal, first-class `qbind-node identity` command is added.
Route A was rejected because `qbind-node` had **no** subcommand framework (a flat
`clap::Parser` flag struct only); Route C was rejected because a stable,
repeatable generation + verification command **can** be provided on the existing
primitives without a broader custody redesign. The command is implemented in
`crates/qbind-node/src/identity_cli.rs` and dispatched from `main.rs` **before**
any flag parsing, so it adds no flag to the node's `CliArgs` and cannot change
default startup behavior.

## 3. Files changed

- `crates/qbind-node/src/identity_cli.rs` — **new** shared implementation
  (generate / verify / print-public / seed-candidate; DevNet-gated; fail-closed).
- `crates/qbind-node/src/lib.rs` — export `pub mod identity_cli;`.
- `crates/qbind-node/src/main.rs` — dispatch the `identity` subcommand before
  `CliArgs::parse_args()`.
- `crates/qbind-node/examples/run_374_public_devnet_identity_generation_helper.rs`
  — converted to a **thin wrapper** over `identity_cli::dispatch` (no duplicated
  logic; Run 374 behavior + evidence preserved).
- `crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs` — **new**
  integration + unit coverage.
- `scripts/devnet/run_375_public_devnet_identity_cli.sh` — **new** release
  harness.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md` — this evidence record.
- `docs/devnet/run_375_public_devnet_identity_cli/` — archive (README, summary,
  `.gitignore`).
- Docs updated: identity package (`README.md`, `IDENTITY_GENERATION.md`,
  `IDENTITY_VERIFY.md`, `SAFETY.md`, `VERIFY.md`), operator (`IDENTITY.md`,
  `QUICKSTART.md`), network (`README.md`), p2p (`PEER_ADMISSION_POLICY.md`,
  `VERIFY.md`), readiness (`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`), protocol
  (`QBIND_C4_C5_CLOSURE_CRITERIA.md`, `QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
  `QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`), ops
  (`QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`), whitepaper (`contradiction.md`),
  `.gitignore` backstops.

## 4. First-class CLI surface

```
qbind-node identity generate <env> <role> <outdir> [validator_index]
qbind-node identity verify <leaf_cert_path>
qbind-node identity print-public <identity_dir>
qbind-node identity seed-candidate <identity_dir>
```

- `env` MUST be `devnet` (MainNet/TestNet refused — DevNet-only, no custody).
- `role` ∈ `full-node | seed | validator-candidate`.
- Exit codes: `0` success, `2` usage, `3` fail-closed refusal, `1` I/O failure
  (invalid output path fails safely, never panics).

## 5. Identity package updates

The Run 374 identity package (`docs/release/public-devnet/identity/`) now
documents the first-class command as the preferred entry point; the schema
(`OPERATOR_IDENTITY_SCHEMA.json`) and example (`EXAMPLE_PUBLIC_IDENTITY.json`)
are unchanged and still validate the emitted `public-identity.json`.

## 6. Identity types covered

Node identity, peer identity, trust-root / root-authority identity, KEMTLS leaf
identity, validator-candidate identity (DevNet fixture label), and the seed-list
identity fields. Consensus **signing** identity is out of scope (pre-existing
signer surfaces).

## 7. Generated material summary (per role, into an operator-selected temp dir)

| File | Public? | Content |
|------|---------|---------|
| `public-identity.json` | public | Publishable identity doc; validates against `OPERATOR_IDENTITY_SCHEMA.json`. Also stdout. |
| `leaf.cert.bin` | public | Encoded `NetworkDelegationCert` (`--p2p-leaf-cert`). |
| `root.id.hex` / `root.pk.hex` | public | root_key_id + root ML-DSA-44 public key. |
| `trusted-root.spec` | public | Ready-to-copy `--p2p-trusted-root` value. |
| `leaf.kem.sk.bin` | **PRIVATE (0600)** | ML-KEM-768 secret key (`--p2p-leaf-cert-key`). Never published/committed. |

The **root ML-DSA-44 signing key is held in memory only and never written to
disk** (`root_signing_key_on_disk=NONE` in the harness).

## 8. Public vs private material

- **Public:** `node_id`/`peer_id`, leaf cert + fingerprint, `root_key_id` + root
  public key + fingerprint, `trusted_root_spec`, `validator_address` (candidate).
- **Private (never publish):** ML-KEM-768 secret key, root signing key.
  `public-identity.json` records private-file **paths only**, not contents.

## 9. Operator commands

```
# generate
qbind-node identity generate devnet full-node           <outdir>
qbind-node identity generate devnet seed                <outdir>
qbind-node identity generate devnet validator-candidate <outdir> [validator_index]
# verify / re-derive public identity from the cert
qbind-node identity verify <outdir>/leaf.cert.bin
# print the stored public identity / emit a seed-list candidate
qbind-node identity print-public   <outdir>
qbind-node identity seed-candidate <outdir>
# run qbind-node on the generated material (pre-existing flags)
qbind-node … --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$(cat <outdir>/trusted-root.spec)" \
  --p2p-leaf-cert <outdir>/leaf.cert.bin --p2p-leaf-cert-key <outdir>/leaf.kem.sk.bin \
  --validator-id <index>
```

## 10. Schema / seed-list mapping

- `public-identity.json` validates against
  `docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json` (draft-07,
  `jsonschema`) for all three roles.
- `identity seed-candidate` emits a Run 357 seed-list `seed_node` candidate
  (`status: planned`, `last_reachability_evidence: null`, operator placeholders
  for host/operator/genesis) that validates against
  `devnet-seed-list.schema.json` after the operator fills the placeholders.

## 11. KEMTLS / static-root verification evidence

Real loopback boot of `target/release/qbind-node` under
`--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` with the
**generated** material:

```
loopback_strict_auth_boot=OK qbind_p2p_pqc_root_mode 1 qbind_p2p_pqc_roots_configured 1
```

Deterministic identity: `identity verify` re-derives the exact `node_id`
recorded in `public-identity.json` for all three roles
(`deterministic_node_id_verify=OK`), because
`node_id = sha3_256("QBIND:nodeid:v1" || leaf_kem_pk)` is a pure function of the
public certificate.

## 12. Rejection / fail-closed evidence

- **Mismatched material fails closed:** booting the generated material under a
  mismatched `--validator-id` exits the node closed —
  `mismatched_material_fail_closed=OK (node exited: local leaf cert validator_id
  does not match --validator-id)`.
- **MainNet/TestNet refused:** `identity generate mainnet …` and
  `identity generate testnet …` exit `3` and write **no** material
  (`mainnet_testnet_generation=REFUSED`). Unknown roles and non-u64 validator
  indices are likewise refused (`unknown_role_generation=REFUSED`).
- **Invalid output path fails safely:** exit `1`, no panic.

## 13. Default compatibility / no runtime behavior change

The `identity` subcommand is intercepted **before** `CliArgs::parse_args()` and
only when `identity` is the first CLI token; it adds no flag to the node's
`CliArgs`, opens no socket, and mutates no runtime state. A normal `qbind-node …`
invocation is bit-for-bit unaffected (mutual-auth disabled, test-grade root mode
by default). The generated material is consumed only through the pre-existing
public `--p2p-*` flags.

## 14. Readiness matrix delta for M6

- **M6:** Yellow / Partial → **Yellow / Partial (first-class generation +
  verification half Green-for-scope, Run 375)**: the stable, documented,
  release-binary-evidenced, schema-compatible first-class `qbind-node identity`
  command now exists. M6 as a whole stays Yellow / Partial because a **live
  registration path** is absent (M4-gated) and operator-supplied root
  reuse/rotation/revocation is C4/C5-OPEN.
- **M4:** unchanged **Yellow / launch-blocking**.
- **M12:** unchanged **Green** (this run does not contradict prior M12 evidence).
- **Public DevNet:** unchanged **NOT launch-ready**.

## 15. Current public DevNet readiness status

**NOT launch-ready.** M4 remains Yellow/launch-blocking; M6 remains
Yellow/Partial; other must-haves unchanged.

## 16. Remaining public DevNet blockers

- **M4** — live seed/bootnode reachability evidence (launch-blocking).
- **M6** — live registration path into a running public DevNet (M4-gated);
  operator-supplied root reuse/rotation/revocation (C4/C5).

## 17. Public TestNet blockers

TestNet custody/readiness is out of scope; TestNet identity generation is
refused fail-closed. No TestNet readiness is claimed.

## 18. MainNet blockers

MainNet custody, authority rotation/revocation (Red), and full C4/C5 closure
remain open. MainNet identity generation is refused fail-closed. No MainNet
readiness is claimed.

## 19. C4/C5 status

Full **C4 remains OPEN**; **C5 remains OPEN**. This run makes no C4/C5 closure
claim.

## 20. Tests run (exact)

- `cargo build -p qbind-node --release --bin qbind-node` — **OK**.
- `cargo build -p qbind-node --release --example run_374_public_devnet_identity_generation_helper`
  — **OK** (thin wrapper).
- `cargo test -p qbind-node --test run_375_public_devnet_identity_cli_tests` —
  **13 passed; 0 failed**.
- `cargo test -p qbind-node --lib identity_cli` — **4 passed; 0 failed**.
- `scripts/devnet/run_375_public_devnet_identity_cli.sh` — **RESULT=PASS**
  (release build; generate ×3 roles `kem_sk_perms=600`; root signing key not on
  disk; identity-schema validation ×3; deterministic verify ×3; seed-list
  candidate insertion; loopback strict-auth boot `qbind_p2p_pqc_root_mode 1`;
  mismatch fail-closed; MainNet + TestNet + unknown-role refusal).

## 21. Security scans

Secret scanning over all changed files — **no secrets detected**. No generated
private key, root signing key, KEM secret key, mnemonic, credential, real
endpoint, data dir, or log is committed. The KEM secret key is written `0600` to
an operator-selected temp path only; `.gitignore` adds backstop patterns
(`*.kem.sk.bin`, `*.cert.bin`, `root.pk.hex`, `root.id.hex`, `trusted-root.spec`,
`public-identity.json`, `qbind-identity-out/`).

## 22. CodeQL

See the finalization note in the PR summary for the exact CodeQL result on the
Rust source change.

## 23. Provenance

- rustc 1.97.1 (8bab26f4f 2026-07-14); cargo 1.97.1 (c980f4866 2026-06-30).
- `target/release/qbind-node` sha256
  `970bce217670c83120ffb37cbe0c70fa984d862646a60c3abeb3e07935ef31db`, Build ID
  `94f9faab4f748916e2d5f85d3c7eb6deb4eac63c`.
- Binary hashes are environment-specific and recorded for provenance only.

## 24. Honest limitations

- The command mints its **own** ephemeral DevNet root per run; it does not
  support operator-supplied root reuse, rotation, or revocation (C4/C5 OPEN).
- No consensus **signing** identity is generated (uses pre-existing signer
  surfaces).
- No live registration path exists (M4-gated); published `node_id`s are candidate
  identities only, never live/reachable.
- `seed-candidate` emits operator placeholders for host/operator/genesis that the
  operator MUST replace with real values before use.

## 25. Suggested Run 376 next step

Pair the first-class `identity` command with M4 live seed/bootnode reachability
evidence, and add operator-supplied-root support (reuse across restarts, plus a
rotation/revocation design) so M6 can move fully Green independently of a fresh
per-run root.