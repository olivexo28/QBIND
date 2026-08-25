# QBIND DevNet Evidence — Run 374

Public DevNet **operator identity-generation and verification** evidence. Run 374
consolidates the pre-existing DevNet identity primitives into a single,
documented, release-built helper
(`run_374_public_devnet_identity_generation_helper`) and a canonical
operator-facing identity package under
`docs/release/public-devnet/identity/`, so an external DevNet operator can
**generate, inspect, verify, and safely handle** the identity material a
`qbind-node` peer needs to join a KEMTLS strict-auth
(`PqcRootMode::PqcStaticRoot`) DevNet — and map it to the Run 357 seed-list and
the pre-existing P2P flags.

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready · **Route B**
> (release-built example helper + docs only; no production source change; no new
> `qbind-node` CLI flag; no live deployment; no seed/faucet/RPC/explorer/status
> page; no P2P wire-format change; no peer-admission weakening — strict
> mutual-auth only TIGHTENS admission; no trust/validator/epoch mutation).

## 1. Exact verdict

**PARTIAL-POSITIVE / public-DevNet operator identity-generation positive —
M6 materially narrowed, remains Yellow / Partial.**

A stable, repeatable, release-built operator-facing identity **generation +
verification** package now exists (helper + harness + schema + example + docs +
evidence). Every required proof lands, including a **real loopback strict-auth
boot** of the standalone `target/release/qbind-node` on the generated static-root
material. M6 is intentionally kept **Yellow / Partial** because generation is
delivered as a **release-built example helper** (the repo's established
operator-tooling pattern) rather than a first-class `qbind-node` subcommand, and
because **no live public DevNet exists to register an identity into** (that
registration path is gated on M4). M4 stays Yellow/launch-blocking; public DevNet
remains NOT launch-ready; C4/C5 remain OPEN.

## 2. Decision gate route

**Route B** — a small dedicated DevNet identity helper is added as a
**release-built example only** (matching the repo's existing operator helper
pattern: `devnet_pqc_root_helper`, `devnet_pqc_trust_bundle_helper`,
`devnet_consensus_signer_keystore_helper`). No production runtime behavior
changes; no new `qbind-node` CLI flag. Route A was rejected because no single
existing helper emits a schema-validated operator public-identity document that
maps to the seed-list; Route C was rejected because a stable, repeatable
generation+verification command **can** be provided on the existing primitives.

## 3. Identity package contents (`docs/release/public-devnet/identity/`)

`README.md`, `IDENTITY_GENERATION.md`, `IDENTITY_VERIFY.md`,
`OPERATOR_IDENTITY_SCHEMA.json`, `EXAMPLE_PUBLIC_IDENTITY.json`, `SAFETY.md`,
`VERIFY.md`.

Tooling: `crates/qbind-node/examples/run_374_public_devnet_identity_generation_helper.rs`
(`generate` + `verify` modes); harness
`scripts/devnet/run_374_public_devnet_identity_generation.sh`.

## 4. Identity types covered

Node identity, peer identity, trust-root / root-authority identity, KEMTLS leaf
identity, validator-candidate identity (DevNet fixture label), and the seed-list
identity fields. Consensus **signing** identity is explicitly out of scope of this
helper (documented, uses the pre-existing signer surfaces).

## 5. Generated material summary (per role, into an operator-selected temp dir)

| File | Public? | Content |
|------|---------|---------|
| `public-identity.json` | public | Publishable identity doc; validates against `OPERATOR_IDENTITY_SCHEMA.json`. Also stdout. |
| `leaf.cert.bin` | public | Encoded `NetworkDelegationCert` (`--p2p-leaf-cert`). |
| `root.id.hex` / `root.pk.hex` | public | root_key_id + root ML-DSA-44 public key. |
| `trusted-root.spec` | public | Ready-to-copy `--p2p-trusted-root` value. |
| `leaf.kem.sk.bin` | **PRIVATE (0600)** | ML-KEM-768 secret key (`--p2p-leaf-cert-key`). Never published/committed. |

The **root ML-DSA-44 signing key is held in memory only and never written to
disk** (matches `devnet_pqc_root_helper`).

## 6. Public vs private material

- **Public:** `node_id`/`peer_id`, leaf cert + fingerprint, `root_key_id` + root
  public key + fingerprint, `trusted_root_spec`, `validator_address` (candidate).
- **Private (never publish):** ML-KEM-768 secret key, root signing key, any
  validator/trust-bundle signing key, mnemonics, credentials. `public-identity.json`
  records private-file **paths only**, not contents. Full rules in `SAFETY.md`.

## 7. Operator commands

```
# generate
run_374_..._helper generate devnet full-node          <outdir>
run_374_..._helper generate devnet seed               <outdir>
run_374_..._helper generate devnet validator-candidate <outdir> [validator_index]
# verify / re-derive public identity from the cert
run_374_..._helper verify <outdir>/leaf.cert.bin
# run qbind-node on the generated material (pre-existing flags)
qbind-node … --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$(cat <outdir>/trusted-root.spec)" \
  --p2p-leaf-cert <outdir>/leaf.cert.bin --p2p-leaf-cert-key <outdir>/leaf.kem.sk.bin \
  --validator-id <index>
```

## 8. Schema / seed-list mapping

- `public-identity.json` validates against
  `docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json` (draft-07,
  `jsonschema` — no new dependency).
- The generated public identity inserts into a Run 357 seed-list `seed_node`
  candidate (`status: planned`, `last_reachability_evidence: null`) without
  violating `devnet-seed-list.schema.json`. Field mapping: `node_id`→`node_id`,
  `peer_id`→`peer_id`, `validator_address`→`validator_address`,
  `pqc_suite`→`pqc_suite`, `transport_security_mode`→`transport_security_mode`.

## 9. KEMTLS / static-root verification evidence

Real loopback boot of `target/release/qbind-node` under
`--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` with the
**generated** `--p2p-trusted-root` / `--p2p-leaf-cert` / `--p2p-leaf-cert-key`:

```
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true
loopback_strict_auth_boot=OK qbind_p2p_pqc_root_mode 1 qbind_p2p_pqc_roots_configured 1
```

Deterministic identity: `verify` re-derives the exact `node_id` recorded in
`public-identity.json` for all three roles
(`deterministic_node_id_verify=OK`), because
`node_id = sha3_256("QBIND:nodeid:v1" || leaf_kem_pk)` is a pure function of the
public certificate.

## 10. Rejection / fail-closed evidence

- **Mismatched material fails closed:** booting the generated material under a
  mismatched `--validator-id 7` exits the node closed —
  `mismatched_material_fail_closed=OK (node exited: local leaf cert validator_id
  does not match --validator-id)`.
- **MainNet/TestNet refused:** `generate mainnet …` and `generate testnet …` exit
  non-zero and write **no** material —
  `mainnet_testnet_generation=REFUSED (fail closed, non-zero exit, no material
  written)`. Unknown roles are likewise refused.

## 11. Default compatibility / no runtime behavior change

No production source changed; no new `qbind-node` CLI flag; the helper consumes
**pre-existing** public flags only. Node defaults are untouched (mutual-auth
disabled, test-grade root mode) — the operator must opt in to strict-auth +
static-root exactly as before.

## 12. Readiness matrix delta

- **M6:** Yellow / Partial → **Yellow / Partial (materially narrowed, Run 374)**:
  stable operator-facing identity generation + verification package (schema,
  commands, safety, evidence, loopback proof) now published; still not a
  first-class CLI subcommand and no live registration path (M4-gated).
- **M4:** unchanged **Yellow / launch-blocking**.
- **M12:** unchanged **Green** (this run does not contradict prior M12 evidence).
- **Public DevNet:** unchanged **NOT launch-ready**.

## 13. Tests run (exact)

- `cargo build -p qbind-node --release` — **OK**.
- `cargo build -p qbind-node --release --example run_374_public_devnet_identity_generation_helper` — **OK**.
- `cargo build -p qbind-node --release --bin qbind-node` — **OK** (for loopback boot).
- `cargo test -p qbind-node --lib` — **1390 passed; 0 failed; 0 ignored**.
- `scripts/devnet/run_374_public_devnet_identity_generation.sh` — **RESULT=PASS**
  (helper build; generate ×3 roles with `kem_sk_perms=600`; identity-schema
  validation ×3; deterministic verify ×3; seed-list candidate insertion; loopback
  strict-auth boot `qbind_p2p_pqc_root_mode 1`; mismatch fail-closed; MainNet +
  TestNet refusal).
- Identity schema validation + seed-list schema validation via `jsonschema`
  (draft-07) — **OK**.

## 14. Security scans

Secret scanning over all changed files — **no secrets detected**. No generated
private key, mnemonic, credential, real endpoint, generated root, generated leaf
key, data dir, or log is committed. The KEM secret key is written `0600` to an
operator-selected temp path only; `.gitignore` adds backstop patterns
(`*.kem.sk.bin`, `*.cert.bin`, `qbind-identity-out/`).

## 15. CodeQL

See the finalization note in the PR summary for the exact CodeQL result on the
Rust example change.

## 16. Provenance

- rustc 1.97.1 (8bab26f4f 2026-07-14); cargo 1.97.1.
- helper `run_374_public_devnet_identity_generation_helper` sha256
  `4e38cfba9742e7daad0e95a544e05bc64000ac7fc23c3a840b664ae3e00e45ce`.
- `target/release/qbind-node` sha256
  `e28775a2c44d02466b3c86dfff5e5641d93d983bde89e6d0f4701cc257131669`, Build ID
  `05e9e0b9b78599fe1c4d5f6bd1fd8786f3a4b9ec`.
- Binary hashes are environment-specific and recorded for provenance only.

## 17. Honest limitations

- Generation is a **release-built example helper**, not a first-class
  `qbind-node` subcommand; this is why M6 stays Yellow / Partial.
- The helper mints its **own** ephemeral DevNet root per run; it does not support
  operator-supplied root reuse, rotation, or revocation (C4/C5 OPEN).
- No consensus **signing** identity is generated here (uses pre-existing signer
  surfaces).
- No live registration path exists (M4-gated); published `node_id`s are candidate
  identities only, never live/reachable.

## 18. Suggested Run 375 next step

Promote the identity helper into a stable, first-class `qbind-node identity
generate/verify` subcommand (or an equivalent stable CLI procedure) with
operator-supplied-root support, so M6 can move Green independently of M4 — then
pair it with M4 live seed/bootnode reachability evidence to unblock launch.