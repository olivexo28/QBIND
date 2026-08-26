# QBIND Public DevNet — Identity Generation (Run 374, first-class command Run 375)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.

> **Run 375 — first-class command (preferred).** Generation is now a stable
> `qbind-node identity generate` subcommand. Wherever this document shows
> `"$BIN" generate …`, you may equivalently run `qbind-node identity generate …`
> against the release node binary — identical output, files, perms, and
> refusals. Example:
>
> ```bash
> qbind-node identity generate devnet full-node "$OUT/node"
> qbind-node identity generate devnet validator-candidate "$OUT/val" 0
> ```

> **Run 376 — registration / admission-check.** After generating, run
> `qbind-node identity register-check "$OUT/node/public-identity.json"
> --seed-list <seed-list.json> [--role <role>] [--cert "$OUT/node/leaf.cert.bin"]`
> to confirm the material is admissible as a future (planned) seed-list entry
> before publishing. It is non-mutating, opens no socket, and makes no
> live/reachability claim. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md`.

This document gives the **exact** operator commands to generate DevNet identity
material, and describes every file written. The first-class `qbind-node
identity` command (Run 375) is DevNet-gated and changes no default node
behavior; the Run 374 `run_374_public_devnet_identity_generation_helper` example
remains available as a thin wrapper over the same implementation.

## 0. Prerequisites

Build the node binary (which carries the first-class `identity` command); the
Run 374 example is optional:

```bash
cargo build -p qbind-node --release --bin qbind-node
# optional (Run 374 example, thin wrapper over the same code):
cargo build -p qbind-node --release --example run_374_public_devnet_identity_generation_helper
```

Choose an output directory that is **outside any git tree** — e.g. a `mktemp -d`
path. The repository `.gitignore` also ignores `*.kem.sk.bin`, `*.cert.bin`, and a
conventional `qbind-identity-out/` directory as a backstop (see `SAFETY.md`).

```bash
OUT="$(mktemp -d)"        # operator-selected temp dir; never commit its contents
# First-class command (Run 375):
BIN="./target/release/qbind-node identity"
# or the Run 374 example wrapper:
#   BIN=./target/release/examples/run_374_public_devnet_identity_generation_helper
```

## 1. Generate a full-node identity

```bash
"$BIN" generate devnet full-node "$OUT/node"
```

`devnet` is the **only** accepted environment — `mainnet` / `testnet` are refused
with a non-zero exit (this tooling creates no MainNet/TestNet custody).

## 2. Generate a seed / bootnode identity

```bash
"$BIN" generate devnet seed "$OUT/seed"
```

## 3. Generate a validator-candidate identity

Optionally pass a validator **index** (default `0`); it binds the leaf cert to
`qbind-val-<index>` so the material loads under `--validator-id <index>` and sets
the public `validator_address` to the DevNet fixture label:

```bash
"$BIN" generate devnet validator-candidate "$OUT/val" 0
```

## 4. Files written (per identity, into the chosen sub-directory)

| File | Public? | Content |
|------|---------|---------|
| `public-identity.json` | **public** | The publishable identity document (also printed to stdout). Validates against `OPERATOR_IDENTITY_SCHEMA.json`. |
| `leaf.cert.bin` | public\* | Encoded `NetworkDelegationCert` for `--p2p-leaf-cert`. |
| `root.id.hex` | public | 64-hex `root_key_id`. |
| `root.pk.hex` | public | Root ML-DSA-44 public key, hex. |
| `trusted-root.spec` | public | Ready-to-copy `--p2p-trusted-root` value `id:100:pk`. |
| `leaf.kem.sk.bin` | **PRIVATE** | ML-KEM-768 **secret** key for `--p2p-leaf-cert-key`. Mode `0600`. **NEVER publish or commit.** |

\* The leaf cert is public transport material; operators typically keep the whole
output directory private because it is co-located with the secret KEM key.

The **root ML-DSA-44 signing key is generated fresh in memory on every run and is
never written to disk in any form** (matching `devnet_pqc_root_helper`). A
production CA / custody / rotation / revocation flow is out of scope and tracked
under **C4/C5** (`docs/whitepaper/contradiction.md`).

## 5. Derive / print the NodeId and fingerprints

The `node_id` and fingerprints are already in `public-identity.json`. To
re-derive them from the public cert alone (no secret material touched):

```bash
"$BIN" verify "$OUT/node/leaf.cert.bin"
```

The `node_id` is `sha3_256("QBIND:nodeid:v1" || leaf_kem_pk)` — the exact value a
deployed `PqcStaticRoot` listener registers an admitted peer under, so it is
deterministic from the public certificate.

## 6. Use the generated material with `qbind-node` (pre-existing flags)

The generated identity plugs directly into the **pre-existing** public flags:

```bash
NODE=./target/release/qbind-node
SPEC="$(cat "$OUT/node/trusted-root.spec")"

QBIND_METRICS_HTTP_ADDR=127.0.0.1:9645 "$NODE" \
  --env devnet --network-mode p2p --enable-p2p \
  --validator-id 0 \
  --data-dir "$OUT/node-data" \
  --p2p-listen-addr 127.0.0.1:0 \
  --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$SPEC" \
  --p2p-leaf-cert "$OUT/node/leaf.cert.bin" \
  --p2p-leaf-cert-key "$OUT/node/leaf.kem.sk.bin"
```

Live `/metrics` then reports `qbind_p2p_pqc_root_mode 1` and
`qbind_p2p_pqc_roots_configured 1`, confirming the deployed binary accepted the
generated static-root material. A **peer's** identity is supplied to a dialing
node with `--p2p-peer <index>@<host:port>` + `--p2p-peer-leaf-cert
<index>:<leaf.cert.bin>`.

### Field → flag mapping

| `public-identity.json` field | Consumed by |
|------------------------------|-------------|
| `trusted_root_spec` | `--p2p-trusted-root` |
| `leaf.cert.bin` (path) | `--p2p-leaf-cert` (self) / `--p2p-peer-leaf-cert <idx>:<path>` (peer) |
| `leaf.kem.sk.bin` (path, PRIVATE) | `--p2p-leaf-cert-key` (self only) |
| validator index (leaf `validator_id` = `qbind-val-<index>`) | `--validator-id <index>` |
| `node_id` / `peer_id` | Peer identity a dialer pins; seed-list `node_id` / `peer_id` |

## 7. One-shot evidence harness

To reproduce all Run 374 evidence (build, generate, schema-validate, deterministic
verify, seed-list insertion, loopback strict-auth boot, mismatch fail-closed,
MainNet/TestNet refusal) in a temp dir:

```bash
bash scripts/devnet/run_374_public_devnet_identity_generation.sh
```

## 8. Validator-candidate onboarding (DevNet)

On DevNet the validator set is a **genesis fixture**; there is no live public
validator set to register into. The `validator-candidate` role therefore produces
a **candidate** identity whose `validator_address` is the fixture label
`qbind-val-<index>` and whose leaf cert loads under `--validator-id <index>`. A
validator additionally needs a consensus **signing** identity via the pre-existing
signer surfaces (`--signer-mode`, `--signer-keystore-path`, …; see
`docs/release/public-devnet/operator/IDENTITY.md` §2) — this helper does **not**
generate consensus signing keys. What remains before a candidate becomes a live
validator is the same as **M4**: a live public DevNet with a registration path.