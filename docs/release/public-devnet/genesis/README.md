# QBIND Public DevNet — Canonical Genesis Package (Run 356)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**
>
> This is a **DevNet-only** package. All key/root/validator/signer material below is
> **DevNet-only, no value, resettable, and NOT MainNet**. Public DevNet is **NOT launch-ready**
> (see §15). This package makes **no** public DevNet launch claim, **no** public TestNet
> readiness claim, and **no** MainNet readiness claim.

This directory publishes the canonical public DevNet genesis artifact and its associated
network-parameter and genesis-hash evidence, produced under Run 356. It is **docs / artifact /
verification only**: no seed node, bootnode, faucet, RPC gateway, explorer, or status page is
deployed by this run, and no new CLI flag was added.

## Package contents

| File | Purpose |
|------|---------|
| `README.md` | This document (environment, chain id, hash, safety labels, verification pointers). |
| `devnet-genesis.json` | Canonical DevNet `GenesisConfig` JSON (public material only). |
| `devnet-genesis.sha256` | SHA-256 of `devnet-genesis.json` (file-byte digest). |
| `devnet-network-parameters.md` | Canonical operator-facing network-parameter publication. |
| `VERIFY.md` | Exact operator verification commands and expected outputs. |

## 1. Environment

**DevNet only.** This artifact must not be used for TestNet or MainNet. TestNet and MainNet are
unaffected by this package.

## 2. Chain ID

- **Genesis config `chain_id` (string field):** `qbind-devnet-v0`
- **Runtime environment ChainId (DevNet), from `QBIND_DEVNET_CHAIN_ID`:**
  `0x51424E4444455600` = `5855328520645203456` (domain scope `DEV`).

The runtime environment ChainId is fixed by the `--env devnet` mapping in
`crates/qbind-types/src/primitives.rs`; it is the value used in domain-separated signing preimages.
The genesis-config `chain_id` string is a separate human-readable label carried inside the
`GenesisConfig`.

## 3. Genesis hash (canonical Run 101 hash)

```
0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

This is the canonical Run 101 genesis hash computed by `qbind-node --print-genesis-hash` over the
*parsed* `GenesisConfig` under the DevNet environment policy (`--env devnet`). It is
authority-, chain_id-, and environment-sensitive and is independent of JSON whitespace/key order.

## 4. Genesis file SHA-256

```
d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c  devnet-genesis.json
```

This is a file-byte SHA-256 (distinct from the canonical Run 101 genesis hash in §3). Verify with
`sha256sum -c devnet-genesis.sha256`.

## 5. Network name

QBIND Public DevNet (experimental, resettable). Network scope: `DEV`.

## 6. Consensus / network parameters that are safe to publish

Published in `devnet-network-parameters.md`. Summary: environment scope `DEV`, runtime ChainId
`0x51424E4444455600`, genesis config `chain_id` `qbind-devnet-v0`, `genesis_time_unix_ms`
`1738000000000`, plus the monetary parameters embedded in `devnet-genesis.json`. Only non-secret
parameters are published.

## 7. Validator set included in the genesis package

One DevNet-only fixture validator:

- `address`: `0x2222…2222`
- `pqc_public_key`: `abab…abab` (fixture/dev-only **public** key placeholder; no value; resettable)
- `stake`: `100`

This is a **fixture/dev-only public** validator entry. It is **not** a production validator and
carries **no** MainNet meaning.

## 8. Council / allocation / monetary parameters

- **Allocation:** one DevNet-only allocation of `100` to `0x1111…1111` (no value; resettable).
- **Council:** 3 fixture member addresses (`0x3333…`, `0x4444…`, `0x5555…`), threshold `2`.
- **Monetary:** DevNet monetary parameters as embedded in `devnet-genesis.json` (see
  `devnet-network-parameters.md`).

All addresses/amounts are **DevNet-only fixture values with no economic value**.

## 9. PQC trust-root / signing-key status

The genesis `authority` block contains **one DevNet-only bundle-signing authority root**
(`label: run133-bundle-signing-authority`, `suite_id: 100`) expressed as a **public** key fingerprint
and **public** key hex. There are **no** private keys, mnemonics, seed phrases, or signing secrets in
this package. The authority block is **not yet consumed by any live ratification verifier**
(see `docs/whitepaper/contradiction.md`, Run 101 non-claims).

## 10. Fixture / dev-only material declaration

Every key, root, validator, allocation, council member, and signing fingerprint in
`devnet-genesis.json` is **fixture / dev-only public material**. No production authority material was
invented, and no private/secret material is included.

## 11. Resettable / no-value safety label

This DevNet package is **experimental, resettable, and carries no monetary value**. The network it
describes may be reset at any time. Nothing here constitutes a MainNet, TestNet, or public DevNet
launch readiness claim, nor a C4/C5 closure claim.

## 12. Operator verification steps

See `VERIFY.md` for the exact commands and expected outputs.

## 13. Exact command to print / verify the genesis hash

```bash
qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --print-genesis-hash
```

Expected stdout: `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`.

## 14. Exact command to boot with the genesis file (already supported flags)

The genesis file is consumed by the existing `--genesis-path` boot flag, and the canonical hash can
be pinned via the existing `--expect-genesis-hash` flag. Full external-reachability boot is **out of
scope for Run 356** (no seed/bootnode deployment). Operators pin the hash with:

```bash
qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

No new CLI flag was added in Run 356; `--genesis-path`, `--print-genesis-hash`, and
`--expect-genesis-hash` are pre-existing.

## 15. What is still missing before public DevNet launch

Public DevNet remains **NOT launch-ready**. Still outstanding (non-exhaustive; see
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`):

- **M3 — release binary reproducibility / BuildID:** still **Red**.
- **M4 — seed/bootnode list for public join:** still **Red**.
- External reachability, status page, alert rules, and seed-node runbook: still outstanding.
- No runtime authority-lifecycle wiring; the genesis `authority` block is not consumed by a live
  verifier.

Because at least one must-have is not Green, public DevNet is **not** launch-ready after Run 356.

## Provenance

Full provenance (git commit, branch, clean/dirty state, artifact paths + SHA-256, genesis hash,
commands, test results, security scan, readiness deltas) is recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_356.md`.

## Source of this artifact

`devnet-genesis.json` is derived from the existing in-repo DevNet fixture
`docs/devnet/run_139_sighup_v2_live_reload_release_binary/fixtures/devnet/genesis.json`
(public material only). It was **not** invented as production authority material.