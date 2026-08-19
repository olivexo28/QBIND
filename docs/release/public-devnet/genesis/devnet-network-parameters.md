# QBIND Public DevNet — Network Parameters (canonical publication, Run 356)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim ·
> no C4/C5 closure claim. **DevNet only.** TestNet and MainNet are unaffected.

This document is the canonical operator-facing publication of the public DevNet network parameters.
Every value below is checked against either the committed `devnet-genesis.json` in this directory or
in-repo source constants, as noted per row.

## Environment / identity parameters

| Parameter | Value | Source of truth |
|-----------|-------|-----------------|
| Environment | DevNet only | `--env devnet` |
| Network name | QBIND Public DevNet (experimental) | this package |
| Domain scope | `DEV` | `crates/qbind-types/src/primitives.rs` (`NetworkEnvironment::Devnet.scope()`) |
| Runtime ChainId | `0x51424E4444455600` = `5855328520645203456` | `QBIND_DEVNET_CHAIN_ID`, `crates/qbind-types/src/primitives.rs` |
| Genesis config `chain_id` (string) | `qbind-devnet-v0` | `devnet-genesis.json` → `chain_id` |
| `genesis_time_unix_ms` | `1738000000000` | `devnet-genesis.json` → `genesis_time_unix_ms` |
| Canonical Run 101 genesis hash | `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f` | `qbind-node --env devnet --genesis-path … --print-genesis-hash` |
| `devnet-genesis.json` SHA-256 | `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c` | `sha256sum devnet-genesis.json` |

## Validator / allocation / council parameters (from `devnet-genesis.json`)

| Parameter | Value | Note |
|-----------|-------|------|
| Validator count | 1 | DevNet-only fixture validator |
| Validator address | `0x2222…2222` | fixture/dev-only, no value |
| Validator PQC public key | `abab…abab` | fixture/dev-only **public** placeholder |
| Validator stake | `100` | no value |
| Allocation count | 1 | DevNet-only |
| Allocation | `100` → `0x1111…1111` | no value, resettable |
| Council members | `0x3333…`, `0x4444…`, `0x5555…` | fixture/dev-only public addresses |
| Council threshold | `2` | of 3 |

## Monetary parameters (from `devnet-genesis.json` → `monetary`)

These are the DevNet monetary-engine parameters committed in `devnet-genesis.json`. They are
DevNet-only and carry no MainNet meaning.

| Parameter | Value |
|-----------|-------|
| `pqc_premium_compute` | `0.3` |
| `pqc_premium_bandwidth` | `0.15` |
| `pqc_premium_storage` | `0.1` |
| `bootstrap_r_target_annual` | `0.05` |
| `bootstrap_inflation_floor_annual` | `0.0` |
| `bootstrap_max_annual_inflation_cap` | `0.12` |
| `bootstrap_ema_lambda_bps` | `700` |
| `bootstrap_max_delta_r_per_epoch_bps` | `25` |
| `transition_r_target_annual` | `0.04` |
| `transition_inflation_floor_annual` | `0.0` |
| `transition_max_annual_inflation_cap` | `0.1` |
| `transition_ema_lambda_bps` | `300` |
| `transition_max_delta_r_per_epoch_bps` | `10` |
| `mature_r_target_annual` | `0.03` |
| `mature_inflation_floor_annual` | `0.01` |
| `mature_max_annual_inflation_cap` | `0.08` |
| `mature_ema_lambda_bps` | `150` |
| `mature_max_delta_r_per_epoch_bps` | `5` |
| `alpha_fee_offset` | `1.0` |

## PQC authority / trust-root parameters (from `devnet-genesis.json` → `authority`)

| Parameter | Value | Note |
|-----------|-------|------|
| `authority_policy_version` | `1` | |
| `authority_sequence` | `0` | |
| `authority_epoch` | `null` | |
| `pqc_transport_roots` | `[]` | none |
| Bundle-signing authority roots | 1 | `label: run133-bundle-signing-authority`, `suite_id: 100` |
| Root material type | **public** fingerprint + **public** key hex | fixture/dev-only, no secret material |

The authority block is **not yet consumed by any live ratification verifier**
(see `docs/whitepaper/contradiction.md`, Run 101 non-claims).

## Parameters intentionally NOT published

- Any private keys, signing secrets, mnemonics, seed phrases, tokens, or credentials — **none exist**
  in this package and none will be published.
- Seed/bootnode addresses — **not published** (M4 remains Red; no seed/bootnode deployment in Run 356).

## Consistency check

The values in this document were cross-checked against `devnet-genesis.json` and the DevNet
environment constants in `crates/qbind-types/src/primitives.rs`. See `VERIFY.md` for the exact
commands that reproduce the genesis hash and the file SHA-256.