# QBIND Public DevNet — Genesis Verification (Run 356)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim ·
> no C4/C5 closure claim. **DevNet only.**

These are the exact operator verification steps for the canonical public DevNet genesis package.
All commands are run from the repository root. Only pre-existing repository tooling and CLI flags are
used (no new CLI flag was added in Run 356).

## Prerequisites

Build the release binary once:

```bash
cargo build -p qbind-node --release
# binary: ./target/release/qbind-node
```

## 1. Genesis file is valid JSON

```bash
python3 -c "import json; json.load(open('docs/release/public-devnet/genesis/devnet-genesis.json')); print('valid json')"
```

Expected: `valid json`.

## 2. Genesis file is parseable by QBIND tooling

`--print-genesis-hash` parses the file as a `GenesisConfig`; a successful parse + hash print proves
parseability (malformed genesis fails closed with a non-zero exit code):

```bash
./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --print-genesis-hash
```

Expected stderr line (provenance) and stdout hash:

```
[run-102] --print-genesis-hash: canonical Run 101 hash over parsed genesis (env=Devnet, chain_id=5855328520645203456, authority=<see genesis file>, source=docs/release/public-devnet/genesis/devnet-genesis.json)
0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

## 3. Printed genesis hash matches the published hash

The stdout value from step 2 must equal the published canonical hash:

```
0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

Operators may additionally pin the hash for boot using the pre-existing flag:

```bash
./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

## 4. SHA-256 in `devnet-genesis.sha256` matches the committed `devnet-genesis.json`

```bash
cd docs/release/public-devnet/genesis && sha256sum -c devnet-genesis.sha256
```

Expected: `devnet-genesis.json: OK`.

## 5. Network parameters match the genesis file / source constants

- Genesis config `chain_id` in `devnet-genesis.json` is `qbind-devnet-v0`.
- Runtime DevNet ChainId is `0x51424E4444455600` (`5855328520645203456`) per
  `crates/qbind-types/src/primitives.rs` (`QBIND_DEVNET_CHAIN_ID`), and the `--print-genesis-hash`
  provenance line above reports `chain_id=5855328520645203456`, confirming the DevNet env mapping.
- Monetary/validator/council/authority values in `devnet-network-parameters.md` are transcribed
  directly from `devnet-genesis.json`.

Optional tamper check (demonstrates the hash is content-sensitive; produces a *different* hash):

```bash
cp docs/release/public-devnet/genesis/devnet-genesis.json /tmp/tamper.json
python3 -c "import json;d=json.load(open('/tmp/tamper.json'));d['chain_id']='qbind-devnet-TAMPER';json.dump(d,open('/tmp/tamper.json','w'))"
./target/release/qbind-node --env devnet --genesis-path /tmp/tamper.json --print-genesis-hash
# -> prints a hash != the published hash
```

## 6. MainNet is not affected

This package sets `--env devnet` only and publishes no MainNet artifact. No MainNet genesis, hash,
custody, or authority material is created or modified. MainNet remains unaffected.

## 7. TestNet is not affected

This package sets `--env devnet` only and publishes no TestNet artifact. TestNet remains unaffected.

## 8. No public DevNet launch claim

This package makes **no** public DevNet launch claim. Public DevNet remains **NOT launch-ready**:
M3 (reproducibility/BuildID) and M4 (seed/bootnodes) remain **Red**. See
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` and `README.md` §15.
