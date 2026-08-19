# QBIND Public DevNet — Seed-List Verification (Run 357)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim ·
> no C4/C5 closure claim. **DevNet only.**

These are the exact operator verification steps for the canonical public DevNet seed-list format and
the placeholder seed-list artifact. All commands are run from the repository root. Only pre-existing
repository tooling is used (Python 3 with the repo-available `jsonschema` package); Run 357 adds **no**
new dependency and **no** new CLI flag.

Paths used below:

- Schema: `docs/release/public-devnet/network/devnet-seed-list.schema.json`
- Placeholder list: `docs/release/public-devnet/network/devnet-seeds.placeholder.json`
- Run 356 genesis package: `docs/release/public-devnet/genesis/`

## 1. Seed-list schema is valid JSON

```bash
python3 -c "import json; json.load(open('docs/release/public-devnet/network/devnet-seed-list.schema.json')); print('schema valid json')"
```

Expected: `schema valid json`.

## 2. Placeholder seed-list is valid JSON

```bash
python3 -c "import json; json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json')); print('placeholder valid json')"
```

Expected: `placeholder valid json`.

## 3. Placeholder seed-list validates against the schema

The repo-available `jsonschema` (draft-07) validator is used; no new dependency is added:

```bash
python3 -c "
import json, jsonschema
schema=json.load(open('docs/release/public-devnet/network/devnet-seed-list.schema.json'))
data=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'))
jsonschema.validate(instance=data, schema=schema)
print('placeholder validates against schema')
"
```

Expected: `placeholder validates against schema`.

## 4. Placeholder seed-list references the Run 356 genesis hash correctly

```bash
python3 -c "
import json
d=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'))
params=open('docs/release/public-devnet/genesis/devnet-network-parameters.md').read()
gh=d['genesis_hash']
assert gh in params, 'genesis hash not found in Run 356 params'
for n in d['seed_nodes']:
    assert n['expected_genesis_hash']==gh, 'seed expected_genesis_hash mismatch'
print('genesis hash matches Run 356:', gh)
"
```

Expected: `genesis hash matches Run 356: 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`.

## 5. Placeholder seed-list references the Run 356 genesis file SHA-256 correctly

```bash
python3 -c "
import json
d=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'))
sha=open('docs/release/public-devnet/genesis/devnet-genesis.sha256').read().split()[0]
assert d['genesis_file_sha256']==sha, 'genesis_file_sha256 mismatch'
print('genesis_file_sha256 matches devnet-genesis.sha256:', sha)
"
```

Expected: `genesis_file_sha256 matches devnet-genesis.sha256: d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`.

## 6. No placeholder entry is falsely marked live

The schema already forbids `last_reachability_evidence` on non-live entries; this is an explicit
cross-check:

```bash
python3 -c "
import json
d=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'))
for n in d['seed_nodes']:
    assert n['status']!='live', 'a live entry is present (unexpected for placeholder list)'
    if n['status'] in ('placeholder','planned','retired'):
        assert n['last_reachability_evidence'] is None, 'non-live entry has reachability evidence'
print('no entry falsely marked live; all non-live entries have null reachability evidence')
"
```

Expected: `no entry falsely marked live; all non-live entries have null reachability evidence`.

## 7. No public DevNet launch claim is present

The placeholder artifact carries an explicit `placeholder_statement` and a `safety_label` asserting
`experimental`, `resettable`, `no_value`, `no_mainnet_readiness_claim`, and `no_c4_c5_closure_claim`:

```bash
python3 -c "
import json
d=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'))
s=d['safety_label']
assert all(s[k] for k in ('experimental','resettable','no_value','no_mainnet_readiness_claim','no_c4_c5_closure_claim'))
assert 'NOT launch-ready' in d['placeholder_statement']
print('safety label + placeholder statement present; no launch claim')
"
```

Expected: `safety label + placeholder statement present; no launch claim`.

## 8. MainNet and TestNet are not affected

This package sets `environment: "devnet"` only and publishes no TestNet or MainNet artifact. No
TestNet/MainNet genesis, seed list, custody, or authority material is created or modified. The change
set for Run 357 is docs/artifact-only under `docs/release/public-devnet/network/` and
`docs/devnet/`, plus narrow readiness/protocol doc updates. TestNet and MainNet remain unaffected.
