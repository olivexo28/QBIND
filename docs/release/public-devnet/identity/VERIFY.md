# QBIND Public DevNet — Identity Package Verification (Run 374)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.

Copy-paste steps a reviewer runs to confirm the Run 374 identity package. Steps
1–7 need only Rust + Python 3 (`jsonschema`); step 6 additionally builds the node
binary.

> **Run 375 — first-class command.** To verify against the first-class command
> instead of the Run 374 example, build the node binary
> (`cargo build -p qbind-node --release --bin qbind-node`) and replace
> `"$BIN" generate …` / `"$BIN" verify …` with `qbind-node identity generate …`
> / `qbind-node identity verify …`. The full first-class evidence harness is
> `scripts/devnet/run_375_public_devnet_identity_cli.sh`.

## 1. Helper builds

```bash
cargo build -p qbind-node --release --example run_374_public_devnet_identity_generation_helper
```

## 2. Generate produces valid material in a temp dir (private key 0600, not on stdout)

```bash
OUT="$(mktemp -d)"
BIN=./target/release/examples/run_374_public_devnet_identity_generation_helper
"$BIN" generate devnet full-node "$OUT/node" > "$OUT/node.public.json"
stat -c '%a %n' "$OUT/node/leaf.kem.sk.bin"      # expect: 600
grep -c BEGIN "$OUT/node.public.json" || true    # expect: 0 (no PEM/secret on stdout)
```

## 3. Public identity validates against the schema

```bash
python3 - "$OUT/node.public.json" <<'PY'
import json, sys, jsonschema
schema=json.load(open('docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json'))
jsonschema.validate(instance=json.load(open(sys.argv[1])), schema=schema)
print("OK: schema valid")
PY
```

## 4. The committed example validates against the schema

```bash
python3 - <<'PY'
import json, jsonschema
schema=json.load(open('docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json'))
jsonschema.validate(instance=json.load(open('docs/release/public-devnet/identity/EXAMPLE_PUBLIC_IDENTITY.json')), schema=schema)
print("OK: EXAMPLE_PUBLIC_IDENTITY.json valid")
PY
```

## 5. Derived NodeId is deterministic (generate == verify)

```bash
GEN="$(python3 -c "import json;print(json.load(open('$OUT/node.public.json'))['node_id'])")"
VER="$("$BIN" verify "$OUT/node/leaf.cert.bin" 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['node_id'])")"
[ "$GEN" = "$VER" ] && echo "OK: deterministic NodeId" || { echo "MISMATCH"; exit 1; }
```

## 6. End-to-end harness (build + boot + fail-closed + refusal)

```bash
bash scripts/devnet/run_374_public_devnet_identity_generation.sh
cat /tmp/qbind-run374-public-devnet-identity-generation/summary.txt
```

Expected summary lines:

- `identity_schema_validation=OK (full-node, seed, validator-candidate)`
- `deterministic_node_id_verify=OK`
- `seed_list_candidate_insertion=OK`
- `loopback_strict_auth_boot=OK qbind_p2p_pqc_root_mode 1 qbind_p2p_pqc_roots_configured 1`
- `mismatched_material_fail_closed=OK`
- `mainnet_testnet_generation=REFUSED`
- `RESULT=PASS`

## 7. MainNet / TestNet generation is refused

```bash
"$BIN" generate mainnet full-node "$OUT/nope"; echo "exit=$?"   # expect non-zero, no dir created
"$BIN" generate testnet seed "$OUT/nope2";     echo "exit=$?"   # expect non-zero
test ! -e "$OUT/nope" && echo "OK: no MainNet material written"
```

## 8. No launch / M4 / C4 / C5 claim

- This package publishes **no** live seed and moves **M4** nowhere (still Yellow).
- It makes **no** launch-ready, TestNet, or MainNet readiness claim.
- It closes **neither C4 nor C5** and creates **no** MainNet custody.
- Confirm the safety label appears in every file in this directory:

```bash
for f in docs/release/public-devnet/identity/*.md; do
  grep -q "no C4/C5 closure claim" "$f" && echo "OK: $f" || echo "MISSING label: $f"
done
```