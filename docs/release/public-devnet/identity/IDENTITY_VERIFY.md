# QBIND Public DevNet — Identity Verification (Run 374, first-class command Run 375)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.

> **Run 375 — first-class command (preferred).** Verification is now a stable
> `qbind-node identity verify` / `qbind-node identity print-public` subcommand.
> Wherever this document shows `"$BIN" verify …`, you may equivalently run
> `qbind-node identity verify …` — identical, public-only output.

This document gives the **exact** commands to print, verify, and cross-check
public identity material. Every step here operates on **public** material only
(no secret key is read), so it is safe for an external reviewer to run on a
published `public-identity.json` + `leaf.cert.bin`.

Set up:

```bash
# First-class command (Run 375):
BIN="./target/release/qbind-node identity"
# or the Run 374 example wrapper:
#   BIN=./target/release/examples/run_374_public_devnet_identity_generation_helper
DIR="$OUT/node"     # a directory produced by IDENTITY_GENERATION.md
```

## 1. Print / verify the public identity from the leaf cert

`verify` decodes the leaf `NetworkDelegationCert` and re-derives the public
identity (NodeId, leaf-cert fingerprint, root_key_id) from the cert bytes:

```bash
"$BIN" verify "$DIR/leaf.cert.bin"
```

## 2. Confirm the NodeId is deterministic (generate == verify)

The re-derived `node_id` must equal the `node_id` recorded in
`public-identity.json`:

```bash
GEN="$(python3 -c "import json;print(json.load(open('$DIR/public-identity.json'))['node_id'])")"
VER="$("$BIN" verify "$DIR/leaf.cert.bin" 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['node_id'])")"
[ "$GEN" = "$VER" ] && echo "OK: NodeId deterministic ($GEN)" || echo "MISMATCH"
```

## 3. Validate the public identity against the schema

```bash
python3 - <<'PY'
import json, jsonschema
schema=json.load(open('docs/release/public-devnet/identity/OPERATOR_IDENTITY_SCHEMA.json'))
data=json.load(open(f"{__import__('os').environ['DIR']}/public-identity.json"))
jsonschema.validate(instance=data, schema=schema)
print("OK: public-identity.json validates against OPERATOR_IDENTITY_SCHEMA.json")
PY
```

(`jsonschema` draft-07 is already used by
`docs/release/public-devnet/network/VERIFY.md`; no new dependency is introduced.)

## 4. Map the public identity into a seed-list candidate

A generated **public** identity slots into a Run 357 seed-list `seed_node`
object. For a non-live candidate use `status: "planned"` (or `"placeholder"`)
with `last_reachability_evidence: null` — publishing a `node_id`/`peer_id` here is
**not** a launch or reachability claim:

```bash
python3 - <<'PY'
import json, jsonschema, os
schema=json.load(open('docs/release/public-devnet/network/devnet-seed-list.schema.json'))
base=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'))
pub=json.load(open(f"{os.environ['DIR']}/public-identity.json"))
cand={
  "node_id": pub["node_id"], "peer_id": pub["peer_id"],
  "validator_address": pub["validator_address"],
  "p2p_host": "192.0.2.20", "p2p_port": 30333, "p2p_multiaddr": "192.0.2.20:30333",
  "transport_security_mode": pub["transport_security_mode"], "pqc_suite": pub["pqc_suite"],
  "trust_bundle_required": False, "expected_genesis_hash": base["genesis_hash"],
  "operator": "example-operator", "status": "planned",
  "last_reachability_evidence": None, "notes": "Run 374 generated candidate; not live.",
}
doc=json.loads(json.dumps(base)); doc["seed_nodes"].append(cand)
jsonschema.validate(instance=doc, schema=schema)
print("OK: generated public identity inserts into seed-list without schema violation")
PY
```

### Field → seed-list mapping

| `public-identity.json` field | seed-list `seed_node` field |
|------------------------------|-----------------------------|
| `node_id` | `node_id` |
| `peer_id` | `peer_id` |
| `validator_address` | `validator_address` (null for full-node/seed) |
| `pqc_suite` | `pqc_suite` |
| `transport_security_mode` | `transport_security_mode` |

`p2p_host` / `p2p_port` / `p2p_multiaddr` / `operator` / `status` /
`last_reachability_evidence` are supplied by the seed-list author, not the
identity helper. A candidate stays non-live until **M4** reachability evidence
lands.

## 5. Loopback strict-auth acceptance (optional, needs node binary)

Booting `qbind-node` under strict mutual-auth + static-root with the generated
material proves the deployed binary accepts it:

```bash
bash scripts/devnet/run_374_public_devnet_identity_generation.sh
grep -E 'loopback_strict_auth_boot|mismatched_material_fail_closed' \
  /tmp/qbind-run374-public-devnet-identity-generation/summary.txt
```

Expected: `loopback_strict_auth_boot=OK qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1` and
`mismatched_material_fail_closed=OK` (a mismatched `--validator-id` fails the node
closed).