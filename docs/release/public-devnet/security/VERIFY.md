# QBIND Public DevNet — Security Package Verification (Run 389)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

These are the exact copy-paste operator checks for the Run 389 security package. All commands run from
the repository root and use **only** pre-existing tooling (the release binary, the DevNet trust-bundle
helper example, `grep`, `stat`, `python3`). Run 389 adds **no** new dependency and **no** new CLI flag.
All generated material is written into a `mktemp -d` directory **outside** the git tree.

Reproduce every check at once with the one-shot harness:

```bash
bash scripts/devnet/run_389_public_devnet_security_key_trust_bootstrap.sh
# expect final line: RESULT=POSITIVE …
```

## 0. Build once

```bash
cargo build -p qbind-node --release --locked --bin qbind-node
cargo build -p qbind-node --release --example devnet_pqc_trust_bundle_helper
NODE=./target/release/qbind-node
TB=./target/release/examples/devnet_pqc_trust_bundle_helper
OUT="$(mktemp -d)"
```

## 1. `--help` surface grep checks (documented flags exist; none invented)

```bash
"$NODE" --help > "$OUT/help.txt" 2>&1
for f in --signer-mode --signer-keystore-path --remote-signer-url --hsm-config-path \
         --p2p-trust-bundle --p2p-trust-bundle-signing-key --p2p-trusted-root \
         --p2p-pqc-root-mode --p2p-leaf-cert --p2p-leaf-cert-key --p2p-peer-leaf-cert \
         --p2p-mutual-auth --expect-genesis-hash; do
  grep -q -- "$f" "$OUT/help.txt" && echo "present: $f" || echo "MISSING: $f"
done
```

Expected: `present:` for all thirteen flags; no `MISSING:`.

## 2. `identity --help` subcommand check

```bash
"$NODE" identity --help
# expect usage for: generate / verify / print-public / seed-candidate / register-check
```

## 3. Generate a temporary DevNet identity

```bash
"$NODE" identity generate devnet full-node "$OUT/node"
ls "$OUT/node"   # public-identity.json leaf.cert.bin leaf.kem.sk.bin root.id.hex root.pk.hex trusted-root.spec
```

## 4. Verify the public identity (re-derive NodeId from the public cert)

```bash
NODE_ID=$(python3 -c "import json;print(json.load(open('$OUT/node/public-identity.json'))['node_id'])")
"$NODE" identity verify "$OUT/node/leaf.cert.bin" | grep -qF "$NODE_ID" \
  && echo "NodeId re-derived from public cert: OK"
```

## 5. Confirm private files are `0600`

```bash
stat -c '%a %n' "$OUT/node/leaf.kem.sk.bin"   # expect: 600
# and the root signing key is NEVER on disk:
for F in root.sk root.sk.hex root.sk.bin root.key root.kem.sk.bin; do
  [ -e "$OUT/node/$F" ] && echo "LEAK: $F present" || true
done
echo "root signing key on disk check done (no LEAK lines = OK)"
```

Expected: `600`; no `LEAK:` lines.

## 6. Confirm no private key appears in the public JSON

```bash
python3 - "$OUT/node/public-identity.json" "$OUT/node/leaf.kem.sk.bin" <<'PY'
import sys
raw = open(sys.argv[1], "rb").read()
sk  = open(sys.argv[2], "rb").read()
assert sk[:32] not in raw, "KEM secret key bytes present in public JSON"
print("public JSON carries no secret key bytes (private_material records paths only): OK")
PY
```

## 7. Trust-bundle helper smoke (mint + signature verify + tamper fail-closed)

```bash
# mint a valid *signed* DevNet bundle
"$TB" "$OUT/tb" 1 signed-devnet >/dev/null
ls "$OUT/tb"   # trust-bundle.json signing-key.{id,pk}.hex signing-key.spec root.{id,pk}.hex v0.cert.bin v0.kem.sk.bin
# no bundle-signing SECRET key file may exist:
ls "$OUT/tb" | grep -qiE 'sign.*(sk|secret)\.(bin|hex)' && echo "LEAK: signing secret on disk" \
  || echo "bundle-signing secret NOT on disk: OK"

# validate the signed bundle (validation-only; no live apply)
SPEC="$(cat "$OUT/tb/signing-key.spec")"
"$NODE" --env devnet \
  --p2p-trust-bundle-reload-check "$OUT/tb/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert "$OUT/tb/v0.cert.bin" \
  --p2p-leaf-cert-key "$OUT/tb/v0.kem.sk.bin" 2>&1 | grep -E "signature_verified=true|VERDICT=valid|no live trust apply"

# tampered bundle fails closed
"$TB" "$OUT/tb-t" 1 signed-tampered >/dev/null
SPEC_T="$(cat "$OUT/tb-t/signing-key.spec")"
"$NODE" --env devnet \
  --p2p-trust-bundle-reload-check "$OUT/tb-t/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SPEC_T" \
  --p2p-leaf-cert "$OUT/tb-t/v0.cert.bin" \
  --p2p-leaf-cert-key "$OUT/tb-t/v0.kem.sk.bin" 2>&1 | grep -q "VERDICT=invalid" \
  && echo "tampered bundle fails closed: OK"
```

Expected: `signature_verified=true`, `VERDICT=valid`, `no live trust apply` on the valid bundle;
`tampered bundle fails closed: OK` on the tampered one.

## 8. Confirm MainNet / TestNet DevNet-only paths fail closed

```bash
for ENV in mainnet testnet; do
  "$NODE" identity generate "$ENV" full-node "$OUT/$ENV" >/dev/null 2>&1 \
    && echo "NOT refused: $ENV" || echo "refused (fail closed): $ENV"
done
```

Expected: `refused (fail closed):` for both `mainnet` and `testnet`.

## 9. Validate example docs for no forbidden claims (non-claim grep)

```bash
grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready' \
    docs/release/public-devnet/security/ \
  | grep -viE 'NOT |not launch-ready|no M4|neither|not a claim|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim' \
  && echo "FOUND forbidden claim" || echo "no forbidden readiness/closure claim: OK"
```

Expected: `no forbidden readiness/closure claim: OK`.

## 10. Confirm cross-links to operator / identity / p2p / PQC lifecycle docs

```bash
for LINK in docs/release/public-devnet/operator/ docs/release/public-devnet/identity/ \
            docs/release/public-devnet/p2p/ docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md; do
  grep -rqF "$LINK" docs/release/public-devnet/security/ && echo "linked: $LINK" || echo "MISSING link: $LINK"
done
```

Expected: `linked:` for all four; no `MISSING link:`.

## 11. Clean up

```bash
rm -rf "$OUT"
```

The `mktemp -d` directory held all generated identity/bundle material (including the `0600` KEM secret
keys); removing it leaves **no** private material behind. Nothing generated by these checks is ever
committed.
