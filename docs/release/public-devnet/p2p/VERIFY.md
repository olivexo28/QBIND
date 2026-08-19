# QBIND Public DevNet — P2P Posture Package Verification (Run 360)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim.

This document lists exact commands an operator/reviewer can run to reproduce every check for the
Run 360 P2P posture package. All commands are run from the repository root. They are **read-only**
verification steps (plus a release build) and modify no artifact.

## 0. Build the binary (for the CLI-surface checks)

```bash
cargo build -p qbind-node --release
BIN=./target/release/qbind-node
```

## 1. Confirm every CLI flag referenced by the P2P docs exists in `--help`

Every `qbind-node` flag referenced by `P2P_PORT_POSTURE.md`, `PEER_ADMISSION_POLICY.md`, and
`ABUSE_DOS_POSTURE.md` must appear in `qbind-node --help` (the only exception is the explicitly
marked **future/unsupported** internal `P2pDiscoveryConfig`, which is **not** an operator CLI flag
and is documented as such — no discovery capability is claimed).

```bash
"$BIN" --help 2>&1 | grep -oE -- '--[a-z0-9-]+' | sort -u > /tmp/qbind_help_flags.txt
for f in enable-p2p p2p-listen-addr p2p-advertised-addr p2p-peer p2p-mutual-auth \
         p2p-trust-bundle p2p-trust-bundle-signing-key p2p-pqc-root-mode p2p-trusted-root \
         p2p-leaf-cert p2p-leaf-cert-key p2p-peer-leaf-cert expect-genesis-hash \
         print-genesis-hash env genesis-path data-dir; do
  grep -qx -- "--$f" /tmp/qbind_help_flags.txt && echo "OK   --$f" || echo "MISS --$f"
done
```

Expected: `OK` for all 17 flags. (Actual Run 360 result: all 17 `OK`.)

## 2. Confirm the Run 357 placeholder seed list still contains no live entries

```bash
python3 -c "import json;d=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'));\
s=[n['status'] for n in d['seed_nodes']];\
print('statuses:',s);\
assert all(x!='live' for x in s),'LIVE ENTRY PRESENT';\
print('OK: no status==live entry')"
```

Expected: `statuses: ['placeholder']` and `OK: no status==live entry`.

## 3–7. Confirm no P2P doc makes a forbidden readiness/closure claim

The P2P docs must not claim public DevNet is launch-ready, TestNet-ready, or MainNet-ready, must not
claim C4/C5 closure, and must not mark M4 Green. These greps should return **no** offending line
(each doc's only mentions are explicit negations).

```bash
P2PDOCS="docs/release/public-devnet/p2p"
# Strip markdown emphasis so negations like "**not**" are matched by word filters.
strip() { grep -rni "$@" "$P2PDOCS" | grep -v 'VERIFY.md' | sed -E 's/[*_>`]/ /g'; }
# 3. launch-ready — must only appear as a negation ("NOT launch-ready" / "launch-blocking")
strip -E 'launch[- ]ready' | grep -viE 'not +launch[- ]?ready|launch-blocking' || echo "OK: no positive launch-ready claim"
# 4. TestNet readiness — must only appear as a negation/disclaimer
strip -E 'testnet[- ]?(ready|readiness)' | grep -viE '\b(no|not|nothing|neither|nor|implies|before|remains)\b|readiness claim' || echo "OK: no TestNet readiness claim"
# 5. MainNet readiness — must only appear as a negation/disclaimer
strip -E 'mainnet[- ]?(ready|readiness)' | grep -viE '\b(no|not|nothing|neither|nor|implies|remains|red)\b|readiness claim' || echo "OK: no MainNet readiness claim"
# 6. C4/C5 closure — must only appear as "OPEN"/negation
strip -E 'C4|C5' | grep -iE 'clos' | grep -viE '\b(no|not|nothing|open|remains)\b' || echo "OK: no C4/C5 closure claim"
# 7. M4 Green — must not be marked (allow future-conditional "moves Green only when …")
strip -E 'M4' | grep -iE 'green' | grep -viE 'not|before|remains|yellow|only when|moves green only|can move' || echo "OK: M4 not marked Green"
```

Expected: an `OK: …` line for each check (no offending lines printed).

## 8. Confirm the safety label appears in every P2P doc

```bash
for f in README.md P2P_PORT_POSTURE.md PEER_ADMISSION_POLICY.md ABUSE_DOS_POSTURE.md VERIFY.md; do
  grep -q 'Safety label' "docs/release/public-devnet/p2p/$f" \
    && echo "OK   $f" || echo "MISS $f"
done
```

Expected: `OK` for all five files.

## 9. Confirm the operator QUICKSTART no longer says M3 is Red and references the Run 359 binary package

```bash
# Must NOT say M3 is Red:
grep -niE 'M3[^.]*Red' docs/release/public-devnet/operator/QUICKSTART.md \
  && echo "FAIL: stale M3-Red wording present" || echo "OK: no 'M3 is Red' wording"
# Must reference the Run 359 binary provenance package:
grep -q 'public-devnet/binary' docs/release/public-devnet/operator/QUICKSTART.md \
  && echo "OK: references Run 359 binary package" || echo "MISS: no binary-package reference"
```

Expected: `OK: no 'M3 is Red' wording` and `OK: references Run 359 binary package`.

## 10. Confirm Run 356/357/358/359 artifacts are referenced but not modified

```bash
git status --short docs/release/public-devnet/genesis docs/release/public-devnet/network \
  docs/release/public-devnet/binary
# Expected: no output for genesis/, network/, or binary/ artifacts (unchanged).
git diff --stat HEAD -- docs/release/public-devnet/operator/QUICKSTART.md \
  docs/release/public-devnet/operator/README.md
# The operator files change ONLY for the narrow Run 359 hygiene fix (M3 wording + binary cross-link).
```

Expected: the genesis / network / binary artifacts show **no** modification; only the operator
`README.md` / `QUICKSTART.md` change, and only for the narrow M3 hygiene correction.

## 11. Secret hygiene

```bash
grep -rniE 'BEGIN [A-Z ]*PRIVATE KEY|mnemonic|seed phrase|api[_-]?key|password|secret' \
  docs/release/public-devnet/p2p || echo "OK: no secret-like content in P2P docs"
```

Expected: `OK` (the only key-material mentions are references to operator-held
`--p2p-leaf-cert-key` files, never a key value).
