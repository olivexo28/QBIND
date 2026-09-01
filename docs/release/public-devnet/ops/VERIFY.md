# QBIND Public DevNet — Ops Package Verification (Run 390)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

These are the exact copy-paste operator checks for the Run 390 ops package. All commands run from the
repository root and use **only** pre-existing tooling (the release binary, `grep`). Run 390 adds
**no** new dependency and **no** new CLI flag.

Reproduce every check at once with the one-shot harness:

```bash
bash scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh
# expect final line: RESULT=POSITIVE …
```

## 0. Build once

```bash
cargo build -p qbind-node --release --locked --bin qbind-node
NODE=./target/release/qbind-node
OPS=docs/release/public-devnet/ops
```

## 1. Documented reset-related CLI flag(s) exist (no invented flag)

`--authority-state-reset` is a pre-existing, **hidden** offline operator-ceremony flag (Run 127). It
is intentionally hidden from `--help`, so verify it against the source CLI definition, and confirm it
is dispatched offline in `main.rs`:

```bash
grep -q -- '--authority-state-reset' crates/qbind-node/src/cli.rs \
  && echo "reset flag defined: OK"
grep -q 'authority_state_reset' crates/qbind-node/src/main.rs \
  && echo "reset flag dispatched offline: OK"
# It must NOT be advertised as a normal startup flag:
"$NODE" --help 2>&1 | grep -q -- '--authority-state-reset' \
  && echo "UNEXPECTED: reset flag advertised in --help" \
  || echo "reset flag hidden from --help (expected): OK"
```

Expected: `reset flag defined: OK`, `reset flag dispatched offline: OK`, `reset flag hidden from
--help (expected): OK`.

## 2. Ops docs contain the safety label

```bash
for f in README RESET_POLICY INCIDENT_RESPONSE SAFETY VERIFY; do
  grep -qi 'experimental' "$OPS/$f.md" \
    && grep -qi 'no value' "$OPS/$f.md" \
    && echo "safety label present: $f" || echo "MISSING safety label: $f"
done
```

Expected: `safety label present:` for all five; no `MISSING`.

## 3. Reset policy contains trigger / notice / evidence / operator-action sections

```bash
for s in 'Reset triggers' 'Notice policy' 'Operator action' 'Reset evidence record' \
         'What never changes silently' 'authority-state-reset'; do
  grep -qi "$s" "$OPS/RESET_POLICY.md" && echo "present: $s" || echo "MISSING: $s"
done
```

Expected: `present:` for all; no `MISSING:`.

## 4. Incident response contains severity / classes / evidence / redaction / cross-link sections

```bash
for s in 'severity level' 'Incident classes' 'First-response' 'Evidence to capture' \
         'Escalation' 'Publication policy' 'non-claim'; do
  grep -qi "$s" "$OPS/INCIDENT_RESPONSE.md" && echo "present: $s" || echo "MISSING: $s"
done
# redaction language present:
grep -qi 'redact' "$OPS/INCIDENT_RESPONSE.md" && echo "present: redaction" || echo "MISSING: redaction"
```

Expected: `present:` for all; no `MISSING:`.

## 5. Docs cross-link operator / observability / security / network / ops runbooks

```bash
for LINK in \
  docs/release/public-devnet/operator/ \
  docs/release/public-devnet/observability/ \
  docs/release/public-devnet/security/ \
  docs/release/public-devnet/network/ \
  docs/ops/QBIND_INCIDENT_RESPONSE.md \
  docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md ; do
  grep -rqF "$LINK" "$OPS/" && echo "linked: $LINK" || echo "MISSING link: $LINK"
done
```

Expected: `linked:` for all six; no `MISSING link:`.

## 6. Non-claim grep passes

```bash
grep -rEi 'launch-ready|M4 Green|C4 closed|C5 closed|TestNet ready|MainNet ready|uptime SLA' \
    "$OPS/" \
  | grep -viE 'NOT |not launch-ready|no M4|no uptime|neither|not a claim|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim' \
  && echo "FOUND forbidden claim" || echo "no forbidden readiness/closure claim: OK"
```

Expected: `no forbidden readiness/closure claim: OK`.

## 7. No private / raw artifacts committed under the ops package

```bash
find "$OPS" -type f \
  \( -name '*.kem.sk.bin' -o -name '*.key' -o -name '*.log' -o -name 'metrics*.txt' \
     -o -name '*.pem' -o -name '*.sk.hex' \) -print \
  | grep -q . && echo "FOUND private/raw artifact" || echo "no private/raw artifacts committed: OK"
```

Expected: `no private/raw artifacts committed: OK`.