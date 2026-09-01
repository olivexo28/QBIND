# QBIND Public DevNet — Recovery Package Verification (Run 394)

> **Safety label:** experimental · resettable · no value · no uptime SLA · no guarantee of data
> permanence · no MainNet readiness claim · no TestNet readiness claim · no C4/C5 closure claim · NOT
> public-DevNet launch-ready.

These are the exact copy-paste operator checks for the Run 394 recovery package. All commands run from
the repository root and use **only** pre-existing tooling (the release binary, `grep`). Run 394 adds
**no** new dependency and **no** new CLI flag.

Reproduce every check at once with the one-shot harness:

```bash
bash scripts/devnet/run_394_public_devnet_operator_recovery_package.sh
# expect final line: RESULT=POSITIVE …
```

## 0. Build once

```bash
cargo build -p qbind-node --release --locked --bin qbind-node
NODE=./target/release/qbind-node
REC=docs/release/public-devnet/recovery
```

## 1. Every documented recovery flag is pre-existing in `--help` (no invented flag)

```bash
"$NODE" --help > /tmp/qbind-help.txt 2>&1
for F in --data-dir --snapshot-dir --snapshot-interval-blocks --snapshot-max-snapshots \
         --restore-from-snapshot --state-retention-mode --state-retain-height \
         --state-prune-interval --genesis-path --print-genesis-hash --expect-genesis-hash; do
  grep -q -- "$F" /tmp/qbind-help.txt && echo "help flag present: $F" || echo "MISSING help flag: $F"
done
```

Expected: `help flag present:` for all eleven; no `MISSING`.

## 2. Recovery docs exist

```bash
for f in README BACKUP_RESTORE DATA_RETENTION UPGRADE_PROCEDURE ROLLBACK_PROCEDURE SAFETY VERIFY; do
  [ -f "$REC/$f.md" ] && echo "present: $f" || echo "MISSING: $f"
done
```

Expected: `present:` for all seven; no `MISSING`.

## 3. Recovery docs contain the safety label

```bash
for f in README BACKUP_RESTORE DATA_RETENTION UPGRADE_PROCEDURE ROLLBACK_PROCEDURE SAFETY VERIFY; do
  grep -qi 'experimental' "$REC/$f.md" \
    && grep -qi 'no value' "$REC/$f.md" \
    && grep -qi 'no guarantee of data permanence' "$REC/$f.md" \
    && echo "safety label present: $f" || echo "MISSING safety label: $f"
done
```

Expected: `safety label present:` for all seven; no `MISSING`.

## 4. BACKUP_RESTORE.md required sections

```bash
for s in 'may be backed up' 'stop-before-copy' 'must NOT be committed' \
         'restore-from-snapshot' 'Genesis-hash pinning' 'Build-provenance' \
         'wipe' ; do
  grep -qi "$s" "$REC/BACKUP_RESTORE.md" && echo "present: $s" || echo "MISSING: $s"
done
```

Expected: `present:` for all; no `MISSING`.

## 5. DATA_RETENTION.md required sections

```bash
for s in 'may be reset' 'best-effort' 'no SLA' 'retention window' 'Redaction' 'reset policy'; do
  grep -qi "$s" "$REC/DATA_RETENTION.md" && echo "present: $s" || echo "MISSING: $s"
done
```

Expected: `present:` for all; no `MISSING`.

## 6. UPGRADE_PROCEDURE.md required sections

```bash
for s in 'provenance' 'Stop the node' 'publish-safe metadata' 'Replace the binary' \
         'same genesis pin' 'build info' 'Rollback criteria'; do
  grep -qi "$s" "$REC/UPGRADE_PROCEDURE.md" && echo "present: $s" || echo "MISSING: $s"
done
```

Expected: `present:` for all; no `MISSING`.

## 7. ROLLBACK_PROCEDURE.md required sections

```bash
for s in 'previous binary' 'matching' 'trust / authority state by hand' \
         'sequence' 'marker' 'wipe' 'incident-response'; do
  grep -qi "$s" "$REC/ROLLBACK_PROCEDURE.md" && echo "present: $s" || echo "MISSING: $s"
done
```

Expected: `present:` for all; no `MISSING`.

## 8. Docs cross-link operator / ops / observability / network / genesis / internal baseline

```bash
for LINK in \
  docs/release/public-devnet/operator/ \
  docs/release/public-devnet/ops/RESET_POLICY.md \
  docs/release/public-devnet/ops/INCIDENT_RESPONSE.md \
  docs/release/public-devnet/observability/ \
  docs/release/public-devnet/network/ \
  docs/release/public-devnet/genesis/ \
  docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md \
  docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md ; do
  grep -rqF "$LINK" "$REC/" && echo "linked: $LINK" || echo "MISSING link: $LINK"
done
```

Expected: `linked:` for all eight; no `MISSING link:`.

## 9. Non-claim grep passes

```bash
grep -rEi 'launch-ready|M4 Green|M6 Green|C4 closed|C5 closed|TestNet ready|MainNet ready|uptime SLA|data permanence' \
    "$REC/" \
  | grep -viE 'NOT |not launch-ready|no M4|no M6|no uptime|neither|not a claim|does not|is not|not as|remains? (open|yellow|red)|grep |negat|Expected:|no C4/C5 closure|C[45] remains OPEN|no .*closure claim|no guarantee of data permanence|no TestNet|no MainNet' \
  && echo "FOUND forbidden claim" || echo "no forbidden readiness/closure claim: OK"
```

Expected: `no forbidden readiness/closure claim: OK`.

## 10. No private / raw artifacts committed under the recovery package

```bash
find "$REC" -type f \
  \( -name '*.kem.sk.bin' -o -name '*.key' -o -name '*.log' -o -name 'metrics*.txt' \
     -o -name '*.pem' -o -name '*.sk.hex' -o -name '*.data' \) -print \
  | grep -q . && echo "FOUND private/raw artifact" || echo "no private/raw artifacts committed: OK"
```

Expected: `no private/raw artifacts committed: OK`.