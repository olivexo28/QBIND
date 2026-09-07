# QBIND DevNet Evidence — Run 416

Public DevNet **M4 live seed Route A** — the **first successful real external
reachability** run for a public DevNet seed. Run 416 packages publish-safe evidence from a
real deployment: a routable public seed VPS and a genuinely independent off-host dialer on a
different network completed external TCP **and** external KEMTLS mutual-auth static-root
reachability. This clears the external-reachability blocker that kept M4 Yellow through
Runs 377–397 (all of which found no external ingress / no independent off-host vantage in
the sandbox and recorded Route C / NEGATIVE-FOR-EXTERNAL).

This is **experimental** DevNet evidence. It is **NOT public-DevNet launch-ready**, makes
**no C4/C5 closure claim**, and asserts **no** TestNet/MainNet readiness. The seed used
**temporary** DevNet PQC material that was discarded, and **no `devnet-seeds.live.json` is
published**, so **M4 stays Yellow / launch-blocking** pending a durable published live seed.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · **external reachability PROVEN (Route A)** · **no M4 Green**
· no M6 fully-Green · no S5 Green · no S7 Green · no TestNet readiness · no MainNet readiness
· **C4/C5 OPEN**. **No private key material is committed.**

## 1. Exact verdict

`RESULT=POSITIVE-FOR-EXTERNAL` — Route A. A real, routable public DevNet seed
(`188.166.227.87:30333`, host `<seed-host>`, listening `0.0.0.0:30333`) was
dialed from an independent off-host vantage (Laptop 1 WSL, host `<dialer-host>`, observed public
egress `<dialer-public-egress>`) under `--p2p-mutual-auth required --p2p-pqc-root-mode
pqc-static-root`. External TCP reachability and an external KEMTLS mutual-auth static-root
handshake both succeeded (`external_tcp_reachability=true`,
`external_kemtls_reachability=true`, `independent_offhost_vantage=true`). Because the seed
identity was ephemeral DevNet PQC material and no `devnet-seeds.live.json` is published,
`m4_green_claim=false` and `c4_c5_closure_claim=false`.

## 2. Files changed

Created:

- `docs/devnet/run_416_public_devnet_m4_live_seed_route_a_evidence/` — publish-safe evidence
  archive: `README.md`, `summary.txt`, `SHA256SUMS.txt`, `.gitignore`, and per-host
  transcriptions `laptop1/{manifest,dialer-process,dialer-sockets,dialer-log-extract,dialer-metrics}.txt`
  and `vps/{manifest,seed-process,seed-sockets,seed-log-extract,seed-metrics}.txt`.
- `docs/release/public-devnet/network/reachability/RUN_416_qbind-devnet-seed-1.md` — the
  Route A reachability evidence record (POSITIVE-FOR-EXTERNAL).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_416.md` (this file).

Updated narrowly:

- `docs/release/public-devnet/network/devnet-seeds.live-candidate.json` — top-level
  `placeholder_statement` reconciled to the accurate Run 416 narrative (candidate stays a
  preflight, `status: planned`, null evidence, RFC 5737 endpoint, non-live posture unchanged).
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — Run 416 narrative row; M4 rows
  updated to record external reachability now PROVEN (Route A) while M4 stays
  Yellow/launch-blocking pending a durable published `devnet-seeds.live.json`.
- `docs/whitepaper/contradiction.md` — Run 416 entry (kept as a separate ledger line).
- `docs/release/public-devnet/ARTIFACT_INDEX.md`,
  `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md`,
  `docs/release/public-devnet/network/README.md` — add the Run 416 reachability record so it
  is discoverable by the Run 415 path/reference lint, and reconcile current-state prose.
- `docs/release/public-devnet/READINESS_ARTIFACT_PATH_REFERENCE_LINT.md` and
  `scripts/devnet/run_415_public_devnet_readiness_artifact_path_reference_lint.sh` — reconcile
  the documented discoverability behavior with the implemented `is_discoverable_in()` (index /
  operator map / documented exception).
- `docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.example.json` — SHA-256 / byte-size
  refresh for the edited package-integrity anchor docs.
- `scripts/devnet/run_404/405/410/411/412/413/414/415_*.sh` — normalized CRLF → LF so the
  committed verification scripts run directly under `bash`.

No production Rust source, `build.rs`, `Cargo.toml`, or CLI file is changed. The committed
`docs/release/public-devnet/network/devnet-seeds.live-candidate.json` **was modified only to
reconcile its explanatory Run 416 narrative** (its top-level `placeholder_statement`). Its
schema fields, `status: planned`, null `last_reachability_evidence` reference, RFC 5737
documentation endpoint (`203.0.113.10`), and non-live posture all remain **unchanged** — there
is no durable live seed to promote.

## 3. Decision gate route

**Route A (real external infrastructure).** Unlike Runs 378/388/391/393/397 (Route C — no
external ingress / no independent vantage in the sandbox), Run 416 was executed on real
operator infrastructure with a routable public endpoint and an independent off-host dialer.

## 4. External seed infrastructure

A DigitalOcean SGP1 droplet (`1vcpu-1gb`, host `<seed-host>`) ran `qbind-node`
bound to `0.0.0.0:30333`, externally reachable at `188.166.227.87:30333`, with exactly the
P2P port `30333/tcp` opened inbound through the host firewall / cloud security group.

## 5. Durable seed identity

**Not durable.** Both sides used **temporary** DevNet PQC material (ML-DSA-44 root +
ML-KEM-768 leaf) generated by `crates/qbind-node/examples/devnet_pqc_root_helper.rs`, which
was discarded after the run. This is deliberately an evidence deployment, not a durably
operated seed, which is why M4 does not fully move Green.

## 6. Public/private separation

Only public identifiers, endpoints, hosts, the runtime evidence commit, and status lines are
committed. The ML-DSA root signing key, ML-KEM leaf secret, leaf certificate, data dirs, raw
logs, and raw metrics dumps live only in the gitignored operator-side bundles
(`bundles/qbind-m4-evidence-laptop1.tgz`, `bundles/qbind-m4-evidence-vps.tgz`) and are **not**
committed. `secret_scanning` and manual review confirm no key material in the tracked files.

## 7. Public endpoint

`188.166.227.87:30333` (routable public IPv4). Seed bound `0.0.0.0:30333`, advertised
`188.166.227.87:30333`.

## 8. Independent vantage evidence

The dialer ran on Laptop 1 WSL (host `<dialer-host>`) on a **different network**; the seed
observed its public egress as `<dialer-public-egress>` (≠ the seed's own `188.166.227.87`), proving
a genuinely independent, off-host, off-NAT vantage. **Independence PROVEN.**

## 9. External TCP evidence

Seed sockets: `LISTEN 0.0.0.0:30333` and `ESTAB 188.166.227.87:30333 →
<dialer-public-egress>:<client-port>`; seed log `[P2P] Accepted connection from
<dialer-public-egress>:<client-port>`; dialer sockets show `ESTAB … → 188.166.227.87:30333`. See
`vps/seed-sockets.txt`, `vps/seed-log-extract.txt`, `laptop1/dialer-sockets.txt`.
**`external_tcp_reachability=true`.**

## 10. External KEMTLS/static-root evidence

Under `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root`, the KEMTLS
mutual-auth static-root handshake completed over the external connection. The dialer supplied
the seed's certified leaf via `--p2p-peer-leaf-cert 0:<redacted-temp-seed-cert-path>` (format
`VID:PATH`; VID `0` = the seed) while running as `--validator-id 1`, so it could verify against
the seed's advertised identity. See `vps/seed-log-extract.txt` /
`laptop1/dialer-log-extract.txt`. **`external_kemtls_reachability=true`.** Certificate
fingerprints are not committed (temporary discarded material).

Directly captured `[Run040]` cryptographic-provider shape (both nodes; see
`vps/seed-metrics.txt` / `laptop1/dialer-metrics.txt` / `summary.txt`) — this is the **complete**
provider-shape evidence, not merely the ML-DSA-44 / ML-KEM-768 names:

- `pqc_root_mode=pqc-static-root`
- `sig_suite_id=100`
- `transport_kem_suite_name=ml-kem-768`
- `transport_aead_suite_name=chacha20-poly1305`
- `dummy_kem_registered=false`
- `dummy_aead_registered=false`

Directly captured PQC cert-verify counters: dialer `qbind_p2p_pqc_root_mode 1`,
`qbind_p2p_pqc_cert_verify_accepted_total 1`, `qbind_p2p_pqc_cert_verify_rejected_total 0`;
seed `qbind_p2p_pqc_root_mode 1`, `qbind_p2p_pqc_cert_verify_accepted_total 2`,
`qbind_p2p_pqc_cert_verify_rejected_total 0`. This provider shape and these counters confirm a
real PQC provider (no dummy KEM/AEAD) and do **not** convert this run into a production PKI,
rotation/revocation, C4/C5 closure, or TestNet/MainNet claim.

### 10a. Peer-gauge discrepancy (mandatory evidence limitation)

During the observation window `qbind_p2p_connections_current`, `qbind_p2p_inbound_peers`, and
`qbind_p2p_outbound_peers` all reported `0` on both nodes even though the socket evidence, the
connection/accept logs, and the PQC cert-verify counters above demonstrate the admitted external
connection. This is recorded as an **observed gauge discrepancy / evidence limitation only** — it
is **not** a diagnosed software bug (no root cause was separately proven), and Run 416 makes **no**
peer-gauge health claim.

## 11. Observed NodeId / cert identity match

Each side logged the peer's public `NodeId(<prefix>)`. Because the seed identity was
ephemeral (not the committed candidate identity), no "observed identity matches a *published
live* entry" claim is made — that check belongs to the remaining M4 Green gate.

## 12. Reachability record

`docs/release/public-devnet/network/reachability/RUN_416_qbind-devnet-seed-1.md` records the
run in the canonical `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` shape with
`external_tcp_reachability=true`, `external_kemtls_reachability=true`,
`independent_offhost_vantage=true`, `m4_green_claim=false`, `c4_c5_closure_claim=false`.

## 13. Seed-list promotion

**None.** `docs/release/public-devnet/network/devnet-seeds.live-candidate.json` stays
`status: planned` with `last_reachability_evidence: null`, and **no `devnet-seeds.live.json`
is published**, because the seed identity was temporary and the endpoint is not durably
operated. Promotion is deferred until a durable operator seed identity is provisioned.

## 14. Runtime provenance (accuracy note)

- **Runtime evidence commit recorded in BOTH manifests:**
  `1c2ba28d1532474a9e1124bc9873cd54193f29b6`. The live `qbind-node` binary on the seed and
  dialer was built from this commit.
- The Run 415 docs commit `50eed16b` (`docs: add Run 415 readiness artifact path reference
  lint`) landed **after** the live binary was built. This evidence does **not** claim the
  live binary was built from `50eed16b`.

## 15. Default compatibility / CLI surface

No new CLI flag, no `build.rs` change, no default change. The run exercises only existing
`qbind-node` P2P/KEMTLS flags (`--p2p-listen-addr`, `--p2p-advertised-addr`,
`--p2p-mutual-auth`, `--p2p-pqc-root-mode`, `--p2p-trusted-root`, `--p2p-leaf-cert[-key]`,
`--p2p-peer-leaf-cert`, `--validator-id`, `--p2p-peer`) and the existing `devnet_pqc_root_helper`
example.

## 16. Runtime mutation check

This run commits documentation/evidence only. It mutates **no** validator set /
`LivePqcTrustState` / sequence / epoch / marker in the repository, applies no trust bundle,
and performs no live/peer-driven apply against committed state.

## 17. Readiness delta — M4

**M4 stays Yellow / launch-blocking**, but materially strengthened: the external-reachability
blocker (unproven since Run 377) is **cleared** — real external TCP + KEMTLS mutual-auth
static-root reachability from an independent off-host vantage is now **PROVEN** (Route A
POSITIVE). The remaining Green gate narrows to a **durable published live seed**: provision a
non-ephemeral operator seed identity on the externally reachable host and publish it as
`devnet-seeds.live.json` with `status: live` and a non-null `last_reachability_evidence`.

## 18. Readiness delta — M6 / S5 / S7

Unchanged. **M6 stays Yellow/Partial** (no live registration path published; still M4-gated
for the live half). **S5 stays Yellow**, **S7 stays Yellow** (operating a *published* live
seed still depends on a durable M4 live seed).

## 19. Public DevNet status

**NOT launch-ready.** M4 remains a launch blocker (Yellow) and M6 remains Yellow/Partial;
public DevNet stays NO-GO. M1–M3/M5/M7–M20 remain Green.

## 20. C4 / C5

**OPEN.** No governance/authority rotation/revocation ceremony ran; operator-supplied root
reuse/rotation/revocation remains C4/C5-OPEN. No closure is claimed.

## 21. TestNet / MainNet non-claims

No TestNet or MainNet readiness is claimed. MainNet authority rotation/revocation remains
Red; N1–N7 untouched.

## 22. Security scans

`secret_scanning` was run over the created/edited files; no API keys, tokens, credentials,
or private key material are present. The archive `.gitignore` blocks the raw bundles and any
key/cert/data-dir/log artifact as a backstop.

## 23. CodeQL

No production code changed (docs + evidence only), so there is no new code path for CodeQL to
analyze; the CodeQL check was still run per policy with a trivial-change declaration.

## 24. Honest limitations

- **Evidence trust model.** Run 416 is operator-attested operational evidence. The committed
  socket, metric and log files are publish-safe transcriptions; reconstructed log lines are not
  independently authenticated raw captures. SHA256SUMS protects the committed evidence after
  publication but does not independently prove the original observations. The Route A positive
  result stands, but "PROVEN" here means proven **within this operator-attested evidence scope**
  (it is not downgraded to Route B/C).
- The seed used **temporary** DevNet PQC material (discarded); the identity is illustrative
  and **not** the committed candidate identity. No durable seed is provisioned.
- The raw operator-side capture bundles are **not** committed; the tracked files are
  publish-safe transcriptions of the facts observed on the operator's machines. The
  `*-log-extract.txt` files are **redacted/reconstructed log transcriptions** (normalized, not
  verbatim raw logs). Fine-grained values (PIDs, ephemeral source ports, certificate
  fingerprints) are redacted and retained only in the gitignored bundles.
- **Exact UTC execution timestamp was not retained in the publish-safe evidence.** It is not
  derived or inferred from commit time, upload time, filename, or filesystem mtime.
- **Genesis pinning was not evidenced by Run 416.** The retained process/log evidence shows no
  `--expect-genesis-hash` or observed genesis-pin result; external reachability is proven
  independently of genesis pinning.
- **Peer-gauge discrepancy:** `qbind_p2p_connections_current` / `qbind_p2p_inbound_peers` /
  `qbind_p2p_outbound_peers` reported `0` during the observation despite the admitted
  connection (evidenced by sockets + logs + PQC cert-verify counters). Recorded as an observed
  gauge discrepancy / evidence limitation only, **not** a diagnosed bug; no peer-gauge health
  claim is made.
- No `devnet-seeds.live.json` is published, so **M4 stays Yellow**; this evidence proves
  external reachability, not a durably operated published seed.

## 25. Next step — durable-seed publication is DEFERRED (not recommended as Run 417)

Durable-seed provisioning and `devnet-seeds.live.json` publication is **not** recommended as an
immediate next run. It is **deferred** until a separate foundational **runtime-security
reconciliation** first audits:

- proposal/vote signing and inbound verification;
- consensus sender identity binding to the authenticated KEMTLS peer;
- QC signature verification and production suite enforcement;
- transaction authentication, empty-auth behavior and keyset thresholds.

This correction records that audit only as a **prerequisite**; it does **not** declare any of
those findings resolved and does **not** change any milestone status. Once that audit is
complete, provisioning a durable operator-controlled DevNet seed identity on an externally
reachable host (keeping the ML-KEM leaf secret / ML-DSA root private and uncommitted), re-running
the Route A reachability capture against that durable identity, and publishing
`devnet-seeds.live.json` (`status: live`, non-null `last_reachability_evidence`) remains the
final step required to move **M4** Yellow → Green.