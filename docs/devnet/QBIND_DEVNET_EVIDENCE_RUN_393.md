# QBIND DevNet Evidence — Run 393

Public DevNet **M4 real external seed reachability** evidence. Run 393 executes the
**Route A** objective for must-have **M4** — deploy or validate a real externally
reachable DevNet seed under strict KEMTLS mutual-auth + PQC static-root, pin the
Run 356 genesis, prove external **TCP + KEMTLS** reachability from an **independent
off-host vantage point**, publish a `status: live` seed-list entry backed by that
evidence (`devnet-seeds.live.json`), and verify it through `qbind-node identity
register-check --status live --reachability-evidence <ref>`. It produces bounded,
honest evidence about whether M4 can move Yellow → Green, and lands a new
reachability record, a release-binary harness, and an archive — **without**
launching a public DevNet, opening an externally reachable port, deploying a
seed/bootnode/faucet/RPC/explorer/status page, adding a CLI flag, or mutating any
runtime state.

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready · **Route C
> (no safe external seed infrastructure available)** — the sandboxed environment
> has no external ingress and no independent off-host vantage point, so a real
> endpoint cannot be exposed and external reachability from outside the seed
> operator's own host/NAT was **not** proven; **M4 stays Yellow**. No production
> source change; no live deployment; no P2P wire-format change; no peer-admission
> weakening; no trust/validator/epoch/sequence/marker/`LivePqcTrustState`
> mutation.

## 1. Exact verdict

**NEGATIVE-FOR-EXTERNAL / public-DevNet M4 external seed reachability — M4 remains
Yellow / launch-blocking (Route C).**

Run 393's primary objective is Route A: expose or validate a real externally
reachable seed and prove external TCP + KEMTLS/static-root reachability from an
independent off-host vantage point. That is **impossible in this sandboxed
environment**, which has no external ingress and no second, independent network to
dial from. Rather than fake an external result, Run 393 records **Route C** — no
safe external seed infrastructure is available — keeps **M4 Yellow**, and documents
the exact infrastructure prerequisites a real operator must satisfy for M4 Green
(consistent with the Run 392 seed-node operations runbook / M4 Route-A checklist,
which was accepted as PASS). For continuity, Run 393 re-proves the **live admission
gate** end-to-end on the release binary (`register-check --status live
--reachability-evidence <ref>` accepts a cert-verified live candidate, and fails
closed both without the evidence reference and for a `planned` entry that falsely
carries reachability evidence) and re-runs the **loopback / same-host** reachability
preflight of the deployed `qbind-node` P2P listener. The committed live-seed
candidate stays at `status: planned` with `last_reachability_evidence: null`, and
**no `devnet-seeds.live.json` is created**. This finding is unchanged from
Run 378/388/391; the Run 386/387 preflight posture (`signed_release=false`,
`slsa_grade=false`) is likewise unchanged. Public DevNet remains **NOT
launch-ready**; C4/C5 remain **OPEN**; MainNet/TestNet remain untouched.

## 2. Files changed

- `scripts/devnet/run_393_public_devnet_m4_real_external_seed_reachability.sh` —
  **new** release-binary harness.
- `docs/release/public-devnet/network/reachability/RUN_393_qbind-devnet-seed-1.md`
  — **new** reachability evidence record (Route C; external reachability not
  proven; Route A infrastructure prerequisites documented).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_393.md` — this evidence record.
- `docs/devnet/run_393_public_devnet_m4_real_external_seed_reachability/` — archive
  (README, summary, `.gitignore`).
- Documentation updates (see §5/§16): network README/VERIFY, the readiness matrix,
  and continuity cross-links in the protocol/ops/whitepaper docs.

**No production Rust source change** and **no `build.rs` change.** The
`register-check --status live --reachability-evidence` gate already exists (Run 376)
and is unchanged; Run 393 exercises and pins it. **No `devnet-seeds.live.json`** is
created (Route A did not succeed).

## 3. Decision gate route

**Route C — no safe external seed infrastructure available.** Route A (real
externally reachable seed proven from an independent off-host vantage point) is the
primary objective but is **not possible** in this sandboxed environment: it has no
external ingress and no second, independent network from which to dial a real public
endpoint. Exposing a real endpoint here would be unsafe and could not be reached
externally anyway, so no endpoint is exposed. Route B (partial external preflight —
e.g. same-cloud-only or VPN-only external reachability) does not apply either,
because **no** external path exists at all — only loopback / same-host. Per Route C,
Run 393 declines to expose an endpoint, keeps **M4 Yellow**, and documents the
infrastructure prerequisites for a future Route A run in the reachability record
§15.

## 4. External seed infrastructure

**None available.** No routable public host/IP or DNS, no openable inbound P2P port
reachable from outside the runner's own host/NAT, and no way to run a durable
externally reachable seed process in this environment. The committed candidate
(`devnet-seeds.live-candidate.json`) documents a non-routable RFC 5737 host
(`203.0.113.10`) that is deliberately **not** dialed and is **not** externally
reachable.

## 5. Durable seed identity

The harness generates a real DevNet seed identity via the first-class Run 375
identity path (`qbind-node identity generate devnet seed <out>`): a real public
`node_id`/`peer_id`, with the ML-KEM-768 leaf secret written `0600` to an ephemeral
temp dir and the in-memory ML-DSA-44 root signing key **never** written to disk.
All secret material is discarded on exit. `register-check --cert` re-derives the
NodeId from the leaf cert deterministically (`cert_verified: true`). The committed
candidate `node_id`/`peer_id` are illustrative public identifiers whose secret
material was discarded; a real operator must generate and retain a durable seed
identity before any live publication.

## 6. Public/private separation

Only publish-safe values are committed: public `node_id`/`peer_id`, loopback and
RFC 5737 documentation addresses, release-binary SHA-256/BuildID/toolchain, and
status lines. No secret key, ML-DSA root signing key, KEM secret key, mnemonic,
seed phrase, credential, token, raw log, raw metrics dump, data directory, private
endpoint, private hostname, or absolute build path is committed. The archive
`.gitignore` is a backstop; per-run `material/` + `node-data/` dirs are removed on
exit.

## 7. Public endpoint

**None exposed.** The only listener booted is a loopback P2P listener on
`127.0.0.1:<ephemeral>` for the same-host preflight. No externally reachable port,
port-forward, NAT rule, load balancer, or security-group ingress is created.

## 8. Independent vantage evidence

**None available.** The reaching client and the listener are on the **same host**
(loopback). No independent off-host vantage point exists in this environment;
therefore external reachability is **NOT_PROVEN** and M4 cannot move Green. This is
stated explicitly rather than masked with a same-host, same-VPC, or same-cloud
result.

## 9. External TCP evidence

Loopback / same-host only: a same-host TCP `connect()` to the release `qbind-node`
P2P listener succeeded and the node logged `Accepted connection`. **No external TCP
dial was performed** — the external TCP-dial requirement of M4 Green is **NOT
satisfied** (`external_tcp_reachability=false`). Recorded in the Run 393 reachability
record §8.

## 10. External KEMTLS/static-root evidence

No external KEMTLS static-root handshake was performed
(`external_kemtls_reachability=false`). The standing KEMTLS strict-auth +
`PqcStaticRoot` evidence is Run 371–373 (in-/cross-process, loopback) and the
loopback strict-auth **boot admission** evidence is Run 374/375; none prove external
reachability. Deterministic NodeId re-derivation from a leaf cert is proven by
`register-check --cert` (Run 376), which Run 393 exercises on the live-admission
path (`cert_verified: true`).

## 11. Observed NodeId / cert identity match

**Not captured** — no external observer exists, so no externally observed remote
NodeId / cert-derived identity could be compared to the published entry. The M4
Green rule that the observed remote identity matches the published entry is
therefore **NOT satisfied**. The listener logs its own `NodeId(<prefix>)` on
bind/accept, and `register-check --cert` deterministically re-derives the NodeId
from the leaf cert on the admission path.

## 12. Reachability record

`network/reachability/RUN_393_qbind-devnet-seed-1.md` captures: run id, UTC
timestamp, seed id / node_id / peer_id / environment / expected genesis hash, source
vantage (same host — no off-host vantage available), public endpoint host/port
(`127.0.0.1:<ephemeral>`; committed RFC 5737 host not dialed), target listener
command + release-binary SHA-256/BuildID/toolchain, route type (Route C / loopback
only), TCP dial result (loopback accepted; no external dial), KEMTLS/static-root
result (not performed externally), observed remote NodeId (not captured — no
external observer), firewall/NAT/LB details (none — no endpoint exposed), redaction
statement, the five-line conclusion (`external_tcp_reachability=false`,
`external_kemtls_reachability=false`, `live_reachability_claim=false`,
`m4_green_claim=false`, `c4_c5_closure_claim=false`), and the **Route A
infrastructure prerequisites**.

## 13. Seed-list promotion

**None.** `devnet-seeds.live-candidate.json` validates against
`devnet-seed-list.schema.json` (Python `jsonschema`, draft-07). Its single entry is
`status: planned` with `last_reachability_evidence: null`, so the schema's status ⇔
reachability `allOf` rule holds and no entry is falsely marked live. **No
`devnet-seeds.live.json` is produced** — there is no live, externally reachable seed
to publish.

## 14. Register-check live admission

On the release binary (referencing the Run 393 evidence record):

| Invocation | Result |
| --- | --- |
| `register-check … --status live --reachability-evidence <ref>` (cert supplied) | **ADMITTED** (exit 0; `candidate_status: live`, `cert_verified: true`) |
| `register-check … --status live` (no evidence) | **REFUSED** (exit 3, fail closed) |
| `register-check … --status planned --reachability-evidence <ref>` | **REFUSED** (exit 3; schema forbids reachability on non-live) |

Even when it admits a `live` candidate, the verdict sets
`live_reachability_claim: false`, `m4_green_claim: false`,
`c4_c5_closure_claim: false`, `socket_opened: false`, `runtime_state_mutated:
false` — the gate is a **structural admission decision, not a reachability proof**.

## 15. Rejection / fail-closed evidence

`--status live` without `--reachability-evidence` → REFUSED; `--status planned` with
`--reachability-evidence` → REFUSED; and all Run 376 fail-closed cases (embedded
private material, malformed NodeId/peer_id/root spec, wrong environment,
MainNet/TestNet material, mismatched cert, mismatched validator index, unknown role)
remain enforced.

## 16. Default compatibility

No production source change. `register-check` is reached only when `identity` is the
first CLI token (dispatched before `CliArgs::parse_args()`); a normal `qbind-node …`
invocation is unaffected. The loopback preflight uses the pre-existing
`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>` default posture
(mutual-auth `Disabled`, test-grade dummy sig) — no new flag, no admission/trust/
wire-format change, and the process is loopback-bound and removed on exit.

## 17. CLI surface

**No new public CLI flag.** Run 393 uses only pre-existing flags/subcommands
(`identity generate`, `identity register-check … --status/--reachability-evidence`,
`--network-mode/--enable-p2p/--p2p-listen-addr/--validator-id/--data-dir`).

## 18. Runtime mutation check

No trust/validator/epoch/sequence/marker/`LivePqcTrustState` mutation. The
`register-check` verdict pins `runtime_state_mutated: false` and `socket_opened:
false`; the loopback listener opens only a localhost socket and is torn down on
exit. No peer-driven trust-bundle apply is enabled.

## 19. Readiness delta M4

**M4 remains Yellow / launch-blocking.** Route A was executed and found infeasible
in this environment (Route C). The live admission gate stays release-proven and a
fresh Run 393 reachability record + schema-valid preflight candidate now exist, but
**external TCP + KEMTLS reachability from outside the operator host/NAT (M4 Green
rules) is unmet**, so M4 does not move Green. The reachability record §15 documents
the exact prerequisites for a future Route A run.

## 20. Readiness delta M6

**M6 remains Yellow / Partial.** The registration/admission-check half is
Green-for-scope (Run 376) and Run 393 re-exercises its *live* branch, but M6 cannot
move fully Green because live registration is inseparable from a live, externally
reachable M4 seed, which has not landed. M6 criteria do not treat an unproven M4 as
sufficient.

## 21. Readiness delta S7

**S7 remains Yellow.** Run 392 published + verified the seed-node operational
runbook / M4 Route-A checklist / reachability template (Red → Yellow). Operating a
**live** seed still depends on M4, which has not moved Green, so S7 does not advance
to Green in Run 393.

## 22. Public DevNet status

**NOT launch-ready.** No live seed, faucet, RPC gateway, explorer, or status page
exists. The committed candidate is a preflight, not a live entry. M12/M13/M14/M15/M16
remain Green.

## 23. Remaining DevNet blockers

- **M4:** a real, externally reachable seed/bootnode with external TCP + KEMTLS
  reachability evidence (Route A) — infeasible in this sandbox; prerequisites
  documented. This is the primary remaining blocker.
- Live registration/admission into a running DevNet (M6 live half; M4-gated).
- All other Yellow/Red must-haves per the readiness matrix.

## 24. TestNet blockers

TestNet identity material is refused by the identity path. No TestNet readiness is
claimed or approached; TestNet remains untouched.

## 25. MainNet blockers

MainNet identity material is refused. MainNet authority rotation/revocation remains
**Red**; no custody, no value, no MainNet readiness. MainNet remains untouched.

## 26. C4 / C5

**C4 OPEN, C5 OPEN.** No authority-lifecycle runtime wiring, no trust-bundle live
apply, no peer-driven apply, no validator-set mutation, no epoch transition. The
register-check verdict sets `c4_c5_closure_claim: false`.

## 27. Tests run

- `cargo build -p qbind-node --release --locked --bin qbind-node` — **OK**.
- `scripts/devnet/run_393_public_devnet_m4_real_external_seed_reachability.sh` —
  **RESULT=NEGATIVE-FOR-EXTERNAL (Route C)**.
- Seed-list schema validation (`devnet-seed-list.schema.json` vs
  `devnet-seeds.live-candidate.json`) — **OK** (Python `jsonschema`, draft-07).
- `register-check --status live --reachability-evidence <ref>` — **ADMITTED**;
  `--status live` without evidence — **REFUSED**; `--status planned` with evidence —
  **REFUSED** (fail-closed).
- Non-claim grep over tracked Run 393 artifacts — **OK** (all conclusions false; no
  positive M4-Green/live/PASS token).
- Secret scan over all changed files — **no secrets**.
- **No Rust production source changed** (docs + harness + JSON-adjacent only), so
  `cargo test --lib` is unchanged from the Run 382/386 baseline and is not re-run —
  recorded honestly as a no-Rust-delta run.

## 28. Security scans

- `runtime-tools-secret_scanning` over all changed files — no secrets.
- No generated private key, root signing key, KEM secret key, data dir, log, or
  metrics dump is committed. Harness material is temporary and removed on exit; the
  archive `.gitignore` is a backstop. The committed candidate `node_id` / `peer_id`
  are **public** identifiers whose secret material was generated ephemerally and
  discarded; the only published host is an RFC 5737 documentation-example address
  (not a real endpoint).

## 29. CodeQL

**No production Rust source or `build.rs` change** in this run (docs + shell harness
+ Markdown/JSON-adjacent text only). Accordingly CodeQL is **not meaningful** for
Run 393 (no changed production source to analyze); this is **not** a clean bill of
health, it reflects the absence of an analyzable production change.

## 30. Provenance

From `scripts/devnet/run_393_public_devnet_m4_real_external_seed_reachability.sh`:

```
release_binary sha256 = 9062d5b5f03bcc4d6b2ee021e76568d7783f7f4e2e18baa2f0da9b627b62fec0
build_id              = bd22f0766824977d8becc09af39416cdacd84a0e
toolchain             = rustc 1.98.0 (88d9e12ae 2026-08-18) / cargo 1.98.0 (797e8a9bc 2026-08-05)
```

(SHA-256 / BuildID are host-specific and reproduced locally by re-running the
harness; only publish-safe values are archived. The hash differs from Run 391's
recorded value because the binary is rebuilt per host/run; the toolchain is
unchanged (1.98.0) and no production source changed.)

## 31. Honest limitations

- **External reachability is not proven.** No external ingress and no independent
  off-host vantage point exist in this environment; only loopback / same-host
  reachability is demonstrable, which is explicitly insufficient for M4 Green.
- Route A cannot be executed here without exposing a real endpoint that this
  environment cannot route to; Run 393 therefore records Route C rather than
  fabricating an external result.
- The loopback listener runs under the default `mutual_auth=Disabled`, test-grade
  dummy-sig posture — a **listener-path** preflight, not a live KEMTLS static-root
  seed, and not booted under the committed candidate's identity.
- The committed candidate `node_id`/`peer_id` are real public identifiers but their
  secret material was discarded; they are illustrative and must be replaced by the
  operator's durable seed identity before any live publication.
- The register-check live gate proves **admissibility of a live-shaped candidate**,
  not that any live seed exists or is reachable.

## 32. Suggested Run 394 next step

Execute **Route A** on real infrastructure per the prerequisites in
`network/reachability/RUN_393_qbind-devnet-seed-1.md` §15 and the Run 392
`M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`: provision a durable operator seed identity
(secrets kept private), deploy it as an externally reachable KEMTLS static-root
listener on a real public host/port with the P2P port opened through the
firewall/NAT/security-group and the Run 356 genesis pinned, and from a genuinely
independent off-host vantage point capture a timestamped external TCP dial + KEMTLS
static-root handshake with the observed remote NodeId matching the entry. Record
that external evidence, set the candidate's `last_reachability_evidence` and promote
it to `status: live` (as `devnet-seeds.live.json`), confirm with `register-check
--status live --reachability-evidence <ref>`, and — only if all other M4 Green rules
hold — move **M4** Yellow → Green and close the M6 live-registration half.