# QBIND Public DevNet Readiness Criteria and Gap Matrix

**Status:** Canonical (Run 355 deliverable — public network release-readiness track, kickoff; updated Run 356 —
M1/M19/M20 moved to Green with the published DevNet genesis package).
**Track:** Public network release-readiness. This is a **separate track** from the internal
authority-lifecycle boundary track (Run 130–354) and from C4/C5 closure.
**Scope of this document:** source/docs/test-only audit and gap matrix. It introduces public DevNet
readiness as a tracked classification. It does **not** launch, deploy, or declare any public network ready.
**Audience:** Internal — protocol engineering, ops, release management.

---

## 0. Relationship to existing documents

This document is intentionally **separate** from, and cross-references, the existing checklists:

- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` — the EXE-2 bring-up audit. It answers a narrower
  question ("can a minimal DevNet be brought up now for internal evidence collection?"). It is **not** a
  public-network launch checklist. This document extends that work into public-DevNet launch classification.
- `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` — operator bring-up practices for internal DevNet.
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md` — DevNet → TestNet → MainNet stage sequencing and exit gates.
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` — MainNet-only readiness gate (not DevNet).
- `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md`, `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` — TestNet stages.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — C4/C5 closure criteria (both remain **OPEN**).

No generic release/MainNet checklist is duplicated here; where an item is owned by one of those documents,
this matrix references it rather than restating it.

---

## 1. Public DevNet launch definition

A **QBIND public DevNet** is an **experimental, externally-reachable, resettable** network that
outside operators may join to run validator/full nodes for evaluation and integration testing.

A public DevNet launch means, at minimum:

1. A canonical, published DevNet **genesis package** (genesis file + published genesis hash + network parameters).
2. A published, **provenance-attested release binary** that external operators can obtain and verify.
3. A published **seed/bootnode entry list** enabling an outside node to join the network.
4. A published **operator quickstart** sufficient for an external party to run a node unassisted.
5. Published **safety disclaimers** (experimental, resettable, no value, no readiness claim).
6. Operational **incident-response, monitoring, and abuse-handling** posture appropriate for an open port.

A public DevNet launch **explicitly is not** claimed by this document. This document only classifies which of
the above are Green (evidenced), Yellow (partial), Red (missing), or N/A for DevNet.

---

## 2. Explicit public DevNet non-goals

- No faucet deployment.
- No public JSON-RPC gateway deployment.
- No block explorer or public status-page deployment.
- No public genesis package published *as ready* by this run.
- No seed-node/bootnode deployment by this run.
- No public TestNet readiness claim.
- No MainNet readiness claim.
- No C4 closure. No C5 closure.
- No runtime wiring of any authority-lifecycle boundary (Run 353/354 stays dead code from runtime).
- No public CLI enablement flag.
- No reinterpretation of any Green-for-scope authority-lifecycle boundary as production readiness.
- No marketing language; evidence-grounded status only.

---

## 3. Public DevNet safety label

Any future public DevNet, when launched, **must** carry and publish this label:

- **experimental** — software and network may fail, fork, or be discontinued at any time;
- **resettable** — network state may be wiped without notice; no state durability guarantee;
- **no value** — no token, asset, or balance on DevNet has or represents monetary value;
- **no MainNet readiness claim** — DevNet participation implies nothing about MainNet readiness;
- **no C4/C5 closure claim** — C4 and C5 remain OPEN irrespective of any DevNet activity.

This label is a **must-have** and is a launch precondition, not a post-launch addendum.

---

## 4. Must-have checklist (public DevNet launch preconditions)

Each item must be genuinely **Green** and evidenced before public DevNet launch. See §10/§16 matrix for status.

- [x] M1. Canonical DevNet genesis package published (file + hash + parameters). — **Green (Run 356)**; see `docs/release/public-devnet/genesis/`.
- [ ] M2. Release binary provenance published (source commit, build inputs, SHA-256).
- [ ] M3. Release binary reproducibility / BuildID documented (deterministic or documented non-determinism).
- [ ] M4. Seed/bootnode list published for public join.
- [ ] M5. Validator/full-node onboarding quickstart for external operators.
- [ ] M6. Validator identity guidance (node identity/key generation) published.
- [ ] M7. Validator key-management guidance (local keystore / remote signer / HSM options) published.
- [ ] M8. PQC trust-bundle bootstrap process for DevNet trust roots published.
- [ ] M9. PQC root / signing-key guidance for DevNet published.
- [ ] M10. Public P2P port posture defined (listen/advertise, `--enable-p2p` default, NAT guidance).
- [ ] M11. Peer admission policy defined for an open network.
- [ ] M12. Abuse / DoS protections documented and enabled (per-peer rate limiting posture).
- [ ] M13. Telemetry / metrics baseline available to operators.
- [ ] M14. Monitoring / alerting baseline available to operators.
- [ ] M15. Reset policy published (when/how DevNet state is wiped).
- [ ] M16. Incident-response process published.
- [ ] M17. Public documentation (how to run a node) sufficient for unassisted external bring-up.
- [ ] M18. User-facing disclaimers published (the §3 safety label).
- [x] M19. Network parameter publication (chain id, env scope, consensus/timing params). — **Green (Run 356)**; see `docs/release/public-devnet/genesis/devnet-network-parameters.md`.
- [x] M20. Genesis hash publication (canonical hash operators verify with `--expect-genesis-hash`). — **Green (Run 356)**; hash `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`, see `docs/release/public-devnet/genesis/VERIFY.md`.

---

## 5. Should-have checklist (strongly recommended, not launch-blocking)

- [ ] S1. Snapshot / backup / restore baseline usable by operators (creation + restore path).
- [ ] S2. Data-retention posture documented for DevNet.
- [ ] S3. Upgrade procedure documented (binary upgrade / rolling restart).
- [ ] S4. Rollback procedure documented.
- [ ] S5. Status page or aggregate health view.
- [ ] S6. Alert-rule definitions / scrape config shipped alongside the metrics baseline.
- [ ] S7. Seed-node operational runbook (operating the published seeds).

---

## 6. TestNet-deferred checklist (not required for public DevNet)

- [ ] T1. Faucet service.
- [ ] T2. Public JSON-RPC gateway.
- [ ] T3. RPC rate limiting.
- [ ] T4. Block explorer.
- [ ] T5. Governance proof production surface hardening at network scale.
- [ ] T6. Validator-set rotation exercised on a live shared network.
- [ ] T7. Formal data-retention SLAs.
- [ ] T8. Multi-region / soak / chaos operational evidence.

---

## 7. MainNet-deferred checklist (not required for public DevNet or TestNet)

- [ ] N1. MainNet custody (production key custody under production authority).
- [ ] N2. MainNet authority rotation / revocation under production custody (**Red**).
- [ ] N3. Runtime wiring of the authority-lifecycle boundary chain into production execution.
- [ ] N4. Reproducible-build hardening / signed release provenance (SLSA-grade) for value-bearing releases.
- [ ] N5. C4 closure (**OPEN**).
- [ ] N6. C5 closure (**OPEN**).
- [ ] N7. Production economic finalization.

---

## 8. Evidence required for each must-have item

| Item | Evidence required to move to Green |
|------|-------------------------------------|
| M1 | Committed canonical genesis artifact + a run that publishes it and records its hash. |
| M2 | Published provenance record: source commit, toolchain, build command, artifact SHA-256. |
| M3 | Documented reproducible-build result or documented, bounded non-determinism. |
| M4 | Committed, published seed/bootnode list + reachability evidence. |
| M5 | Committed external quickstart doc validated against the real `qbind-node` startup path. |
| M6 | Committed node-identity/key-generation guidance validated against CLI. |
| M7 | Committed key-management guidance covering `--signer-mode` local/remote + HSM options. |
| M8 | Committed DevNet trust-root bootstrap procedure validated against `pqc_trust_bundle` surfaces. |
| M9 | Committed PQC root/signing-key guidance referencing `--p2p-trusted-root` / `--p2p-trust-bundle-signing-key`. |
| M10 | Documented listen/advertise/`--enable-p2p`/NAT posture for public exposure. |
| M11 | Documented peer-admission policy (mutual-auth mode, trust-bundle gating) for an open port. |
| M12 | Documented + enabled rate-limiter posture (`peer_rate_limiter`) with configured thresholds. |
| M13 | Operator-facing metrics endpoint doc (`metrics_http` / `QBIND_METRICS_HTTP_ADDR`). |
| M14 | Operator-facing alerting baseline referencing `QBIND_MONITORING_AND_ALERTING_BASELINE.md`. |
| M15 | Published reset policy referencing `--authority-state-reset` and network-wide reset intent. |
| M16 | Reference to `docs/ops/QBIND_INCIDENT_RESPONSE.md` scoped for public DevNet. |
| M17 | Public how-to-run-a-node doc validated against real startup. |
| M18 | The §3 safety label published in operator-facing material. |
| M19 | Network parameters published (chain id per `NetworkEnvironment`, timing/consensus params). |
| M20 | Canonical genesis hash published + verifiable via `--print-genesis-hash` / `--expect-genesis-hash`. |

---

## 9. Owner / source file / evidence location per item

| Item | Owner | Primary source / evidence location |
|------|-------|-------------------------------------|
| M1, M19, M20 | Protocol eng | `crates/qbind-genesis/src/lib.rs`, `crates/qbind-node/src/pqc_boot_genesis.rs`, CLI `--print-genesis-hash`/`--expect-genesis-hash` |
| M2, M3 | Release mgmt | `docs/whitepaper/build.sh`, per-run `artifact_sha256.txt`; no published release-provenance record yet |
| M4, M7 | Ops | CLI `--p2p-peer`; no published seed list; `crates/qbind-remote-signer/` |
| M5, M6, M17 | Docs | `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`, `README.md`; no external quickstart yet |
| M8, M9 | Ops / security | `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `crates/qbind-node/src/pqc_trust_bundle.rs` |
| M10, M11, M12 | Security / net | `crates/qbind-node/src/cli.rs`, `peer_rate_limiter.rs`, `QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` |
| M13, M14 | Observability | `crates/qbind-node/src/metrics_http.rs`, `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` |
| M15 | Ops | CLI `--authority-state-reset`, `crates/qbind-ledger/src/authority_state_reset.rs` |
| M16 | Ops | `docs/ops/QBIND_INCIDENT_RESPONSE.md`, `docs/ops/QBIND_OPERATOR_DRILL_CATALOG.md` |
| M18 | Docs | This document §3 |
| S1, S2 | Ops | `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`, `crates/qbind-ledger/src/state_snapshot.rs` |
| S3, S4 | Release mgmt | `docs/release/QBIND_RELEASE_TRACK_SPEC.md`; no staged upgrade/rollback runbook yet |
| N1, N2, N3 | Governance / custody | `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` |
| N5, N6 | Protocol eng | `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` |

---

## 10. Current status per item

Legend: 🟢 Green (evidenced enough for public DevNet) · 🟡 Yellow (partial / needs one or more runs) ·
🔴 Red (missing) · ⚪ N/A for DevNet.

| Item | Status | Basis |
|------|--------|-------|
| M1 genesis package | 🟢 | **Run 356:** canonical `docs/release/public-devnet/genesis/devnet-genesis.json` committed, hash + SHA-256 published + operator-verifiable. |
| M2 release provenance | 🟡 | Per-run SHA-256 exists; no published release-provenance record. |
| M3 reproducibility / BuildID | 🔴 | No reproducible-build result or BuildID documented. |
| M4 seed/bootnodes | 🔴 | Static `--p2p-peer` only; no published seed list; no discovery. |
| M5 validator onboarding | 🟡 | Operational guide exists; no external quickstart. |
| M6 validator identity | 🟡 | Identity/key CLI exists; no standalone identity guide. |
| M7 key-management | 🟡 | Local keystore / remote signer / HSM surfaces exist; no consolidated guide. |
| M8 trust-bundle bootstrap | 🟡 | Runbook + `pqc_trust_bundle` exist; DevNet root bootstrap not published. |
| M9 PQC root / signing-key guidance | 🟡 | CLI + runbook exist; DevNet-specific guidance not consolidated. |
| M10 public P2P port posture | 🟡 | Configurable; `--enable-p2p` defaults false; public exposure posture not published. |
| M11 peer admission policy | 🟡 | Mutual-auth + trust-bundle gating exist; open-network policy not published. |
| M12 abuse / DoS protections | 🟡 | `peer_rate_limiter` exists; public-network thresholds not published. |
| M13 telemetry / metrics | 🟡 | `/metrics` endpoint + baseline exist; operator-facing exposure doc partial. |
| M14 monitoring / alerting | 🟡 | Baseline doc exists; alert rules / scrape config absent. |
| M15 reset policy | 🟡 | `--authority-state-reset` exists; network-wide reset policy not published. |
| M16 incident response | 🟢 | `QBIND_INCIDENT_RESPONSE.md` comprehensive; DevNet scoping is a small doc note. |
| M17 public documentation | 🟡 | Operational guide exists; README minimal; no external quickstart. |
| M18 user-facing disclaimers | 🟡 | §3 label defined here; not yet in operator-facing release material. |
| M19 network parameter publication | 🟢 | **Run 356:** `devnet-network-parameters.md` published as canonical operator artifact, checked against genesis + `QBIND_DEVNET_CHAIN_ID`. |
| M20 genesis hash publication | 🟢 | **Run 356:** canonical hash `0x48b3a862…af18145f` published + verifiable via `--print-genesis-hash` / `--expect-genesis-hash`. |
| S1 snapshot / backup / restore | 🟡 | Creation supported; restore path partial. |
| S2 data retention | 🟡 | Baseline exists; DevNet retention not formalized. |
| S3 upgrade procedure | 🟡 | Release track spec exists; no staged upgrade runbook. |
| S4 rollback procedure | 🟡 | Authority reset only; no staged rollback runbook. |
| S5 status page | 🔴 | None. |
| S6 alert rules / scrape config | 🔴 | None shipped. |
| S7 seed-node runbook | 🔴 | None (depends on M4). |
| T1 faucet | ⚪ | Explicit DevNet non-goal; TestNet-deferred. |
| T2 RPC gateway | ⚪ | Explicit DevNet non-goal; TestNet-deferred. |
| T3 RPC rate limiting | ⚪ | Depends on T2; TestNet-deferred. |
| T4 explorer | ⚪ | TestNet-deferred. |
| T5 governance proof surface (scale) | 🟡 | Green-for-scope boundaries exist; network-scale hardening TestNet-deferred. |
| T6 validator-set rotation (live) | 🟡 | Green-for-scope boundary only; live-network exercise TestNet-deferred. |
| T7 data-retention SLAs | ⚪ | TestNet-deferred. |
| T8 soak / chaos / multi-region | ⚪ | TestNet-deferred. |
| N1 MainNet custody | 🔴 | MainNet-only. |
| N2 MainNet authority rotation/revocation | 🔴 | **Red**; MainNet-only. |
| N3 runtime authority-lifecycle wiring | 🔴 | Parked future work; Green-for-scope boundary is dead code from runtime. |
| N4 SLSA-grade provenance | 🔴 | MainNet-only. |
| N5 C4 | 🔴 | **OPEN**. |
| N6 C5 | 🔴 | **OPEN**. |
| N7 production economic finalization | 🔴 | MainNet-only. |

---

## 11. Exact next run recommendation for each Red/Yellow must-have

| Item | Status | Next-run recommendation |
|------|--------|--------------------------|
| M1 | 🟢 | **Done (Run 356):** canonical DevNet genesis artifact published + hash recorded (`docs/release/public-devnet/genesis/`). |
| M2 | 🟡 | Run: emit a published release-provenance record (commit + toolchain + build cmd + SHA-256). |
| M3 | 🔴 | Run: attempt reproducible build; document result or bounded non-determinism + BuildID. |
| M4 | 🔴 | Run: define + publish a seed/bootnode list format and a placeholder DevNet seed list (docs-only). |
| M5 | 🟡 | Run: author external validator/full-node quickstart validated against real startup. |
| M6 | 🟡 | Run: author node-identity/key-generation guide (docs, CLI-validated). |
| M7 | 🟡 | Run: consolidate key-management guide (`--signer-mode`, keystore, remote signer, HSM). |
| M8 | 🟡 | Run: publish DevNet trust-root bootstrap procedure. |
| M9 | 🟡 | Run: publish DevNet PQC root/signing-key guidance (fold into M8 run if convenient). |
| M10 | 🟡 | Run: publish public P2P port/NAT/`--enable-p2p` posture doc. |
| M11 | 🟡 | Run: publish open-network peer-admission policy (mutual-auth + trust-bundle gating). |
| M12 | 🟡 | Run: publish rate-limiter thresholds + enablement posture for public exposure. |
| M13 | 🟡 | Run: publish operator metrics exposure guide (fold with M14). |
| M14 | 🟡 | Run: ship alert-rule definitions / scrape config alongside the baseline. |
| M15 | 🟡 | Run: publish DevNet reset policy (trigger conditions, notice, audit trail). |
| M17 | 🟡 | Run: publish external how-to-run-a-node (fold with M5). |
| M18 | 🟡 | Run: fold §3 safety label into operator-facing release material. |
| M19 | 🟢 | **Done (Run 356):** canonical network-parameter artifact published (`devnet-network-parameters.md`). |
| M20 | 🟢 | **Done (Run 356):** canonical genesis hash published + operator-verifiable (`VERIFY.md`). |

Note: several Yellow items can be closed by a small number of consolidated documentation/publication runs
(genesis+params+hash landed in Run 356; remaining: onboarding+identity+key-management+quickstart together;
trust-root bootstrap+PQC guidance together; monitoring+alerting together; port posture+admission+abuse together).

---

## 12. Public DevNet launch blocker summary

Public DevNet is **NOT yet launch-ready**. As of **Run 356**, the Green must-haves are **M1, M16, M19, M20**;
every other must-have remains **Yellow or Red**. The launch blockers are, at minimum:

- **Red:** M3 (reproducibility/BuildID), M4 (seed/bootnodes).
- **Yellow (must reach Green):** M2, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M17, M18.

Because at least one must-have is not Green, this document does **not** mark public DevNet ready.

## 13. Public TestNet blocker summary

Beyond all DevNet must-haves, TestNet additionally requires (distinct from DevNet):

- Faucet (T1), public RPC gateway + rate limiting (T2/T3), explorer (T4).
- Governance-proof surface hardening at network scale (T5) and live validator-set rotation exercise (T6).
- Formal data-retention SLAs (T7) and soak/chaos/multi-region evidence (T8).
- The TestNet Alpha/Beta plan exit gates in `docs/testnet/`.

## 14. MainNet blocker summary

Beyond all DevNet and TestNet items, MainNet additionally requires (distinct from TestNet):

- MainNet custody (N1) and MainNet authority rotation/revocation under production custody (N2 — **Red**).
- Runtime wiring of the authority-lifecycle boundary chain into production execution (N3).
- SLSA-grade signed provenance for value-bearing releases (N4).
- **C4 closure (N5) and C5 closure (N6)** — both **OPEN**.
- Production economic finalization (N7), plus the full `QBIND_MAINNET_READINESS_CHECKLIST.md` gate.

---

## 15. C4/C5 non-closure statement

This document does **not** close C4 or C5. Full **C4 remains OPEN**. **C5 remains OPEN**. The Run 353/354
live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness boundary remains
**Green-for-scope only** and is not reinterpreted as production readiness or as C4/C5 closure. Public DevNet
readiness is a **separate release-readiness track** introduced here; progress on it does not affect the C4/C5
status, and C4/C5 closure is **not** a public DevNet launch precondition (it is MainNet-deferred).

---

## 16. Consolidated gap matrix

Columns: item · release stage · category · status · evidence source · blocker · risk if launched without it · next-run recommendation.

| Item | Stage | Category | Status | Evidence source | Blocker | Risk if launched without | Next run |
|------|-------|----------|--------|-----------------|---------|--------------------------|----------|
| genesis package | DevNet | network | 🟢 | `docs/release/public-devnet/genesis/` (Run 356) | Published + verified | Operators join divergent chains | Done (Run 356) |
| release binary provenance | DevNet | binary | 🟡 | `build.sh`, per-run `artifact_sha256.txt` | No published provenance record | Unverifiable binaries | Emit provenance record |
| release reproducibility / SHA / BuildID | DevNet | binary | 🔴 | none | No reproducible/BuildID result | Cannot attest what operators run | Reproducible-build run |
| seed nodes / bootnodes | DevNet | network | 🔴 | CLI `--p2p-peer` | No published seeds/discovery | Outsiders cannot join | Publish seed-list format + list |
| validator onboarding | DevNet | docs | 🟡 | `QBIND_DEVNET_OPERATIONAL_GUIDE.md` | No external quickstart | Onboarding failures/misconfig | Author external quickstart |
| validator identity | DevNet | security | 🟡 | `cli.rs`, `peer_key_provider.rs` | No identity guide | Identity collisions/misconfig | Identity guide run |
| validator key-management guidance | DevNet | security | 🟡 | `--signer-mode`, `qbind-remote-signer` | No consolidated guide | Key mishandling | Key-management guide run |
| trust-bundle bootstrap | DevNet | security | 🟡 | `pqc_trust_bundle.rs`, PQC runbook | DevNet root bootstrap unpublished | Trust misconfiguration | Trust-root bootstrap run |
| PQC root / signing-key guidance | DevNet | security | 🟡 | CLI trust-root flags, PQC runbook | DevNet guidance not consolidated | Weak/incorrect roots | Fold into bootstrap run |
| faucet | TestNet | ops | ⚪ | n/a (DevNet non-goal) | Deferred | n/a for DevNet | TestNet |
| RPC gateway | TestNet | network | ⚪ | n/a (DevNet non-goal) | Deferred | n/a for DevNet | TestNet |
| RPC rate limiting | TestNet | security | ⚪ | n/a | Deferred | n/a for DevNet | TestNet |
| public P2P port posture | DevNet | network | 🟡 | `cli.rs` (`--p2p-listen-addr`, `--enable-p2p`) | Public exposure posture unpublished | Unintended exposure/NAT issues | Port-posture doc run |
| peer admission policy | DevNet | security | 🟡 | mutual-auth, trust-bundle gating | Open-network policy unpublished | Eclipse/spam admission | Admission-policy doc run |
| telemetry / metrics | DevNet | observability | 🟡 | `metrics_http.rs` | Operator exposure doc partial | Blind operations | Metrics exposure guide |
| monitoring / alerting | DevNet | observability | 🟡 | `QBIND_MONITORING_AND_ALERTING_BASELINE.md` | Alert rules absent | Missed incidents | Ship alert rules |
| status page | DevNet | observability | 🔴 | none | Missing | No shared health view | Should-have run |
| explorer | TestNet | observability | ⚪ | n/a | Deferred | n/a for DevNet | TestNet |
| reset policy | DevNet | ops | 🟡 | `--authority-state-reset`, `authority_state_reset.rs` | Network reset policy unpublished | Surprise wipes / disputes | Reset-policy doc run |
| incident response | DevNet | ops | 🟢 | `QBIND_INCIDENT_RESPONSE.md` | — (scope note only) | — | — |
| abuse handling | DevNet | security | 🟡 | `peer_rate_limiter.rs` | Public thresholds unpublished | DoS/flooding | Abuse-posture doc run |
| snapshot / backup / restore | DevNet | ops | 🟡 | `state_snapshot.rs`, backup baseline | Restore path partial | Data loss on reset | Should-have run |
| data retention | DevNet | ops | 🟡 | backup baseline | DevNet retention not formalized | Unclear retention | Should-have run |
| upgrade procedure | DevNet | ops | 🟡 | `QBIND_RELEASE_TRACK_SPEC.md` | No staged upgrade runbook | Botched upgrades | Should-have run |
| rollback procedure | DevNet | ops | 🟡 | authority reset only | No staged rollback runbook | Unrecoverable bad upgrade | Should-have run |
| public documentation | DevNet | docs | 🟡 | `README.md`, operational guide | No external how-to-run | Operators cannot self-serve | Public docs run |
| user-facing disclaimers | DevNet | docs | 🟡 | this doc §3 | Not in release material | Misperceived value/stability | Publish label |
| network parameter publication | DevNet | network | 🟢 | `devnet-network-parameters.md` (Run 356) | Published + checked vs source | Config divergence | Done (Run 356) |
| genesis hash publication | DevNet | network | 🟢 | `--print-genesis-hash` + `VERIFY.md` (Run 356) | Canonical hash published | Chain divergence | Done (Run 356) |
| DevNet authority lifecycle | DevNet | governance | 🟡 | authority-lifecycle evidence runs | Green-for-scope only | Overclaiming readiness | Keep scoped |
| governance proof status | TestNet | governance | 🟡 | governance evidence runs, surface audit | Scale hardening deferred | Overclaiming readiness | TestNet |
| validator-set rotation status | TestNet | governance | 🟡 | Run 303–310 boundaries | Green-for-scope only; not live | Overclaiming readiness | TestNet |
| runtime wiring for authority lifecycle | MainNet | governance | 🔴 | Run 353/354 (dead code from runtime) | Parked future work | Unsafe activation | MainNet track |
| MainNet custody | MainNet | custody | 🔴 | trust-anchor authority model | MainNet-only | Value at risk | MainNet track |
| MainNet authority rotation/revocation | MainNet | custody | 🔴 | authority model | **Red** | Loss of control of authority | MainNet track |
| C4 | MainNet | governance | 🔴 | `QBIND_C4_C5_CLOSURE_CRITERIA.md` | **OPEN** | Incomplete production governance | MainNet track |
| C5 | MainNet | custody | 🔴 | `QBIND_C4_C5_CLOSURE_CRITERIA.md` | **OPEN** | Incomplete production custody | MainNet track |

---

## 17. Summary

Public DevNet readiness is a **tracked, evidence-grounded classification**. As of **Run 356**, the canonical
DevNet genesis package, network parameters, and genesis hash are published and operator-verifiable, moving
**M1, M19, M20** to Green (joining **M16 incident response**). Public DevNet is still **not launch-ready**: all
other must-haves remain Yellow or Red (notably **Red** for reproducibility/BuildID (M3) and seed/bootnodes (M4)).
C4 and C5 remain **OPEN**, MainNet authority rotation/revocation remains **Red**, and the Run 353/354 boundary
remains Green-for-scope only. The most efficient path forward is a small series of consolidated
documentation/publication runs (onboarding+identity+key-management+quickstart+disclaimers; trust-root bootstrap+PQC
guidance; monitoring+alerting; port-posture+admission+abuse; reset policy; release provenance/reproducibility;
seed/bootnode list).