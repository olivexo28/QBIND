# QBIND DevNet Evidence — Run 075 (operator-playbook prose update for Runs 069–074 hot-reload lifecycle)

**Date**: 2026-05-14
**Status**: ✅ **DOCS-ONLY POSITIVE** (no runtime code, no test source, no helper source changed)
**C4 sub-piece narrowed**: operator-playbook prose coverage for the local-operator hot-reload lifecycle landed by Runs 069 (validation-only reload-check), 070 (apply contract + rollback semantics), 071 (mutable shared `LivePqcTrustState`), 072 (production internal P2P session-eviction hook), 073 (process-start `ProductionLiveTrustApplyContext` adapter + binary removal of `UnsupportedRuntimeContext` from the local-operator path), and 074 (long-running SIGHUP live reload-apply on a running node).
**Whitepaper / Doc Reference**: `docs/whitepaper/contradiction.md` C4; `task/RUN_075_TASK.txt`.

---

## 1. Summary

Run 075 is a **documentation-only** update of the Run 066 operator playbook (`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`) that closes the prose gap previously identified by Runs 069–074 evidence documents: the playbook still claimed "the bundle is loaded exactly once per process lifetime" and "there is no on-the-fly hot reload" — both contradicted by the local-operator hot-reload lifecycle landed in Runs 069/073/074. Run 075 corrects every such stale claim, anchors the new code surfaces (Run 069 `pqc_trust_reload`, Run 070 apply contract, Run 071 `pqc_live_trust`, Run 072 `p2p_session_eviction`, Run 073 `pqc_live_trust_apply`, Run 074 `pqc_live_trust_reload`), adds new invariants to §1.3 (eight new rows), adds a new operator-facing §6.F covering the three hot-reload paths (validation-only reload-check, process-start reload-apply, long-running SIGHUP live reload-apply) end-to-end with workflows, ordering, metrics, evidence, and incident-handling guidance, refreshes §10 residual risks (removes the obsolete "on-the-fly hot reload" open item; adds peer-supplied / gossiped acceptance, admin-API / filesystem-watcher triggers, and selective per-peer session retention as the precise remaining C4-OPEN items), extends §11 mapping with rows for Runs 069–075, and extends §12 glossary with the five new hidden CLI flags. Run 075 also appends a Run 075 narrowing entry to `docs/whitepaper/contradiction.md`.

## 2. Strict scope (what Run 075 IS and is NOT)

### Run 075 IS

- A prose-only update of `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` reflecting Runs 069–074.
- A new `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_075.md` (this document).
- A new Run 075 entry appended to `docs/whitepaper/contradiction.md` recording the prose-gap narrowing.
- **Zero change to** runtime source under `crates/`, test source under `crates/*/tests/`, integration test source, example helpers, `Cargo.toml`, `Cargo.lock`, CI workflows, or any other non-`docs/` file.

### Run 075 is **NOT**

- Any new binary surface (no new CLI flag, no new metric family, no new module, no new dependency).
- Any change to the Run 069/070/073/074 entry points or the Run 071/072 live handles.
- Any change to the Run 050–065 fail-closed boundaries or the Run 065 minimum activation-margin policy.
- Any new peer-supplied / gossiped / admin-API / filesystem-watcher hot-reload surface — those remain explicit C4-OPEN items in the updated §10.

## 3. Files changed

| File | Kind | Purpose |
|---|---|---|
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | edited | Prose update covering Runs 069–074 (header bumped to Run 075; §1 anchors extended; §1.2 stale "loaded exactly once per process lifetime" claim removed; §1.3 eight new invariants — reload-check non-mutation, Run 070 strict ordering, Run 071 live handle, Run 072 session-eviction invariant, Run 073 process-start adapter, Run 074 SIGHUP controller + CAS guard, invalid-candidate non-mutation, no-peer / no-admin-API / no-FS-watcher boundary; new §6.F (10 subsections) covering validation-only reload-check, process-start reload-apply, long-running SIGHUP live reload-apply, ordering, metrics, evidence, normal-rotation workflow, emergency-revocation via live reload, incident handling, and the consolidated "what hot reload is NOT" boundary; §6.E note updated; §7 promotion checklist extended with hot-reload preflight + live-reload trigger smoke + concurrent-trigger smoke items; §8 incident checklist extended with Run 074 emergency-via-SIGHUP + `Fatal` incident-handling items; §9 evidence checklist extended with three hot-reload-specific evidence items; §10 residual risks refreshed — obsolete "on-the-fly hot reload" open item removed and replaced with peer-supplied/gossiped, selective-retention, and admin-API/FS-watcher open items; eight new "closed" entries added for Runs 069/070/071/072/073/074; §11 mapping table extended with rows for Runs 069/070/071/072/073/074/075; §12 glossary extended with five new hidden flags). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_075.md` | new | This document. |
| `docs/whitepaper/contradiction.md` | edited | Run 075 narrowing entry appended under C4 (C4 operator-playbook hot-reload prose-coverage gap closed; full C4 / C5 still OPEN). |

**Zero pre-existing source files touched outside the list above.** No `Cargo.toml` modified. No new dependency. No new metric family. No new CLI flag. No test source modified, added, removed, weakened, or `#[ignore]`-ed.

## 4. Adversary contract (why Run 075 cannot weaken anything)

- **Documentation-only.** The runtime binary, all test source, all helpers, all CI workflows, and all dependency manifests are unchanged. Any claim in the updated playbook that contradicts the binary is, by construction, a defect in the playbook and not in the binary (the playbook's own self-anchoring statement is preserved verbatim at the bottom of the file).
- **No new operator-actionable surface.** Run 075 documents only flags and metrics that already exist in the Run 069/073/074 binary. Operators who follow the playbook trigger the SAME validation pipeline, the SAME apply ordering, the SAME rollback semantics, the SAME session-eviction behaviour, the SAME `/metrics` series, and the SAME log lines that the Run 069–074 integration tests and release-binary smokes already prove.
- **No removed open items.** Run 075 preserves every Run 050–074 fail-closed boundary verbatim (Run 050 schema, Run 051 signature, Run 053 chain_id, Run 055 anti-rollback, Run 057 activation-height, Run 061 local-leaf self-check, Run 062 per-entry revocation activation, Run 063 local-issuer-root self-check, Run 065 minimum-margin policy, Run 069 validation-only non-mutation, Run 070 apply ordering + rollback, Run 071 live handle write-lock atomicity, Run 072 session-eviction `attempted == evicted + failed` invariant, Run 073 production adapter, Run 074 CAS-serialized SIGHUP trigger + `Fatal`-only shutdown). Every previously-OPEN C4 boundary that is NOT closed by Runs 069–074 (peer-supplied / gossiped acceptance, admin-API / filesystem-watcher triggers, `activation_epoch` runtime source, selective per-peer session retention, KMS / HSM custody, signing-key on-chain ratification, fast-sync restore parity, per-environment trust-anchor operation, N-node MainNet peer-connection smoke) remains explicitly OPEN in the updated §10.
- **No `--p2p-trusted-root` fallback strengthened.** The updated playbook explicitly re-pins the Run 074 release-binary CLI top-level refusal of `--p2p-trust-bundle-live-reload-enabled` without `--p2p-trust-bundle <BASELINE-PATH>` and the §1.3 invariant that there is no implicit fallback to `--p2p-trusted-root` on the hot-reload paths.
- **No `Dummy*` primitive referenced.** Run 075 prose continues to require the Run 040 `dummy_kem_registered=false dummy_aead_registered=false` banner in every evidence bundle.

## 5. Test evidence

Run 075 changes no code and no test. The Run 074 evidence document (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md` §5.3) records the full regression suite passing at Run 074's commit, including every Run 050–074 unit + integration test family (Run 074 §5.3: `cargo test -p qbind-node --lib` 1004/1004; `cargo test -p qbind-net --lib` 17/17; `cargo test -p qbind-crypto --lib` 68/68; every Run 050–074 integration test 100% passing). Run 075 does not modify any test or any code path those tests exercise, so the Run 074 evidence transitively applies.

A `cargo check -p qbind-node --bin qbind-node` smoke confirms that the playbook docs change does not break the binary build (docs files are not pulled into the Rust compilation graph, but the check is recorded for transparency).

## 6. Operator-impact summary

After Run 075, an operator reading `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` for the first time learns:

1. The full Run 050–065 fail-closed boundaries (unchanged from Run 066).
2. The three local-operator hot-reload paths (Runs 069/073/074) — what each does, what each MUST NOT do, when to use each, what evidence to collect, and what the strict apply ordering is on every live-apply path.
3. The two hidden CLI flag pairs that arm process-start reload-apply (Run 073) and long-running SIGHUP live reload-apply (Run 074), the partial-config refusals each enforces at startup, and the precise log lines / metric series each emits.
4. The §6.F.5 ordering invariant (`validate → snapshot → swap → evict → commit`) and the four outcome variants (`Applied | AlreadyInProgress | Invalid | Fatal`) the Run 074 controller surfaces.
5. The refreshed §10 residual risks list, which now correctly identifies peer-supplied / gossiped acceptance, admin-API / filesystem-watcher triggers, selective per-peer session retention, and `activation_epoch` runtime sourcing as the precise remaining C4-OPEN items on the trust-bundle axis (NOT "hot reload" as a whole — the local-operator paths are landed).

## 7. Whitepaper contradiction narrowing record (C4)

Run 075 narrows C4 (`docs/whitepaper/contradiction.md`) by closing the prose-coverage gap for the local-operator hot-reload lifecycle landed by Runs 069–074. Full C4 and C5 remain OPEN. The Run 075 entry in `docs/whitepaper/contradiction.md` records:

- Documentation-only update of the Run 066 playbook.
- New §6.F covering the three local-operator hot-reload paths.
- Updated §1.3 invariants, §7 promotion checklist, §8 incident checklist, §9 evidence checklist, §10 residual risks, §11 mapping, §12 glossary.
- Zero runtime code / test / helper / Cargo.toml change.

What remains C4-OPEN after Run 075 (unchanged by this prose update):

- Peer-supplied / gossiped trust-bundle acceptance.
- Admin-API / filesystem-watcher hot-reload trigger surfaces.
- `activation_epoch` runtime sourcing.
- Selective per-peer session retention on live apply.
- KMS / HSM custody for bundle-signing keys.
- Bundle-signing-key on-chain / in-binary ratification.
- Fast-sync / consensus-storage restore parity for live apply.
- Per-environment production trust-anchor operation.
- N-node MainNet release-binary peer-connection smoke.