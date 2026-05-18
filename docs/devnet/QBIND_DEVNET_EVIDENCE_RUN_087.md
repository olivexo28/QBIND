# QBIND DevNet Evidence — Run 087

## Exact objective

Create a formal design-gate specification for peer-driven trust-bundle
propagation and apply safety before implementing peer-driven propagation or
peer-driven live apply. This run is documentation/specification-only unless a
real contradiction is discovered. It must not implement peer-driven apply,
propagation/rebroadcast, `activation_epoch`, KMS/HSM custody, signing-key
ratification, fast-sync restore, KEMTLS redesign, or consensus redesign.

## Exact verdict

**Strongest positive for the scoped Run 087 design/specification objective.**

- `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` created.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` updated with a short Run 087
  pointer preserving the current operating boundary.
- `docs/whitepaper/contradiction.md` updated with a C4 Run 087 note.
- This evidence file created.
- No contradictions were found.
- No source files were required or touched.
- Peer-candidate `0x05` remains validation-only.
- Full C4 and C5 remain open.

## Exact files changed

- `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` — new safety
  specification and design gate.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 087 pointer preserving
  validation-only `0x05`, local SIGHUP as the only running-node apply path, and
  future separately scoped implementation requirement.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_087.md` — this evidence document.
- `docs/whitepaper/contradiction.md` — C4 Run 087 note.

No `crates/**/src/**` source file was changed.

## Exact commands run

### Baseline build/type-check before edits

```text
cargo check -p qbind-node --bin qbind-node
```

### Required forbidden-guidance grep checks

```text
changed_lines() { { git --no-pager diff --unified=0 -- docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md docs/whitepaper/contradiction.md | grep '^+' | grep -v '^+++'; cat docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_087.md; } }
check_pipe() {
  name="$1"; shift
  out=$(changed_lines | bash -o pipefail -c "$*" || true)
  if [ -n "$out" ]; then printf '%s\n%s\n' "FAILED: $name" "$out"; exit 1; fi
  printf 'PASS: %s\n' "$name"
}
check_pipe 'no --p2p-trusted-root fallback recommendation' "grep -nE 'recommend|use|fallback' | grep -E -- '--p2p-trusted-root' | grep -viE 'MUST NOT|reject|rejects|rejected|refuse|forbidden|no .*fallback|never|unsafe|falls back|No recommendation|grep|no --p2p-trusted-root'"
check_pipe 'no DummySig/DummyKem/DummyAead recommendation' "grep -nE 'recommend|use|uses|using' | grep -E 'Dummy(Sig|Kem|Aead)' | grep -viE 'MUST NOT|reject|rejected|refuse|forbidden|no active|not|unsafe|production trust|No recommendation|grep|no unsafe'"
check_pipe 'no unsigned TestNet/MainNet bundle recommendation' "grep -nEi 'unsigned.*(testnet|mainnet)|(testnet|mainnet).*unsigned' | grep -viE 'MUST NOT|reject|rejected|refuse|fail closed|not accept|does not accept|forbidden|unsafe|No recommendation|grep'"
check_pipe 'no current peer-driven live apply implementation claim' "grep -nEi 'peer-driven.*(live )?apply.*(implemented|exists|today)|implemented.*peer-driven.*(live )?apply' | grep -viE 'not implemented|requires a future|future separately scoped|does not implement|before implementing|OPEN|No peer-driven|No claim|grep|no peer-driven live apply|not as a statement|statement that'"
check_pipe 'no current propagation implementation claim' "grep -nEi 'propagat(e|ion|ed|ing).*(implemented|exists|today)|implemented.*propagat(e|ion|ed|ing)' | grep -viE 'not implemented|requires a future|future separately scoped|does not implement|before implementing|Before any propagation|OPEN|no propagation|No propagation|if propagation is ever implemented|No claim|grep|not as a statement|statement that'"
check_pipe 'no peer candidate sequence burn guidance' "grep -nEi 'peer.*candidate.*sequence.*burn|sequence.*burn.*peer.*candidate|peer.*validation.*sequence.*(commit|burn|write)' | grep -viE 'MUST NOT|no sequence|no pre-apply|do not|does not|unsafe|reject|without|No sequence|No peer-candidate|grep|no sequence commit'"
check_pipe 'no peer-candidate 0x05 consensus-ratification treatment' "grep -nEi '0x05.*consensus ratification|consensus ratification.*0x05' | grep -viE 'MUST NOT|not|reject|unsafe|no consensus|No treatment|grep'"
```

### Final build/type-check

```text
cargo check -p qbind-node --bin qbind-node
```

## Checks pass/fail

| Check | Result |
|---|---|
| Baseline `cargo check -p qbind-node --bin qbind-node` before edits | **pass** |
| Forbidden-guidance grep 1 — no unsafe `--p2p-trusted-root` fallback recommendation | **pass** |
| Forbidden-guidance grep 2 — no unsafe DummySig/DummyKem/DummyAead recommendation | **pass** |
| Forbidden-guidance grep 3 — no unsigned TestNet/MainNet bundle recommendation | **pass** |
| Forbidden-guidance grep 4 — no claim peer-driven live apply is currently implemented | **pass** |
| Forbidden-guidance grep 5 — no claim propagation is currently implemented | **pass** |
| Forbidden-guidance grep 6 — no peer-candidate sequence burn guidance | **pass** |
| Forbidden-guidance grep 7 — no `0x05` consensus-ratification treatment | **pass** |
| Final `cargo check -p qbind-node --bin qbind-node` | **pass** |

The cargo check emits two pre-existing deprecation warnings in
`crates/qbind-node/src/binary_consensus_loop.rs` for `bincode::config`; no Run
087 source changes are involved.

## Investigation findings

- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` already documents the Run
  076–085 peer-candidate `0x05` lifecycle as validation-only: no apply, no
  propagation, no sequence write, no live trust mutation, and no session
  eviction. Run 087 adds the future-design-gate pointer without changing that
  boundary.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md` through Run 075 document the
  local operator lifecycle: validation-only reload-check, process-start local
  reload-apply, SIGHUP live reload-apply, session eviction, and sequence commit
  ordering.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_076.md` through Run 086 document the
  peer-candidate validation-only lifecycle and its N=2 DevNet / N=4 MainNet
  evidence.
- `docs/whitepaper/contradiction.md` keeps C4 and C5 open; Run 087 only adds a
  safety-spec note and does not claim closure.
- Reference code inspection found the same boundaries: `pqc_trust_reload.rs`
  validates local candidates without mutation; `pqc_live_trust_reload.rs` drives
  SIGHUP local apply; `pqc_live_trust_apply.rs` preserves
  `validate -> snapshot -> swap -> evict -> commit`; `pqc_live_trust.rs` holds
  the live trust snapshot; `p2p_session_eviction.rs` provides the evict-all hook;
  `pqc_trust_peer_candidate.rs` and `pqc_peer_candidate_wire.rs` are
  validation-only and bounded; `p2p_tcp.rs`, `p2p_node_builder.rs`, `main.rs`,
  `cli.rs`, and `metrics.rs` expose disabled-by-default peer-candidate surfaces
  and metrics without apply/propagation authority.

## Design decisions

- The new safety specification is explicitly future-facing and design-gate only.
- Peer authority is advisory only unless a future ratification mechanism exists.
- The candidate lifecycle allows current peer receive to reach only
  `ObservedOnly`.
- Propagation requires validation-before-rebroadcast, duplicate suppression,
  rate limiting, loop prevention, no apply side effect, no sequence commit, no
  session eviction, clear metrics, and per-peer abuse handling.
- Peer-driven apply requires a separate authority model, local policy approval,
  signing-key ratification or equivalent authority, rollback handling, session
  eviction policy, post-swap sequence commit, fail-closed behavior, and evidence
  capture.

## Contradictions found or not found

**None found.** The docs and reference code agree that current peer-candidate
`0x05` behavior is validation-only. No runtime code change was required.

## Remaining open C4/C5 items

- **C4-OPEN:** peer-driven live apply / propagation implementation.
- **C4-OPEN:** `activation_epoch` runtime source.
- **C4-OPEN:** KMS/HSM custody.
- **C4-OPEN:** in-binary / on-chain signing-key ratification.
- **C4-OPEN:** production fast-sync / consensus-storage restore parity.
- **C4-OPEN:** per-environment production trust-anchor operation.
- **C5-OPEN / narrowed:** timeout-verification activation, forged-traffic
  rejection, transport-root dependency, and broader production KEMTLS lifecycle
  remain tracked outside Run 087.
- **C4/C5 full closure:** not claimed.

## Exact immediate next action

Use `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` as the design
gate for any future peer-driven propagation/apply run. The next implementation
run should address only one explicitly scoped gate, starting with propagation
without apply side effects or, separately, the missing authority/ratification
model for peer-driven apply.