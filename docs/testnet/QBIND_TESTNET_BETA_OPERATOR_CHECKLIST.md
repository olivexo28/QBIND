# QBIND TestNet Beta Operator Checklist

**Version**: 1.0  
**Date**: 2026-05-03  
**Status**: Canonical Internal Operator Checklist — TestNet Beta  
**Audience**: Validator-candidate operators, Beta coordinators, internal SRE / ops, incident-triage support personnel, and (optionally) integrators running critical Beta-facing infrastructure

---

## 1. Purpose and Scope

This document is the **canonical internal operator checklist for QBIND TestNet Beta**.

Its sole purpose is to make Beta participation **operationally consistent, auditable, and aligned with Beta goals** as defined in the canonical Beta plan and Beta economics scope.

**What this document is:**
- A practical, internal, operator-facing checklist
- A reviewable artifact used by Beta coordinators to confirm that operators are running Beta with the expected discipline
- A source of structured evidence that feeds the Beta evidence packet

**What this document is NOT:**
- It is **not** a public guide or marketing document
- It is **not** a MainNet validator onboarding document
- It is **not** a MainNet readiness checklist
- It does **not** authorize MainNet participation
- It does **not** imply any MainNet allocation, redemption, presale, airdrop, priority, or other rights
- It does **not** override canonical protocol behavior or release sequencing

**Canonical protocol behavior remains defined by:**
- `docs/whitepaper/QBIND_WHITEPAPER.md`
- `docs/protocol/QBIND_PROTOCOL_REPORT.md`
- `docs/protocol/QBIND_M_SERIES_COVERAGE.md`
- `docs/whitepaper/contradiction.md`

**Release sequencing remains governed by:**
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md`

**Beta execution posture remains governed by:**
- `docs/testnet/QBIND_TESTNET_BETA_PLAN.md`
- `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md`

If any item in this checklist appears to conflict with the documents above, **the canonical documents win**. This checklist only operationalizes those documents for Beta operators.

---

## 2. Relationship to Beta Plan and MainNet Readiness

This checklist is a **subordinate instrument** to:

- `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` — defines Beta scope, posture, participants, and policy
- `docs/economics/QBIND_BETA_ECONOMICS_SCOPE.md` — defines Beta economics dry-run posture
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` — defines the gates between Beta and MainNet

How they relate:

- **This checklist operationalizes Beta participation.** It turns Beta plan policy into concrete, repeatable operator actions.
- **Evidence produced through disciplined checklist use feeds the Beta evidence packet.** Logs, incident notes, upgrade records, and chain-health observations gathered while following this checklist are exactly the inputs Beta coordinators need.
- **This checklist is not itself a MainNet-readiness checklist.** Passing this checklist does not certify MainNet readiness; that determination is governed exclusively by `QBIND_MAINNET_READINESS_CHECKLIST.md`.
- **However, poor Beta operator discipline can directly block MainNet readiness later.** Missing logs, untracked incidents, undisciplined upgrades, or silent anomalies during Beta degrade the evidence base used for MainNet readiness assessment. Operators should treat this checklist as upstream of MainNet readiness, even though it does not certify it.

---

## 3. Who Should Use This Checklist

This checklist is intended for:

- **Validator-candidate operators** participating in Beta in preparation for potential MainNet validator candidacy
- **Beta coordinators** running Beta operations, change management, upgrades, and incident response
- **Internal SRE / ops participants** running core Beta infrastructure on behalf of the project
- **Support personnel** assisting with incident triage, log collection, and operator follow-up
- *(Optional)* **Integrators** running critical Beta-facing infrastructure (e.g., RPC endpoints, indexers, bridges-in-test) when their operational posture materially affects Beta evidence

Casual users, end-users of test wallets, or read-only observers are **not** the audience for this checklist.

---

## 4. Pre-Participation Checklist

Complete every item before joining Beta as an operator.

- [ ] Operator has **read** `QBIND_TESTNET_BETA_PLAN.md` end to end.
- [ ] Operator has **read** `QBIND_BETA_ECONOMICS_SCOPE.md` and understands it is draft / evidence-only.
- [ ] Operator has reviewed `QBIND_RELEASE_TRACK_SPEC.md` to understand where Beta sits in the release sequence.
- [ ] Operator understands Beta is **non-MainNet** and **non-economic**.
- [ ] Operator understands **no allocation, redemption, presale, airdrop, or priority rights** are created by Beta participation.
- [ ] Operator understands Beta tokens / balances / keys carry **no monetary value** and **no claim**.
- [ ] Operator knows the official **communication channels** used by Beta coordinators.
- [ ] Operator knows the official **incident escalation channel(s)** and contact protocol.
- [ ] Operator has reviewed and can meet the **minimum hardware, network, and uptime** expectations published for Beta.
- [ ] Operator is prepared to meet **Beta uptime and discipline expectations** (Beta is not a casual sandbox).
- [ ] Operator agrees **not to run modified binaries** unless explicitly coordinated with Beta coordinators.
- [ ] Operator agrees to **report anomalies honestly** and not silently work around them.
- [ ] Operator has confirmed they are authorized (where applicable) to participate on behalf of their organization.

---

## 5. Environment and Artifact Verification Checklist

Complete before the node ever starts on Beta.

- [ ] Confirmed correct **Beta network identifier** (chain-id / network name) per Beta plan.
- [ ] Confirmed correct **genesis file** and any Beta-specific configuration artifacts.
- [ ] Verified **binary version** matches the version published for the current Beta phase.
- [ ] Verified binary **checksum** against the published value.
- [ ] Verified binary **signature** where applicable.
- [ ] Confirmed **bootstrap / seed peers** match the Beta-published list.
- [ ] Confirmed the node will **not** accidentally connect to **DevNet**, **Alpha**, or any environment labelled MainNet.
- [ ] Confirmed time synchronization (NTP / chrony) is configured and healthy.
- [ ] Confirmed local environment (OS, kernel, container runtime, file descriptors, disk layout) matches the required Beta posture.
- [ ] Confirmed no leftover state from previous environments (Alpha / DevNet / prior Beta resets) is being reused unintentionally.

---

## 6. Key Handling and Signer Checklist

- [ ] Validator / signer keys used in Beta are **freshly generated for Beta** and unique to this environment.
- [ ] Keys are **not reused** from DevNet, Alpha, personal wallets, or any external system.
- [ ] Key material is stored with appropriate **local protection** (filesystem permissions, encryption at rest where applicable).
- [ ] Key backups, if any, are stored securely and access is limited to authorized personnel.
- [ ] **Signer mode** matches the mode published for Beta (e.g., local signer, remote signer, KMS, or other coordinated configuration). Operators do not silently substitute a different signer mode.
- [ ] Operator knows the **rotation procedure** in the event of suspected key compromise.
- [ ] Operator knows the **compromise reporting** procedure and the relevant escalation channel.
- [ ] Validator keys are **not casually copied** between hosts, laptops, containers, or shared drives.
- [ ] Operator understands that Beta participation does **not** confer MainNet-grade rights, identity reuse, or validator status carryover.

> Note: This checklist does not require HSM use unless explicitly required by canonical Beta documentation. Operators should follow whatever signer posture Beta coordinators have published — no more, no less.

---

## 7. Node Bring-Up Checklist

Run sequentially. Do not skip steps even if they appear obvious.

- [ ] Configuration files loaded and validated.
- [ ] Storage / data directory initialized (or correctly carried over) per documented procedure.
- [ ] Process **starts cleanly** with no fatal errors.
- [ ] **Startup logs reviewed** for warnings or errors (not just success messages).
- [ ] Node successfully **joins the Beta network** (handshakes complete, identity registered).
- [ ] Node begins **syncing / catching up** to the current Beta tip.
- [ ] Sync **completes** within an expected time window for Beta.
- [ ] **Health endpoints / metrics endpoints** are reachable locally and (where applicable) by coordinators.
- [ ] **Validator state** (if a validator) is visible as expected (e.g., in validator set, voting, or queued per Beta policy).
- [ ] No unexpected restart loops, panics, or repeated reconnections.

---

## 8. Peering and Network Health Checklist

Verify continuously, not just at startup.

- [ ] All published **bootstrap / seed peers reachable** from the node.
- [ ] Node has reached and sustains a **healthy peer count** consistent with Beta guidance.
- [ ] No **persistent handshake failures** with known-good peers.
- [ ] No indicators of a **persistent network partition** affecting this node.
- [ ] **Peer churn** is reviewed periodically and is within reasonable bounds.
- [ ] **Latency / connectivity issues** that materially affect peering are escalated promptly.
- [ ] Firewall / NAT / port configuration verified and not silently dropping P2P traffic.
- [ ] Operator does **not** quietly hard-pin to a tiny number of friendly peers as a workaround for an unreported peering problem.

---

## 9. Consensus and Chain-Health Checklist

This section is critical. Operators must **actively verify** chain health, not assume it.

- [ ] **Block / commit progress** is observed continuously.
- [ ] **No unexplained stalls** in block production or commits.
- [ ] **Finality / commit lag** is within the posture expected for Beta.
- [ ] **Validator participation** (signing / voting) is visible as expected for this node and the network.
- [ ] **Slashing or evidence anomalies** are noticed promptly and escalated.
- [ ] Operator can **distinguish a local node issue from a network-wide issue** (e.g., is only this node falling behind, or is the chain itself stalled?).
- [ ] Operator does **not** silently assume "it'll catch up" when commit progress is degraded.
- [ ] Operator preserves logs and metrics covering any consensus anomaly window for later review.

---

## 10. Economics and Beta-Policy Awareness Checklist

This section aligns operators with `QBIND_BETA_ECONOMICS_SCOPE.md`. None of these are MainNet commitments.

- [ ] Operator acknowledges Beta economics are **draft and evidence-only**.
- [ ] Operator acknowledges issuance, fees, and rewards observed in Beta are **not MainNet commitments** and may change.
- [ ] Operator acknowledges any **minimum stake** value used in Beta is **Beta policy only**, not a MainNet promise.
- [ ] Operator acknowledges the **C3 (or equivalent) posture in Beta is Beta policy only** and may differ from any future MainNet posture.
- [ ] Operator acknowledges the Beta **test asset has no value, no claim, no redemption, and no convertibility**.
- [ ] Operator does **not** publicly market, trade, or advertise Beta balances as having value.
- [ ] Operator can **surface economics anomalies** (e.g., reward miscounts, fee surprises, unexpected balance changes, parameter behavior that doesn't match the scope) to Beta coordinators.
- [ ] Operator records economics-related observations with enough context to be useful as evidence (timestamps, heights, addresses, observed vs expected behavior).

---

## 11. Upgrade and Maintenance Checklist

For every Beta upgrade or maintenance event.

- [ ] Operator has **received and acknowledged** the upgrade / maintenance notice through official channels.
- [ ] Operator has verified the **target version, artifacts, checksums, and signatures** for the upgrade.
- [ ] **Maintenance window** (start, expected duration, expected impact) is understood.
- [ ] Operator has confirmed any **pre-upgrade state requirements** (snapshots, backups, halt heights, etc.).
- [ ] Upgrade is executed **in the documented order** and at the documented time.
- [ ] **Post-upgrade health** is checked: process up, peers reconnected, sync resumed or maintained, validator participation restored if applicable.
- [ ] Operator knows the **rollback / escalation path** if the upgrade fails or behaves unexpectedly.
- [ ] Operator does **not** improvise version skips, custom flags, or out-of-order upgrades without coordination.
- [ ] Operator records the upgrade outcome (start time, end time, issues, mitigations) in a form usable as evidence.

---

## 12. Incident Reporting and Escalation Checklist

Aligned with the Beta plan's incident model.

- [ ] Operator knows the defined **incident categories** used in Beta (operator issue, software defect, protocol/safety concern, infrastructure issue, economics-policy issue, security concern).
- [ ] Operator can **classify** an observed issue into the right category, or flag it as ambiguous.
- [ ] Operator reports incidents **quickly**, with logs, timestamps, version, and relevant context.
- [ ] Operator distinguishes:
  - operator / local environment issue
  - software defect
  - protocol or safety concern
  - infrastructure issue (network, hosting, time sync, etc.)
  - economics-policy issue
- [ ] Operator does **not silently ignore** anomalies, even if they appear minor.
- [ ] Operator records, at minimum: **time observed**, **symptoms**, **affected components**, **attempted mitigations**, **current status**.
- [ ] Operator follows up on incidents until they are resolved or formally closed by coordinators.
- [ ] Operator does not publicly disclose unresolved security / safety concerns outside the coordinated channel.

---

## 13. Restart / Recovery Checklist

- [ ] **Planned restarts** follow a documented procedure (graceful shutdown, signal handling, verified clean exit).
- [ ] After a **crash**, operator collects logs and core/state evidence **before** wiping or aggressively retrying.
- [ ] Post-restart: process up, configuration unchanged unless intentionally changed, signer reattached.
- [ ] **Resync / catch-up** verified: node is making forward progress and converges to the Beta tip.
- [ ] **Post-restart peer health** verified (peer count, no persistent handshake failures).
- [ ] **Post-restart consensus health** verified (commits observed, validator participation restored if applicable).
- [ ] Operator escalates **instead of repeatedly retrying** when:
  - the node fails to start or stay up across multiple attempts,
  - the node cannot catch up,
  - the node repeatedly diverges, panics, or corrupts state,
  - or any anomaly recurs after restart.
- [ ] Repeated recovery issues are treated as **important evidence**, not noise. They are reported even if the operator eventually recovered locally.

---

## 14. Ongoing Operator Discipline Checklist

These are recurring expectations for the duration of Beta participation.

- [ ] **Monitor node health** continuously (process, resources, disk, descriptors, errors).
- [ ] **Monitor peer health** (peer count, connectivity, churn).
- [ ] **Watch commit progress** and finality / commit lag.
- [ ] **Respond to coordinator notices** in a timely manner via the official channels.
- [ ] Maintain **logs and metrics** with sufficient retention to support post-hoc analysis.
- [ ] **Report anomalies honestly**, including operator mistakes — Beta is an evidence stage, not a performance review.
- [ ] **Do not treat Beta as a casual sandbox.** Beta posture is intentionally near-production.
- [ ] **Preserve evidence** that may be useful for the Beta evidence packet and downstream MainNet readiness assessment.
- [ ] Periodically re-read the Beta plan and this checklist as they are updated.

---

## 15. Beta Exit / Handover Checklist

When Beta ends, resets, or an operator's participation concludes.

- [ ] Provide any **requested logs, metrics, and incident notes** to Beta coordinators.
- [ ] Confirm **any unresolved issues** are documented and handed off, not silently closed.
- [ ] Confirm **validator shutdown / transition steps** are followed if Beta ends or is reset (e.g., signer stopped, keys retired or rotated per coordinator guidance).
- [ ] Confirm operator holds **no assumption of state, identity, or position carryover** to MainNet.
- [ ] Confirm operator holds **no expectation of rights, allocations, redemption, or priority** arising from Beta participation.
- [ ] Securely retire or rotate **Beta-only key material** as instructed.
- [ ] Confirm any contact / role changes have been communicated to Beta coordinators.

---

## 16. Explicit Non-Rights / Non-Claims Notice

This section is intentionally explicit and must be acknowledged by every operator.

- Beta participation **creates no MainNet rights** of any kind.
- Beta participation creates **no allocation, redemption, presale, airdrop, priority, whitelisting, or pre-registration** rights.
- Beta keys, Beta balances, Beta validator status, and Beta participation history **do not imply MainNet status, MainNet validator candidacy, or MainNet eligibility**.
- Beta tokens / test assets carry **no value, no claim, and no convertibility**.
- This checklist is **operational only**. It is not a contract, not an offer, and not an invitation to invest.
- Any future MainNet authorization, validator selection, or economic policy is governed exclusively by canonical MainNet documents (notably `QBIND_MAINNET_READINESS_CHECKLIST.md` and the canonical protocol and release-track documents), and not by this checklist or by Beta participation.

---

## 17. Final Checklist Summary

Before each Beta phase, and on a recurring basis during Beta, every operator should be able to answer **yes** to all of the following:

- [ ] I have read and understood the Beta plan, Beta economics scope, and this checklist.
- [ ] My environment, artifacts, and signer posture match published Beta requirements.
- [ ] My node is healthy: it starts cleanly, peers correctly, and tracks consensus.
- [ ] I monitor node, peer, and chain health continuously and act on anomalies.
- [ ] I follow the documented upgrade and maintenance procedure without improvisation.
- [ ] I report incidents quickly, classify them honestly, and preserve evidence.
- [ ] I treat restarts and recoveries as evidence, not as noise to be suppressed.
- [ ] I acknowledge that Beta is non-economic and creates no MainNet rights.
- [ ] I am preserving logs, metrics, and notes that can be handed to Beta coordinators on request.
- [ ] I understand that poor Beta discipline can degrade MainNet readiness evidence later, even though this checklist does not certify MainNet readiness.

If any answer is **no**, the operator should pause, remediate, and — when in doubt — escalate to Beta coordinators before continuing.

---

*End of QBIND TestNet Beta Operator Checklist.*