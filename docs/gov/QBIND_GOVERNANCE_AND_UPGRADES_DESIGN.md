# QBIND Governance & Upgrades Design v1

**Task**: T224  
**Status**: Design Specification  
**Date**: 2026-02-08

---

## Table of Contents

1. [Objectives & Threat Model](#1-objectives--threat-model)
2. [Governance Model for MainNet v0](#2-governance-model-for-mainnet-v0)
3. [Upgrade Classes and Processes](#3-upgrade-classes-and-processes)
4. [Upgrade Envelope & Versioning Model](#4-upgrade-envelope--versioning-model)
5. [Upgrade Rollout Process](#5-upgrade-rollout-process)
6. [Failure Modes & Mitigations](#6-failure-modes--mitigations)
7. [Roadmap to On-Chain Governance](#7-roadmap-to-on-chain-governance)
8. [Related Documents](#8-related-documents)

---

## 1. Objectives & Threat Model

### 1.1 Objectives

The QBIND governance and upgrade model is designed to achieve the following goals:

| Objective | Description |
| :--- | :--- |
| **Controlled Upgrades** | All protocol upgrades must follow a documented, auditable process with clear approval authority. |
| **Fail-Safe Operations** | Upgrades must be reversible or fail gracefully; no single action should cause irreversible chain damage. |
| **Multi-Party Approval** | No single individual or key can unilaterally change the protocol (minimizes "single-key failure" risk). |
| **Emergency Response** | Security vulnerabilities (including PQC-related) can be patched quickly with abbreviated but still-controlled processes. |
| **Audit Transparency** | External auditors can verify upgrade history, approval records, and change provenance. |
| **Future Extensibility** | The v0 off-chain model must be compatible with future on-chain governance modules. |

### 1.2 Threat Model

The governance system must defend against the following threat categories:

#### 1.2.1 Governance Key Compromise

| Threat | Description | Severity |
| :--- | :--- | :--- |
| **Single council key compromise** | Attacker gains control of one council member's PQC signing key | High |
| **Threshold key compromise** | Attacker gains control of M or more council keys | Critical |
| **Backup key exposure** | Council key backups leaked or improperly secured | High |

**Mitigations**:
- M-of-N multi-signature requirement (no single key can approve upgrades)
- Council keys held on HSMs or hardware wallets with PQC support
- Geographic and organizational distribution of council members
- Key rotation schedule for council keys (annual or upon member change)
- Separate emergency response keys with higher threshold

#### 1.2.2 Rogue Upgrade (Malicious Insider)

| Threat | Description | Severity |
| :--- | :--- | :--- |
| **Unauthorized code insertion** | Developer inserts malicious code into release | Critical |
| **Binary tampering** | Release binary modified after council approval | Critical |
| **Supply chain attack** | Dependency compromised with malicious code | High |

**Mitigations**:
- Multiple code reviewers required for all consensus-affecting changes
- Reproducible builds with published build instructions
- Council signs specific binary hashes, not just version numbers
- Dependency audit and pinning (Cargo.lock)
- TestNet Beta soak period before MainNet deployment

#### 1.2.3 Operator Misconfiguration Leading to Chain Splits

| Threat | Description | Severity |
| :--- | :--- | :--- |
| **Premature upgrade** | Operator upgrades before activation height/epoch | High |
| **Missed upgrade** | Operator fails to upgrade; runs incompatible version | High |
| **Wrong configuration** | Operator sets incorrect flags (e.g., wrong `dag_coupling_mode`) | High |

**Mitigations**:
- Clear communication channels for upgrade announcements
- Activation height encoded in binary (not just configuration)
- Node startup validation against expected protocol version
- Runbook checklists for upgrade procedures
- Monitoring/alerting for version mismatches across validator set

#### 1.2.4 Failure to Coordinate Upgrade

| Threat | Description | Severity |
| :--- | :--- | :--- |
| **Persistent minority chain** | Significant stake remains on old version | High |
| **Communication failure** | Upgrade announcement not received by all operators | Medium |
| **Activation timing dispute** | Disagreement on when upgrade activates | Medium |

**Mitigations**:
- Long activation windows (weeks, not hours) for non-emergency upgrades
- Multiple communication channels (email, Discord, governance forum, on-chain signal)
- Soft-fork where possible (old nodes can still follow new chain)
- Version mismatch metrics and alerting

---

## 2. Governance Model for MainNet v0

### 2.1 Off-Chain Governance Overview

**MainNet v0 governance is explicitly off-chain and social + multi-sig**, not on-chain. This is a deliberate design choice for v0:

| Aspect | MainNet v0 Approach |
| :--- | :--- |
| **Decision Making** | Off-chain deliberation via governance forum, calls, and async discussion |
| **Approval Mechanism** | M-of-N PQC multi-signature by Protocol Council |
| **Enforcement** | Social consensus + operator compliance |
| **Audit Trail** | Signed documents published to governance repository |

**Rationale**: On-chain governance introduces significant complexity and attack surface. For v0, a well-documented off-chain process with cryptographic accountability provides equivalent security while allowing rapid iteration on governance processes before codifying them on-chain.

### 2.2 Protocol Council

The **Protocol Council** is the governing body for MainNet v0 upgrades. Council responsibilities include:

| Responsibility | Description |
| :--- | :--- |
| **Approve Protocol Versions** | Sign off on new releases before MainNet deployment |
| **Authorize Hard Forks** | Approve changes to consensus rules, block format, or monetary policy |
| **Approve Emergency Patches** | Fast-track security fixes with abbreviated review |
| **Mediate Disputes** | Resolve disagreements on upgrade timing or parameters |
| **Maintain Upgrade Envelope Registry** | Publish and archive signed upgrade envelopes |

### 2.3 Council Composition

| Parameter | MainNet v0 Value | Rationale |
| :--- | :--- | :--- |
| **Total Members (N)** | 7 | Odd number prevents ties; large enough for diversity |
| **Approval Threshold (M)** | 5 | Supermajority (≥70%) required for protocol changes |
| **Emergency Threshold** | 4 | Slightly lower for time-critical security fixes |
| **Term Length** | 2 years | Balances continuity with rotation |
| **Diversity Requirement** | Min 3 distinct organizations | No single org controls majority |

**Council Member Requirements**:
- Must hold a PQC signing key (ML-DSA-44) on HSM or equivalent secure hardware
- Must be reachable via secure communication channel
- Must commit to 48-hour response SLA for emergency votes
- Must disclose conflicts of interest

### 2.4 Cryptographic Requirements

Council approvals use **PQC signatures** consistent with the QBIND cryptographic suite:

| Algorithm | Usage | Reference |
| :--- | :--- | :--- |
| **ML-DSA-44** | Signing upgrade envelopes and approvals | [FIPS 204](https://csrc.nist.gov/publications/detail/fips/204/final) |
| **SHAKE256** | Hashing upgrade envelope contents | Standard |

**Upgrade Envelope Signature Format**:
```
envelope_hash = SHAKE256(envelope_json)
signature = ML-DSA-44.Sign(council_member_private_key, envelope_hash)
```

**Multi-Signature Aggregation** (v0 approach):
- Individual signatures are collected and concatenated
- Verification requires checking each signature and confirming ≥M are valid
- Future enhancement: threshold signature scheme for compactness

### 2.5 Council Key Management

Council members MUST follow key management practices equivalent to MainNet validator requirements:

| Requirement | Description |
| :--- | :--- |
| **Key Storage** | HSM-backed or equivalent hardware security |
| **Key Backup** | Secure offline backup with documented recovery procedure |
| **Key Rotation** | Annual rotation or upon suspected compromise |
| **Emergency Key** | Separate key for emergency-only use with higher accountability |

See [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) for detailed key management practices.

---

## 3. Upgrade Classes and Processes

### 3.1 Upgrade Classification

All QBIND upgrades are classified into three classes based on their impact on the network:

| Class | Description | Examples | Coordination Required |
| :--- | :--- | :--- | :--- |
| **Class A** | Non-consensus changes | CLI tooling, observability, documentation, test infrastructure | None |
| **Class B** | Consensus-compatible upgrades | Performance improvements, internal refactoring that doesn't change wire format or block validity | Rolling deployment |
| **Class C** | Hard-fork / protocol changes | Consensus rules, block format, monetary policy, P2P wire protocol | Coordinated activation |

### 3.2 Class A: Non-Consensus Upgrades

**Definition**: Changes that do not affect consensus, block validity, or network interoperability.

**Examples**:
- CLI user experience improvements
- Logging and metrics additions
- Documentation updates
- Internal code refactoring (no API changes)
- Test harness improvements

**Approval Process**:

| Step | Action | Responsible Party |
| :--- | :--- | :--- |
| 1 | Code review and merge to main | Maintainers (2+ approvals) |
| 2 | CI passes (tests, lints, clippy) | Automated |
| 3 | Release tagged and published | Release manager |
| 4 | Changelog updated | Release manager |

**Council Involvement**: Not required. Class A changes are approved by maintainers through standard code review.

**Operator Action**: Optional. Operators may upgrade at their convenience.

**Rollback Process**:
- Revert to previous binary
- No chain coordination required

### 3.3 Class B: Consensus-Compatible Upgrades

**Definition**: Changes that improve node behavior but do not alter consensus rules, block format, or P2P wire protocol.

**Examples**:
- Performance optimizations to VM execution
- Improved parallel scheduling algorithms
- Mempool policy changes that don't affect block validity
- P2P connection management improvements
- Database backend optimizations

**Distinguishing Characteristic**: A node running version N can interoperate with a node running version N+1 without consensus divergence.

**Approval Process**:

| Step | Action | Responsible Party |
| :--- | :--- | :--- |
| 1 | Code review and merge to main | Maintainers (2+ approvals) |
| 2 | CI passes | Automated |
| 3 | Deploy to DevNet | Engineering |
| 4 | Deploy to TestNet Beta | Engineering |
| 5 | Soak period on Beta (min 1 week) | Engineering + Operators |
| 6 | Council signs Upgrade Envelope | Protocol Council (M-of-N) |
| 7 | Release tagged and published | Release manager |
| 8 | Operators upgrade (rolling) | Operators |

**Council Involvement**: Required. Council signs an Upgrade Envelope confirming the release has passed testing.

**Operator Action**: Rolling deployment. Operators may upgrade at their convenience within a reasonable window (typically 2 weeks).

**Rollback Process**:
- Revert to previous binary
- No chain coordination required (consensus-compatible)

### 3.4 Class C: Hard-Fork / Protocol Changes

**Definition**: Changes that alter consensus rules, block format, monetary policy, or P2P wire protocol in ways that make old and new nodes incompatible.

**Examples**:
- New transaction types or payload formats
- Changes to gas costs or fee calculations
- Modifications to HotStuff consensus parameters
- Cryptographic suite updates (e.g., new PQC algorithm)
- Block header format changes
- Monetary policy parameter changes (inflation rate, phase transitions)
- DAG coupling mode changes

**Distinguishing Characteristic**: A node running version N will reject blocks from version N+1 (or vice versa) without explicit activation.

**Approval Process**:

| Step | Action | Responsible Party |
| :--- | :--- | :--- |
| 1 | Design RFC published | Engineering |
| 2 | Community review period (min 2 weeks) | All stakeholders |
| 3 | Code review and merge to main | Maintainers (2+ approvals) |
| 4 | CI passes | Automated |
| 5 | Deploy to DevNet | Engineering |
| 6 | Chaos harness testing (T222) | Engineering |
| 7 | Deploy to TestNet Beta | Engineering |
| 8 | Stage B soak harness testing (T223) | Engineering |
| 9 | Beta soak period (min 4 weeks) | Engineering + Operators |
| 10 | Council signs Upgrade Envelope with activation height | Protocol Council (M-of-N) |
| 11 | Operators upgrade and configure activation | Operators |
| 12 | Activation at specified height/epoch | Automatic |

**Council Involvement**: Required. Council signs an Upgrade Envelope specifying:
- Target protocol version
- Activation height or epoch
- Backward compatibility notes
- Emergency rollback procedure (if any)

**Operator Action**: Coordinated. All operators MUST upgrade before activation height. Post-activation, non-upgraded nodes will fork off.

**Rollback Process**:
- **Pre-activation**: Revert to previous binary; no issues
- **Post-activation**: Coordinated rollback required; council must sign a revert Upgrade Envelope; significant coordination

---

## 4. Upgrade Envelope & Versioning Model

### 4.1 Protocol Version Envelope

An **Upgrade Envelope** is a signed document that represents Council approval for a specific protocol version. It serves as the authoritative record for upgrade decisions.

**Envelope Structure** (JSON format):

```json
{
  "envelope_version": "1.0",
  "envelope_id": "T224-2026-02-08-001",
  "upgrade_class": "C",
  "protocol_version": {
    "major": 0,
    "minor": 1,
    "patch": 0
  },
  "binary_hashes": {
    "linux-x86_64": "sha3-256:<hash>",
    "linux-aarch64": "sha3-256:<hash>",
    "darwin-aarch64": "sha3-256:<hash>"
  },
  "activation": {
    "type": "height",
    "value": 1000000,
    "estimated_time": "2026-03-15T12:00:00Z"
  },
  "features": {
    "stage_b_enabled": true,
    "dag_coupling_mode": "enforce",
    "monetary_version": 1
  },
  "backward_compatibility": {
    "min_compatible_version": "0.0.9",
    "requires_data_migration": false
  },
  "references": {
    "rfc": "https://github.com/qbind/rfcs/blob/main/RFC-001-example.md",
    "testnet_report": "https://github.com/qbind/testnet-reports/blob/main/2026-02-beta-soak.md",
    "changelog": "https://github.com/qbind/qbind/releases/tag/v0.1.0"
  },
  "council_approvals": [
    {
      "member_id": "council-1",
      "public_key": "<ml-dsa-44-public-key>",
      "signature": "<ml-dsa-44-signature>",
      "timestamp": "2026-02-08T10:00:00Z"
    },
    {
      "member_id": "council-2",
      "public_key": "<ml-dsa-44-public-key>",
      "signature": "<ml-dsa-44-signature>",
      "timestamp": "2026-02-08T11:30:00Z"
    }
  ],
  "created_at": "2026-02-08T09:00:00Z",
  "notes": "MainNet v0.1.0 introduces Stage B parallel execution and DAG coupling enforcement."
}
```

### 4.2 Protocol Versioning Model

QBIND uses **semantic versioning** (major.minor.patch) with the following interpretation:

| Version Component | Interpretation | Upgrade Class |
| :--- | :--- | :--- |
| **Major** | Breaking consensus changes, fundamental protocol redesign | Class C |
| **Minor** | Protocol changes requiring coordinated activation | Class C |
| **Patch** | Bug fixes, performance improvements, consensus-compatible | Class B |

**Version → Feature Mapping**:

Each protocol version is associated with a specific feature set. The Upgrade Envelope explicitly lists feature flags:

| Feature | Description | Introduced |
| :--- | :--- | :--- |
| `stage_b_enabled` | Stage B parallel execution available | v0.1.0 |
| `dag_coupling_mode` | DAG–consensus coupling enforcement level | v0.1.0 |
| `monetary_version` | Monetary policy version (phase gates, parameters) | v0.1.0 |
| `payload_v1_required` | TransferPayloadV1 required (v0 rejected) | v0.1.0 |

### 4.3 Operator Version Pinning

MainNet v0 operators MUST:

1. **Pin to a specific binary version** matching a Council-approved Upgrade Envelope
2. **Use `--profile mainnet`** to enforce MainNet invariants
3. **Verify binary hash** against the signed Upgrade Envelope before deployment

**Version Verification Command** (example):
```bash
# Verify binary hash
sha3-256 /usr/local/bin/qbind-node
# Compare against envelope binary_hashes.linux-x86_64

# Verify envelope signatures (hypothetical CLI)
qbind-envelope verify \
  --envelope /etc/qbind/upgrade-envelope-v0.1.0.json \
  --council-keys /etc/qbind/council-pubkeys.json
```

**Upgrade Authorization**:

Operators should only upgrade when:
1. A signed Upgrade Envelope exists for the target version
2. The envelope has ≥M valid council signatures
3. The release has passed TestNet Beta soak
4. The operator has reviewed the changelog and runbook updates

---

## 5. Upgrade Rollout Process

### 5.1 Class C Upgrade (Hard-Fork) Step-by-Step

This section provides the detailed process for a Class C upgrade from initial design through MainNet activation.

#### Phase 1: Design & Specification

| Step | Action | Output | Duration |
| :--- | :--- | :--- | :--- |
| 1.1 | Author publishes Design RFC | RFC document in governance repo | - |
| 1.2 | Community review period | Comments, objections, refinements | 2+ weeks |
| 1.3 | RFC accepted or revised | Final RFC version | - |

#### Phase 2: Implementation & Testing

| Step | Action | Output | Duration |
| :--- | :--- | :--- | :--- |
| 2.1 | Implementation PRs merged | Code in main branch | Variable |
| 2.2 | Deploy to DevNet | DevNet running new code | 1-2 days |
| 2.3 | DevNet testing | Bug fixes, refinements | 1+ week |
| 2.4 | Run chaos harness (T222) | Chaos test report | 1-2 days |
| 2.5 | Deploy to TestNet Beta | Beta running new code | 1-2 days |
| 2.6 | Run Stage B soak harness (T223) | Soak test report | 1-2 days |
| 2.7 | Beta soak period | Metrics, operator feedback | 4+ weeks |

#### Phase 3: Approval & Preparation

| Step | Action | Output | Duration |
| :--- | :--- | :--- | :--- |
| 3.1 | Prepare Upgrade Envelope | Draft envelope JSON | 1 day |
| 3.2 | Council review period | Council feedback | 1 week |
| 3.3 | Council members sign envelope | Signed Upgrade Envelope | 1-3 days |
| 3.4 | Publish signed envelope | Envelope in governance repo | 1 day |
| 3.5 | Announce upgrade to operators | Email, Discord, forum post | 1 day |

#### Phase 4: Deployment & Activation

| Step | Action | Output | Duration |
| :--- | :--- | :--- | :--- |
| 4.1 | Operators download and verify binary | Binary on validator hosts | - |
| 4.2 | Operators update configuration | Config files updated | - |
| 4.3 | Operators upgrade nodes (rolling) | New binary running | 1-2 weeks |
| 4.4 | Monitor version metrics | Dashboard shows version distribution | Ongoing |
| 4.5 | Activation height reached | Protocol change active | - |
| 4.6 | Post-activation monitoring | Consensus health, no forks | 48+ hours |

### 5.2 Emergency Security Patch Process

For critical security vulnerabilities (e.g., PQC algorithm weakness, consensus bug), an abbreviated process is available:

| Step | Action | Output | Duration |
| :--- | :--- | :--- | :--- |
| 1 | Security team identifies vulnerability | Private disclosure | - |
| 2 | Fix developed and reviewed (private branch) | Patched code | 1-7 days |
| 3 | Council emergency meeting | Emergency approval (4-of-7) | < 24 hours |
| 4 | Emergency Upgrade Envelope signed | Signed envelope | < 24 hours |
| 5 | Private disclosure to operators | Advance notice to validators | 24-48 hours |
| 6 | Public release and announcement | Binary + envelope published | - |
| 7 | Operators upgrade ASAP | Patched nodes running | < 48 hours |

**Emergency Process Constraints**:
- Lower threshold (4-of-7 instead of 5-of-7)
- Abbreviated testing (may skip full Beta soak)
- Documented justification required (why emergency process was necessary)
- Post-incident review within 2 weeks

### 5.3 Pre-Upgrade Checklist for Operators

Before applying any Council-approved upgrade:

- [ ] **Verify Upgrade Envelope** is signed by ≥M council members
- [ ] **Verify binary hash** matches envelope `binary_hashes`
- [ ] **Review changelog** and release notes
- [ ] **Review runbook updates** (if any)
- [ ] **Backup current state** (snapshot)
- [ ] **Run pre-release tests** on staging/test validator:
  - [ ] Chaos harness passes (T222)
  - [ ] Stage B soak passes (T223)
- [ ] **Verify configuration** matches expected profile (`--profile mainnet`)
- [ ] **Verify activation height** (for Class C upgrades) matches envelope
- [ ] **Notify team** of planned upgrade window
- [ ] **Monitor dashboards** during and after upgrade

### 5.4 Emergency Downgrade Procedure

If a post-upgrade issue is detected:

**For Class A/B (consensus-compatible)**:
1. Stop node: `systemctl stop qbind-node`
2. Restore previous binary: `mv /usr/local/bin/qbind-node.backup /usr/local/bin/qbind-node`
3. Start node: `systemctl start qbind-node`
4. Monitor metrics for normal operation

**For Class C (post-activation)**:
1. **Do NOT unilaterally downgrade** — this will fork you off the network
2. **Report issue** to Council and engineering team immediately
3. **Wait for coordinated response** (emergency rollback envelope or hotfix)
4. If Council approves rollback:
   - Follow Emergency Security Patch Process in reverse
   - Activation height for rollback specified in rollback envelope

---

## 6. Failure Modes & Mitigations

### 6.1 Split Brain (Partial Upgrade)

**Scenario**: Some operators upgrade and activate, others do not; chain splits.

**Detection**:
- `qbind_consensus_fork_detected` metric increases
- Block hash divergence at or after activation height
- Reduced validator participation on both forks

**Immediate Response**:
1. **Identify fork point**: Query multiple validators for block at activation height
2. **Determine canonical chain**: Chain with supermajority (>2/3) stake is canonical
3. **Contact non-upgraded validators**: Direct communication to upgrade ASAP
4. **Monitor convergence**: Watch for validators rejoining canonical chain

**Post-Mortem Actions**:
- Review communication channels (why were some operators not reached?)
- Extend activation windows for future upgrades
- Implement better version mismatch alerting

**Mitigation (Preventive)**:
- Long activation windows (2+ weeks for non-emergency)
- Multiple communication channels
- Version mismatch alerting before activation
- "Feature flag" approach where possible (soft fork)

### 6.2 Council Key Compromise

**Scenario**: Attacker gains control of M or more council signing keys.

**Detection**:
- Unexpected Upgrade Envelope published
- Council members report unauthorized signatures
- Binary with unknown hash approved

**Immediate Response**:
1. **Freeze**: Do not deploy any envelopes signed after suspected compromise
2. **Verify**: Contact all council members to confirm recent signatures
3. **Revoke**: Publish council key revocation notice
4. **Rotate**: Generate new council keys, update envelope verification tooling

**Post-Mortem Actions**:
- Investigate compromise vector
- Review council key management practices
- Consider increasing threshold or council size

**Mitigation (Preventive)**:
- HSM-backed council keys
- Geographic and organizational distribution
- Regular key rotation
- Multi-factor authentication for signing ceremonies

### 6.3 Incompatible Configuration

**Scenario**: Operator sets wrong configuration flags (e.g., wrong `dag_coupling_mode` or missing required flag).

**Detection**:
- Node fails `validate_mainnet_invariants()` at startup
- Node produces blocks that other validators reject
- `qbind_dag_coupling_validation_failed_total` metric increases

**Immediate Response**:
1. **Check startup logs**: Look for invariant validation failures
2. **Compare configuration**: Diff against known-good config
3. **Fix configuration**: Apply correct flags from runbook
4. **Restart node**: `systemctl restart qbind-node`

**Post-Mortem Actions**:
- Update runbook with clearer configuration guidance
- Add more specific error messages for misconfiguration
- Consider config validation CLI tool

**Mitigation (Preventive)**:
- `validate_mainnet_invariants()` blocks startup on misconfiguration
- Runbook checklists for configuration verification
- Configuration examples in Upgrade Envelopes

### 6.4 Binary Tampering / Supply Chain Attack

**Scenario**: Released binary contains malicious code not in signed Upgrade Envelope.

**Detection**:
- Binary hash does not match envelope `binary_hashes`
- Reproducible build produces different hash
- Unexpected behavior observed in node logs

**Immediate Response**:
1. **Do NOT deploy** the tampered binary
2. **Report** to security team and Council
3. **Verify** binary hash against envelope
4. **Obtain** verified binary from trusted source (reproduce from source if needed)

**Post-Mortem Actions**:
- Investigate tampering vector (build server, CDN, etc.)
- Strengthen build pipeline security
- Implement multiple independent build attestations

**Mitigation (Preventive)**:
- Reproducible builds
- Binary hashes in signed Upgrade Envelopes
- Multiple independent build servers
- CDN integrity verification

---

## 7. Roadmap to On-Chain Governance

### 7.1 On-Chain Governance Vision

MainNet v0 uses off-chain governance as a deliberate starting point. Future versions will migrate selected governance functions on-chain:

| Phase | Governance Scope | Timeline |
| :--- | :--- | :--- |
| **v0** | Off-chain council + multi-sig envelopes | Current |
| **v0.x** | On-chain upgrade signaling (validators signal readiness) | 6-12 months |
| **v1.0** | On-chain parameter governance (subset of parameters) | 12-18 months |
| **v1.x** | Full on-chain governance with voting | 18-24 months |

### 7.2 Planned On-Chain Governance Components

The following components are planned for future implementation:

| Component | Description | Target Version |
| :--- | :--- | :--- |
| **UpgradeSignalModule** | Validators signal readiness for pending upgrades | v0.x |
| **SuiteRegistry** | On-chain registry of supported cryptographic suites | v1.0 |
| **ParameterGovernance** | Stake-weighted voting on tunable parameters | v1.0 |
| **ProposalModule** | On-chain proposals with voting periods | v1.x |
| **TreasuryGovernance** | On-chain treasury allocation decisions | v1.x |

### 7.3 Migration Path

The v0 off-chain governance model is designed to be compatible with on-chain migration:

| v0 Concept | On-Chain Equivalent |
| :--- | :--- |
| Upgrade Envelope | On-chain UpgradeProposal transaction |
| Council multi-sig | Stake-weighted validator voting |
| Activation height | On-chain upgrade block with automatic activation |
| Feature flags | On-chain feature registry |

**Transition Strategy**:
1. Implement on-chain upgrade signaling alongside off-chain envelopes
2. Require both on-chain supermajority signal AND council envelope for Class C upgrades
3. Gradually shift authority from council envelope to on-chain voting
4. Deprecate off-chain envelopes once on-chain governance is mature

### 7.4 Future Tasks (T23x+)

| Task | Description | Dependencies |
| :--- | :--- | :--- |
| **T230** | On-chain upgrade signaling module | T224 (this task) |
| **T231** | On-chain SuiteRegistry | T230 |
| **T232** | Parameter governance module | T230 |
| **T233** | Integration with key-management (key rotation via governance) | T231, T213 |
| **T234** | Monetary policy governance integration | T232, T194 |

---

## 8. Related Documents

| Document | Path | Description |
| :--- | :--- | :--- |
| **MainNet v0 Spec** | [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) | MainNet architecture |
| **MainNet Audit** | [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) | Risk tracking |
| **MainNet Runbook** | [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) | Operational procedures |
| **Key Management Design** | [QBIND_KEY_MANAGEMENT_DESIGN.md](../keys/QBIND_KEY_MANAGEMENT_DESIGN.md) | Key architecture (T209) |
| **Monetary Policy Design** | [QBIND_MONETARY_POLICY_DESIGN.md](../econ/QBIND_MONETARY_POLICY_DESIGN.md) | Monetary policy (T194) |
| **TestNet Beta Spec** | [QBIND_TESTNET_BETA_SPEC.md](../testnet/QBIND_TESTNET_BETA_SPEC.md) | Beta specification |
| **Consensus Chaos Harness** | `t222_consensus_chaos_harness.rs` | Chaos testing (T222) |
| **Stage B Soak Harness** | `t223_stage_b_soak_harness.rs` | Soak testing (T223) |

---

*End of Document*