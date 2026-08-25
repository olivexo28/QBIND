# QBIND Public DevNet — Peer Admission Policy (Run 360)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim.

This document defines the **peer-admission policy** for QBIND public DevNet, described only against
the **pre-existing** KEMTLS mutual-auth, PQC trust-root, and trust-bundle surfaces
(`crates/qbind-node/src/cli.rs`, `p2p_tcp.rs`, `pqc_trust_bundle.rs`, `p2p_inbound.rs`). Run 360
changes **no** peer-admission logic and adds **no** CLI flag. All flags below are pre-existing and
validated to appear in `qbind-node --help` (see `VERIFY.md`).

## 1. How a peer is admitted on public DevNet

Admission uses the **existing** KEMTLS handshake path. On an open public DevNet port, the intended
posture is:

1. The node binds a listener (`--p2p-listen-addr`) with `--enable-p2p true`.
2. On an inbound connection (or an outbound dial to a `--p2p-peer`), a **KEMTLS handshake** runs.
3. Under `--p2p-mutual-auth required`, the listener requires a v2 `ClientInit` carrying a **verified**
   client `NetworkDelegationCert`; the accepted-session identity is derived from the cert's
   `validator_id`, **not** from the dialer's self-asserted `client_random`.
4. The peer's certificate/root material is validated against the loaded trust anchors (from
   `--p2p-trust-bundle` and/or `--p2p-trusted-root`). If validation fails, the connection is
   **rejected** during the handshake.
5. Both sides must be bound to the **same genesis / chain / environment** (see §5). A node started
   with `--expect-genesis-hash` refuses to start against the wrong genesis before any peer is dialed.

Admission is therefore a function of: mutual-auth mode, PQC suite, trust-bundle/trust-root
validation, and genesis/chain/environment binding.

## 2. Mutual-auth mode expectations

- `--p2p-mutual-auth` accepts `required`, `optional`, `disabled` (plus aliases parsed by
  `parse_mutual_auth_mode`).
- It defaults to **`disabled`** to preserve pre-B12 test-grade DevNet behaviour. Also readable from
  `QBIND_MUTUAL_AUTH` (the env var only takes effect when the flag is unset).
- **Public DevNet posture:** an open public port should run `--p2p-mutual-auth required` so that
  inbound peers must present a verified `NetworkDelegationCert` and session identity is cert-derived.
  This matches the Run 357 seed-list placeholder's `transport_security_mode:
  "kemtls-mutual-auth-required"`.

## 3. PQC suite expectations

- `--p2p-pqc-root-mode` selects the PQC trust-root mode: `test-grade-dummy-sig` (DevNet-only
  DummySig; aliases `test-grade`/`dummy`/`test`) or `pqc-static-root` (production ML-DSA-44; aliases
  `pqc-static`/`pqc`/`static-root`).
- Production/root and bundle material use **suite ID 100 = ML-DSA-44**; the trust-bundle loader
  accepts only suite `100` and fails closed on any other suite.
- This matches the Run 357 seed-list placeholder's `pqc_suite: "ml-dsa-44"`.

## 4. Trust-bundle requirement expectations

- `--p2p-trust-bundle` supplies a PQC transport trust-anchor bundle (JSON). At load it is validated
  for: **environment binding**, per-root **validity windows** (`not_before`/`not_after`), **root
  status** (`active | retired | revoked`), an explicit **revocation list**, **suite ID**, and (for
  signed bundles) **signature**.
- `--p2p-trust-bundle-signing-key` supplies bundle-signing verification keys
  (`KEYID:SUITE:PK`, suite `100`), required for TestNet/MainNet when a bundle is supplied. On DevNet,
  an unsigned bundle is accepted; a signed bundle is verified against the configured keys.
- This matches the Run 357 seed-list placeholder's `trust_bundle_required: true`.

## 5. Genesis-hash / chain / environment binding expectations

- Every node pins the canonical genesis hash with `--expect-genesis-hash`
  (`0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f` for Run 356 DevNet); on
  mismatch the node **refuses to start** before any network/consensus start.
- The trust bundle carries a `TrustBundleEnvironment` (`devnet`/`testnet`/`mainnet`) that must match
  the runtime `--env`; a mismatched environment **fails closed** at load.
- The Run 357 seed list additionally carries `runtime_chain_id`
  (`0x51424E4444455600`), `genesis_hash`, and `genesis_file_sha256`, all of which must match the
  genesis a joining node verified.

## 6. Peer identity / certificate / root material expectations

- `--p2p-trusted-root` supplies trusted PQC transport root public keys
  (`ROOT_KEY_ID_HEX:SUITE:ROOT_PK_HEX`, suite `100`), repeatable; required for production
  `pqc-static-root` mode.
- `--p2p-leaf-cert` / `--p2p-leaf-cert-key` supply this node's `NetworkDelegationCert` and its KEM
  secret key (required under `--p2p-mutual-auth required` + `--p2p-pqc-root-mode pqc-static-root`).
  The secret-key file must be readable by `qbind-node` only and is **never** logged.
- `--p2p-peer-leaf-cert` (`VID:PATH`, repeatable) maps a peer's validator id to its leaf certificate
  under `pqc-static-root` mode.
- **No secret material is published** by this package; these flags describe where an operator points
  their **own** locally held material.

## 7. Failure behaviour

Admission **fails closed** in each of the following cases (rejection at handshake/load, no silent
acceptance):

| Condition | Behaviour |
|-----------|-----------|
| Wrong genesis | Node refuses to start under `--expect-genesis-hash` mismatch, before any peer contact. |
| Wrong chain | `runtime_chain_id` / genesis binding mismatch is rejected. |
| Wrong environment | Trust bundle whose `TrustBundleEnvironment` ≠ runtime `--env` fails closed at load. |
| Wrong trust root | Peer cert not chaining to a loaded trusted root is rejected during KEMTLS handshake. |
| Revoked leaf/root | A root marked `revoked` or listed in the bundle revocation list fails closed at load; a revoked peer is not admitted. |
| Malformed bundle | Strict parsing; any parse/validity/signature failure aborts startup with a typed error. |
| Untrusted peer | A peer that cannot present a verified `NetworkDelegationCert` under `required` mode is rejected. |
| Placeholder / non-live seed | The Run 357 placeholder host (`192.0.2.1`) is non-routable and must never be dialed; only `status: "live"` entries are admissible. |

## 8. Peer claims are advisory only

Any information a peer asserts about itself (self-reported identity, peer-candidate propagation,
claimed trust material) is **advisory only**. It does **not** bypass the local admission checks above
and does **not** bypass ratification: a peer cannot promote itself into any trusted set merely by
asserting membership. Local trust-root / trust-bundle validation is authoritative.

## 9. Peer-driven apply remains out of scope

Peer-driven trust-bundle **apply** (a peer causing a node to adopt new trust material) remains **out
of scope** for public DevNet admission. See
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`. This package documents admission
against locally configured trust anchors only; it does **not** enable peer-driven apply and changes
no such behaviour.

## 10. MainNet authority rotation/revocation remains Red

Nothing in this admission policy implies MainNet readiness. MainNet authority rotation/revocation
remains **Red**, Full **C4 remains OPEN**, and **C5 remains OPEN**. This policy governs public DevNet
peer admission only and makes no MainNet claim.

## 11. Operator identity material for admission (Run 374)

The KEMTLS leaf cert + trusted-root material a peer presents for admission under
`--p2p-mutual-auth required` / `--p2p-pqc-root-mode pqc-static-root` can be generated with the Run 374
operator identity package (`docs/release/public-devnet/identity/`). That package is
**generation/verification only**: it does **not** weaken admission (strict mutual-auth only tightens
it), change the peer-admission policy, alter the P2P wire format, or apply any trust bundle. A generated
identity that presents mismatched material fails admission closed exactly as before.