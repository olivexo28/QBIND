use crate::hash::sha3_256_tagged;
use qbind_types::Hash32;
use qbind_wire::io::{len_to_u16, put_bytes, put_u16, put_u64, put_u8};
use qbind_wire::net::{NetworkDelegationCert, CERT_TYPE_NETWORK_DELEGATION};

/// Compute the canonical digest for a NetworkDelegationCert according to the spec.
/// This is what the root network key signs.
pub fn network_delegation_cert_digest(cert: &NetworkDelegationCert) -> Hash32 {
    let mut out = Vec::new();

    // cert_type and version
    put_u8(&mut out, CERT_TYPE_NETWORK_DELEGATION);
    put_u8(&mut out, cert.version);

    // validator_id, root_key_id
    put_bytes(&mut out, &cert.validator_id);
    put_bytes(&mut out, &cert.root_key_id);

    // leaf_kem_suite_id and reserved1
    put_u8(&mut out, cert.leaf_kem_suite_id);
    put_u8(&mut out, 0); // reserved1

    // leaf_pk_len + leaf_kem_pk
    let leaf_pk_len = cert.leaf_kem_pk.len();
    let leaf_pk_len_u16 = len_to_u16(leaf_pk_len);
    put_u16(&mut out, leaf_pk_len_u16);
    put_bytes(&mut out, &cert.leaf_kem_pk);

    // not_before, not_after
    put_u64(&mut out, cert.not_before);
    put_u64(&mut out, cert.not_after);

    // ext_len + ext_bytes
    let ext_len = cert.ext_bytes.len();
    let ext_len_u16 = len_to_u16(ext_len);
    put_u16(&mut out, ext_len_u16);
    put_bytes(&mut out, &cert.ext_bytes);

    sha3_256_tagged("QBIND:NETCERT", &out)
}

/// Domain tag for NodeId derivation (M7).
pub const NODEID_DOMAIN_TAG: &str = "QBIND:nodeid:v1";

/// Domain tag for inbound session identifier (M7).
///
/// This is used for server-side inbound connections where the client's
/// cryptographic identity cannot be derived from the KEMTLS handshake alone.
/// The session identifier provides uniqueness but is NOT cryptographically
/// bound to the client's identity.
pub const INBOUND_SESSION_DOMAIN_TAG: &str = "QBIND:inbound:session:v1";

/// Derive a NodeId from a NetworkDelegationCert (M7).
///
/// The NodeId is cryptographically bound to the peer's KEMTLS identity by
/// hashing the canonical cert bytes with a domain-separated SHA3-256.
///
/// # Formula
///
/// ```text
/// node_id = sha3_256("QBIND:nodeid:v1" || canonical_cert_bytes)
/// ```
///
/// # Arguments
///
/// * `cert` - The peer's NetworkDelegationCert from the KEMTLS handshake
///
/// # Returns
///
/// A 32-byte NodeId derived deterministically from the certificate.
pub fn derive_node_id_from_cert(cert: &NetworkDelegationCert) -> Hash32 {
    // Build canonical cert bytes (same encoding as network_delegation_cert_digest
    // but including the signature for full binding)
    let mut out = Vec::new();

    // cert_type and version
    put_u8(&mut out, CERT_TYPE_NETWORK_DELEGATION);
    put_u8(&mut out, cert.version);

    // validator_id, root_key_id
    put_bytes(&mut out, &cert.validator_id);
    put_bytes(&mut out, &cert.root_key_id);

    // leaf_kem_suite_id and reserved1
    put_u8(&mut out, cert.leaf_kem_suite_id);
    put_u8(&mut out, 0); // reserved1

    // leaf_pk_len + leaf_kem_pk
    let leaf_pk_len = cert.leaf_kem_pk.len();
    let leaf_pk_len_u16 = len_to_u16(leaf_pk_len);
    put_u16(&mut out, leaf_pk_len_u16);
    put_bytes(&mut out, &cert.leaf_kem_pk);

    // not_before, not_after
    put_u64(&mut out, cert.not_before);
    put_u64(&mut out, cert.not_after);

    // ext_len + ext_bytes
    let ext_len = cert.ext_bytes.len();
    let ext_len_u16 = len_to_u16(ext_len);
    put_u16(&mut out, ext_len_u16);
    put_bytes(&mut out, &cert.ext_bytes);

    // sig_suite_id, reserved2, sig_len + sig_bytes (full cert binding)
    put_u8(&mut out, cert.sig_suite_id);
    put_u8(&mut out, 0); // reserved2
    let sig_len = cert.sig_bytes.len();
    let sig_len_u16 = len_to_u16(sig_len);
    put_u16(&mut out, sig_len_u16);
    put_bytes(&mut out, &cert.sig_bytes);

    sha3_256_tagged(NODEID_DOMAIN_TAG, &out)
}

/// Derive a NodeId from a raw KEM public key (M7).
///
/// This is an alternative derivation when the full cert is not available,
/// such as when only the public key bytes are known.
///
/// # Formula
///
/// ```text
/// node_id = sha3_256("QBIND:nodeid:v1" || kem_public_key_bytes)
/// ```
///
/// # Arguments
///
/// * `kem_pk` - The peer's KEM public key bytes
///
/// # Returns
///
/// A 32-byte NodeId derived deterministically from the public key.
pub fn derive_node_id_from_pubkey(kem_pk: &[u8]) -> Hash32 {
    sha3_256_tagged(NODEID_DOMAIN_TAG, kem_pk)
}