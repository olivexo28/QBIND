//! Core EVM-related types for QBIND execution layer.
//!
//! This module defines the fundamental types needed for EVM execution,
//! including addresses, 256-bit integers, and account state representations.

use std::collections::HashMap;
use std::fmt;

/// 20-byte Ethereum-compatible address.
///
/// Used for EVM accounts (EOAs and contracts).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Create a zero address.
    pub const fn zero() -> Self {
        Address([0u8; 20])
    }

    /// Create an address from a 20-byte array.
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    /// Create an address from a slice. Panics if slice is not 20 bytes.
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Address(bytes)
    }

    /// Get the underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(0x")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }
}

impl From<Address> for [u8; 20] {
    fn from(addr: Address) -> Self {
        addr.0
    }
}

/// 256-bit unsigned integer for EVM values (balances, storage, etc.).
///
/// Stored as big-endian 32-byte array for consistency with EVM semantics.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
pub struct U256(pub [u8; 32]);

impl U256 {
    /// Create a zero value.
    pub const fn zero() -> Self {
        U256([0u8; 32])
    }

    /// Create from a u64 value.
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        U256(bytes)
    }

    /// Create from a u128 value.
    pub fn from_u128(value: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[16..32].copy_from_slice(&value.to_be_bytes());
        U256(bytes)
    }

    /// Create from a 32-byte big-endian array.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        U256(bytes)
    }

    /// Create from a byte slice. Panics if slice is longer than 32 bytes.
    /// Pads with leading zeros if shorter.
    pub fn from_slice(slice: &[u8]) -> Self {
        assert!(slice.len() <= 32, "U256 slice too long");
        let mut bytes = [0u8; 32];
        let offset = 32 - slice.len();
        bytes[offset..].copy_from_slice(slice);
        U256(bytes)
    }

    /// Get the underlying big-endian bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if value is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Attempt to convert to u64. Returns None if value exceeds u64::MAX.
    pub fn to_u64(&self) -> Option<u64> {
        // Check that leading 24 bytes are zero
        for &b in &self.0[0..24] {
            if b != 0 {
                return None;
            }
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.0[24..32]);
        Some(u64::from_be_bytes(bytes))
    }

    /// Attempt to convert to u128. Returns None if value exceeds u128::MAX.
    pub fn to_u128(&self) -> Option<u128> {
        // Check that leading 16 bytes are zero
        for &b in &self.0[0..16] {
            if b != 0 {
                return None;
            }
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.0[16..32]);
        Some(u128::from_be_bytes(bytes))
    }

    /// Checked subtraction. Returns None on underflow.
    pub fn checked_sub(&self, other: &U256) -> Option<U256> {
        let mut result = [0u8; 32];
        let mut borrow: u16 = 0;
        for i in (0..32).rev() {
            let a = self.0[i] as u16;
            let b = other.0[i] as u16 + borrow;
            if a < b {
                result[i] = (256 + a - b) as u8;
                borrow = 1;
            } else {
                result[i] = (a - b) as u8;
                borrow = 0;
            }
        }
        if borrow != 0 {
            None
        } else {
            Some(U256(result))
        }
    }

    /// Checked addition. Returns None on overflow.
    pub fn checked_add(&self, other: &U256) -> Option<U256> {
        let mut result = [0u8; 32];
        let mut carry: u16 = 0;
        for i in (0..32).rev() {
            let sum = self.0[i] as u16 + other.0[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }
        if carry != 0 {
            None
        } else {
            Some(U256(result))
        }
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U256(0x")?;
        // Skip leading zeros for readability
        let mut started = false;
        for byte in &self.0 {
            if *byte != 0 || started {
                write!(f, "{:02x}", byte)?;
                started = true;
            }
        }
        if !started {
            write!(f, "0")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        let mut started = false;
        for byte in &self.0 {
            if *byte != 0 || started {
                write!(f, "{:02x}", byte)?;
                started = true;
            }
        }
        if !started {
            write!(f, "0")?;
        }
        Ok(())
    }
}

/// EVM account state representation.
///
/// Captures the state of an account as needed for EVM execution:
/// - Balance (in wei-equivalent)
/// - Nonce (transaction count for EOAs, creation count for contracts)
/// - Code (bytecode for contract accounts, empty for EOAs)
/// - Storage (key-value mapping for contract state)
#[derive(Clone, Debug, Default)]
pub struct EvmAccountState {
    /// Account balance in the smallest unit.
    pub balance: U256,

    /// Transaction nonce for EOAs, or code version for contracts.
    pub nonce: u64,

    /// EVM bytecode (empty for EOAs).
    pub code: Vec<u8>,

    /// Contract storage slots (256-bit key → 256-bit value).
    pub storage: HashMap<U256, U256>,
}

impl EvmAccountState {
    /// Create a new empty account (zero balance, zero nonce, no code).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an EOA with the given balance.
    pub fn with_balance(balance: U256) -> Self {
        EvmAccountState {
            balance,
            nonce: 0,
            code: Vec::new(),
            storage: HashMap::new(),
        }
    }

    /// Create a contract account with given code and balance.
    pub fn with_code(code: Vec<u8>, balance: U256) -> Self {
        EvmAccountState {
            balance,
            nonce: 1, // Contract accounts start with nonce 1
            code,
            storage: HashMap::new(),
        }
    }

    /// Check if this is a contract account (has code).
    pub fn is_contract(&self) -> bool {
        !self.code.is_empty()
    }

    /// Check if this is an empty account (no balance, no nonce, no code).
    pub fn is_empty(&self) -> bool {
        self.balance.is_zero() && self.nonce == 0 && self.code.is_empty()
    }

    /// Get a storage value, returning zero if not set.
    pub fn get_storage(&self, key: &U256) -> U256 {
        self.storage.get(key).copied().unwrap_or(U256::zero())
    }

    /// Set a storage value.
    pub fn set_storage(&mut self, key: U256, value: U256) {
        if value.is_zero() {
            self.storage.remove(&key);
        } else {
            self.storage.insert(key, value);
        }
    }
}

/// Log entry produced during EVM execution.
///
/// Corresponds to Ethereum LOG0-LOG4 opcodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    /// Address of the contract that emitted the log.
    pub address: Address,

    /// Indexed topics (0-4).
    pub topics: Vec<U256>,

    /// Non-indexed log data.
    pub data: Vec<u8>,
}

impl LogEntry {
    /// Create a new log entry.
    pub fn new(address: Address, topics: Vec<U256>, data: Vec<u8>) -> Self {
        LogEntry {
            address,
            topics,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_creation() {
        let zero = Address::zero();
        assert_eq!(zero.0, [0u8; 20]);

        let bytes: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let addr = Address::from_bytes(bytes);
        assert_eq!(addr.as_bytes(), &bytes);
    }

    #[test]
    fn test_address_display() {
        let addr = Address::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ]);
        let s = format!("{}", addr);
        assert_eq!(s, "0x123456789abcdef0112233445566778899aabbcc");
    }

    #[test]
    fn test_u256_creation() {
        let zero = U256::zero();
        assert!(zero.is_zero());

        let from_u64 = U256::from_u64(0x1234567890abcdef);
        assert_eq!(from_u64.to_u64(), Some(0x1234567890abcdef));

        let from_u128 = U256::from_u128(0x123456789abcdef0123456789abcdef0);
        assert_eq!(
            from_u128.to_u128(),
            Some(0x123456789abcdef0123456789abcdef0)
        );
    }

    #[test]
    fn test_u256_arithmetic() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(30);

        let sum = a.checked_add(&b).unwrap();
        assert_eq!(sum.to_u64(), Some(130));

        let diff = a.checked_sub(&b).unwrap();
        assert_eq!(diff.to_u64(), Some(70));

        // Test underflow
        assert!(b.checked_sub(&a).is_none());
    }

    #[test]
    fn test_evm_account_state() {
        let mut account = EvmAccountState::with_balance(U256::from_u64(1000));
        assert!(!account.is_contract());
        assert!(!account.is_empty());

        account.set_storage(U256::from_u64(1), U256::from_u64(42));
        assert_eq!(account.get_storage(&U256::from_u64(1)).to_u64(), Some(42));

        // Setting to zero removes the key
        account.set_storage(U256::from_u64(1), U256::zero());
        assert!(account.get_storage(&U256::from_u64(1)).is_zero());
    }

    #[test]
    fn test_log_entry() {
        let addr = Address::from_bytes([1u8; 20]);
        let topics = vec![U256::from_u64(0xdead), U256::from_u64(0xbeef)];
        let data = vec![1, 2, 3, 4];
        let log = LogEntry::new(addr, topics.clone(), data.clone());
        assert_eq!(log.address, addr);
        assert_eq!(log.topics, topics);
        assert_eq!(log.data, data);
    }
}
