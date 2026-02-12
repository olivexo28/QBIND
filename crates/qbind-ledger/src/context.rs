use crate::auth::verify_transaction_auth;
use crate::store::AccountStore;
use crate::ExecutionError;
use qbind_crypto::CryptoProvider;
use qbind_wire::tx::Transaction;
use std::sync::Arc;

/// Execution context for a single transaction or block.
/// Provides access to accounts and to cryptographic suites.
pub struct ExecutionContext<'a, S: AccountStore> {
    pub store: &'a mut S,
    pub crypto: Arc<dyn CryptoProvider>,
    /// M2: Minimum stake required for validator registration (in microQBIND).
    /// This parameter is enforced by the ValidatorProgram during registration.
    pub min_validator_stake: u64,
}

impl<'a, S: AccountStore> ExecutionContext<'a, S> {
    pub fn new(store: &'a mut S, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self {
            store,
            crypto,
            // Default: 0 for backwards compatibility with existing tests
            // Production code should use new_with_min_stake()
            min_validator_stake: 0,
        }
    }

    /// Create a new ExecutionContext with a specified minimum validator stake.
    ///
    /// # Arguments
    ///
    /// * `store` - The account store for reading/writing account state
    /// * `crypto` - The crypto provider for signature verification
    /// * `min_validator_stake` - Minimum stake required for validator registration
    pub fn new_with_min_stake(
        store: &'a mut S,
        crypto: Arc<dyn CryptoProvider>,
        min_validator_stake: u64,
    ) -> Self {
        Self {
            store,
            crypto,
            min_validator_stake,
        }
    }

    /// Verify all transaction auth entries against on-chain keyset accounts.
    pub fn verify_tx_auth(&mut self, tx: &Transaction) -> Result<(), ExecutionError> {
        verify_transaction_auth(self.store, self.crypto.clone(), tx)
    }
}
