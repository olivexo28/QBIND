use crate::account::Account;
use crate::ExecutionError;
use qbind_types::AccountId;
use std::collections::HashMap;

/// Fixed-size failure categories for bounded account reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedReadError {
    /// The store does not implement a coherent bounded read.
    Unsupported,
    /// The account data exceeds the caller-supplied logical byte budget.
    Oversized,
    /// The backend could not materialize the admitted account.
    Backend,
}

/// Abstract account storage used by the execution engine.
/// Implementations can be in-memory (for tests) or persistent (for nodes).
pub trait AccountStore {
    /// Fetch an account by its AccountId.
    fn get(&self, id: &AccountId) -> Option<Account>;

    /// Fetch an account only if its data length is within `max_data_bytes`.
    ///
    /// Implementations must check the limit and materialize the returned
    /// account from one coherent read/version. The default intentionally does
    /// not fall back to `get`, since that could allocate an unbounded copy.
    fn get_bounded(
        &self,
        _id: &AccountId,
        _max_data_bytes: usize,
    ) -> Result<Option<Account>, BoundedReadError> {
        Err(BoundedReadError::Unsupported)
    }

    /// Insert or replace an account.
    fn put(&mut self, account: Account) -> Result<(), ExecutionError>;

    /// Remove an account.
    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError>;
}

/// Simple in-memory HashMap-backed account store for tests and local execution.
pub struct InMemoryAccountStore {
    inner: HashMap<AccountId, Account>,
}

impl InMemoryAccountStore {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
}

impl Default for InMemoryAccountStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountStore for InMemoryAccountStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.inner.get(id).cloned()
    }

    fn get_bounded(
        &self,
        id: &AccountId,
        max_data_bytes: usize,
    ) -> Result<Option<Account>, BoundedReadError> {
        let Some(account) = self.inner.get(id) else {
            return Ok(None);
        };
        if account.data.len() > max_data_bytes {
            return Err(BoundedReadError::Oversized);
        }

        materialize_account(account).map(Some)
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.inner.insert(account.id, account);
        Ok(())
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.inner.remove(id);
        Ok(())
    }
}

fn materialize_account(account: &Account) -> Result<Account, BoundedReadError> {
    #[cfg(test)]
    observe_materialization_boundary(account.data.len());

    let mut data = Vec::new();
    data.try_reserve_exact(account.data.len())
        .map_err(|_| BoundedReadError::Backend)?;
    data.extend_from_slice(&account.data);

    Ok(Account {
        id: account.id,
        header: account.header.clone(),
        data,
    })
}

#[cfg(test)]
thread_local! {
    static MATERIALIZATION_OBSERVER: std::cell::Cell<(usize, usize)> =
        std::cell::Cell::new((0, 0));
}

#[cfg(test)]
fn observe_materialization_boundary(requested_data_len: usize) {
    MATERIALIZATION_OBSERVER.with(|observer| {
        let (calls, _) = observer.get();
        observer.set((calls + 1, requested_data_len));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountHeader;
    use std::cell::Cell;

    fn account(id_byte: u8, data: Vec<u8>) -> Account {
        Account {
            id: [id_byte; 32],
            header: AccountHeader {
                owner: [id_byte.wrapping_add(1); 32],
                lamports: 0x0102_0304_0506_0708,
                is_executable: true,
                rent_epoch: 0x1112_1314_1516_1718,
                reserved: [id_byte.wrapping_add(2); 8],
            },
            data,
        }
    }

    fn observed_materializations() -> (usize, usize) {
        MATERIALIZATION_OBSERVER.with(Cell::get)
    }

    fn reset_materialization_observer() {
        MATERIALIZATION_OBSERVER.with(|observer| observer.set((0, 0)));
    }

    struct LegacyOnlyStore {
        get_calls: Cell<usize>,
        put_calls: Cell<usize>,
        delete_calls: Cell<usize>,
    }

    impl AccountStore for LegacyOnlyStore {
        fn get(&self, _id: &AccountId) -> Option<Account> {
            self.get_calls.set(self.get_calls.get() + 1);
            None
        }

        fn put(&mut self, _account: Account) -> Result<(), ExecutionError> {
            self.put_calls.set(self.put_calls.get() + 1);
            Ok(())
        }

        fn delete(&mut self, _id: &AccountId) -> Result<(), ExecutionError> {
            self.delete_calls.set(self.delete_calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn run422_bounded_account_read_default_is_unsupported_without_legacy_calls() {
        let mut store = LegacyOnlyStore {
            get_calls: Cell::new(0),
            put_calls: Cell::new(0),
            delete_calls: Cell::new(0),
        };
        let id = [1; 32];

        assert_eq!(store.get(&id), None);
        store.put(account(1, vec![])).unwrap();
        store.delete(&id).unwrap();
        assert_eq!(store.get_calls.get(), 1);
        assert_eq!(store.put_calls.get(), 1);
        assert_eq!(store.delete_calls.get(), 1);

        store.get_calls.set(0);
        store.put_calls.set(0);
        store.delete_calls.set(0);
        let object_safe_store: &dyn AccountStore = &store;
        assert_eq!(
            object_safe_store.get_bounded(&id, 0),
            Err(BoundedReadError::Unsupported)
        );
        assert_eq!(store.get_calls.get(), 0);
        assert_eq!(store.put_calls.get(), 0);
        assert_eq!(store.delete_calls.get(), 0);
    }

    #[test]
    fn run422_bounded_account_read_missing_and_zero_budget_semantics() {
        let store = InMemoryAccountStore::new();
        assert_eq!(store.get_bounded(&[9; 32], 0), Ok(None));
        assert_eq!(store.get(&[9; 32]), None);

        let mut store = store;
        let empty = account(2, Vec::new());
        store.put(empty.clone()).unwrap();
        assert_eq!(store.get_bounded(&empty.id, 0), Ok(Some(empty.clone())));
        assert_eq!(store.get(&empty.id), Some(empty));
    }

    #[test]
    fn run422_bounded_account_read_exact_limit_preserves_complete_account() {
        let mut store = InMemoryAccountStore::new();
        let expected = account(3, vec![0xA5; 12]);
        let id = expected.id;
        store.put(expected.clone()).unwrap();

        let result = store.get_bounded(&id, expected.data.len()).unwrap();
        assert_eq!(result, Some(expected.clone()));
        assert_eq!(store.get(&id), Some(expected));
    }

    #[test]
    fn run422_bounded_account_read_one_byte_over_limit_refuses() {
        let mut store = InMemoryAccountStore::new();
        let stored = account(4, vec![0x5A; 13]);
        let id = stored.id;
        store.put(stored.clone()).unwrap();

        assert_eq!(store.get_bounded(&id, 12), Err(BoundedReadError::Oversized));
        assert_eq!(store.get_bounded(&id, 0), Err(BoundedReadError::Oversized));
        assert_eq!(store.get(&id), Some(stored));
    }

    #[test]
    fn run422_bounded_account_read_ignores_source_spare_capacity() {
        let mut source_data = Vec::with_capacity(16 * 1024);
        source_data.extend_from_slice(b"bounded-data");
        let source_capacity = source_data.capacity();
        let expected_len = source_data.len();
        let mut store = InMemoryAccountStore::new();
        let stored = account(5, source_data);
        let id = stored.id;
        store.put(stored).unwrap();

        let result = store
            .get_bounded(&id, expected_len)
            .unwrap()
            .expect("stored account");
        assert_eq!(result.data.len(), expected_len);
        assert!(result.data.capacity() >= expected_len);
        assert!(result.data.capacity() < source_capacity);
        assert_eq!(result, store.get(&id).unwrap());
    }

    #[test]
    fn run422_bounded_account_read_returns_independent_owned_data() {
        let mut store = InMemoryAccountStore::new();
        let original = account(6, vec![1, 2, 3, 4]);
        let id = original.id;
        store.put(original.clone()).unwrap();

        let mut result = store.get_bounded(&id, 4).unwrap().unwrap();
        result.data[0] = 0xFF;
        result.header.reserved[0] = 0xEE;
        drop(result);

        assert_eq!(store.get(&id), Some(original));
    }

    #[test]
    fn run422_bounded_account_read_observes_refusal_before_materialization() {
        reset_materialization_observer();
        let mut store = InMemoryAccountStore::new();
        let stored = account(7, vec![0xCC; 32]);
        let id = stored.id;
        store.put(stored.clone()).unwrap();

        assert_eq!(store.get_bounded(&id, 31), Err(BoundedReadError::Oversized));
        assert_eq!(observed_materializations(), (0, 0));
        assert_eq!(store.get(&id), Some(stored.clone()));

        let returned = store.get_bounded(&id, 32).unwrap().unwrap();
        assert_eq!(returned, stored);
        assert_eq!(observed_materializations(), (1, 32));
        assert_eq!(store.get(&id), Some(stored));
    }

    #[test]
    fn run422_bounded_account_read_supported_through_trait_object() {
        let mut store = InMemoryAccountStore::new();
        let expected = account(8, vec![0x42; 5]);
        let id = expected.id;
        store.put(expected.clone()).unwrap();

        let object_safe_store: &dyn AccountStore = &store;
        assert_eq!(
            object_safe_store.get_bounded(&id, 5),
            Ok(Some(expected.clone()))
        );
        assert_eq!(store.get(&id), Some(expected));
    }
}
