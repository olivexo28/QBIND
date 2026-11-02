use qbind_ledger::{AccountStore, ExecutionContext, ExecutionError, Program};
use qbind_types::ProgramId;
use qbind_wire::io::WireDecode;
use qbind_wire::keyset::{CreateKeysetCall, OP_KEYSET_CREATE};
use qbind_wire::tx::Transaction;

pub use qbind_types::KEYSET_PROGRAM_ID;

pub struct KeysetProgram;

impl KeysetProgram {
    pub fn new() -> Self {
        KeysetProgram
    }

    pub fn id() -> ProgramId {
        KEYSET_PROGRAM_ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_ledger::InMemoryAccountStore;

    #[test]
    fn run422_keyset_program_id_shared_constant_preserves_both_methods() {
        let shared: ProgramId = qbind_types::KEYSET_PROGRAM_ID;
        assert_eq!(shared, [0x4B; 32]);
        assert_eq!(KEYSET_PROGRAM_ID, shared);
        assert_eq!(KeysetProgram::id(), shared);
        assert_eq!(
            <KeysetProgram as Program<InMemoryAccountStore>>::id(&KeysetProgram::new()),
            shared
        );
    }
}

impl Default for KeysetProgram {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_err(label: &'static str) -> ExecutionError {
    ExecutionError::InvalidCallData(label)
}

fn unavailable_authority() -> ExecutionError {
    ExecutionError::ProgramError("native keyset creation authority unavailable")
}

impl<S: AccountStore> Program<S> for KeysetProgram {
    fn id(&self) -> ProgramId {
        KEYSET_PROGRAM_ID
    }

    fn execute(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        if tx.program_id != KEYSET_PROGRAM_ID {
            return Err(ExecutionError::ProgramError(
                "program_id mismatch for KeysetProgram",
            ));
        }
        if tx.call_data.is_empty() {
            return Err(ExecutionError::InvalidCallData("empty call_data"));
        }

        match tx.call_data[0] {
            OP_KEYSET_CREATE => self.handle_create(ctx, tx),
            _ => Err(ExecutionError::ProgramError("unsupported keyset opcode")),
        }
    }
}

impl KeysetProgram {
    fn handle_create<S: AccountStore>(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let call = CreateKeysetCall::decode(&mut input)
            .map_err(|_| decode_err("invalid CreateKeysetCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData(
                "extra bytes after CreateKeysetCall",
            ));
        }

        // Ensure account does not yet exist.
        if ctx.store.get(&call.target_id).is_some() {
            return Err(ExecutionError::ProgramError(
                "keyset account already exists",
            ));
        }

        Err(unavailable_authority())
    }
}
