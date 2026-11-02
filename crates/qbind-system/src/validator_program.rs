use qbind_ledger::{AccountStore, ExecutionContext, ExecutionError, Program};
use qbind_types::{AccountId, ProgramId};
use qbind_wire::io::WireDecode;
use qbind_wire::tx::Transaction;
use qbind_wire::validator::{RegisterValidatorCall, OP_REGISTER_VALIDATOR};

/// Hard-coded ProgramId for the validator system program (placeholder for now).
pub const VALIDATOR_PROGRAM_ID: ProgramId = [0x56; 32]; // 'V'

// ============================================================================
// M2: Validator Error Types
// ============================================================================

/// Errors specific to validator operations.
///
/// These errors provide detailed information about validation failures
/// during validator registration and other validator-related operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorError {
    /// The stake provided is below the required minimum.
    ///
    /// This error is returned when a validator registration attempt
    /// provides stake less than the network's `min_validator_stake` parameter.
    StakeTooLow {
        /// The stake amount provided in the registration call.
        stake: u64,
        /// The minimum stake required by the network.
        min: u64,
    },
    /// The validator account already exists.
    AlreadyExists,
    /// Invalid registration data.
    InvalidData(&'static str),
}

impl std::fmt::Display for ValidatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidatorError::StakeTooLow { stake, min } => {
                write!(
                    f,
                    "stake {} is below minimum required stake {} for validator registration",
                    stake, min
                )
            }
            ValidatorError::AlreadyExists => {
                write!(f, "validator already exists")
            }
            ValidatorError::InvalidData(msg) => {
                write!(f, "invalid validator data: {}", msg)
            }
        }
    }
}

impl std::error::Error for ValidatorError {}

/// ValidatorProgram implements validator registration and, later, key rotation and slashing.
pub struct ValidatorProgram;

impl ValidatorProgram {
    pub fn new() -> Self {
        ValidatorProgram
    }

    pub fn id() -> ProgramId {
        VALIDATOR_PROGRAM_ID
    }
}

impl Default for ValidatorProgram {
    fn default() -> Self {
        Self::new()
    }
}

fn native_validator_registration_authority_unavailable() -> Result<(), ExecutionError> {
    Err(ExecutionError::ProgramError(
        "native validator registration authority unavailable",
    ))
}

impl<S: AccountStore> Program<S> for ValidatorProgram {
    fn id(&self) -> ProgramId {
        VALIDATOR_PROGRAM_ID
    }

    fn execute(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        // Basic sanity: ensure the tx is actually targeting this program.
        if tx.program_id != VALIDATOR_PROGRAM_ID {
            return Err(ExecutionError::ProgramError(
                "program_id mismatch for ValidatorProgram",
            ));
        }

        // For now, we only support RegisterValidator (OP_REGISTER_VALIDATOR).
        if tx.call_data.is_empty() {
            return Err(ExecutionError::InvalidCallData("empty call_data"));
        }

        match tx.call_data[0] {
            OP_REGISTER_VALIDATOR => self.handle_register(ctx, tx),
            _ => Err(ExecutionError::ProgramError("unsupported validator opcode")),
        }
    }
}

impl ValidatorProgram {
    fn handle_register<S: AccountStore>(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        // Decode call_data into RegisterValidatorCall.
        let mut input: &[u8] = &tx.call_data;
        let call = RegisterValidatorCall::decode(&mut input)
            .map_err(|_| ExecutionError::InvalidCallData("invalid RegisterValidatorCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData(
                "extra bytes after RegisterValidatorCall",
            ));
        }

        let validator_id: AccountId = call.validator_id;

        // Ensure validator account does not already exist.
        if ctx.store.get(&validator_id).is_some() {
            return Err(ExecutionError::ProgramError("validator already exists"));
        }

        // M2: Enforce minimum stake requirement.
        // Validators must have at least min_validator_stake to register.
        let min_stake = ctx.min_validator_stake;
        if call.stake < min_stake {
            return Err(ExecutionError::ProgramError(
                "stake below minimum required for validator registration",
            ));
        }

        native_validator_registration_authority_unavailable()
    }
}

// ============================================================================
// M2: Helper functions for minimum stake validation
// ============================================================================

/// Check if a validator's stake meets the minimum threshold.
///
/// This function is used during epoch transitions to determine validator eligibility.
///
/// # Arguments
///
/// * `stake` - The validator's current stake in microQBIND
/// * `min_stake` - The minimum required stake in microQBIND
///
/// # Returns
///
/// `true` if stake >= min_stake, `false` otherwise.
pub fn is_stake_sufficient(stake: u64, min_stake: u64) -> bool {
    stake >= min_stake
}
