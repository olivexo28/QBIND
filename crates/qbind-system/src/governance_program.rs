//! Native governance calls are parsed but refused until governance authority is
//! independently available.

use qbind_ledger::{AccountStore, ExecutionContext, ExecutionError, Program};
use qbind_types::{AccountId, ProgramId, SuiteStatus};
use qbind_wire::gov::{
    GovSetMainnetStatusCall, GovUpdateLaunchChecklistCall, GovUpdateParamRegistryCall,
    GovUpdateSuiteStatusCall, OP_GOV_SET_MAINNET_STATUS, OP_GOV_UPDATE_LAUNCH_CHECKLIST,
    OP_GOV_UPDATE_PARAM_REGISTRY, OP_GOV_UPDATE_SUITE_STATUS,
};
use qbind_wire::io::WireDecode;
use qbind_wire::tx::Transaction;

/// Hard-coded ProgramId for governance.
pub const GOVERNANCE_PROGRAM_ID: ProgramId = [0x47; 32]; // 'G'

/// Well-known system account IDs for core governance state.
pub const SUITE_REGISTRY_ACCOUNT_ID: AccountId = [0xA1; 32];
pub const PARAM_REGISTRY_ACCOUNT_ID: AccountId = [0xA2; 32];
pub const LAUNCH_CHECKLIST_ACCOUNT_ID: AccountId = [0xA3; 32];

/// Safety Council keyset and member account IDs for genesis.
/// These are well-known, fixed IDs; in a production deployment, the chain
/// operator would replace the dummy keys, not the IDs.
pub const SAFETY_COUNCIL_KEYSET_ACCOUNT_ID: AccountId = [0xB0; 32];

pub const SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS: [AccountId; 7] = [
    [0xB1; 32], [0xB2; 32], [0xB3; 32], [0xB4; 32], [0xB5; 32], [0xB6; 32], [0xB7; 32],
];

/// GovernanceProgram handles governance-related state mutations.
pub struct GovernanceProgram;

impl GovernanceProgram {
    pub fn new() -> Self {
        GovernanceProgram
    }

    pub fn id() -> ProgramId {
        GOVERNANCE_PROGRAM_ID
    }
}

impl Default for GovernanceProgram {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_err(label: &'static str) -> ExecutionError {
    ExecutionError::InvalidCallData(label)
}

fn native_governance_authority_unavailable() -> Result<(), ExecutionError> {
    Err(ExecutionError::ProgramError(
        "native governance authority unavailable",
    ))
}

impl<S: AccountStore> Program<S> for GovernanceProgram {
    fn id(&self) -> ProgramId {
        GOVERNANCE_PROGRAM_ID
    }

    fn execute(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        if tx.program_id != GOVERNANCE_PROGRAM_ID {
            return Err(ExecutionError::ProgramError(
                "program_id mismatch for GovernanceProgram",
            ));
        }
        if tx.call_data.is_empty() {
            return Err(ExecutionError::InvalidCallData("empty call_data"));
        }

        match tx.call_data[0] {
            OP_GOV_UPDATE_SUITE_STATUS => self.handle_update_suite_status(ctx, tx),
            OP_GOV_UPDATE_PARAM_REGISTRY => self.handle_update_param_registry(ctx, tx),
            OP_GOV_UPDATE_LAUNCH_CHECKLIST => self.handle_update_launch_checklist(ctx, tx),
            OP_GOV_SET_MAINNET_STATUS => self.handle_set_mainnet_status(ctx, tx),
            _ => Err(ExecutionError::ProgramError(
                "unsupported governance opcode",
            )),
        }
    }
}

impl GovernanceProgram {
    /// Validate GovUpdateSuiteStatusCall before refusing unavailable authority.
    fn handle_update_suite_status<S: AccountStore>(
        &self,
        _ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let call = GovUpdateSuiteStatusCall::decode(&mut input)
            .map_err(|_| decode_err("invalid GovUpdateSuiteStatusCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData(
                "extra bytes after GovUpdateSuiteStatusCall",
            ));
        }

        // Map new_status (u8) into SuiteStatus enum.
        let _new_status = match call.new_status {
            0 => SuiteStatus::Active,
            1 => SuiteStatus::Legacy,
            2 => SuiteStatus::Disabled,
            _ => return Err(ExecutionError::InvalidCallData("invalid SuiteStatus")),
        };

        native_governance_authority_unavailable()
    }

    /// Validate GovUpdateParamRegistryCall before refusing unavailable authority.
    fn handle_update_param_registry<S: AccountStore>(
        &self,
        _ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let _call = GovUpdateParamRegistryCall::decode(&mut input)
            .map_err(|_| decode_err("invalid GovUpdateParamRegistryCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData(
                "extra bytes after GovUpdateParamRegistryCall",
            ));
        }

        native_governance_authority_unavailable()
    }

    /// Validate GovUpdateLaunchChecklistCall before refusing unavailable authority.
    fn handle_update_launch_checklist<S: AccountStore>(
        &self,
        _ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let _call = GovUpdateLaunchChecklistCall::decode(&mut input)
            .map_err(|_| decode_err("invalid GovUpdateLaunchChecklistCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData(
                "extra bytes after GovUpdateLaunchChecklistCall",
            ));
        }

        native_governance_authority_unavailable()
    }

    /// Validate GovSetMainnetStatusCall before refusing unavailable authority.
    fn handle_set_mainnet_status<S: AccountStore>(
        &self,
        _ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let _call = GovSetMainnetStatusCall::decode(&mut input)
            .map_err(|_| decode_err("invalid GovSetMainnetStatusCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData(
                "extra bytes after GovSetMainnetStatusCall",
            ));
        }

        native_governance_authority_unavailable()
    }
}
