use revm::{
    bytecode::{Bytecode, OpCode},
    context::{ContextTr, TxEnv},
    context_interface::result::ExecutionResult,
    database::CacheDB,
    database_interface::EmptyDB,
    handler::EvmTr,
    inspector::{InspectCommitEvm, Inspector},
    interpreter::{
        interpreter_types::Jumps, CreateInputs, CreateOutcome, Interpreter, InterpreterTypes,
    },
    primitives::{Address, Bytes, TxKind, U256},
    state::AccountInfo,
    Context, MainBuilder, MainContext,
};

use crate::addresses::ExecutionAddresses;

/// Intrinsic gas cost for a plain CALL transaction (EIP-2028 baseline).
pub const TX_INTRINSIC_GAS: u64 = 21_000;

struct OpcodeCoverageInspector {
    opcode_counts: [u64; 256],
    trace: Vec<u8>,
    root_address: Address,
    created_contracts: Vec<Address>,
}

impl OpcodeCoverageInspector {
    fn new(root_address: Address) -> Self {
        Self {
            opcode_counts: [0; 256],
            trace: Vec::new(),
            root_address,
            created_contracts: Vec::new(),
        }
    }
}

impl<CTX, INTR: InterpreterTypes> Inspector<CTX, INTR> for OpcodeCoverageInspector {
    fn step(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        let opcode = interp.bytecode.opcode();
        self.opcode_counts[opcode as usize] += 1;
        self.trace.push(opcode);
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if inputs.caller() == self.root_address && outcome.instruction_result().is_ok() {
            if let Some(address) = outcome.address {
                self.created_contracts.push(address);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub result: ExecutionResult,
    pub opcode_counts: [u64; 256],
    pub trace: Vec<String>,
    pub created_contracts: Vec<Address>,
    pub nonces: Vec<(Address, u64)>,
}

pub fn run(bytecode: &[u8], gas_budget: u64) -> RunSummary {
    run_with_addresses(bytecode, gas_budget, ExecutionAddresses::default())
}

pub fn run_with_addresses(
    bytecode: &[u8],
    gas_budget: u64,
    addresses: ExecutionAddresses,
) -> RunSummary {
    addresses.assert_valid();
    let code_addr = addresses.contract;
    let caller = addresses.caller;
    let call_value = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    let code = Bytecode::new_raw(Bytes::copy_from_slice(bytecode));
    let mut db = CacheDB::new(EmptyDB::default());
    let account = AccountInfo::new(U256::ZERO, 1, code.hash_slow(), code);
    db.insert_account_info(code_addr, account);
    let caller_balance = call_value.saturating_add(U256::from(u128::MAX));
    let mut caller_account = AccountInfo::default();
    caller_account.balance = caller_balance;
    db.insert_account_info(caller, caller_account);

    let inspector = OpcodeCoverageInspector::new(code_addr);
    let ctx = Context::mainnet().with_db(db);
    let mut evm = ctx.build_mainnet_with_inspector(inspector);

    let result = evm
        .inspect_tx_commit(
            TxEnv::builder()
                .caller(caller)
                .kind(TxKind::Call(code_addr))
                .data(Bytes::new())
                .gas_limit(gas_budget.saturating_add(TX_INTRINSIC_GAS + 1))
                .value(call_value)
                .build()
                .unwrap(),
        )
        .expect("evm transact failed");

    let mut created_contracts = if matches!(result, ExecutionResult::Success { .. }) {
        evm.inspector.created_contracts.clone()
    } else {
        Vec::new()
    };
    created_contracts.sort_unstable_by(|left, right| left.as_slice().cmp(right.as_slice()));
    let nonces = if matches!(result, ExecutionResult::Success { .. }) {
        nonce_snapshot(evm.ctx_ref().db(), caller, code_addr, &created_contracts)
    } else {
        Vec::new()
    };
    let trace = evm
        .inspector
        .trace
        .iter()
        .map(|op| OpCode::name_by_op(*op).to_string())
        .collect();

    RunSummary {
        result,
        opcode_counts: evm.inspector.opcode_counts,
        trace,
        created_contracts,
        nonces,
    }
}

fn nonce_snapshot(
    db: &CacheDB<EmptyDB>,
    caller: Address,
    code_addr: Address,
    created_contracts: &[Address],
) -> Vec<(Address, u64)> {
    let mut addresses = vec![caller, code_addr];
    addresses.extend_from_slice(created_contracts);

    let mut snapshot: Vec<_> = addresses
        .into_iter()
        .map(|address| (address, account_nonce(db, address)))
        .collect();
    snapshot.sort_unstable_by(|left, right| left.0.as_slice().cmp(right.0.as_slice()));
    snapshot
}

fn account_nonce(db: &CacheDB<EmptyDB>, address: Address) -> u64 {
    db.cache
        .accounts
        .get(&address)
        .and_then(|account| account.info().map(|info| info.nonce))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addresses::ExecutionAddresses;
    use crate::{
        machine::{Config, Machine},
        opcodes::Opcode,
    };
    use fastrand::Rng;

    #[test]
    fn run_tracks_created_contracts() {
        let mut machine = Machine::new(100_000, Rng::with_seed(7), Config::default());

        assert!(machine
            .ingest(Opcode::Create(vec![0x60, 0x00, 0x60, 0x00, 0xF3]))
            .is_ok());

        let summary = run(&machine.bytecode(), 100_000);
        assert_eq!(summary.created_contracts, machine.created_contracts());
        assert_eq!(summary.nonces, machine.nonce_snapshot());
    }

    #[test]
    fn run_uses_configured_addresses() {
        let addresses = ExecutionAddresses {
            caller: Address::from([0xAA; 20]),
            contract: Address::from([0xBB; 20]),
        };
        let config = Config {
            addresses,
            ..Config::default()
        };
        let mut machine = Machine::new(100_000, Rng::with_seed(7), config);

        assert!(machine
            .ingest(Opcode::Create(vec![0x60, 0x00, 0x60, 0x00, 0xF3]))
            .is_ok());

        let summary = run_with_addresses(&machine.bytecode(), 100_000, addresses);
        assert_eq!(summary.created_contracts, machine.created_contracts());
        assert_eq!(summary.nonces, machine.nonce_snapshot());
    }
}
