use revm::{
    Context, MainBuilder, MainContext,
    bytecode::{Bytecode, OpCode},
    context::TxEnv,
    context_interface::result::ExecutionResult,
    database::CacheDB,
    database_interface::EmptyDB,
    inspector::{InspectEvm, Inspector},
    interpreter::{
        CreateInputs, CreateOutcome, Interpreter, InterpreterTypes, interpreter_types::Jumps,
    },
    primitives::{Address, Bytes, TxKind, U256},
    state::AccountInfo,
};

/// Intrinsic gas cost for a plain CALL transaction (EIP-2028 baseline).
const TX_INTRINSIC_GAS: u64 = 21_000;

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
}

pub fn run(bytecode: &[u8], gas_budget: u64) -> RunSummary {
    let code_addr = Address::from([0x42; 20]);
    let caller = Address::from([0x11; 20]);
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
        .inspect_one_tx(
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

    let inspector = evm.inspector;
    let mut created_contracts = if matches!(result, ExecutionResult::Success { .. }) {
        inspector.created_contracts
    } else {
        Vec::new()
    };
    created_contracts.sort_unstable_by(|left, right| left.as_slice().cmp(right.as_slice()));
    let trace = inspector
        .trace
        .iter()
        .map(|op| OpCode::name_by_op(*op).to_string())
        .collect();

    RunSummary {
        result,
        opcode_counts: inspector.opcode_counts,
        trace,
        created_contracts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        machine::{Config, Machine},
        opcodes::Opcode,
    };
    use fastrand::Rng;

    #[test]
    fn run_tracks_created_contracts() {
        let mut machine = Machine::new(100_000, Rng::with_seed(7), Config::default());

        assert!(
            machine
                .ingest(Opcode::Create(vec![0x60, 0x00, 0x60, 0x00, 0xF3]))
                .is_ok()
        );

        let summary = run(&machine.bytecode(), 100_000);
        assert_eq!(summary.created_contracts, machine.created_contracts());
    }
}
