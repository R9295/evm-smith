
use revm::{
    Database, Evm, EvmContext, Inspector,
    db::{CacheDB, EmptyDB},
    inspector_handle_register,
    interpreter::Interpreter,
    primitives::{AccountInfo, Address, Bytecode, Bytes, ExecutionResult, TxKind, U256},
};

/// Intrinsic gas cost for a plain CALL transaction (EIP-2028 baseline).
const TX_INTRINSIC_GAS: u64 = 21_000;

struct OpcodeCoverageInspector {
    opcode_counts: [u64; 256],
    trace: Vec<u8>,
}

impl Default for OpcodeCoverageInspector {
    fn default() -> Self {
        Self {
            opcode_counts: [0; 256],
            trace: Vec::new(),
        }
    }
}

impl<DB: Database> Inspector<DB> for OpcodeCoverageInspector {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        let opcode = interp.current_opcode();
        self.opcode_counts[opcode as usize] += 1;
        self.trace.push(opcode);
    }
}
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub result: ExecutionResult,
    pub opcode_counts: [u64; 256],
    pub trace: Vec<String>,
}

pub fn run(bytecode: &[u8], gas_budget: u64) -> RunSummary {
    // Avoid the 0x01..=0x09 precompile range so revm executes our installed bytecode.
    let code_addr = Address::from_word(U256::from(0x100).into());
    let caller = Address::from_word(U256::from(0x200).into());

    let call_value = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    let mut db = CacheDB::new(EmptyDB::default());
    let code = Bytecode::new_raw(Bytes::copy_from_slice(bytecode));
    let account = AccountInfo::new(U256::ZERO, 0, code.hash_slow(), code);
    db.insert_account_info(code_addr, account);
    // Fund the caller so it can supply `call_value` plus worst-case gas.
    let caller_balance = call_value.saturating_add(U256::from(u128::MAX));
    let caller_account = AccountInfo::new(caller_balance, 0, Default::default(), Bytecode::new());
    db.insert_account_info(caller, caller_account);

    let mut evm = Evm::builder()
        .with_db(db)
        .with_external_context(OpcodeCoverageInspector::default())
        .modify_tx_env(|tx| {
            tx.caller = caller;
            tx.transact_to = TxKind::Call(code_addr);
            tx.data = Bytes::new();
            tx.gas_limit = gas_budget.saturating_add(TX_INTRINSIC_GAS);
            tx.value = call_value;
        })
        .append_handler_register(inspector_handle_register)
        .build();

    let result = evm.transact().expect("evm transact failed").result;
    let inspector = evm.into_context().external;

    RunSummary {
        result,
        opcode_counts: inspector.opcode_counts,
        trace: vec![],
    }
}
