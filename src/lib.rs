#![allow(dead_code)]

pub mod addresses;
mod error;
pub mod machine;
pub mod opcodes;
mod runner;

#[cfg(test)]
mod test {
    use crate::{
        machine::Machine,
        runner::{self, RunSummary},
    };
    use revm::bytecode::OpCode;

    #[test]
    fn generated_bytecode_matches_runtime_state() {
        use crate::{machine::Config, opcodes::Opcode};
        use revm::context_interface::result::{ExecutionResult, HaltReason, OutOfGasError};
        use std::time::SystemTime;

        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut rand = fastrand::Rng::with_seed(seed.clone());
        let mut totals = [0u64; 256];
        let config = Config::default();
        for _ in 0..1000 {
            let machine_rand = fastrand::Rng::with_seed(seed);
            let gas = 3_000_000;
            let mut machine = Machine::new(gas, machine_rand, config.clone());
            loop {
                let op = Opcode::generate_with_memory_limits(
                    &mut rand,
                    config.memory_offset_limit,
                    config.memory_length_limit,
                );
                let Ok(_) = machine.ingest(op) else {
                    break;
                };
            }
            let run_summary =
                runner::run_with_addresses(&machine.bytecode(), gas as u64, config.addresses);
            if matches!(&run_summary.result, ExecutionResult::Success { .. }) {
                assert_machine_state_valid(&machine, &run_summary);
            }
            let mut all_count = 0;
            for (i, count) in run_summary.opcode_counts.iter().enumerate() {
                totals[i] = totals[i].saturating_add(*count);
                all_count += count;
            }
            println!("RUN: /dev/shm/evm-fuzz-core-0/bug.json{:?}", all_count);
            match run_summary.result {
                ExecutionResult::Success { .. } => {}
                ExecutionResult::Revert { .. } => {
                    report_error(&run_summary);
                }
                ExecutionResult::Halt { ref reason, .. } => {
                    eprintln!("{:?}", reason);
                    match reason {
                        HaltReason::OutOfGas(oog_cause) => match oog_cause {
                            OutOfGasError::Basic => report_error(&run_summary),
                            OutOfGasError::MemoryLimit => report_error(&run_summary),
                            OutOfGasError::Memory => report_error(&run_summary),
                            OutOfGasError::Precompile => report_error(&run_summary),
                            OutOfGasError::InvalidOperand => {}
                            OutOfGasError::ReentrancySentry => {}
                        },
                        HaltReason::OpcodeNotFound => report_error(&run_summary),
                        HaltReason::InvalidFEOpcode => {}
                        HaltReason::InvalidJump => {}
                        HaltReason::NotActivated => {}
                        HaltReason::StackUnderflow => report_error(&run_summary),
                        HaltReason::StackOverflow => report_error(&run_summary),
                        HaltReason::OutOfOffset => report_error(&run_summary),
                        HaltReason::CreateCollision => report_error(&run_summary),
                        HaltReason::PrecompileError => {}
                        HaltReason::PrecompileErrorWithContext(_) => {}
                        HaltReason::NonceOverflow => report_error(&run_summary),
                        HaltReason::CreateContractSizeLimit => report_error(&run_summary),
                        HaltReason::CreateContractStartingWithEF => report_error(&run_summary),
                        HaltReason::CreateInitCodeSizeLimit => report_error(&run_summary),
                        HaltReason::OverflowPayment => {}
                        HaltReason::StateChangeDuringStaticCall => {}
                        HaltReason::CallNotAllowedInsideStatic => {}
                        HaltReason::OutOfFunds => {}
                        HaltReason::CallTooDeep => {}
                    };
                }
            }
        }
        print_opcode_summary(&totals);
    }

    fn assert_machine_state_valid(machine: &Machine, run_summary: &RunSummary) {
        let machine_created = machine.created_contracts();
        if machine_created != run_summary.created_contracts {
            report_state_error(run_summary, &machine_created, &machine.nonce_snapshot());
        }

        let machine_nonces = machine.nonce_snapshot();
        if machine_nonces != run_summary.nonces {
            report_state_error(run_summary, &machine_created, &machine_nonces);
        }
    }

    /// Returns true for opcodes only active under EOF (not on any current mainnet
    /// spec — Cancun is the latest as of revm 14). Filtered out of the mainnet
    /// summary so the "never executed" list isn't dominated by EOF-only entries.
    fn is_eof_only(byte: u8) -> bool {
        matches!(
            byte,
            0xD0..=0xD3   // DATALOAD, DATALOADN, DATASIZE, DATACOPY (EIP-7480)
            | 0xE0..=0xE8 // RJUMP, RJUMPI, RJUMPV, CALLF, RETF, JUMPF, DUPN, SWAPN, EXCHANGE
            | 0xEC        // EOFCREATE
            | 0xEE        // RETURNCONTRACT
            | 0xF7        // RETURNDATALOAD
            | 0xF8        // EXTCALL
            | 0xF9        // EXTDELEGATECALL
            | 0xFB        // EXTSTATICCALL
        )
    }

    fn print_opcode_summary(totals: &[u64; 256]) {
        let mut ran: Vec<(&'static str, u64)> = Vec::new();
        let mut not_ran: Vec<&'static str> = Vec::new();
        for byte in 0u8..=255 {
            if OpCode::new(byte).is_none() || is_eof_only(byte) {
                continue;
            }
            let name = OpCode::name_by_op(byte);
            let count = totals[byte as usize];
            if count > 0 {
                ran.push((name, count));
            } else {
                not_ran.push(name);
            }
        }
        ran.sort_by(|a, b| b.1.cmp(&a.1));

        println!("\n=== Opcodes executed ({} distinct) ===", ran.len());
        for (name, count) in &ran {
            println!("  {:<16} {}", name, count);
        }
        println!("\n=== Opcodes never executed ({}) ===", not_ran.len());
        for name in &not_ran {
            println!("  {}", name);
        }
    }

    fn report_error(run_summary: &RunSummary) {
        eprintln!("bad halt! result: {:?}", run_summary.result);
        eprintln!("opcodes run ({}):", run_summary.trace.len());
        eprintln!("ops: {:?}", run_summary.trace);
        panic!("FATAL ERROR: generator invariant violated");
    }

    fn report_state_error(
        run_summary: &RunSummary,
        machine_created: &[revm::primitives::Address],
        machine_nonces: &[(revm::primitives::Address, u64)],
    ) {
        eprintln!("machine created contracts: {:?}", machine_created);
        eprintln!(
            "runtime created contracts: {:?}",
            run_summary.created_contracts
        );
        eprintln!("machine nonces: {:?}", machine_nonces);
        eprintln!("runtime nonces: {:?}", run_summary.nonces);
        report_error(run_summary);
    }
}
