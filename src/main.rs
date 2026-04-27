mod error;
mod machine;
mod opcodes;
mod runner;

use crate::{
    machine::Machine,
    opcodes::{Opcode},
    runner::RunSummary,
};
use revm::interpreter::OpCode;
use revm::primitives::{ExecutionResult, HaltReason, OutOfGasError};
use std::time::SystemTime;

fn main() {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rand = fastrand::Rng::with_seed(seed.clone());
    let mut totals = [0u64; 256];
    for _ in 0..1000 {
        let machine_rand = fastrand::Rng::with_seed(seed);
        let gas = 3_00_000;
        let mut machine = Machine::new(gas, machine_rand);
        loop {
            let op = Opcode::generate(&mut rand);
            let Ok(_) = machine.ingest(op) else {
                break;
            };
        }
        let run_summary = runner::run(&machine.bytecode(), gas as u64);
        for (i, count) in run_summary.opcode_counts.iter().enumerate() {
            totals[i] = totals[i].saturating_add(*count);
        }
        match run_summary.result {
            ExecutionResult::Success {
                reason,
                gas_used,
                gas_refunded,
                logs,
                output,
            } => {}
            ExecutionResult::Revert { gas_used, output } => {}
            ExecutionResult::Halt { reason, gas_used } => {
                match reason {
                    HaltReason::OutOfGas(oog_cause) => match oog_cause {
                        OutOfGasError::Basic => report_error(&run_summary),
                        OutOfGasError::MemoryLimit => report_error(&run_summary),
                        OutOfGasError::Memory => report_error(&run_summary),
                        OutOfGasError::Precompile => report_error(&run_summary),
                        OutOfGasError::InvalidOperand => {}
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
                    HaltReason::NonceOverflow => report_error(&run_summary),
                    HaltReason::CreateContractSizeLimit => report_error(&run_summary),
                    HaltReason::CreateContractStartingWithEF => report_error(&run_summary),
                    HaltReason::CreateInitCodeSizeLimit => report_error(&run_summary),
                    HaltReason::EofAuxDataOverflow => {}
                    HaltReason::EofAuxDataTooSmall => {}
                    HaltReason::EOFFunctionStackOverflow => {}
                    HaltReason::InvalidEXTCALLTarget => {}
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
