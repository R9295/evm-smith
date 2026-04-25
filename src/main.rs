mod machine;
mod runner;
mod opcodes;
mod error;

use crate::{machine::Machine, opcodes::{Opcode, ALL_OPCODES}, runner::RunSummary};

use fastrand::Rng;
use revm::primitives::{ExecutionResult, HaltReason, OutOfGasError};
use std::time::SystemTime;

fn main() {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rand = fastrand::Rng::with_seed(seed.clone());
    let machine_rand = fastrand::Rng::with_seed(seed);
    let gas = 300_000;
    let mut machine = Machine::new(gas, machine_rand);
    loop {
        let op = get_next_op(&mut rand);
        let Ok(_) = machine.ingest(op) else {
            break;
        };
    };
    let run_summary = runner::run(&machine.bytecode(), gas as u64);
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

fn get_next_op(rand: &mut Rng) -> &'static dyn Opcode {
    ALL_OPCODES[rand.usize(0..ALL_OPCODES.len())]
}

fn report_error(run_summary: &RunSummary) {
    eprintln!("bad halt! trace: {:?}", run_summary);
    panic!("FATAL ERROR: generator invariant violated");
}
