use alloy_primitives::U256;
use fastrand::Rng;

use crate::{
    error::Error,
    opcodes::{Opcode, Resource},
};

/// Tunables for the symbolic generator.
#[derive(Debug, Clone)]
pub struct Config {
    /// Fraction of the *remaining* gas budgeted for the CREATE/CREATE2 sub-call,
    /// expressed as a percent in `0..=100`. Reserved for the upcoming CREATE
    /// opcode wiring.
    pub create_gas_percentage: u8,
    /// When `false`, terminating ops (STOP / INVALID / RETURN / REVERT /
    /// SELFDESTRUCT) drawn by the generator are silently skipped instead of
    /// halting the machine.
    pub allow_termination: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            create_gas_percentage: 50,
            allow_termination: true,
        }
    }
}

#[derive(Debug)]
pub struct Machine {
    config: Config,
    rng: Rng,
    gas: u64,
    stack: Vec<U256>,
    memory: u64,
    bytecode: Vec<Opcode>,
    halted: bool,
}

impl Machine {
    pub fn new(gas: u64, rng: Rng, config: Config) -> Self {
        Self {
            config,
            gas,
            rng,
            memory: 0,
            stack: vec![],
            bytecode: vec![],
            halted: false,
        }
    }

    pub fn memory(&self) -> u64 {
        self.memory
    }

    pub fn ingest(&mut self, op: Opcode) -> anyhow::Result<(), Error> {
        if self.halted {
            return Err(Error::HaltConditionEncountered);
        }
        if !self.config.allow_termination && op.is_terminating() {
            return Ok(());
        }
        let mut stack = vec![op];
        while let Some(op) = stack.pop() {
            let requires = op.requires(self);
            let provides = op.provides(self);
            let constraints = self.constraints(&requires, &provides);
            if constraints.is_none() {
                self.gas = self.gas.checked_sub(requires.gas()).unwrap();
                if requires.stack() > 0 {
                    for _ in 0..requires.stack() {
                        self.stack.pop();
                    }
                }
                if provides.stack() > 0 {
                    for _ in 0..provides.stack() {
                        self.stack.push(U256::ONE);
                    }
                }
                self.memory = self.memory.saturating_add(provides.memory());
                debug_assert!(self.stack.len() <= 1024);
                self.bytecode.push(op);
                if op.is_terminating() {
                    self.halted = true;
                    return Err(Error::HaltConditionEncountered);
                }
                continue;
            }
            // SAFE: just validated earlier
            let constraints = constraints.unwrap();
            // Since we have constraints, add this back to the stack
            stack.insert(0, op);
            if constraints.gas() > 0 {
                return Err(Error::OutOfGas);
            }
            // Proceed to solve constraints before we resolve the op.
            if constraints.stack() > 0 {
                stack.insert(0, Opcode::generate_push(&mut self.rng));
            }
            if constraints.stack() < 0 {
                stack.insert(0, Opcode::Pop);
            }
        }
        Ok(())
    }

    pub fn bytecode(&self) -> Vec<u8> {
        self.bytecode.iter().flat_map(|op| op.render()).collect()
    }

    pub fn constraints(&self, requires: &Resource, provides: &Resource) -> Option<Resource> {
        let current_stack = self.stack.len();
        let gas_delta = if self.gas < requires.gas() {
            requires.gas() - self.gas
        } else {
            0
        };
        let mut stack_delta = if (current_stack as isize) < requires.stack() {
            requires.stack() - (current_stack as isize)
        } else {
            0
        };
        if self.stack.len() == 1024 && provides.stack() > 0 {
            stack_delta = 0 - provides.stack();
        }
        if stack_delta == 0 && gas_delta == 0 {
            None
        } else {
            Some(
                Resource::builder()
                    .stack(stack_delta)
                    .gas(gas_delta)
                    .build(),
            )
        }
    }
}
