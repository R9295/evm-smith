use alloy_primitives::U256;
use fastrand::Rng;

use crate::{
    error::Error,
    opcodes::{Opcode, Resource},
};

#[derive(Debug)]
pub struct Machine {
    rng: Rng,
    gas: u64,
    stack: Vec<U256>,
    bytecode: Vec<Opcode>,
}

impl Machine {
    pub fn new(gas: u64, rng: Rng) -> Self {
        Self {
            gas,
            rng,
            stack: vec![],
            bytecode: vec![],
        }
    }

    pub fn ingest(&mut self, op: Opcode) -> anyhow::Result<(), Error> {
        let mut stack = vec![op];
        while let Some(op) = stack.pop() {
            let requires = op.requires();
            let provides = op.provides();
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
                debug_assert!(self.stack.len() <= 1024);
                self.bytecode.push(op);
                continue;
            }
            // SAFE: just validated earlier
            let constraints = constraints.unwrap();
            stack.insert(0, op);
            if constraints.gas() > 0 {
                return Err(Error::OutOfGas);
            }
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