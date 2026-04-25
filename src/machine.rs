use alloy_primitives::U256;
use fastrand::Rng;

use crate::{
    error::Error,
    opcodes::{Opcode, Resource, PUSH_OPCODES},
};

#[derive(Debug)]
pub struct Machine {
    rng: Rng,
    gas: u64,
    stack: Vec<U256>,
    pub bytecode: Vec<&'static dyn Opcode>,
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
    pub fn ingest(&mut self, op: &'static dyn Opcode) -> anyhow::Result<(), Error> {
        let requires = op.requires();
        match self.constraints(&requires) {
            None => self.bytecode.push(op),
            Some(mut constraint) => {
                if constraint.gas() > 0 {
                    return Err(Error::OutOfGas);
                }
                if constraint.stack() > 0 {
                    while constraint.stack() != 0 {
                        let push_op = get_push_op(&mut self.rng);
                        self.ingest(push_op)?;
                        constraint.set_stack(constraint.stack() - 1);
                    }
                    self.bytecode.push(op);
                }
            }
        }
        self.gas = self.gas.saturating_sub(requires.gas());
        Ok(())
    }

    pub fn constraints(&self, requires: &Resource) -> Option<Resource> {
        let current_stack = self.stack.len();
        let gas_delta = if self.gas < requires.gas() {
            requires.gas() - self.gas
        } else {
            0
        };
        let mut stack_delta = if current_stack < requires.stack() {
            requires.stack() - current_stack
        } else {
            0
        };
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

fn get_push_op(rand: &mut Rng) -> &'static dyn Opcode {
    PUSH_OPCODES[rand.usize(0..PUSH_OPCODES.len())]
}
