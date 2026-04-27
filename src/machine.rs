use alloy_primitives::{Address, U256};
use fastrand::Rng;
use std::collections::HashMap;

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
    call_stack: Vec<Address>,
    nonces: HashMap<Address, u64>,
    memory: u64,
    bytecode: Vec<Opcode>,
    halted: bool,
}

impl Machine {
    pub fn new(gas: u64, rng: Rng, config: Config) -> Self {
        let caller = Address::from([0x11; 20]);
        Self {
            config,
            gas,
            rng,
            memory: 0,
            stack: vec![],
            call_stack: vec![caller],
            nonces: HashMap::from([(caller, 0)]),
            bytecode: vec![],
            halted: false,
        }
    }

    pub fn memory(&self) -> u64 {
        self.memory
    }

    pub fn gas(&self) -> u64 {
        self.gas
    }

    pub fn create_gas_percentage(&self) -> u8 {
        self.config.create_gas_percentage
    }

    pub fn bytecode_ops(&self) -> &[Opcode] {
        &self.bytecode
    }

    pub fn ingest(&mut self, op: Opcode) -> anyhow::Result<(), Error> {
        if self.halted {
            return Err(Error::HaltConditionEncountered);
        }
        if !self.config.allow_termination && op.is_terminating() {
            return Ok(());
        }
        // Materialize placeholder CREATE/CREATE2 ops (empty payloads from
        // `Opcode::generate`) now that we have access to the outer machine's
        // gas budget and RNG.
        let op = match op {
            Opcode::Create(ref payload) if payload.is_empty() => {
                Opcode::Create(self.build_init_code())
            }
            Opcode::Create2(ref payload, salt) if payload.is_empty() => {
                Opcode::Create2(self.build_init_code(), salt)
            }
            other => other,
        };
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
                let terminating = op.is_terminating();
                self.bytecode.push(op);
                if terminating {
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

    /// Generates the init code shared by CREATE and CREATE2: spawns a fresh
    /// sub-machine with `allow_termination = false` and a fraction of the
    /// outer's *current* remaining gas (per the configured percentage), runs
    /// the same generation loop as `main`, then truncates at the last
    /// whole-opcode boundary that fits under the EIP-3860 init code limit and
    /// appends a `RETURN(0, 0)` so the deploy frame returns empty runtime
    /// code (always passes EIP-170 / EIP-3541).
    ///
    /// Nested CREATE/CREATE2 is allowed: the inner generator can itself draw
    /// one, which recursively materializes at the next depth. Recursion is
    /// self-bounded — each level uses `create_gas_percentage`% of the
    /// parent's symbolic gas, so the budget shrinks geometrically until the
    /// op's `requires.gas` exceeds it and the inner ingest stops with
    /// `OutOfGas`.
    ///
    /// Caveat: a deeply nested deploy *may* silently fail at runtime even
    /// though the symbolic accounting is conservative. Each level forwards
    /// 63/64 of remaining gas (EIP-150) and we charge ⌈64·sub_budget/63⌉ to
    /// cover the rounding, but if a sub-call OOGs at runtime the EVM consumes
    /// all forwarded gas and pushes a zero address, then the parent frame
    /// continues with only the 1/64 retained portion. That doesn't violate
    /// any outer invariant (the harness still doesn't panic), but the inner
    /// deploy simply produces no contract.
    fn build_init_code(&mut self) -> Vec<u8> {
        // EIP-3860 caps init code at 49152 bytes; reserve 5 bytes for the
        // appended RETURN(0, 0) tail (PUSH1 0, PUSH1 0, RETURN).
        const MAX_INIT_CODE: usize = 49152 - 5;

        let pct = self.config.create_gas_percentage as u64;
        let sub_budget = self.gas.saturating_mul(pct) / 100;
        // Fork two independent RNGs from the outer's so the sub-machine's
        // internal constraint solver and the inner generator don't share state.
        let gen_seed = self.rng.u64(..);
        let machine_seed = self.rng.u64(..);
        let mut sub_config = self.config.clone();
        sub_config.allow_termination = false;
        let mut sub_machine = Machine::new(sub_budget, Rng::with_seed(machine_seed), sub_config);
        let mut gen_rng = Rng::with_seed(gen_seed);
        loop {
            let inner = Opcode::generate(&mut gen_rng);
            if sub_machine.ingest(inner).is_err() {
                break;
            }
        }

        let mut init_code: Vec<u8> = Vec::new();
        for op in sub_machine.bytecode_ops() {
            let rendered = op.render();
            if init_code.len() + rendered.len() > MAX_INIT_CODE {
                break;
            }
            init_code.extend_from_slice(&rendered);
        }
        // PUSH1 0 (length), PUSH1 0 (offset), RETURN.
        init_code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xF3]);
        init_code
    }

    pub fn constraints(&self, requires: &Resource, provides: &Resource) -> Option<Resource> {
        let current_stack = self.stack.len() as isize;
        let gas_delta = if self.gas < requires.gas() {
            requires.gas() - self.gas
        } else {
            0
        };

        // Underflow: ensure stack has at least requires.stack() items present.
        // Positive delta tells the solver to synthesize PUSHes.
        let underflow = (requires.stack() - current_stack).max(0);

        // Overflow: peak runtime stack reaches `current + max(stack_reserved,
        // provides.stack - requires.stack, 0)`. If that exceeds 1024 the
        // solver emits POPs (negative delta) to make room — never PUSHes,
        // since stack_reserved is about free slots, not items to consume.
        let net_growth = (provides.stack() - requires.stack()).max(0);
        let peak_above = (requires.stack_reserved() as isize).max(net_growth);
        let overflow = (1024 - current_stack - peak_above).min(0);

        let stack_delta = if underflow > 0 { underflow } else { overflow };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_machine_initializes_caller_state() {
        let caller = Address::from([0x11; 20]);
        let machine = Machine::new(1, Rng::with_seed(7), Config::default());

        assert_eq!(machine.call_stack, vec![caller]);
        assert_eq!(machine.nonces.get(&caller), Some(&0));
    }
}
