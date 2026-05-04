use alloy_primitives::{Address, U256, keccak256};
#[cfg(feature = "arbitrary")]
use arbitrary::Unstructured;
#[cfg(feature = "rng")]
use fastrand::Rng;
use std::collections::HashMap;

use crate::{
    Error,
    addresses::ExecutionAddresses,
    opcodes::{Opcode, Provides, Render, Requires, Resource},
};

pub use crate::opcodes::{DEFAULT_MEMORY_LENGTH_LIMIT, DEFAULT_MEMORY_OFFSET_LIMIT, OpcodeWeights};

/// Tunables for the symbolic generator.
#[derive(Debug, Clone)]
pub struct Config {
    /// Root transaction caller and contract addresses.
    pub addresses: ExecutionAddresses,
    /// Fraction of the *remaining* gas budgeted for the CREATE/CREATE2 sub-call,
    /// expressed as a percent in `0..=100`. Reserved for the upcoming CREATE
    /// opcode wiring.
    pub create_gas_percentage: u8,
    /// When `false`, terminating ops (STOP / INVALID / RETURN / SELFDESTRUCT)
    /// drawn by the generator are silently skipped instead of halting the
    /// machine.
    pub allow_termination: bool,
    /// When `true`, CREATE/CREATE2 grows `callable_addresses` with the new
    /// contract. Disabled inside sub-machines so the rendered init code is
    /// identical across the CREATE2 probe/final passes (the new address would
    /// otherwise depend on sub `current_address`, which differs between the
    /// passes by construction).
    pub grow_callable_on_create: bool,
    /// Inclusive upper bound for memory offsets sampled by generated opcodes.
    /// The default preserves the historical `u16` cap.
    pub memory_offset_limit: u64,
    /// Inclusive upper bound for memory lengths sampled by generated opcodes.
    /// The default preserves the historical `u8` cap.
    pub memory_length_limit: u64,
    /// Family-level opcode weights used by machine-driven generation. The
    /// default balanced profile gives stateful/call/create/memory opcodes more
    /// chances than flat variant sampling while `OpcodeWeights::uniform()`
    /// preserves the historical distribution.
    pub opcode_weights: OpcodeWeights,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addresses: ExecutionAddresses::default(),
            create_gas_percentage: 50,
            allow_termination: true,
            grow_callable_on_create: true,
            memory_offset_limit: DEFAULT_MEMORY_OFFSET_LIMIT,
            memory_length_limit: DEFAULT_MEMORY_LENGTH_LIMIT,
            opcode_weights: OpcodeWeights::balanced(),
        }
    }
}

pub trait MachineSource: Clone {
    fn pick_index(&mut self, len: usize) -> anyhow::Result<usize, Error>;
    fn next_opcode(&mut self, config: &Config) -> anyhow::Result<Opcode, Error>;
    fn push_opcode(&mut self) -> anyhow::Result<Opcode, Error>;
    fn fork(&mut self) -> anyhow::Result<(Self, Self), Error>;
}

#[cfg(feature = "arbitrary")]
pub type DefaultMachineSource = ArbitraryMachineSource;
#[cfg(all(not(feature = "arbitrary"), feature = "rng"))]
pub type DefaultMachineSource = RngMachineSource;
#[cfg(not(any(feature = "rng", feature = "arbitrary")))]
pub type DefaultMachineSource = MissingMachineSource;

#[cfg(feature = "rng")]
#[derive(Debug, Clone)]
pub struct RngMachineSource {
    rng: Rng,
}

#[cfg(feature = "rng")]
impl RngMachineSource {
    pub fn new(rng: Rng) -> Self {
        Self { rng }
    }
}

#[cfg(feature = "rng")]
impl MachineSource for RngMachineSource {
    fn pick_index(&mut self, len: usize) -> anyhow::Result<usize, Error> {
        Ok(self.rng.usize(0..len))
    }

    fn next_opcode(&mut self, config: &Config) -> anyhow::Result<Opcode, Error> {
        Ok(Opcode::generate_weighted(&mut self.rng, config))
    }

    fn push_opcode(&mut self) -> anyhow::Result<Opcode, Error> {
        Ok(Opcode::generate_push(&mut self.rng))
    }

    fn fork(&mut self) -> anyhow::Result<(Self, Self), Error> {
        let gen_seed = self.rng.u64(..);
        let machine_seed = self.rng.u64(..);
        Ok((
            Self::new(Rng::with_seed(gen_seed)),
            Self::new(Rng::with_seed(machine_seed)),
        ))
    }
}

#[cfg(feature = "arbitrary")]
#[derive(Debug, Clone, Default)]
pub struct ArbitraryMachineSource {
    data: Vec<u8>,
    cursor: usize,
}

#[cfg(feature = "arbitrary")]
impl ArbitraryMachineSource {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            data: data.into(),
            cursor: 0,
        }
    }

    fn with_unstructured<T>(
        &mut self,
        f: impl FnOnce(&mut Unstructured<'_>) -> arbitrary::Result<T>,
    ) -> anyhow::Result<T, Error> {
        let before = self.data.len().saturating_sub(self.cursor);
        let result;
        let consumed;
        {
            let mut u = Unstructured::new(&self.data[self.cursor..]);
            result = f(&mut u);
            consumed = before.saturating_sub(u.len());
        }
        self.cursor = self.cursor.saturating_add(consumed);
        result.map_err(|_| Error::InputExhausted)
    }

    fn child_source(&mut self) -> anyhow::Result<Self, Error> {
        let data = self.with_unstructured(|u| {
            let len = u.arbitrary_len::<u8>()?;
            Ok(u.bytes(len)?.to_vec())
        })?;
        Ok(Self::new(data))
    }
}

#[cfg(feature = "arbitrary")]
impl MachineSource for ArbitraryMachineSource {
    fn pick_index(&mut self, len: usize) -> anyhow::Result<usize, Error> {
        self.with_unstructured(|u| u.choose_index(len))
    }

    fn next_opcode(&mut self, config: &Config) -> anyhow::Result<Opcode, Error> {
        self.with_unstructured(|u| Opcode::arbitrary_weighted(u, config))
    }

    fn push_opcode(&mut self) -> anyhow::Result<Opcode, Error> {
        self.with_unstructured(Opcode::arbitrary_push)
    }

    fn fork(&mut self) -> anyhow::Result<(Self, Self), Error> {
        Ok((self.child_source()?, self.child_source()?))
    }
}

#[cfg(not(any(feature = "rng", feature = "arbitrary")))]
#[derive(Debug, Clone)]
pub struct MissingMachineSource;

#[cfg(not(any(feature = "rng", feature = "arbitrary")))]
impl MachineSource for MissingMachineSource {
    fn pick_index(&mut self, _len: usize) -> anyhow::Result<usize, Error> {
        unreachable!("enable either the `rng` or `arbitrary` feature")
    }

    fn next_opcode(&mut self, _config: &Config) -> anyhow::Result<Opcode, Error> {
        unreachable!("enable either the `rng` or `arbitrary` feature")
    }

    fn push_opcode(&mut self) -> anyhow::Result<Opcode, Error> {
        unreachable!("enable either the `rng` or `arbitrary` feature")
    }

    fn fork(&mut self) -> anyhow::Result<(Self, Self), Error> {
        unreachable!("enable either the `rng` or `arbitrary` feature")
    }
}

#[derive(Debug)]
pub struct Machine<S: MachineSource = DefaultMachineSource> {
    config: Config,
    source: S,
    gas: u64,
    stack: Vec<U256>,
    address_stack: Vec<Address>,
    call_stack: Vec<Address>,
    nonces: HashMap<Address, u64>,
    /// Curated list of CALL targets that we know have empty runtime code, so
    /// the sub-frame is a no-op and symbolic / runtime state stay in sync.
    /// Seeded with the safe baseline (root: caller; sub-machine: its own
    /// being-deployed `current_address`) and grown by every CREATE / CREATE2
    /// (their init returns 0 bytes via the appended `RETURN(0, 0)` tail).
    /// Notably excludes the root `code_addr` — calling it would recurse into
    /// the test bytecode and bump the creator's nonce in unobservable ways.
    callable_addresses: Vec<Address>,
    memory: u64,
    bytecode: Vec<Opcode>,
    halted: bool,
}

#[derive(Debug, Clone, Copy)]
struct CreatedContractState {
    address: Address,
    nonce: u64,
}

impl Machine<DefaultMachineSource> {
    #[cfg(feature = "arbitrary")]
    pub fn new(gas: u64, data: impl Into<Vec<u8>>, config: Config) -> Self {
        Self::from_source(gas, ArbitraryMachineSource::new(data), config)
    }

    #[cfg(all(not(feature = "arbitrary"), feature = "rng"))]
    pub fn new(gas: u64, rng: Rng, config: Config) -> Self {
        Self::from_source(gas, RngMachineSource::new(rng), config)
    }
}

#[cfg(feature = "rng")]
impl Machine<RngMachineSource> {
    pub fn new_rng(gas: u64, rng: Rng, config: Config) -> Self {
        Self::from_source(gas, RngMachineSource::new(rng), config)
    }
}

#[cfg(feature = "arbitrary")]
impl Machine<ArbitraryMachineSource> {
    pub fn new_arbitrary(gas: u64, data: impl Into<Vec<u8>>, config: Config) -> Self {
        Self::from_source(gas, ArbitraryMachineSource::new(data), config)
    }
}

impl<S: MachineSource> Machine<S> {
    fn from_source(gas: u64, source: S, config: Config) -> Self {
        config.addresses.assert_valid();
        let caller = config.addresses.caller;
        let current_address = config.addresses.contract;
        // Root: the only safe initial CALL target is `caller` (a pre-funded
        // EOA with no code). `current_address` is the test contract — it has
        // code, so excluded.
        let mut machine = Self::with_context(
            gas,
            source,
            config,
            current_address,
            caller,
            1,
            vec![caller],
        );
        // Match EVM transaction execution semantics: the tx sender's nonce is
        // bumped before any bytecode runs.
        machine.bump_nonce(caller);
        machine
    }

    fn with_context(
        gas: u64,
        source: S,
        config: Config,
        current_address: Address,
        caller: Address,
        current_nonce: u64,
        callable_addresses: Vec<Address>,
    ) -> Self {
        let mut nonces = HashMap::from([(caller, 0)]);
        nonces.insert(current_address, current_nonce);
        Self {
            config,
            gas,
            source,
            memory: 0,
            stack: vec![],
            address_stack: vec![current_address],
            call_stack: vec![caller],
            nonces,
            callable_addresses,
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

    /// Draws the next opcode using this machine's configured source, opcode
    /// weights, and memory limits.
    pub fn next_opcode(&mut self) -> anyhow::Result<Opcode, Error> {
        self.source.next_opcode(&self.config)
    }

    /// Draws and ingests one configured opcode.
    pub fn ingest_next(&mut self) -> anyhow::Result<(), Error> {
        let op = self.next_opcode()?;
        self.ingest(op)
    }

    pub fn create_gas_percentage(&self) -> u8 {
        self.config.create_gas_percentage
    }

    pub fn bytecode_ops(&self) -> &[Opcode] {
        &self.bytecode
    }

    pub fn created_contracts(&self) -> Vec<Address> {
        let root_caller = *self
            .call_stack
            .first()
            .expect("machine call stack is always seeded with the root caller");
        let root_address = *self
            .address_stack
            .first()
            .expect("machine address stack is always seeded with the root contract");
        let mut created: Vec<_> = self
            .nonces
            .keys()
            .copied()
            .filter(|address| *address != root_caller && *address != root_address)
            .collect();
        created.sort_unstable_by(|left, right| left.as_slice().cmp(right.as_slice()));
        created
    }

    pub fn nonce_snapshot(&self) -> Vec<(Address, u64)> {
        let mut snapshot: Vec<_> = self
            .nonces
            .iter()
            .map(|(address, nonce)| (*address, *nonce))
            .collect();
        snapshot.sort_unstable_by(|left, right| left.0.as_slice().cmp(right.0.as_slice()));
        snapshot
    }

    fn current_address(&self) -> Address {
        *self
            .address_stack
            .last()
            .expect("machine address stack is always seeded with the current contract")
    }

    fn nonce_of(&self, address: Address) -> u64 {
        *self.nonces.get(&address).unwrap_or(&0)
    }

    fn bump_nonce(&mut self, address: Address) {
        let nonce = self.nonces.entry(address).or_insert(0);
        *nonce = nonce.checked_add(1).expect("nonce overflow");
    }

    fn pick_callable_address(&mut self) -> anyhow::Result<Address, Error> {
        let idx = self.source.pick_index(self.callable_addresses.len())?;
        Ok(self.callable_addresses[idx])
    }

    fn record_created_contract(
        &mut self,
        op: &Opcode,
        created_state: Option<CreatedContractState>,
    ) {
        match op {
            Opcode::Create(_init_code) => {
                let creator = self.current_address();
                let created_state = created_state.unwrap_or(CreatedContractState {
                    address: create_address(creator, self.nonce_of(creator)),
                    nonce: 1,
                });
                self.bump_nonce(creator);
                self.nonces
                    .insert(created_state.address, created_state.nonce);
                if self.config.grow_callable_on_create {
                    self.callable_addresses.push(created_state.address);
                }
            }
            Opcode::Create2(init_code, salt) => {
                let creator = self.current_address();
                let created_state = created_state.unwrap_or(CreatedContractState {
                    address: creator.create2_from_code(salt.to_be_bytes::<32>(), init_code),
                    nonce: 1,
                });
                self.bump_nonce(creator);
                self.nonces
                    .insert(created_state.address, created_state.nonce);
                if self.config.grow_callable_on_create {
                    self.callable_addresses.push(created_state.address);
                }
            }
            _ => {}
        }
    }

    fn validate_init_code_len(init_code_len: usize) -> anyhow::Result<(), Error> {
        const MAX_INIT_CODE: usize = 49152;
        if init_code_len > MAX_INIT_CODE {
            return Err(Error::MaxInitCode);
        }
        Ok(())
    }

    fn create_sub_budget(&self) -> u64 {
        let pct = self.config.create_gas_percentage as u64;
        self.gas.saturating_mul(pct) / 100
    }

    fn build_generated_submachine(
        &self,
        sub_budget: u64,
        mut gen_source: S,
        machine_source: S,
        current_address: Address,
        caller: Address,
    ) -> anyhow::Result<Self, Error> {
        let mut sub_config = self.config.clone();
        sub_config.allow_termination = false;
        sub_config.grow_callable_on_create = false;
        // Sub-machine inherits the parent's `callable_addresses` so CALL
        // target selection is independent of the sub's `current_address`.
        // That matters for CREATE2: `build_create2_init_code` runs two passes
        // (probe with placeholder address, final with the derived address),
        // and the rendered bytecode must be identical across both — otherwise
        // the keccak-derived create2 address diverges from runtime. The
        // parent's set already contains only safe (empty-code) targets.
        let mut sub_machine = Self::with_context(
            sub_budget,
            machine_source,
            sub_config,
            current_address,
            caller,
            1,
            self.callable_addresses.clone(),
        );
        loop {
            let inner = match gen_source.next_opcode(&sub_machine.config) {
                Ok(inner) => inner,
                Err(Error::InputExhausted) => break,
                Err(err) => return Err(err),
            };
            if sub_machine.ingest(inner).is_err() {
                break;
            }
        }
        Ok(sub_machine)
    }

    fn render_init_code<T: MachineSource>(
        sub_machine: &Machine<T>,
    ) -> anyhow::Result<Vec<u8>, Error> {
        // EIP-3860 caps init code at 49152 bytes; reserve 5 bytes for the
        // appended RETURN(0, 0) tail (PUSH1 0, PUSH1 0, RETURN).
        const MAX_INIT_CODE: usize = 49152 - 5;
        const RETURN_TAIL: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xF3];

        let mut init_code: Vec<u8> = Vec::new();
        for op in sub_machine.bytecode_ops() {
            let rendered = op.render();
            if init_code.len() + rendered.len() > MAX_INIT_CODE {
                return Err(Error::MaxInitCode);
            }
            init_code.extend_from_slice(&rendered);
        }
        init_code.extend_from_slice(&RETURN_TAIL);
        Self::validate_init_code_len(init_code.len())?;
        Ok(init_code)
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
        // gas budget and generation source.
        let (op, pending_created_state) = match op {
            Opcode::Create(ref payload) if payload.is_empty() => {
                let creator = self.current_address();
                let created_address = create_address(creator, self.nonce_of(creator));
                let init = self.build_init_code(created_address)?;
                (
                    Opcode::Create(init.code),
                    Some(CreatedContractState {
                        address: created_address,
                        nonce: init.created_nonce,
                    }),
                )
            }
            Opcode::Create2(ref payload, salt) if payload.is_empty() => {
                let creator = self.current_address();
                let init = self.build_create2_init_code(creator, salt)?;
                (
                    Opcode::Create2(init.code, salt),
                    Some(CreatedContractState {
                        address: init.address,
                        nonce: init.created_nonce,
                    }),
                )
            }
            // CALL materialization: pick the gas to forward (25% of remaining
            // outer gas) and a target address from the curated callable set.
            // The carried `gas` is what the rendered region pushes, so it must
            // match what `requires` charges — keep both in sync via the field
            // baked into the variant here.
            Opcode::Call {
                address,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            } if address == Address::ZERO => {
                let materialized_gas = self.gas / 4;
                let target = self.pick_callable_address()?;
                (
                    Opcode::Call {
                        gas: materialized_gas,
                        address: target,
                        args_offset,
                        args_size,
                        ret_offset,
                        ret_size,
                    },
                    None,
                )
            }
            Opcode::StaticCall {
                address,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            } if address == Address::ZERO => {
                let materialized_gas = self.gas / 4;
                let target = self.pick_callable_address()?;
                (
                    Opcode::StaticCall {
                        gas: materialized_gas,
                        address: target,
                        args_offset,
                        args_size,
                        ret_offset,
                        ret_size,
                    },
                    None,
                )
            }
            Opcode::DelegateCall {
                address,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            } if address == Address::ZERO => {
                let materialized_gas = self.gas / 4;
                let target = self.pick_callable_address()?;
                (
                    Opcode::DelegateCall {
                        gas: materialized_gas,
                        address: target,
                        args_offset,
                        args_size,
                        ret_offset,
                        ret_size,
                    },
                    None,
                )
            }
            other => (other, None),
        };
        match &op {
            Opcode::Create(init_code) | Opcode::Create2(init_code, _) => {
                Self::validate_init_code_len(init_code.len())?;
            }
            _ => {}
        }
        let mut pending_created_state = pending_created_state;
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
                let created_state = if matches!(op, Opcode::Create(_) | Opcode::Create2(_, _)) {
                    pending_created_state.take()
                } else {
                    None
                };
                self.record_created_contract(&op, created_state);
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
                stack.insert(0, self.source.push_opcode()?);
            }
            if constraints.stack() < 0 {
                stack.insert(0, Opcode::Pop);
            }
        }
        Ok(())
    }

    pub fn bytecode(&self) -> Vec<u8> {
        let mut bytecode: Vec<u8> = self.bytecode.iter().flat_map(|op| op.render()).collect();
        bytecode.push(0x00);
        bytecode
    }

    /// Generates the init code shared by CREATE and CREATE2: spawns a fresh
    /// sub-machine with `allow_termination = false` and a fraction of the
    /// outer's *current* remaining gas (per the configured percentage), runs
    /// the same generation loop as `main`, then either returns
    /// `Error::MaxInitCode` when another opcode would exceed the EIP-3860
    /// init code limit or appends a `RETURN(0, 0)` so the deploy frame
    /// returns empty runtime code (always passes EIP-170 / EIP-3541).
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
    fn build_init_code(
        &mut self,
        current_address: Address,
    ) -> anyhow::Result<GeneratedInitCode, Error> {
        let sub_budget = self.create_sub_budget();
        // Fork two independent sources from the outer's so the sub-machine's
        // internal constraint solver and the inner generator don't share state.
        let (gen_source, machine_source) = self.source.fork()?;
        let creator = self.current_address();
        let sub_machine = self.build_generated_submachine(
            sub_budget,
            gen_source,
            machine_source,
            current_address,
            creator,
        )?;
        let init_code = Self::render_init_code(&sub_machine)?;
        Ok(GeneratedInitCode {
            address: current_address,
            code: init_code,
            created_nonce: sub_machine.nonce_of(current_address),
        })
    }

    fn build_create2_init_code(
        &mut self,
        creator: Address,
        salt: U256,
    ) -> anyhow::Result<GeneratedInitCode, Error> {
        let sub_budget = self.create_sub_budget();
        let (gen_source, machine_source) = self.source.fork()?;

        let probe_machine = self.build_generated_submachine(
            sub_budget,
            gen_source.clone(),
            machine_source.clone(),
            Address::ZERO,
            creator,
        )?;
        let probe_code = Self::render_init_code(&probe_machine)?;
        let created_address = creator.create2_from_code(salt.to_be_bytes::<32>(), &probe_code);

        let final_machine = self.build_generated_submachine(
            sub_budget,
            gen_source,
            machine_source,
            created_address,
            creator,
        )?;
        let final_code = Self::render_init_code(&final_machine)?;
        debug_assert_eq!(probe_code, final_code);

        Ok(GeneratedInitCode {
            address: created_address,
            code: final_code,
            created_nonce: final_machine.nonce_of(created_address),
        })
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

#[derive(Debug)]
struct GeneratedInitCode {
    address: Address,
    code: Vec<u8>,
    created_nonce: u64,
}

fn create_address(caller: Address, nonce: u64) -> Address {
    let nonce_rlp = rlp_encode_nonce(nonce);
    let payload_len = 1 + 20 + nonce_rlp.len();
    let mut out = Vec::with_capacity(1 + payload_len);

    out.push(0xc0 + payload_len as u8);
    out.push(0x94);
    out.extend_from_slice(caller.as_slice());
    out.extend_from_slice(&nonce_rlp);

    Address::from_word(keccak256(out))
}

fn rlp_encode_nonce(nonce: u64) -> Vec<u8> {
    if nonce == 0 {
        return vec![0x80];
    }

    let bytes = nonce.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-zero nonce must have a non-zero byte");
    let trimmed = &bytes[first_non_zero..];

    if trimmed.len() == 1 && trimmed[0] < 0x80 {
        vec![trimmed[0]]
    } else {
        let mut out = Vec::with_capacity(1 + trimmed.len());
        out.push(0x80 + trimmed.len() as u8);
        out.extend_from_slice(trimmed);
        out
    }
}

#[cfg(all(test, feature = "rng"))]
mod tests {
    use super::*;

    #[test]
    fn new_machine_initializes_caller_state() {
        let addresses = ExecutionAddresses::default();
        let caller = addresses.caller;
        let machine = Machine::new_rng(1, Rng::with_seed(7), Config::default());

        assert_eq!(machine.call_stack, vec![caller]);
        assert_eq!(machine.nonces.get(&caller), Some(&1));
    }

    #[test]
    fn new_machine_uses_configured_addresses() {
        let addresses = ExecutionAddresses {
            caller: Address::from([0xAA; 20]),
            contract: Address::from([0xBB; 20]),
        };
        let config = Config {
            addresses,
            ..Config::default()
        };
        let machine = Machine::new_rng(1, Rng::with_seed(7), config);

        assert_eq!(machine.call_stack, vec![addresses.caller]);
        assert_eq!(machine.address_stack, vec![addresses.contract]);
        assert_eq!(machine.callable_addresses, vec![addresses.caller]);
        assert_eq!(machine.nonces.get(&addresses.caller), Some(&1));
        assert_eq!(machine.nonces.get(&addresses.contract), Some(&1));
    }

    #[test]
    fn ingest_next_uses_configured_opcode_weights() {
        let config = Config {
            opcode_weights: OpcodeWeights {
                calls: 1,
                ..OpcodeWeights::zero()
            },
            memory_offset_limit: 0,
            memory_length_limit: 0,
            ..Config::default()
        };
        let mut machine = Machine::new_rng(1_000_000, Rng::with_seed(7), config);

        machine.ingest_next().unwrap();

        assert!(matches!(
            machine.bytecode_ops()[0],
            Opcode::Call { .. } | Opcode::StaticCall { .. } | Opcode::DelegateCall { .. }
        ));
    }

    #[test]
    fn create_updates_nonce_map() {
        let addresses = ExecutionAddresses::default();
        let caller = addresses.caller;
        let code_addr = addresses.contract;
        let created = create_address(code_addr, 1);
        let mut machine = Machine::new_rng(100_000, Rng::with_seed(7), Config::default());

        assert!(
            machine
                .ingest(Opcode::Create(vec![0x60, 0x00, 0x60, 0x00, 0xF3]))
                .is_ok()
        );

        assert_eq!(machine.nonces.get(&caller), Some(&1));
        assert_eq!(machine.nonces.get(&code_addr), Some(&2));
        assert_eq!(machine.nonces.get(&created), Some(&1));
    }

    #[test]
    fn create2_updates_nonce_map() {
        let addresses = ExecutionAddresses::default();
        let caller = addresses.caller;
        let code_addr = addresses.contract;
        let init_code = vec![0x60, 0x00, 0x60, 0x00, 0xF3];
        let salt = U256::from(0x1234_u64);
        let created = code_addr.create2_from_code(salt.to_be_bytes::<32>(), &init_code);
        let mut machine = Machine::new_rng(100_000, Rng::with_seed(11), Config::default());

        assert!(machine.ingest(Opcode::Create2(init_code, salt)).is_ok());

        assert_eq!(machine.nonces.get(&caller), Some(&1));
        assert_eq!(machine.nonces.get(&code_addr), Some(&2));
        assert_eq!(machine.nonces.get(&created), Some(&1));
    }

    #[test]
    fn bytecode_always_appends_terminal_stop() {
        let mut machine = Machine::new_rng(100_000, Rng::with_seed(7), Config::default());

        machine.ingest(Opcode::Push1([0xAA])).unwrap();

        assert_eq!(machine.bytecode(), vec![0x60, 0xAA, 0x00]);
    }

    #[test]
    fn render_init_code_keeps_return_tail_without_export_stop() {
        let mut machine = Machine::new_rng(100_000, Rng::with_seed(7), Config::default());
        machine.ingest(Opcode::Push1([0xAA])).unwrap();

        let init_code = Machine::<RngMachineSource>::render_init_code(&machine).unwrap();

        assert_eq!(init_code, vec![0x60, 0xAA, 0x60, 0x00, 0x60, 0x00, 0xF3]);
    }

    #[test]
    fn oversized_init_code_returns_max_init_code() {
        let mut machine = Machine::new_rng(10_000_000, Rng::with_seed(13), Config::default());
        let oversized = vec![0u8; 49_153];

        let err = machine.ingest(Opcode::Create(oversized)).unwrap_err();

        assert_eq!(err, Error::MaxInitCode);
    }

    /// Demonstrates the invariant violation that `grow_callable_on_create =
    /// false` protects in sub-machines built for CREATE2.
    ///
    /// CREATE2's address derivation runs the sub-machine twice with the same
    /// seeds but DIFFERENT `current_address` (probe = `Address::ZERO`, final =
    /// the predicted address). For the predicted address to match what the
    /// runtime computes, both passes must render identical bytecode. With
    /// `grow_callable_on_create = true`, a nested CREATE inside the sub
    /// appends `create_address(sub.current_address, nonce)` to
    /// `callable_addresses` — and that entry differs between probe and final
    /// because `current_address` does. A subsequent CALL that picks that
    /// entry bakes 20 different bytes into the rendered bytecode via PUSH20.
    #[test]
    fn nested_create_taints_callable_when_grow_on_create_is_true() {
        let caller = Address::from([0x11; 20]);
        let mut config = Config::default();
        config.allow_termination = false;
        config.grow_callable_on_create = true; // bug-prone configuration

        let make_sub = |current_address: Address| {
            Machine::with_context(
                10_000_000,
                RngMachineSource::new(Rng::with_seed(0)),
                config.clone(),
                current_address,
                caller,
                1,
                vec![caller],
            )
        };

        // Probe pass uses Address::ZERO; final pass stands in for the
        // predicted CREATE2 address.
        let mut probe = make_sub(Address::ZERO);
        let mut finalised = make_sub(Address::from([0x42; 20]));

        // Concrete init code (RETURN(0,0)) so ingest doesn't recurse into a
        // sub-sub-machine — that would obscure the leak we're isolating.
        let init_code = vec![0x60, 0x00, 0x60, 0x00, 0xF3];
        probe.ingest(Opcode::Create(init_code.clone())).unwrap();
        finalised.ingest(Opcode::Create(init_code)).unwrap();

        // (1) callable_addresses now diverges. Index 0 (the inherited
        //     caller) matches; index 1 — the just-pushed nested-CREATE
        //     address — does not, because it's
        //     `create_address(current_address, 1)`.
        assert_eq!(probe.callable_addresses[0], caller);
        assert_eq!(finalised.callable_addresses[0], caller);
        assert_ne!(
            probe.callable_addresses[1], finalised.callable_addresses[1],
            "nested CREATE leaks current_address into callable_addresses"
        );

        // (2) Rendering a CALL with the diverging entry produces bytecode
        //     that differs in exactly the 20 bytes of the PUSH20 immediate
        //     — that is the divergence that would propagate through
        //     keccak256 and produce a wrong CREATE2 address.
        let render_call_to = |target: Address| {
            Opcode::Call {
                gas: 1_000,
                address: target,
                args_offset: 0,
                args_size: 0,
                ret_offset: 0,
                ret_size: 0,
            }
            .render()
        };
        let probe_call = render_call_to(probe.callable_addresses[1]);
        let final_call = render_call_to(finalised.callable_addresses[1]);

        assert_eq!(probe_call.len(), final_call.len());
        let diverging = probe_call
            .iter()
            .zip(final_call.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(diverging, 20, "exactly the PUSH20 address bytes diverge");
    }

    /// Counterpart to the previous test showing the fix in production code:
    /// with `grow_callable_on_create = false`, the nested CREATE still bumps
    /// nonces and tracks the new contract in `nonces`, but doesn't mutate
    /// `callable_addresses` — so probe and final passes carry identical
    /// callable lists, which is what makes their rendered bytecode match.
    #[test]
    fn nested_create_leaves_callable_alone_when_grow_on_create_is_false() {
        let caller = Address::from([0x11; 20]);
        let mut config = Config::default();
        config.allow_termination = false;
        config.grow_callable_on_create = false; // production setting in subs

        let make_sub = |current_address: Address| {
            Machine::with_context(
                10_000_000,
                RngMachineSource::new(Rng::with_seed(0)),
                config.clone(),
                current_address,
                caller,
                1,
                vec![caller],
            )
        };

        let mut probe = make_sub(Address::ZERO);
        let mut finalised = make_sub(Address::from([0x42; 20]));

        let init_code = vec![0x60, 0x00, 0x60, 0x00, 0xF3];
        probe.ingest(Opcode::Create(init_code.clone())).unwrap();
        finalised.ingest(Opcode::Create(init_code)).unwrap();

        // callable_addresses is identical (no append) → no leak path.
        assert_eq!(probe.callable_addresses, vec![caller]);
        assert_eq!(finalised.callable_addresses, vec![caller]);

        // Nonces still diverge — that's expected, but it doesn't affect
        // rendered bytecode. The outer doesn't read sub's internal nonce
        // map; it only reads `nonce_of(current_address)`, which is the
        // count of nested CREATEs (deterministic from the seed).
        let probe_nested_nonce = probe.nonce_of(Address::ZERO);
        let final_nested_nonce = finalised.nonce_of(Address::from([0x42; 20]));
        assert_eq!(probe_nested_nonce, final_nested_nonce);
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod arbitrary_tests {
    use super::*;

    #[test]
    fn new_machine_accepts_arbitrary_input_when_feature_is_enabled() {
        let mut machine = Machine::new(100_000, vec![0xAA, 0xBB], Config::default());

        machine.ingest(Opcode::Push1([0xCC])).unwrap();

        assert_eq!(machine.bytecode(), vec![0x60, 0xCC, 0x00]);
    }

    #[test]
    fn arbitrary_machine_materializes_placeholder_call() {
        let mut machine = Machine::new_arbitrary(100_000, Vec::new(), Config::default());

        machine
            .ingest(Opcode::Call {
                gas: 0,
                address: Address::ZERO,
                args_offset: 0,
                args_size: 0,
                ret_offset: 0,
                ret_size: 0,
            })
            .unwrap();

        let Opcode::Call { gas, address, .. } = &machine.bytecode_ops()[0] else {
            panic!("placeholder call should materialize into a call");
        };
        assert_eq!(*gas, 25_000);
        assert_eq!(*address, Config::default().addresses.caller);
    }
}
