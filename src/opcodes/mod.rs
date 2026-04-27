mod resource;
pub use resource::*;

use alloy_primitives::{Address, U256};
use fastrand::Rng;

use crate::machine::Machine;

/// EVM memory pricing: 3 * words + words^2 / 512, where words is the
/// number of 32-byte words required to cover `size_bytes`.
fn memory_word_cost(size_bytes: u64) -> u64 {
    let words = (size_bytes + 31) / 32;
    3u64.saturating_mul(words)
        .saturating_add(words.saturating_mul(words) / 512)
}

/// Round `bytes` up to the next 32-byte word boundary.
fn round_up_to_word(bytes: u64) -> u64 {
    ((bytes + 31) / 32).saturating_mul(32)
}

#[derive(Debug, Clone)]
pub enum Opcode {
    // Arithmetic (0x01..0x0B)
    Add,
    Mul,
    Sub,
    Div,
    SDiv,
    Mod,
    SMod,
    AddMod,
    MulMod,
    Exp,
    SignExtend,

    // Comparison (0x10..0x15)
    Lt,
    Gt,
    Slt,
    Sgt,
    Eq,
    IsZero,

    // Bitwise (0x16..0x1E)
    And,
    Or,
    Xor,
    Not,
    Byte,
    Shl,
    Shr,
    Sar,
    // Count leading zeros (EIP-7939, Osaka).
    Clz,

    // Environmental info (0x30..0x3F)
    Address,
    Balance,
    Origin,
    Caller,
    CallValue,
    CallDataSize,
    CodeSize,
    GasPrice,
    ExtCodeSize,
    ReturnDataSize,
    ExtCodeHash,

    // Block info (0x40..0x4A)
    BlockHash,
    CoinBase,
    TimeStamp,
    Number,
    PrevRandao,
    GasLimit,
    ChainId,
    SelfBalance,
    BaseFee,
    BlobHash,
    BlobBaseFee,

    // Stack / info / storage (0x50..0x5D)
    Pop,
    SLoad,
    SStore,
    Pc,
    MSize,
    Gas,
    TLoad,
    TStore,

    // Push (0x5F..0x7F)
    Push0,
    Push1([u8; 1]),
    Push2([u8; 2]),
    Push3([u8; 3]),
    Push4([u8; 4]),
    Push5([u8; 5]),
    Push6([u8; 6]),
    Push7([u8; 7]),
    Push8([u8; 8]),
    Push9([u8; 9]),
    Push10([u8; 10]),
    Push11([u8; 11]),
    Push12([u8; 12]),
    Push13([u8; 13]),
    Push14([u8; 14]),
    Push15([u8; 15]),
    Push16([u8; 16]),
    Push17([u8; 17]),
    Push18([u8; 18]),
    Push19([u8; 19]),
    Push20([u8; 20]),
    Push21([u8; 21]),
    Push22([u8; 22]),
    Push23([u8; 23]),
    Push24([u8; 24]),
    Push25([u8; 25]),
    Push26([u8; 26]),
    Push27([u8; 27]),
    Push28([u8; 28]),
    Push29([u8; 29]),
    Push30([u8; 30]),
    Push31([u8; 31]),
    Push32([u8; 32]),

    // Dup (0x80..0x8F)
    Dup1,
    Dup2,
    Dup3,
    Dup4,
    Dup5,
    Dup6,
    Dup7,
    Dup8,
    Dup9,
    Dup10,
    Dup11,
    Dup12,
    Dup13,
    Dup14,
    Dup15,
    Dup16,

    // Swap (0x90..0x9F)
    Swap1,
    Swap2,
    Swap3,
    Swap4,
    Swap5,
    Swap6,
    Swap7,
    Swap8,
    Swap9,
    Swap10,
    Swap11,
    Swap12,
    Swap13,
    Swap14,
    Swap15,
    Swap16,

    // Memory store (rendered as PUSH32 value, PUSH8 offset, MSTORE).
    MStore(u64, U256),
    // Memory load (rendered as PUSH8 offset, MLOAD).
    MLoad(u64),

    // LOG_N: (offset, length, topic1.., topicN). Rendered as PUSH32 topicN ‖ ... ‖
    // PUSH32 topic1 ‖ PUSH8 length ‖ PUSH8 offset ‖ LOGN.
    Log0(u64, u64),
    Log1(u64, u64, U256),
    Log2(u64, u64, U256, U256),
    Log3(u64, u64, U256, U256, U256),
    Log4(u64, u64, U256, U256, U256, U256),

    // 1-byte memory store: (offset, byte). PUSH1 byte ‖ PUSH8 offset ‖ MSTORE8.
    MStore8(u64, u8),
    // Memory→memory copy: (destOffset, srcOffset, length).
    MCopy(u64, u64, u64),
    // External-data → memory copies: (destOffset, srcOffset, length).
    CallDataCopy(u64, u64, u64),
    CodeCopy(u64, u64, u64),
    // (address, destOffset, srcOffset, length).
    ExtCodeCopy(U256, u64, u64, u64),

    // Halts the execution frame.
    Stop,
    // Reads 32 bytes from calldata at the given offset. Carried offset is
    // pushed on the stack via PUSH8 and CALLDATALOAD pops it / pushes the word.
    CallDataLoad(u64),

    // Frame-terminating ops with memory range (offset, length). Rendered as
    // PUSH8 length ‖ PUSH8 offset ‖ RETURN/REVERT.
    Return(u64, u64),
    Revert(u64, u64),

    // Hash of memory[offset..offset+length]. Rendered as
    // PUSH8 length ‖ PUSH8 offset ‖ KECCAK256.
    Keccak256(u64, u64),
    // Frame-terminating; sends the contract's balance to the beneficiary
    // address (low 160 bits of the U256). Rendered as PUSH32 ‖ SELFDESTRUCT.
    SelfDestruct(U256),

    // CREATE (0xF0). The carried `Vec<u8>` is the rendered init code (with a
    // trailing RETURN(0, 0) appended) that this op will MSTORE into outer
    // memory before issuing the CREATE. An empty `Vec` is the placeholder form
    // produced by `Opcode::generate`; `Machine::ingest` swaps it for a real
    // payload built from a sub-machine that uses a configured fraction of the
    // outer's remaining gas. Rendered as <MSTORE chain> ‖ PUSH8 size ‖
    // PUSH1 0 (offset) ‖ PUSH1 0 (value) ‖ CREATE.
    Create(Vec<u8>),
    // CREATE2 (0xF5). Same scheme as CREATE plus a U256 salt — the deployed
    // address depends on (caller, salt, keccak256(init_code)) per EIP-1014.
    // The salt is sampled at variant-generation time; the init code is
    // materialized lazily in `Machine::ingest` from a sub-machine. Rendered as
    // <MSTORE chain> ‖ PUSH32 salt ‖ PUSH8 size ‖ PUSH1 0 (offset) ‖
    // PUSH1 0 (value) ‖ CREATE2.
    Create2(Vec<u8>, U256),

    // CALL (0xF1). Memory ranges (`args_*`, `ret_*`) are sampled at generate
    // time; `gas` and `address` are materialized lazily by `Machine::ingest`
    // from outer state (gas = 25% of remaining; address = random pick from
    // `Machine::callable_addresses`). Placeholder form has `address ==
    // Address::ZERO`.
    //
    // The target is always an address with empty runtime code (caller of root,
    // or contracts created via our CREATE/CREATE2 — their init returns 0
    // bytes). That keeps the sub-call a no-op so the symbolic and runtime
    // state stay in sync without us tracking sub-frame effects.
    //
    // Rendered as: PUSH8 retSize ‖ PUSH8 retOffset ‖ PUSH8 argsSize ‖
    // PUSH8 argsOffset ‖ PUSH0 (value=0) ‖ PUSH20 address ‖ PUSH8 gas ‖ CALL.
    Call {
        gas: u64,
        address: Address,
        args_offset: u64,
        args_size: u64,
        ret_offset: u64,
        ret_size: u64,
    },

    // STATICCALL (0xFA). Same layout as CALL minus the value argument. The
    // sub-frame can't perform state-modifying ops; with our empty-code
    // targets it's a no-op anyway. Materialization mirrors CALL.
    StaticCall {
        gas: u64,
        address: Address,
        args_offset: u64,
        args_size: u64,
        ret_offset: u64,
        ret_size: u64,
    },

    // DELEGATECALL (0xF4). Same layout as STATICCALL. Executes the callee's
    // code in the caller's storage / sender / value context — but our
    // targets have empty code, so the sub-frame is a no-op. Materialization
    // mirrors CALL.
    DelegateCall {
        gas: u64,
        address: Address,
        args_offset: u64,
        args_size: u64,
        ret_offset: u64,
        ret_size: u64,
    },
}

/// Memory size required to access `offset..offset+length`. EVM does no memory
/// access (and no expansion) when length is zero.
fn memory_range_size(offset: u64, length: u64) -> u64 {
    if length == 0 {
        0
    } else {
        round_up_to_word(offset.saturating_add(length))
    }
}

/// Random `(offset, length)` for ops that touch a memory range. Offset capped
/// at `u16::MAX` to bound memory expansion gas; length capped at `u8::MAX` to
/// bound per-byte charges (e.g. LOG_DATA).
fn random_memory_range(rng: &mut Rng) -> (u64, u64) {
    (rng.u16(..) as u64, rng.u8(..) as u64)
}

fn random_topic(rng: &mut Rng) -> U256 {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    U256::from_be_bytes(bytes)
}

/// Per-word charge for *COPY / KECCAK256 style ops: 3 * ceil(length / 32).
fn copy_word_gas(length: u64) -> u64 {
    3u64.saturating_mul(length.saturating_add(31) / 32)
}

/// Memory size required by an op that writes `length` bytes at `dest`.
fn copy_memory_size_dest(dest: u64, length: u64) -> u64 {
    if length == 0 {
        0
    } else {
        round_up_to_word(dest.saturating_add(length))
    }
}

/// Memory size required by MCOPY (touches both source and destination regions).
fn copy_memory_size_two(dest: u64, src: u64, length: u64) -> u64 {
    if length == 0 {
        0
    } else {
        let a = round_up_to_word(dest.saturating_add(length));
        let b = round_up_to_word(src.saturating_add(length));
        a.max(b)
    }
}

/// (destOffset capped at u16, srcOffset capped at u16, length capped at u8).
fn random_copy_range(rng: &mut Rng) -> (u64, u64, u64) {
    (rng.u16(..) as u64, rng.u16(..) as u64, rng.u8(..) as u64)
}

impl Opcode {
    pub fn requires(&self, machine: &Machine) -> Resource {
        match self {
            // 3 gas, 2 stack (binary verylow ops)
            Opcode::Add
            | Opcode::Sub
            | Opcode::Lt
            | Opcode::Gt
            | Opcode::Slt
            | Opcode::Sgt
            | Opcode::Eq
            | Opcode::And
            | Opcode::Or
            | Opcode::Xor
            | Opcode::Byte
            | Opcode::Shl
            | Opcode::Shr
            | Opcode::Sar => Resource::builder().stack(2).gas(3).build(),

            // 3 gas, 1 stack (unary verylow ops)
            Opcode::IsZero | Opcode::Not => Resource::builder().stack(1).gas(3).build(),

            // 5 gas, 1 stack (CLZ — EIP-7939, Osaka).
            Opcode::Clz => Resource::builder().stack(1).gas(5).build(),

            // 5 gas, 2 stack (low ops)
            Opcode::Mul
            | Opcode::Div
            | Opcode::SDiv
            | Opcode::Mod
            | Opcode::SMod
            | Opcode::SignExtend => Resource::builder().stack(2).gas(5).build(),

            // 8 gas, 3 stack
            Opcode::AddMod | Opcode::MulMod => Resource::builder().stack(3).gas(8).build(),

            // EIP-160: 10 + 50 * byte_size(exponent); worst case is a 32-byte exponent.
            Opcode::Exp => Resource::builder().stack(2).gas(10 + 50 * 32).build(),

            // 2 gas, 1 stack
            Opcode::Pop => Resource::builder().stack(1).gas(2).build(),

            // EIP-2929: cold SLOAD costs 2100 gas.
            Opcode::SLoad => Resource::builder().stack(1).gas(2100).build(),
            // EIP-2929 + EIP-2200: cold + zero->nonzero SSTORE = 2100 + 20000 = 22100.
            // Worst case also satisfies the EIP-2200 2300-gas sentry.
            Opcode::SStore => Resource::builder().stack(2).gas(22100).build(),

            // EIP-1153: transient storage is flat 100 gas (no cold/warm split).
            Opcode::TLoad => Resource::builder().stack(1).gas(100).build(),
            Opcode::TStore => Resource::builder().stack(2).gas(100).build(),

            // 2 gas, 0 stack (base/nullary ops)
            Opcode::Address
            | Opcode::Origin
            | Opcode::Caller
            | Opcode::CallValue
            | Opcode::CallDataSize
            | Opcode::CodeSize
            | Opcode::GasPrice
            | Opcode::ReturnDataSize
            | Opcode::CoinBase
            | Opcode::TimeStamp
            | Opcode::Number
            | Opcode::PrevRandao
            | Opcode::GasLimit
            | Opcode::ChainId
            | Opcode::BaseFee
            | Opcode::BlobBaseFee
            | Opcode::Pc
            | Opcode::MSize
            | Opcode::Gas
            | Opcode::Push0 => Resource::builder().gas(2).build(),

            // EIP-2929: cold account access = 2600 gas
            Opcode::Balance | Opcode::ExtCodeSize | Opcode::ExtCodeHash => {
                Resource::builder().stack(1).gas(2600).build()
            }

            // 20 gas, 1 stack
            Opcode::BlockHash => Resource::builder().stack(1).gas(20).build(),

            // 5 gas, 0 stack
            Opcode::SelfBalance => Resource::builder().gas(5).build(),

            // 3 gas, 1 stack
            Opcode::BlobHash => Resource::builder().stack(1).gas(3).build(),

            // PUSH1..32: 3 gas, 0 stack
            Opcode::Push1(_)
            | Opcode::Push2(_)
            | Opcode::Push3(_)
            | Opcode::Push4(_)
            | Opcode::Push5(_)
            | Opcode::Push6(_)
            | Opcode::Push7(_)
            | Opcode::Push8(_)
            | Opcode::Push9(_)
            | Opcode::Push10(_)
            | Opcode::Push11(_)
            | Opcode::Push12(_)
            | Opcode::Push13(_)
            | Opcode::Push14(_)
            | Opcode::Push15(_)
            | Opcode::Push16(_)
            | Opcode::Push17(_)
            | Opcode::Push18(_)
            | Opcode::Push19(_)
            | Opcode::Push20(_)
            | Opcode::Push21(_)
            | Opcode::Push22(_)
            | Opcode::Push23(_)
            | Opcode::Push24(_)
            | Opcode::Push25(_)
            | Opcode::Push26(_)
            | Opcode::Push27(_)
            | Opcode::Push28(_)
            | Opcode::Push29(_)
            | Opcode::Push30(_)
            | Opcode::Push31(_)
            | Opcode::Push32(_) => Resource::builder().gas(3).build(),

            // DUP_n: 3 gas, requires n items present
            Opcode::Dup1 => Resource::builder().stack(1).gas(3).build(),
            Opcode::Dup2 => Resource::builder().stack(2).gas(3).build(),
            Opcode::Dup3 => Resource::builder().stack(3).gas(3).build(),
            Opcode::Dup4 => Resource::builder().stack(4).gas(3).build(),
            Opcode::Dup5 => Resource::builder().stack(5).gas(3).build(),
            Opcode::Dup6 => Resource::builder().stack(6).gas(3).build(),
            Opcode::Dup7 => Resource::builder().stack(7).gas(3).build(),
            Opcode::Dup8 => Resource::builder().stack(8).gas(3).build(),
            Opcode::Dup9 => Resource::builder().stack(9).gas(3).build(),
            Opcode::Dup10 => Resource::builder().stack(10).gas(3).build(),
            Opcode::Dup11 => Resource::builder().stack(11).gas(3).build(),
            Opcode::Dup12 => Resource::builder().stack(12).gas(3).build(),
            Opcode::Dup13 => Resource::builder().stack(13).gas(3).build(),
            Opcode::Dup14 => Resource::builder().stack(14).gas(3).build(),
            Opcode::Dup15 => Resource::builder().stack(15).gas(3).build(),
            Opcode::Dup16 => Resource::builder().stack(16).gas(3).build(),

            // SWAP_n: 3 gas, requires n+1 items present
            Opcode::Swap1 => Resource::builder().stack(2).gas(3).build(),
            Opcode::Swap2 => Resource::builder().stack(3).gas(3).build(),
            Opcode::Swap3 => Resource::builder().stack(4).gas(3).build(),
            Opcode::Swap4 => Resource::builder().stack(5).gas(3).build(),
            Opcode::Swap5 => Resource::builder().stack(6).gas(3).build(),
            Opcode::Swap6 => Resource::builder().stack(7).gas(3).build(),
            Opcode::Swap7 => Resource::builder().stack(8).gas(3).build(),
            Opcode::Swap8 => Resource::builder().stack(9).gas(3).build(),
            Opcode::Swap9 => Resource::builder().stack(10).gas(3).build(),
            Opcode::Swap10 => Resource::builder().stack(11).gas(3).build(),
            Opcode::Swap11 => Resource::builder().stack(12).gas(3).build(),
            Opcode::Swap12 => Resource::builder().stack(13).gas(3).build(),
            Opcode::Swap13 => Resource::builder().stack(14).gas(3).build(),
            Opcode::Swap14 => Resource::builder().stack(15).gas(3).build(),
            Opcode::Swap15 => Resource::builder().stack(16).gas(3).build(),
            Opcode::Swap16 => Resource::builder().stack(17).gas(3).build(),

            // Rendered as PUSH32 value (3) + PUSH8 offset (3) + MSTORE (3 + memory expansion).
            // Peak stack rise = 2 (the two embedded PUSHes before MSTORE pops them).
            Opcode::MStore(offset, _value) => {
                let new_size = round_up_to_word(offset.saturating_add(32));
                let expansion =
                    memory_word_cost(new_size).saturating_sub(memory_word_cost(machine.memory()));
                Resource::builder()
                    .stack_reserved(2)
                    .gas(9 + expansion)
                    .build()
            }
            // Rendered as PUSH8 offset (3) + MLOAD (3 + memory expansion). Peak rise = 1.
            Opcode::MLoad(offset) => {
                let new_size = round_up_to_word(offset.saturating_add(32));
                let expansion =
                    memory_word_cost(new_size).saturating_sub(memory_word_cost(machine.memory()));
                Resource::builder()
                    .stack_reserved(1)
                    .gas(6 + expansion)
                    .build()
            }
            // LOG_N: (N+2) embedded pushes (3 gas each) + 375*(N+1) base + 8*length + expansion.
            // Peak rise = N+2 (all embedded pushes accumulate before LOG_N pops them).
            Opcode::Log0(offset, length) => {
                let needed = memory_range_size(*offset, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (0 + 2);
                let log_gas = 375 * (0 + 1) + 8u64.saturating_mul(*length);
                Resource::builder()
                    .stack_reserved(2)
                    .gas(push_gas + log_gas + expansion)
                    .build()
            }
            Opcode::Log1(offset, length, _) => {
                let needed = memory_range_size(*offset, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (1 + 2);
                let log_gas = 375 * (1 + 1) + 8u64.saturating_mul(*length);
                Resource::builder()
                    .stack_reserved(3)
                    .gas(push_gas + log_gas + expansion)
                    .build()
            }
            Opcode::Log2(offset, length, _, _) => {
                let needed = memory_range_size(*offset, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (2 + 2);
                let log_gas = 375 * (2 + 1) + 8u64.saturating_mul(*length);
                Resource::builder()
                    .stack_reserved(4)
                    .gas(push_gas + log_gas + expansion)
                    .build()
            }
            Opcode::Log3(offset, length, _, _, _) => {
                let needed = memory_range_size(*offset, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (3 + 2);
                let log_gas = 375 * (3 + 1) + 8u64.saturating_mul(*length);
                Resource::builder()
                    .stack_reserved(5)
                    .gas(push_gas + log_gas + expansion)
                    .build()
            }
            Opcode::Log4(offset, length, _, _, _, _) => {
                let needed = memory_range_size(*offset, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (4 + 2);
                let log_gas = 375 * (4 + 1) + 8u64.saturating_mul(*length);
                Resource::builder()
                    .stack_reserved(6)
                    .gas(push_gas + log_gas + expansion)
                    .build()
            }
            // PUSH1 byte (3) + PUSH8 offset (3) + MSTORE8 (3 + memory expansion). Peak rise = 2.
            Opcode::MStore8(offset, _byte) => {
                let new_size = round_up_to_word(offset.saturating_add(1));
                let expansion =
                    memory_word_cost(new_size).saturating_sub(memory_word_cost(machine.memory()));
                Resource::builder()
                    .stack_reserved(2)
                    .gas(9 + expansion)
                    .build()
            }
            // 3 PUSH8 (9) + MCOPY (3 + 3·words(length) + expansion over both regions). Peak rise = 3.
            Opcode::MCopy(dest, src, length) => {
                let needed = copy_memory_size_two(*dest, *src, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                Resource::builder()
                    .stack_reserved(3)
                    .gas(12 + copy_word_gas(*length) + expansion)
                    .build()
            }
            // 3 PUSH8 (9) + COPY_OP (3 + 3·words(length) + expansion to dest+length). Peak rise = 3.
            Opcode::CallDataCopy(dest, _src, length) | Opcode::CodeCopy(dest, _src, length) => {
                let needed = copy_memory_size_dest(*dest, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                Resource::builder()
                    .stack_reserved(3)
                    .gas(12 + copy_word_gas(*length) + expansion)
                    .build()
            }
            // PUSH8 length + PUSH8 src + PUSH8 dest + PUSH32 address (12) +
            // EXTCODECOPY (2600 cold + 3·words(length) + expansion to dest+length). Peak rise = 4.
            Opcode::ExtCodeCopy(_addr, dest, _src, length) => {
                let needed = copy_memory_size_dest(*dest, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                Resource::builder()
                    .stack_reserved(4)
                    .gas(12 + 2600 + copy_word_gas(*length) + expansion)
                    .build()
            }
            // STOP terminates execution. After committing it, `Machine::ingest`
            // returns Err(HaltConditionEncountered) to stop emitting
            // unreachable bytecode.
            Opcode::Stop => Resource::builder().build(),
            // PUSH8 offset (3) + CALLDATALOAD (3); no memory expansion. Peak rise = 1.
            Opcode::CallDataLoad(_offset) => Resource::builder().stack_reserved(1).gas(6).build(),
            // PUSH8 length (3) + PUSH8 offset (3) + RETURN/REVERT (0 + memory expansion).
            // Peak rise = 2.
            Opcode::Return(offset, length) | Opcode::Revert(offset, length) => {
                let needed = memory_range_size(*offset, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                Resource::builder()
                    .stack_reserved(2)
                    .gas(6 + expansion)
                    .build()
            }
            // PUSH8 length (3) + PUSH8 offset (3) + KECCAK256
            // (30 base + 6·words(length) + memory expansion). Peak rise = 2.
            Opcode::Keccak256(offset, length) => {
                let needed = memory_range_size(*offset, *length);
                let expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
                let words = length.saturating_add(31) / 32;
                Resource::builder()
                    .stack_reserved(2)
                    .gas(6 + 30 + 6u64.saturating_mul(words) + expansion)
                    .build()
            }
            // PUSH32 beneficiary (3) + SELFDESTRUCT (5000 + 2600 cold +
            // 25000 new-account; 32603 total worst case). Peak rise = 1.
            Opcode::SelfDestruct(_beneficiary) => {
                Resource::builder().stack_reserved(1).gas(3 + 32600).build()
            }
            // CREATE: outer charge breakdown (everything the rendered region
            // consumes from the outer's gas, conservatively over-estimated):
            //   - per-word setup MSTOREs of the init code: 9 gas/word
            //     (PUSH32 value + PUSH8 offset + MSTORE) plus memory expansion.
            //   - 9 gas for the 3 args we push (PUSH8 size, PUSH1 0, PUSH1 0).
            //   - 32000 base.
            //   - EIP-3860: 2 gas/word of init code.
            //   - Sub-call budget. EVM forwards 63/64 of the gas remaining
            //     after the base fee, so we charge ⌈64·sub_budget/63⌉ to
            //     guarantee that the forwarded amount covers the sub-machine's
            //     worst-case symbolic consumption (= sub_budget).
            //
            // Stack model: `stack_reserved(3)` (the 3 PUSHes raise the peak
            // by 3 above entry before CREATE pops them) and `provides.stack(1)`
            // for the resulting address. The constraint solver pops as many
            // items as needed to keep entry + 3 ≤ 1024.
            Opcode::Create(init_code) => {
                let init_code_len = init_code.len() as u64;
                let words = init_code_len.saturating_add(31) / 32;
                let new_mem = words.saturating_mul(32);
                let mem_expansion =
                    memory_word_cost(new_mem).saturating_sub(memory_word_cost(machine.memory()));
                let mstore_setup = 9u64.saturating_mul(words);
                let push_args = 9u64; // PUSH8 size + 2 * PUSH1 0
                let create_base = 32000u64;
                let eip3860 = 2u64.saturating_mul(words);
                let pct = machine.create_gas_percentage() as u64;
                let sub_budget = machine.gas().saturating_mul(pct) / 100;
                // ⌈64·sub_budget/63⌉ — guarantees 63/64-forwarded gas covers it.
                let sub_charge = sub_budget.saturating_mul(64).saturating_add(62) / 63;
                let total = create_base
                    .saturating_add(eip3860)
                    .saturating_add(mstore_setup)
                    .saturating_add(mem_expansion)
                    .saturating_add(push_args)
                    .saturating_add(sub_charge);
                Resource::builder().stack_reserved(3).gas(total).build()
            }
            // CREATE2: same as CREATE plus 6 gas/word for the keccak over the
            // init code (EIP-1014 address derivation), plus one extra PUSH32
            // (3 gas) for the salt argument. Stack model: stack_reserved(4)
            // because the render pushes salt + size + offset + value before
            // CREATE2 pops them.
            Opcode::Create2(init_code, _salt) => {
                let init_code_len = init_code.len() as u64;
                let words = init_code_len.saturating_add(31) / 32;
                let new_mem = words.saturating_mul(32);
                let mem_expansion =
                    memory_word_cost(new_mem).saturating_sub(memory_word_cost(machine.memory()));
                let mstore_setup = 9u64.saturating_mul(words);
                let push_args = 12u64; // PUSH32 salt + PUSH8 size + 2 * PUSH1 0
                let create2_base = 32000u64;
                let eip3860 = 2u64.saturating_mul(words);
                let keccak_cost = 6u64.saturating_mul(words);
                let pct = machine.create_gas_percentage() as u64;
                let sub_budget = machine.gas().saturating_mul(pct) / 100;
                let sub_charge = sub_budget.saturating_mul(64).saturating_add(62) / 63;
                let total = create2_base
                    .saturating_add(eip3860)
                    .saturating_add(keccak_cost)
                    .saturating_add(mstore_setup)
                    .saturating_add(mem_expansion)
                    .saturating_add(push_args)
                    .saturating_add(sub_charge);
                Resource::builder().stack_reserved(4).gas(total).build()
            }
            // CALL outer charge: 100 (warm base — all targets are pre-warmed)
            // + 20 (push gas: 4·PUSH8 + PUSH0 + PUSH20 + PUSH8) + memory
            // expansion (max of args and ret regions) + `gas` (the forwarded
            // budget, baked in at materialization). Worst case the EVM forwards
            // exactly `gas` and the sub-frame consumes all of it.
            //
            // Stack model: stack_reserved(7) for the 7 inline pushes; CALL
            // pops them and pushes the success flag.
            Opcode::Call {
                gas,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            } => {
                let args_region = memory_range_size(*args_offset, *args_size);
                let ret_region = memory_range_size(*ret_offset, *ret_size);
                let needed = args_region.max(ret_region);
                let mem_expansion = memory_word_cost(needed)
                    .saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 4 * 3 + 2 + 3 + 3; // 4·PUSH8 + PUSH0 + PUSH20 + PUSH8
                let base = 100u64;
                let total = base
                    .saturating_add(push_gas)
                    .saturating_add(mem_expansion)
                    .saturating_add(*gas);
                Resource::builder().stack_reserved(7).gas(total).build()
            }
            // STATICCALL / DELEGATECALL: same shape as CALL minus the value
            // arg. Push gas drops to 18 (4·PUSH8 + PUSH20 + PUSH8) and only
            // 6 inline pushes get reserved on the stack.
            Opcode::StaticCall {
                gas,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            }
            | Opcode::DelegateCall {
                gas,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            } => {
                let args_region = memory_range_size(*args_offset, *args_size);
                let ret_region = memory_range_size(*ret_offset, *ret_size);
                let needed = args_region.max(ret_region);
                let mem_expansion = memory_word_cost(needed)
                    .saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 4 * 3 + 3 + 3; // 4·PUSH8 + PUSH20 + PUSH8
                let base = 100u64;
                let total = base
                    .saturating_add(push_gas)
                    .saturating_add(mem_expansion)
                    .saturating_add(*gas);
                Resource::builder().stack_reserved(6).gas(total).build()
            }
        }
    }

    /// Returns true for opcodes that halt the current execution frame on
    /// commit (STOP, RETURN, REVERT, SELFDESTRUCT).
    pub fn is_terminating(&self) -> bool {
        matches!(
            self,
            Opcode::Stop | Opcode::Return(..) | Opcode::Revert(..) | Opcode::SelfDestruct(..)
        )
    }

    pub fn provides(&self, machine: &Machine) -> Resource {
        match self {
            Opcode::Pop | Opcode::SStore | Opcode::TStore | Opcode::Stop => {
                Resource::builder().build()
            }
            // RETURN / REVERT produce no stack output but may grow memory to
            // cover offset..offset+length.
            Opcode::Return(offset, length) | Opcode::Revert(offset, length) => {
                let needed = memory_range_size(*offset, *length);
                let increment = needed.saturating_sub(machine.memory());
                Resource::builder().memory(increment).build()
            }
            // KECCAK256 pushes the hash and may grow memory.
            Opcode::Keccak256(offset, length) => {
                let needed = memory_range_size(*offset, *length);
                let increment = needed.saturating_sub(machine.memory());
                Resource::builder().stack(1).memory(increment).build()
            }
            // SELFDESTRUCT produces nothing on the stack and halts the frame.
            Opcode::SelfDestruct(_beneficiary) => Resource::builder().build(),
            // MStore is stack-neutral; it grows memory to cover offset..offset+32.
            Opcode::MStore(offset, _value) => {
                let new_size = round_up_to_word(offset.saturating_add(32));
                let increment = new_size.saturating_sub(machine.memory());
                Resource::builder().memory(increment).build()
            }
            // MLoad pushes the loaded word and grows memory to cover offset..offset+32.
            Opcode::MLoad(offset) => {
                let new_size = round_up_to_word(offset.saturating_add(32));
                let increment = new_size.saturating_sub(machine.memory());
                Resource::builder().stack(1).memory(increment).build()
            }
            // LOG_N produces no stack output; it may grow memory to cover offset..offset+length.
            Opcode::Log0(offset, length)
            | Opcode::Log1(offset, length, ..)
            | Opcode::Log2(offset, length, ..)
            | Opcode::Log3(offset, length, ..)
            | Opcode::Log4(offset, length, ..) => {
                let needed = memory_range_size(*offset, *length);
                let increment = needed.saturating_sub(machine.memory());
                Resource::builder().memory(increment).build()
            }
            // MSTORE8 grows memory to cover offset..offset+1.
            Opcode::MStore8(offset, _byte) => {
                let new_size = round_up_to_word(offset.saturating_add(1));
                let increment = new_size.saturating_sub(machine.memory());
                Resource::builder().memory(increment).build()
            }
            // MCOPY touches both regions; expansion = max of the two.
            Opcode::MCopy(dest, src, length) => {
                let needed = copy_memory_size_two(*dest, *src, *length);
                let increment = needed.saturating_sub(machine.memory());
                Resource::builder().memory(increment).build()
            }
            // *COPY (writes only) — only the dest region matters.
            Opcode::CallDataCopy(dest, _src, length) | Opcode::CodeCopy(dest, _src, length) => {
                let needed = copy_memory_size_dest(*dest, *length);
                let increment = needed.saturating_sub(machine.memory());
                Resource::builder().memory(increment).build()
            }
            Opcode::ExtCodeCopy(_addr, dest, _src, length) => {
                let needed = copy_memory_size_dest(*dest, *length);
                let increment = needed.saturating_sub(machine.memory());
                Resource::builder().memory(increment).build()
            }
            // CREATE writes the init code to memory[0..init_code_len_padded]
            // and pushes the deployed address (or zero on sub-call failure).
            Opcode::Create(init_code) | Opcode::Create2(init_code, _) => {
                let words = (init_code.len() as u64).saturating_add(31) / 32;
                let new_mem = words.saturating_mul(32);
                let increment = new_mem.saturating_sub(machine.memory());
                Resource::builder().stack(1).memory(increment).build()
            }
            // CALL / STATICCALL / DELEGATECALL push the 0/1 success flag
            // and may grow memory to cover the args input and ret output
            // regions.
            Opcode::Call {
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            }
            | Opcode::StaticCall {
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            }
            | Opcode::DelegateCall {
                args_offset,
                args_size,
                ret_offset,
                ret_size,
                ..
            } => {
                let args_region = memory_range_size(*args_offset, *args_size);
                let ret_region = memory_range_size(*ret_offset, *ret_size);
                let needed = args_region.max(ret_region);
                let increment = needed.saturating_sub(machine.memory());
                Resource::builder().stack(1).memory(increment).build()
            }
            // DUP_n leaves n+1 items; SWAP_n leaves n+1 items.
            Opcode::Dup1 | Opcode::Swap1 => Resource::builder().stack(2).build(),
            Opcode::Dup2 | Opcode::Swap2 => Resource::builder().stack(3).build(),
            Opcode::Dup3 | Opcode::Swap3 => Resource::builder().stack(4).build(),
            Opcode::Dup4 | Opcode::Swap4 => Resource::builder().stack(5).build(),
            Opcode::Dup5 | Opcode::Swap5 => Resource::builder().stack(6).build(),
            Opcode::Dup6 | Opcode::Swap6 => Resource::builder().stack(7).build(),
            Opcode::Dup7 | Opcode::Swap7 => Resource::builder().stack(8).build(),
            Opcode::Dup8 | Opcode::Swap8 => Resource::builder().stack(9).build(),
            Opcode::Dup9 | Opcode::Swap9 => Resource::builder().stack(10).build(),
            Opcode::Dup10 | Opcode::Swap10 => Resource::builder().stack(11).build(),
            Opcode::Dup11 | Opcode::Swap11 => Resource::builder().stack(12).build(),
            Opcode::Dup12 | Opcode::Swap12 => Resource::builder().stack(13).build(),
            Opcode::Dup13 | Opcode::Swap13 => Resource::builder().stack(14).build(),
            Opcode::Dup14 | Opcode::Swap14 => Resource::builder().stack(15).build(),
            Opcode::Dup15 | Opcode::Swap15 => Resource::builder().stack(16).build(),
            Opcode::Dup16 | Opcode::Swap16 => Resource::builder().stack(17).build(),
            _ => Resource::builder().stack(1).build(),
        }
    }

    /// Returns a uniformly-random `Opcode` variant. For `Push*` variants the
    /// immediate-byte array is filled with random bytes from `rng`.
    pub fn generate(rng: &mut Rng) -> Opcode {
        const VARIANT_COUNT: usize = 144;
        Self::nth_variant(rng.usize(0..VARIANT_COUNT), rng)
    }

    /// Returns a uniformly-random `Push*` variant with random immediate bytes.
    /// (Picks among Push1..Push32; Push0 is excluded.)
    pub fn generate_push(rng: &mut Rng) -> Opcode {
        const PUSH_OFFSET: usize = 56;
        const PUSH_COUNT: usize = 32;
        Self::nth_variant(PUSH_OFFSET + rng.usize(0..PUSH_COUNT), rng)
    }

    fn nth_variant(idx: usize, rng: &mut Rng) -> Opcode {
        match idx {
            0 => Opcode::Add,
            1 => Opcode::Mul,
            2 => Opcode::Sub,
            3 => Opcode::Div,
            4 => Opcode::SDiv,
            5 => Opcode::Mod,
            6 => Opcode::SMod,
            7 => Opcode::AddMod,
            8 => Opcode::MulMod,
            9 => Opcode::Exp,
            10 => Opcode::SignExtend,
            11 => Opcode::Lt,
            12 => Opcode::Gt,
            13 => Opcode::Slt,
            14 => Opcode::Sgt,
            15 => Opcode::Eq,
            16 => Opcode::IsZero,
            17 => Opcode::And,
            18 => Opcode::Or,
            19 => Opcode::Xor,
            20 => Opcode::Not,
            21 => Opcode::Byte,
            22 => Opcode::Shl,
            23 => Opcode::Shr,
            24 => Opcode::Sar,
            25 => Opcode::Address,
            26 => Opcode::Balance,
            27 => Opcode::Origin,
            28 => Opcode::Caller,
            29 => Opcode::CallValue,
            30 => Opcode::CallDataSize,
            31 => Opcode::CodeSize,
            32 => Opcode::GasPrice,
            33 => Opcode::ExtCodeSize,
            34 => Opcode::ReturnDataSize,
            35 => Opcode::ExtCodeHash,
            36 => Opcode::BlockHash,
            37 => Opcode::CoinBase,
            38 => Opcode::TimeStamp,
            39 => Opcode::Number,
            40 => Opcode::PrevRandao,
            41 => Opcode::GasLimit,
            42 => Opcode::ChainId,
            43 => Opcode::SelfBalance,
            44 => Opcode::BaseFee,
            45 => Opcode::BlobHash,
            46 => Opcode::BlobBaseFee,
            47 => Opcode::Pop,
            48 => Opcode::SLoad,
            49 => Opcode::SStore,
            50 => Opcode::Pc,
            51 => Opcode::MSize,
            52 => Opcode::Gas,
            53 => Opcode::TLoad,
            54 => Opcode::TStore,
            55 => Opcode::Push0,
            56 => {
                let mut b = [0u8; 1];
                rng.fill(&mut b);
                Opcode::Push1(b)
            }
            57 => {
                let mut b = [0u8; 2];
                rng.fill(&mut b);
                Opcode::Push2(b)
            }
            58 => {
                let mut b = [0u8; 3];
                rng.fill(&mut b);
                Opcode::Push3(b)
            }
            59 => {
                let mut b = [0u8; 4];
                rng.fill(&mut b);
                Opcode::Push4(b)
            }
            60 => {
                let mut b = [0u8; 5];
                rng.fill(&mut b);
                Opcode::Push5(b)
            }
            61 => {
                let mut b = [0u8; 6];
                rng.fill(&mut b);
                Opcode::Push6(b)
            }
            62 => {
                let mut b = [0u8; 7];
                rng.fill(&mut b);
                Opcode::Push7(b)
            }
            63 => {
                let mut b = [0u8; 8];
                rng.fill(&mut b);
                Opcode::Push8(b)
            }
            64 => {
                let mut b = [0u8; 9];
                rng.fill(&mut b);
                Opcode::Push9(b)
            }
            65 => {
                let mut b = [0u8; 10];
                rng.fill(&mut b);
                Opcode::Push10(b)
            }
            66 => {
                let mut b = [0u8; 11];
                rng.fill(&mut b);
                Opcode::Push11(b)
            }
            67 => {
                let mut b = [0u8; 12];
                rng.fill(&mut b);
                Opcode::Push12(b)
            }
            68 => {
                let mut b = [0u8; 13];
                rng.fill(&mut b);
                Opcode::Push13(b)
            }
            69 => {
                let mut b = [0u8; 14];
                rng.fill(&mut b);
                Opcode::Push14(b)
            }
            70 => {
                let mut b = [0u8; 15];
                rng.fill(&mut b);
                Opcode::Push15(b)
            }
            71 => {
                let mut b = [0u8; 16];
                rng.fill(&mut b);
                Opcode::Push16(b)
            }
            72 => {
                let mut b = [0u8; 17];
                rng.fill(&mut b);
                Opcode::Push17(b)
            }
            73 => {
                let mut b = [0u8; 18];
                rng.fill(&mut b);
                Opcode::Push18(b)
            }
            74 => {
                let mut b = [0u8; 19];
                rng.fill(&mut b);
                Opcode::Push19(b)
            }
            75 => {
                let mut b = [0u8; 20];
                rng.fill(&mut b);
                Opcode::Push20(b)
            }
            76 => {
                let mut b = [0u8; 21];
                rng.fill(&mut b);
                Opcode::Push21(b)
            }
            77 => {
                let mut b = [0u8; 22];
                rng.fill(&mut b);
                Opcode::Push22(b)
            }
            78 => {
                let mut b = [0u8; 23];
                rng.fill(&mut b);
                Opcode::Push23(b)
            }
            79 => {
                let mut b = [0u8; 24];
                rng.fill(&mut b);
                Opcode::Push24(b)
            }
            80 => {
                let mut b = [0u8; 25];
                rng.fill(&mut b);
                Opcode::Push25(b)
            }
            81 => {
                let mut b = [0u8; 26];
                rng.fill(&mut b);
                Opcode::Push26(b)
            }
            82 => {
                let mut b = [0u8; 27];
                rng.fill(&mut b);
                Opcode::Push27(b)
            }
            83 => {
                let mut b = [0u8; 28];
                rng.fill(&mut b);
                Opcode::Push28(b)
            }
            84 => {
                let mut b = [0u8; 29];
                rng.fill(&mut b);
                Opcode::Push29(b)
            }
            85 => {
                let mut b = [0u8; 30];
                rng.fill(&mut b);
                Opcode::Push30(b)
            }
            86 => {
                let mut b = [0u8; 31];
                rng.fill(&mut b);
                Opcode::Push31(b)
            }
            87 => {
                let mut b = [0u8; 32];
                rng.fill(&mut b);
                Opcode::Push32(b)
            }
            88 => Opcode::Dup1,
            89 => Opcode::Dup2,
            90 => Opcode::Dup3,
            91 => Opcode::Dup4,
            92 => Opcode::Dup5,
            93 => Opcode::Dup6,
            94 => Opcode::Dup7,
            95 => Opcode::Dup8,
            96 => Opcode::Dup9,
            97 => Opcode::Dup10,
            98 => Opcode::Dup11,
            99 => Opcode::Dup12,
            100 => Opcode::Dup13,
            101 => Opcode::Dup14,
            102 => Opcode::Dup15,
            103 => Opcode::Dup16,
            104 => Opcode::Swap1,
            105 => Opcode::Swap2,
            106 => Opcode::Swap3,
            107 => Opcode::Swap4,
            108 => Opcode::Swap5,
            109 => Opcode::Swap6,
            110 => Opcode::Swap7,
            111 => Opcode::Swap8,
            112 => Opcode::Swap9,
            113 => Opcode::Swap10,
            114 => Opcode::Swap11,
            115 => Opcode::Swap12,
            116 => Opcode::Swap13,
            117 => Opcode::Swap14,
            118 => Opcode::Swap15,
            119 => Opcode::Swap16,
            120 => {
                // NOTE: MSTORE memory offset capped at u16.
                // Cap offset at u16 to keep memory expansion gas tractable.
                let offset = rng.u16(..) as u64;
                let mut value_bytes = [0u8; 32];
                rng.fill(&mut value_bytes);
                Opcode::MStore(offset, U256::from_be_bytes(value_bytes))
            }
            121 => {
                // NOTE: MLOAD memory offset capped at u16.
                let offset = rng.u16(..) as u64;
                Opcode::MLoad(offset)
            }
            122 => {
                let (offset, length) = random_memory_range(rng);
                Opcode::Log0(offset, length)
            }
            123 => {
                let (offset, length) = random_memory_range(rng);
                Opcode::Log1(offset, length, random_topic(rng))
            }
            124 => {
                let (offset, length) = random_memory_range(rng);
                Opcode::Log2(offset, length, random_topic(rng), random_topic(rng))
            }
            125 => {
                let (offset, length) = random_memory_range(rng);
                Opcode::Log3(
                    offset,
                    length,
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                )
            }
            126 => {
                let (offset, length) = random_memory_range(rng);
                Opcode::Log4(
                    offset,
                    length,
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                )
            }
            127 => Opcode::MStore8(rng.u16(..) as u64, rng.u8(..)),
            128 => {
                let (dest, src, length) = random_copy_range(rng);
                Opcode::MCopy(dest, src, length)
            }
            129 => {
                let (dest, src, length) = random_copy_range(rng);
                Opcode::CallDataCopy(dest, src, length)
            }
            130 => {
                let (dest, src, length) = random_copy_range(rng);
                Opcode::CodeCopy(dest, src, length)
            }
            131 => {
                let (dest, src, length) = random_copy_range(rng);
                Opcode::ExtCodeCopy(random_topic(rng), dest, src, length)
            }
            132 => Opcode::Stop,
            133 => Opcode::CallDataLoad(rng.u16(..) as u64),
            134 => {
                let (offset, length) = random_memory_range(rng);
                Opcode::Return(offset, length)
            }
            135 => {
                let (offset, length) = random_memory_range(rng);
                Opcode::Revert(offset, length)
            }
            136 => {
                let (offset, length) = random_memory_range(rng);
                Opcode::Keccak256(offset, length)
            }
            137 => Opcode::SelfDestruct(random_topic(rng)),
            // Placeholder. Real init code is materialized by `Machine::ingest`
            // (which has access to outer gas + RNG) the first time this is
            // ingested; subsequent ingestions of the same value would re-use
            // the populated payload.
            138 => Opcode::Create(Vec::new()),
            // CREATE2 placeholder; salt is sampled now (it does not depend on
            // outer machine state), init code is materialized lazily.
            139 => Opcode::Create2(Vec::new(), random_topic(rng)),
            // CALL placeholder. Memory ranges are sampled now; gas and target
            // address are filled in by `Machine::ingest` (they depend on outer
            // state). The placeholder is detected by `address == Address::ZERO`.
            140 => {
                let (args_offset, args_size) = random_memory_range(rng);
                let (ret_offset, ret_size) = random_memory_range(rng);
                Opcode::Call {
                    gas: 0,
                    address: Address::ZERO,
                    args_offset,
                    args_size,
                    ret_offset,
                    ret_size,
                }
            }
            // STATICCALL / DELEGATECALL placeholders. Same materialization
            // rules as CALL.
            141 => {
                let (args_offset, args_size) = random_memory_range(rng);
                let (ret_offset, ret_size) = random_memory_range(rng);
                Opcode::StaticCall {
                    gas: 0,
                    address: Address::ZERO,
                    args_offset,
                    args_size,
                    ret_offset,
                    ret_size,
                }
            }
            142 => {
                let (args_offset, args_size) = random_memory_range(rng);
                let (ret_offset, ret_size) = random_memory_range(rng);
                Opcode::DelegateCall {
                    gas: 0,
                    address: Address::ZERO,
                    args_offset,
                    args_size,
                    ret_offset,
                    ret_size,
                }
            }
            143 => Opcode::Clz,
            _ => unreachable!("nth_variant: idx {} out of range", idx),
        }
    }

    pub fn render(&self) -> Vec<u8> {
        match self {
            Opcode::Add => vec![0x01],
            Opcode::Mul => vec![0x02],
            Opcode::Sub => vec![0x03],
            Opcode::Div => vec![0x04],
            Opcode::SDiv => vec![0x05],
            Opcode::Mod => vec![0x06],
            Opcode::SMod => vec![0x07],
            Opcode::AddMod => vec![0x08],
            Opcode::MulMod => vec![0x09],
            Opcode::Exp => vec![0x0A],
            Opcode::SignExtend => vec![0x0B],
            Opcode::Lt => vec![0x10],
            Opcode::Gt => vec![0x11],
            Opcode::Slt => vec![0x12],
            Opcode::Sgt => vec![0x13],
            Opcode::Eq => vec![0x14],
            Opcode::IsZero => vec![0x15],
            Opcode::And => vec![0x16],
            Opcode::Or => vec![0x17],
            Opcode::Xor => vec![0x18],
            Opcode::Not => vec![0x19],
            Opcode::Byte => vec![0x1A],
            Opcode::Shl => vec![0x1B],
            Opcode::Shr => vec![0x1C],
            Opcode::Sar => vec![0x1D],
            Opcode::Clz => vec![0x1E],
            Opcode::Address => vec![0x30],
            Opcode::Balance => vec![0x31],
            Opcode::Origin => vec![0x32],
            Opcode::Caller => vec![0x33],
            Opcode::CallValue => vec![0x34],
            Opcode::CallDataSize => vec![0x36],
            Opcode::CodeSize => vec![0x38],
            Opcode::GasPrice => vec![0x3A],
            Opcode::ExtCodeSize => vec![0x3B],
            Opcode::ReturnDataSize => vec![0x3D],
            Opcode::ExtCodeHash => vec![0x3F],
            Opcode::BlockHash => vec![0x40],
            Opcode::CoinBase => vec![0x41],
            Opcode::TimeStamp => vec![0x42],
            Opcode::Number => vec![0x43],
            Opcode::PrevRandao => vec![0x44],
            Opcode::GasLimit => vec![0x45],
            Opcode::ChainId => vec![0x46],
            Opcode::SelfBalance => vec![0x47],
            Opcode::BaseFee => vec![0x48],
            Opcode::BlobHash => vec![0x49],
            Opcode::BlobBaseFee => vec![0x4A],
            Opcode::Pop => vec![0x50],
            Opcode::SLoad => vec![0x54],
            Opcode::SStore => vec![0x55],
            Opcode::Pc => vec![0x58],
            Opcode::MSize => vec![0x59],
            Opcode::Gas => vec![0x5A],
            Opcode::TLoad => vec![0x5C],
            Opcode::TStore => vec![0x5D],
            Opcode::Push0 => vec![0x5F],
            Opcode::Push1(b) => render_push(0x60, b),
            Opcode::Push2(b) => render_push(0x61, b),
            Opcode::Push3(b) => render_push(0x62, b),
            Opcode::Push4(b) => render_push(0x63, b),
            Opcode::Push5(b) => render_push(0x64, b),
            Opcode::Push6(b) => render_push(0x65, b),
            Opcode::Push7(b) => render_push(0x66, b),
            Opcode::Push8(b) => render_push(0x67, b),
            Opcode::Push9(b) => render_push(0x68, b),
            Opcode::Push10(b) => render_push(0x69, b),
            Opcode::Push11(b) => render_push(0x6A, b),
            Opcode::Push12(b) => render_push(0x6B, b),
            Opcode::Push13(b) => render_push(0x6C, b),
            Opcode::Push14(b) => render_push(0x6D, b),
            Opcode::Push15(b) => render_push(0x6E, b),
            Opcode::Push16(b) => render_push(0x6F, b),
            Opcode::Push17(b) => render_push(0x70, b),
            Opcode::Push18(b) => render_push(0x71, b),
            Opcode::Push19(b) => render_push(0x72, b),
            Opcode::Push20(b) => render_push(0x73, b),
            Opcode::Push21(b) => render_push(0x74, b),
            Opcode::Push22(b) => render_push(0x75, b),
            Opcode::Push23(b) => render_push(0x76, b),
            Opcode::Push24(b) => render_push(0x77, b),
            Opcode::Push25(b) => render_push(0x78, b),
            Opcode::Push26(b) => render_push(0x79, b),
            Opcode::Push27(b) => render_push(0x7A, b),
            Opcode::Push28(b) => render_push(0x7B, b),
            Opcode::Push29(b) => render_push(0x7C, b),
            Opcode::Push30(b) => render_push(0x7D, b),
            Opcode::Push31(b) => render_push(0x7E, b),
            Opcode::Push32(b) => render_push(0x7F, b),
            Opcode::Dup1 => vec![0x80],
            Opcode::Dup2 => vec![0x81],
            Opcode::Dup3 => vec![0x82],
            Opcode::Dup4 => vec![0x83],
            Opcode::Dup5 => vec![0x84],
            Opcode::Dup6 => vec![0x85],
            Opcode::Dup7 => vec![0x86],
            Opcode::Dup8 => vec![0x87],
            Opcode::Dup9 => vec![0x88],
            Opcode::Dup10 => vec![0x89],
            Opcode::Dup11 => vec![0x8A],
            Opcode::Dup12 => vec![0x8B],
            Opcode::Dup13 => vec![0x8C],
            Opcode::Dup14 => vec![0x8D],
            Opcode::Dup15 => vec![0x8E],
            Opcode::Dup16 => vec![0x8F],
            Opcode::Swap1 => vec![0x90],
            Opcode::Swap2 => vec![0x91],
            Opcode::Swap3 => vec![0x92],
            Opcode::Swap4 => vec![0x93],
            Opcode::Swap5 => vec![0x94],
            Opcode::Swap6 => vec![0x95],
            Opcode::Swap7 => vec![0x96],
            Opcode::Swap8 => vec![0x97],
            Opcode::Swap9 => vec![0x98],
            Opcode::Swap10 => vec![0x99],
            Opcode::Swap11 => vec![0x9A],
            Opcode::Swap12 => vec![0x9B],
            Opcode::Swap13 => vec![0x9C],
            Opcode::Swap14 => vec![0x9D],
            Opcode::Swap15 => vec![0x9E],
            Opcode::Swap16 => vec![0x9F],
            Opcode::MStore(offset, value) => {
                let mut out = Vec::with_capacity(1 + 32 + 1 + 8 + 1);
                out.push(0x7F); // PUSH32 value
                out.extend_from_slice(&value.to_be_bytes::<32>());
                out.push(0x67); // PUSH8 offset
                out.extend_from_slice(&offset.to_be_bytes());
                out.push(0x52); // MSTORE
                out
            }
            Opcode::MLoad(offset) => {
                let mut out = Vec::with_capacity(1 + 8 + 1);
                out.push(0x67); // PUSH8 offset
                out.extend_from_slice(&offset.to_be_bytes());
                out.push(0x51); // MLOAD
                out
            }
            Opcode::Log0(offset, length) => render_log(0xA0, *offset, *length, &[]),
            Opcode::Log1(offset, length, t1) => render_log(0xA1, *offset, *length, &[*t1]),
            Opcode::Log2(offset, length, t1, t2) => render_log(0xA2, *offset, *length, &[*t1, *t2]),
            Opcode::Log3(offset, length, t1, t2, t3) => {
                render_log(0xA3, *offset, *length, &[*t1, *t2, *t3])
            }
            Opcode::Log4(offset, length, t1, t2, t3, t4) => {
                render_log(0xA4, *offset, *length, &[*t1, *t2, *t3, *t4])
            }
            Opcode::MStore8(offset, byte) => {
                let mut out = Vec::with_capacity(2 + 9 + 1);
                out.push(0x60); // PUSH1 byte
                out.push(*byte);
                out.push(0x67); // PUSH8 offset
                out.extend_from_slice(&offset.to_be_bytes());
                out.push(0x53); // MSTORE8
                out
            }
            Opcode::MCopy(dest, src, length) => render_copy3(0x5E, *dest, *src, *length),
            Opcode::CallDataCopy(dest, src, length) => render_copy3(0x37, *dest, *src, *length),
            Opcode::CodeCopy(dest, src, length) => render_copy3(0x39, *dest, *src, *length),
            Opcode::ExtCodeCopy(addr, dest, src, length) => {
                let mut out = Vec::with_capacity(9 + 9 + 9 + 33 + 1);
                out.push(0x67); // PUSH8 length
                out.extend_from_slice(&length.to_be_bytes());
                out.push(0x67); // PUSH8 srcOffset
                out.extend_from_slice(&src.to_be_bytes());
                out.push(0x67); // PUSH8 destOffset
                out.extend_from_slice(&dest.to_be_bytes());
                out.push(0x7F); // PUSH32 address
                out.extend_from_slice(&addr.to_be_bytes::<32>());
                out.push(0x3C); // EXTCODECOPY
                out
            }
            Opcode::Stop => vec![0x00],
            Opcode::CallDataLoad(offset) => {
                let mut out = Vec::with_capacity(1 + 8 + 1);
                out.push(0x67); // PUSH8 offset
                out.extend_from_slice(&offset.to_be_bytes());
                out.push(0x35); // CALLDATALOAD
                out
            }
            Opcode::Return(offset, length) => render_return_like(0xF3, *offset, *length),
            Opcode::Revert(offset, length) => render_return_like(0xFD, *offset, *length),
            Opcode::Keccak256(offset, length) => render_return_like(0x20, *offset, *length),
            Opcode::SelfDestruct(beneficiary) => {
                let mut out = Vec::with_capacity(1 + 32 + 1);
                out.push(0x7F); // PUSH32 beneficiary
                out.extend_from_slice(&beneficiary.to_be_bytes::<32>());
                out.push(0xFF); // SELFDESTRUCT
                out
            }
            Opcode::Create(init_code) => render_create(init_code),
            Opcode::Create2(init_code, salt) => render_create2(init_code, *salt),
            Opcode::Call {
                gas,
                address,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
            } => render_call(
                *gas,
                *address,
                *args_offset,
                *args_size,
                *ret_offset,
                *ret_size,
            ),
            Opcode::StaticCall {
                gas,
                address,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
            } => render_call_no_value(
                0xFA,
                *gas,
                *address,
                *args_offset,
                *args_size,
                *ret_offset,
                *ret_size,
            ),
            Opcode::DelegateCall {
                gas,
                address,
                args_offset,
                args_size,
                ret_offset,
                ret_size,
            } => render_call_no_value(
                0xF4,
                *gas,
                *address,
                *args_offset,
                *args_size,
                *ret_offset,
                *ret_size,
            ),
        }
    }
}

/// Lays `init_code` into outer memory at offset 0 via PUSH32/PUSH8/MSTORE per
/// 32-byte chunk (last chunk zero-padded). Used by both CREATE and CREATE2.
fn render_init_code_setup(out: &mut Vec<u8>, init_code: &[u8]) {
    let words = init_code.len().div_ceil(32);
    for chunk_idx in 0..words {
        let start = chunk_idx * 32;
        let end = (start + 32).min(init_code.len());
        let mut chunk = [0u8; 32];
        chunk[..end - start].copy_from_slice(&init_code[start..end]);
        out.push(0x7F); // PUSH32 word
        out.extend_from_slice(&chunk);
        out.push(0x67); // PUSH8 mem offset
        out.extend_from_slice(&(start as u64).to_be_bytes());
        out.push(0x52); // MSTORE
    }
}

/// Renders a CREATE region: lays the init code into outer memory, pushes
/// `(value=0, offset=0, size=init_code_len)` bottom-up so `value` is on top of
/// the stack as CREATE expects, then emits the CREATE opcode (0xF0). The op's
/// `stack_reserved(3)` ensures the constraint solver has popped enough items
/// that the 3 trailing pushes can't overflow.
fn render_create(init_code: &[u8]) -> Vec<u8> {
    let init_code_len = init_code.len() as u64;
    let words = init_code.len().div_ceil(32);
    let mut out = Vec::with_capacity(words * 43 + 9 + 4 + 1);
    render_init_code_setup(&mut out, init_code);
    // Bottom-up so CREATE pops in order: value (top), offset, size (bottom).
    out.push(0x67); // PUSH8 size
    out.extend_from_slice(&init_code_len.to_be_bytes());
    out.push(0x60); // PUSH1 0 (mem offset of init code)
    out.push(0x00);
    out.push(0x60); // PUSH1 0 (value)
    out.push(0x00);
    out.push(0xF0); // CREATE
    out
}

/// Renders a CREATE2 region: same setup as CREATE, plus a PUSH32 salt at the
/// bottom so CREATE2 pops `(value, offset, size, salt)` in order. The op's
/// `stack_reserved(4)` covers the 4 trailing pushes.
fn render_create2(init_code: &[u8], salt: U256) -> Vec<u8> {
    let init_code_len = init_code.len() as u64;
    let words = init_code.len().div_ceil(32);
    let mut out = Vec::with_capacity(words * 43 + 33 + 9 + 4 + 1);
    render_init_code_setup(&mut out, init_code);
    // Bottom-up so CREATE2 pops in order: value (top), offset, size, salt (bottom).
    out.push(0x7F); // PUSH32 salt
    out.extend_from_slice(&salt.to_be_bytes::<32>());
    out.push(0x67); // PUSH8 size
    out.extend_from_slice(&init_code_len.to_be_bytes());
    out.push(0x60); // PUSH1 0 (mem offset)
    out.push(0x00);
    out.push(0x60); // PUSH1 0 (value)
    out.push(0x00);
    out.push(0xF5); // CREATE2
    out
}

/// Renders STATICCALL (0xFA) or DELEGATECALL (0xF4). Same arg layout as CALL
/// minus the `value` argument. Pushes the 6 args bottom-up so the opcode pops
/// them in the canonical order (gas on top, then addr, argsOffset, argsSize,
/// retOffset, retSize).
fn render_call_no_value(
    opcode: u8,
    gas: u64,
    address: Address,
    args_offset: u64,
    args_size: u64,
    ret_offset: u64,
    ret_size: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + 9 + 9 + 9 + 21 + 9 + 1);
    out.push(0x67); // PUSH8 retSize
    out.extend_from_slice(&ret_size.to_be_bytes());
    out.push(0x67); // PUSH8 retOffset
    out.extend_from_slice(&ret_offset.to_be_bytes());
    out.push(0x67); // PUSH8 argsSize
    out.extend_from_slice(&args_size.to_be_bytes());
    out.push(0x67); // PUSH8 argsOffset
    out.extend_from_slice(&args_offset.to_be_bytes());
    out.push(0x73); // PUSH20 address
    out.extend_from_slice(address.as_slice());
    out.push(0x67); // PUSH8 gas
    out.extend_from_slice(&gas.to_be_bytes());
    out.push(opcode);
    out
}

/// Renders a CALL region. Pushes the 7 args bottom-up so CALL pops them in the
/// canonical order (gas on top, then addr, value, argsOffset, argsSize,
/// retOffset, retSize). Value is hard-coded to 0; `address` is rendered as
/// PUSH20 (zero-extended on the stack to U256, low 160 bits read by CALL).
fn render_call(
    gas: u64,
    address: Address,
    args_offset: u64,
    args_size: u64,
    ret_offset: u64,
    ret_size: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + 9 + 9 + 9 + 1 + 21 + 9 + 1);
    out.push(0x67); // PUSH8 retSize
    out.extend_from_slice(&ret_size.to_be_bytes());
    out.push(0x67); // PUSH8 retOffset
    out.extend_from_slice(&ret_offset.to_be_bytes());
    out.push(0x67); // PUSH8 argsSize
    out.extend_from_slice(&args_size.to_be_bytes());
    out.push(0x67); // PUSH8 argsOffset
    out.extend_from_slice(&args_offset.to_be_bytes());
    out.push(0x5F); // PUSH0 (value = 0)
    out.push(0x73); // PUSH20 address
    out.extend_from_slice(address.as_slice());
    out.push(0x67); // PUSH8 gas
    out.extend_from_slice(&gas.to_be_bytes());
    out.push(0xF1); // CALL
    out
}

/// Renders `[offset, length]` frame-terminating ops:
/// PUSH8 length ‖ PUSH8 offset ‖ <opcode>. Pushed bottom-up so offset ends up on
/// top of the stack as RETURN/REVERT expect.
fn render_return_like(opcode: u8, offset: u64, length: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + 9 + 1);
    out.push(0x67); // PUSH8 length
    out.extend_from_slice(&length.to_be_bytes());
    out.push(0x67); // PUSH8 offset
    out.extend_from_slice(&offset.to_be_bytes());
    out.push(opcode);
    out
}

/// Renders a `[destOffset, srcOffset, length]` copy op:
/// PUSH8 length ‖ PUSH8 srcOffset ‖ PUSH8 destOffset ‖ <opcode>.
/// Pushed bottom-up so destOffset ends up on top of the stack as the EVM expects.
fn render_copy3(opcode: u8, dest: u64, src: u64, length: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + 9 + 9 + 1);
    out.push(0x67); // PUSH8 length
    out.extend_from_slice(&length.to_be_bytes());
    out.push(0x67); // PUSH8 srcOffset
    out.extend_from_slice(&src.to_be_bytes());
    out.push(0x67); // PUSH8 destOffset
    out.extend_from_slice(&dest.to_be_bytes());
    out.push(opcode);
    out
}

/// Renders LOG_N as: PUSH32 topicN ‖ … ‖ PUSH32 topic1 ‖ PUSH8 length ‖ PUSH8 offset ‖ LOGN.
/// Topics are passed in canonical order [topic1, topic2, …, topicN]; pushed in reverse so
/// topic1 ends up just below `length` on the stack as LOG_N expects.
fn render_log(opcode: u8, offset: u64, length: u64, topics: &[U256]) -> Vec<u8> {
    let mut out = Vec::with_capacity(topics.len() * 33 + 9 + 9 + 1);
    for topic in topics.iter().rev() {
        out.push(0x7F); // PUSH32
        out.extend_from_slice(&topic.to_be_bytes::<32>());
    }
    out.push(0x67); // PUSH8 length
    out.extend_from_slice(&length.to_be_bytes());
    out.push(0x67); // PUSH8 offset
    out.extend_from_slice(&offset.to_be_bytes());
    out.push(opcode);
    out
}

fn render_push(opcode: u8, immediate: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + immediate.len());
    v.push(opcode);
    v.extend_from_slice(immediate);
    v
}
