mod resource;
pub use resource::*;

use alloy_primitives::U256;
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

#[derive(Debug, Clone, Copy)]
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

    // Bitwise (0x16..0x1D)
    And,
    Or,
    Xor,
    Not,
    Byte,
    Shl,
    Shr,
    Sar,

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
}

/// Memory size required to access `offset..offset+length`. EVM does no memory
/// access (and no expansion) when length is zero.
fn log_memory_size(offset: u64, length: u64) -> u64 {
    if length == 0 {
        0
    } else {
        round_up_to_word(offset.saturating_add(length))
    }
}

/// LOG offset capped at u16 (memory expansion gas), length capped at u8
/// (per-byte LOG_DATA gas).
/// NOTE: memory offset capped at u16
fn random_log_range(rng: &mut Rng) -> (u64, u64) {
    (rng.u16(..) as u64, rng.u8(..) as u64)
}

fn random_topic(rng: &mut Rng) -> U256 {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    U256::from_be_bytes(bytes)
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
            Opcode::MStore(offset, _value) => {
                let new_size = round_up_to_word(offset.saturating_add(32));
                let expansion = memory_word_cost(new_size)
                    .saturating_sub(memory_word_cost(machine.memory()));
                // NOTE: stack = 2 since we push our own offset + value onto the stack
                Resource::builder().stack(2).gas(9 + expansion).build()
            }
            // Rendered as PUSH8 offset (3) + MLOAD (3 + memory expansion).
            Opcode::MLoad(offset) => {
                let new_size = round_up_to_word(offset.saturating_add(32));
                let expansion = memory_word_cost(new_size)
                    .saturating_sub(memory_word_cost(machine.memory()));
                // NOTE: stack = 1 since we push our own offset onto the stack.
                Resource::builder().stack(1).gas(6 + expansion).build()
            }
            // LOG_N: (N+2) embedded pushes (3 gas each) + 375*(N+1) base + 8*length + expansion.
            Opcode::Log0(offset, length) => {
                let needed = log_memory_size(*offset, *length);
                let expansion = memory_word_cost(needed)
                    .saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (0 + 2);
                let log_gas = 375 * (0 + 1) + 8u64.saturating_mul(*length);
                Resource::builder().stack(2).gas(push_gas + log_gas + expansion).build()
            }
            Opcode::Log1(offset, length, _) => {
                let needed = log_memory_size(*offset, *length);
                let expansion = memory_word_cost(needed)
                    .saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (1 + 2);
                let log_gas = 375 * (1 + 1) + 8u64.saturating_mul(*length);
                Resource::builder().stack(3).gas(push_gas + log_gas + expansion).build()
            }
            Opcode::Log2(offset, length, _, _) => {
                let needed = log_memory_size(*offset, *length);
                let expansion = memory_word_cost(needed)
                    .saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (2 + 2);
                let log_gas = 375 * (2 + 1) + 8u64.saturating_mul(*length);
                Resource::builder().stack(4).gas(push_gas + log_gas + expansion).build()
            }
            Opcode::Log3(offset, length, _, _, _) => {
                let needed = log_memory_size(*offset, *length);
                let expansion = memory_word_cost(needed)
                    .saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (3 + 2);
                let log_gas = 375 * (3 + 1) + 8u64.saturating_mul(*length);
                Resource::builder().stack(5).gas(push_gas + log_gas + expansion).build()
            }
            Opcode::Log4(offset, length, _, _, _, _) => {
                let needed = log_memory_size(*offset, *length);
                let expansion = memory_word_cost(needed)
                    .saturating_sub(memory_word_cost(machine.memory()));
                let push_gas = 3 * (4 + 2);
                let log_gas = 375 * (4 + 1) + 8u64.saturating_mul(*length);
                Resource::builder().stack(6).gas(push_gas + log_gas + expansion).build()
            }
        }
    }

    pub fn provides(&self, machine: &Machine) -> Resource {
        match self {
            Opcode::Pop | Opcode::SStore | Opcode::TStore => Resource::builder().build(),
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
                let needed = log_memory_size(*offset, *length);
                let increment = needed.saturating_sub(machine.memory());
                Resource::builder().memory(increment).build()
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
        const VARIANT_COUNT: usize = 127;
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
            56 => { let mut b = [0u8; 1]; rng.fill(&mut b); Opcode::Push1(b) }
            57 => { let mut b = [0u8; 2]; rng.fill(&mut b); Opcode::Push2(b) }
            58 => { let mut b = [0u8; 3]; rng.fill(&mut b); Opcode::Push3(b) }
            59 => { let mut b = [0u8; 4]; rng.fill(&mut b); Opcode::Push4(b) }
            60 => { let mut b = [0u8; 5]; rng.fill(&mut b); Opcode::Push5(b) }
            61 => { let mut b = [0u8; 6]; rng.fill(&mut b); Opcode::Push6(b) }
            62 => { let mut b = [0u8; 7]; rng.fill(&mut b); Opcode::Push7(b) }
            63 => { let mut b = [0u8; 8]; rng.fill(&mut b); Opcode::Push8(b) }
            64 => { let mut b = [0u8; 9]; rng.fill(&mut b); Opcode::Push9(b) }
            65 => { let mut b = [0u8; 10]; rng.fill(&mut b); Opcode::Push10(b) }
            66 => { let mut b = [0u8; 11]; rng.fill(&mut b); Opcode::Push11(b) }
            67 => { let mut b = [0u8; 12]; rng.fill(&mut b); Opcode::Push12(b) }
            68 => { let mut b = [0u8; 13]; rng.fill(&mut b); Opcode::Push13(b) }
            69 => { let mut b = [0u8; 14]; rng.fill(&mut b); Opcode::Push14(b) }
            70 => { let mut b = [0u8; 15]; rng.fill(&mut b); Opcode::Push15(b) }
            71 => { let mut b = [0u8; 16]; rng.fill(&mut b); Opcode::Push16(b) }
            72 => { let mut b = [0u8; 17]; rng.fill(&mut b); Opcode::Push17(b) }
            73 => { let mut b = [0u8; 18]; rng.fill(&mut b); Opcode::Push18(b) }
            74 => { let mut b = [0u8; 19]; rng.fill(&mut b); Opcode::Push19(b) }
            75 => { let mut b = [0u8; 20]; rng.fill(&mut b); Opcode::Push20(b) }
            76 => { let mut b = [0u8; 21]; rng.fill(&mut b); Opcode::Push21(b) }
            77 => { let mut b = [0u8; 22]; rng.fill(&mut b); Opcode::Push22(b) }
            78 => { let mut b = [0u8; 23]; rng.fill(&mut b); Opcode::Push23(b) }
            79 => { let mut b = [0u8; 24]; rng.fill(&mut b); Opcode::Push24(b) }
            80 => { let mut b = [0u8; 25]; rng.fill(&mut b); Opcode::Push25(b) }
            81 => { let mut b = [0u8; 26]; rng.fill(&mut b); Opcode::Push26(b) }
            82 => { let mut b = [0u8; 27]; rng.fill(&mut b); Opcode::Push27(b) }
            83 => { let mut b = [0u8; 28]; rng.fill(&mut b); Opcode::Push28(b) }
            84 => { let mut b = [0u8; 29]; rng.fill(&mut b); Opcode::Push29(b) }
            85 => { let mut b = [0u8; 30]; rng.fill(&mut b); Opcode::Push30(b) }
            86 => { let mut b = [0u8; 31]; rng.fill(&mut b); Opcode::Push31(b) }
            87 => { let mut b = [0u8; 32]; rng.fill(&mut b); Opcode::Push32(b) }
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
                let (offset, length) = random_log_range(rng);
                Opcode::Log0(offset, length)
            }
            123 => {
                let (offset, length) = random_log_range(rng);
                Opcode::Log1(offset, length, random_topic(rng))
            }
            124 => {
                let (offset, length) = random_log_range(rng);
                Opcode::Log2(offset, length, random_topic(rng), random_topic(rng))
            }
            125 => {
                let (offset, length) = random_log_range(rng);
                Opcode::Log3(
                    offset,
                    length,
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                )
            }
            126 => {
                let (offset, length) = random_log_range(rng);
                Opcode::Log4(
                    offset,
                    length,
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                )
            }
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
        }
    }
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
