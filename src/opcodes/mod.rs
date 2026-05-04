mod resource;
#[cfg(feature = "arbitrary")]
use arbitrary::Unstructured;
pub use resource::*;
pub mod requires;
pub use requires::*;
pub mod provides;
pub use provides::*;
pub mod render;
pub use render::*;
pub mod source;
pub use source::*;
pub mod weights;
pub use weights::*;
#[cfg(test)]
mod tests;
use alloy_primitives::{Address, U256};
#[cfg(feature = "rng")]
use fastrand::Rng;

use crate::machine::Config;

pub const DEFAULT_MEMORY_OFFSET_LIMIT: u64 = u16::MAX as u64;
pub const DEFAULT_MEMORY_LENGTH_LIMIT: u64 = u8::MAX as u64;

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

    // Halts the execution frame. Kept for explicit insertion; random
    // generation does not emit it.
    Stop,
    // Reads 32 bytes from calldata at the given offset. Carried offset is
    // pushed on the stack via PUSH8 and CALLDATALOAD pops it / pushes the word.
    CallDataLoad(u64),

    // Frame-terminating op with memory range (offset, length). Kept for
    // explicit insertion; random generation does not emit it. Rendered as
    // PUSH8 length ‖ PUSH8 offset ‖ RETURN.
    Return(u64, u64),

    // Hash of memory[offset..offset+length]. Rendered as
    // PUSH8 length ‖ PUSH8 offset ‖ KECCAK256.
    Keccak256(u64, u64),
    // Frame-terminating; sends the contract's balance to the beneficiary
    // address (low 160 bits of the U256). Kept for explicit insertion;
    // random generation does not emit it. Rendered as PUSH32 ‖ SELFDESTRUCT.
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

/// Round `bytes` up to the next 32-byte word boundary.
pub fn round_up_to_word(bytes: u64) -> u64 {
    (bytes.saturating_add(31) / 32).saturating_mul(32)
}

/// Memory size required by an op that writes `length` bytes at `dest`.
pub fn copy_memory_size_dest(dest: u64, length: u64) -> u64 {
    if length == 0 {
        0
    } else {
        round_up_to_word(dest.saturating_add(length))
    }
}

/// Memory size required by MCOPY (touches both source and destination regions).
pub fn copy_memory_size_two(dest: u64, src: u64, length: u64) -> u64 {
    if length == 0 {
        0
    } else {
        let a = round_up_to_word(dest.saturating_add(length));
        let b = round_up_to_word(src.saturating_add(length));
        a.max(b)
    }
}

fn generated_topic<S: OpcodeSource>(source: &mut S) -> Result<U256, S::Error> {
    Ok(U256::from_be_bytes(source.bytes::<32>()?))
}

fn generated_memory_range<S: OpcodeSource>(
    source: &mut S,
    config: &Config,
) -> Result<(u64, u64), S::Error> {
    Ok((
        source.u64_inclusive(config.memory_offset_limit)?,
        source.u64_inclusive(config.memory_length_limit)?,
    ))
}

fn generated_copy_range<S: OpcodeSource>(
    source: &mut S,
    config: &Config,
) -> Result<(u64, u64, u64), S::Error> {
    Ok((
        source.u64_inclusive(config.memory_offset_limit)?,
        source.u64_inclusive(config.memory_offset_limit)?,
        source.u64_inclusive(config.memory_length_limit)?,
    ))
}

impl Opcode {
    /// Returns true for opcodes that halt the current execution frame on
    /// commit (STOP, RETURN, SELFDESTRUCT).
    pub fn is_terminating(&self) -> bool {
        matches!(
            self,
            Opcode::Stop | Opcode::Return(..) | Opcode::SelfDestruct(..)
        )
    }

    /// Returns a weighted-random generated `Opcode` variant using the opcode
    /// weights and memory limits from `config`.
    #[cfg(feature = "rng")]
    pub fn generate(rng: &mut Rng, config: &Config) -> Opcode {
        let mut source = RngOpcodeSource::new(rng);
        let idx = match weighted_variant_index(&mut source, &config.opcode_weights) {
            Ok(idx) => idx,
            Err(err) => match err {},
        };
        match Self::nth_variant_from(idx, &mut source, config) {
            Ok(op) => op,
            Err(err) => match err {},
        }
    }

    /// Returns a uniformly-random `Push*` variant with random immediate bytes.
    /// Picks among Push1..Push32; Push0 is excluded.
    #[cfg(feature = "rng")]
    pub fn generate_push(rng: &mut Rng) -> Opcode {
        let idx = PUSH_VARIANT_OFFSET + rng.usize(0..PUSH_VARIANT_COUNT);
        Self::nth_variant_rng(idx, rng, &Config::default())
    }

    /// Returns a weighted generated `Opcode` variant from arbitrary input bytes
    /// using the opcode weights and memory limits from `config`.
    #[cfg(feature = "arbitrary")]
    pub fn arbitrary(u: &mut Unstructured<'_>, config: &Config) -> arbitrary::Result<Opcode> {
        let mut source = ArbitraryOpcodeSource::new(u);
        let idx = weighted_variant_index(&mut source, &config.opcode_weights)?;
        Self::nth_variant_from(idx, &mut source, config)
    }

    /// Returns a `Push*` variant generated from arbitrary input bytes.
    /// Picks among Push1..Push32; Push0 is excluded.
    #[cfg(feature = "arbitrary")]
    pub fn arbitrary_push(u: &mut Unstructured<'_>) -> arbitrary::Result<Opcode> {
        let idx = PUSH_VARIANT_OFFSET + u.int_in_range(0..=PUSH_VARIANT_COUNT - 1)?;
        Self::nth_variant_arbitrary(idx, u, &Config::default())
    }

    #[cfg(feature = "rng")]
    fn nth_variant_rng(idx: usize, rng: &mut Rng, config: &Config) -> Opcode {
        let mut source = RngOpcodeSource::new(rng);
        match Self::nth_variant_from(idx, &mut source, config) {
            Ok(op) => op,
            Err(err) => match err {},
        }
    }

    #[cfg(feature = "arbitrary")]
    fn nth_variant_arbitrary(
        idx: usize,
        u: &mut Unstructured<'_>,
        config: &Config,
    ) -> arbitrary::Result<Opcode> {
        let mut source = ArbitraryOpcodeSource::new(u);
        Self::nth_variant_from(idx, &mut source, config)
    }

    fn nth_variant_from<S: OpcodeSource>(
        idx: usize,
        source: &mut S,
        config: &Config,
    ) -> Result<Opcode, S::Error> {
        Ok(match idx {
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
            56 => Opcode::Push1(source.bytes()?),
            57 => Opcode::Push2(source.bytes()?),
            58 => Opcode::Push3(source.bytes()?),
            59 => Opcode::Push4(source.bytes()?),
            60 => Opcode::Push5(source.bytes()?),
            61 => Opcode::Push6(source.bytes()?),
            62 => Opcode::Push7(source.bytes()?),
            63 => Opcode::Push8(source.bytes()?),
            64 => Opcode::Push9(source.bytes()?),
            65 => Opcode::Push10(source.bytes()?),
            66 => Opcode::Push11(source.bytes()?),
            67 => Opcode::Push12(source.bytes()?),
            68 => Opcode::Push13(source.bytes()?),
            69 => Opcode::Push14(source.bytes()?),
            70 => Opcode::Push15(source.bytes()?),
            71 => Opcode::Push16(source.bytes()?),
            72 => Opcode::Push17(source.bytes()?),
            73 => Opcode::Push18(source.bytes()?),
            74 => Opcode::Push19(source.bytes()?),
            75 => Opcode::Push20(source.bytes()?),
            76 => Opcode::Push21(source.bytes()?),
            77 => Opcode::Push22(source.bytes()?),
            78 => Opcode::Push23(source.bytes()?),
            79 => Opcode::Push24(source.bytes()?),
            80 => Opcode::Push25(source.bytes()?),
            81 => Opcode::Push26(source.bytes()?),
            82 => Opcode::Push27(source.bytes()?),
            83 => Opcode::Push28(source.bytes()?),
            84 => Opcode::Push29(source.bytes()?),
            85 => Opcode::Push30(source.bytes()?),
            86 => Opcode::Push31(source.bytes()?),
            87 => Opcode::Push32(source.bytes()?),
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
                let offset = source.u64_inclusive(config.memory_offset_limit)?;
                let value = U256::from_be_bytes(source.bytes::<32>()?);
                Opcode::MStore(offset, value)
            }
            121 => Opcode::MLoad(source.u64_inclusive(config.memory_offset_limit)?),
            122 => {
                let (offset, length) = generated_memory_range(source, config)?;
                Opcode::Log0(offset, length)
            }
            123 => {
                let (offset, length) = generated_memory_range(source, config)?;
                Opcode::Log1(offset, length, generated_topic(source)?)
            }
            124 => {
                let (offset, length) = generated_memory_range(source, config)?;
                Opcode::Log2(
                    offset,
                    length,
                    generated_topic(source)?,
                    generated_topic(source)?,
                )
            }
            125 => {
                let (offset, length) = generated_memory_range(source, config)?;
                Opcode::Log3(
                    offset,
                    length,
                    generated_topic(source)?,
                    generated_topic(source)?,
                    generated_topic(source)?,
                )
            }
            126 => {
                let (offset, length) = generated_memory_range(source, config)?;
                Opcode::Log4(
                    offset,
                    length,
                    generated_topic(source)?,
                    generated_topic(source)?,
                    generated_topic(source)?,
                    generated_topic(source)?,
                )
            }
            127 => Opcode::MStore8(
                source.u64_inclusive(config.memory_offset_limit)?,
                source.u8()?,
            ),
            128 => {
                let (dest, src, length) = generated_copy_range(source, config)?;
                Opcode::MCopy(dest, src, length)
            }
            129 => {
                let (dest, src, length) = generated_copy_range(source, config)?;
                Opcode::CallDataCopy(dest, src, length)
            }
            130 => {
                let (dest, src, length) = generated_copy_range(source, config)?;
                Opcode::CodeCopy(dest, src, length)
            }
            131 => {
                let (dest, src, length) = generated_copy_range(source, config)?;
                Opcode::ExtCodeCopy(generated_topic(source)?, dest, src, length)
            }
            132 => Opcode::CallDataLoad(source.u64_inclusive(config.memory_offset_limit)?),
            133 => {
                let (offset, length) = generated_memory_range(source, config)?;
                Opcode::Keccak256(offset, length)
            }
            134 => Opcode::Create(Vec::new()),
            135 => Opcode::Create2(Vec::new(), generated_topic(source)?),
            136 => {
                let (args_offset, args_size) = generated_memory_range(source, config)?;
                let (ret_offset, ret_size) = generated_memory_range(source, config)?;
                Opcode::Call {
                    gas: 0,
                    address: Address::ZERO,
                    args_offset,
                    args_size,
                    ret_offset,
                    ret_size,
                }
            }
            137 => {
                let (args_offset, args_size) = generated_memory_range(source, config)?;
                let (ret_offset, ret_size) = generated_memory_range(source, config)?;
                Opcode::StaticCall {
                    gas: 0,
                    address: Address::ZERO,
                    args_offset,
                    args_size,
                    ret_offset,
                    ret_size,
                }
            }
            138 => {
                let (args_offset, args_size) = generated_memory_range(source, config)?;
                let (ret_offset, ret_size) = generated_memory_range(source, config)?;
                Opcode::DelegateCall {
                    gas: 0,
                    address: Address::ZERO,
                    args_offset,
                    args_size,
                    ret_offset,
                    ret_size,
                }
            }
            139 => Opcode::Clz,
            _ => unreachable!("nth_variant: idx {} out of range", idx),
        })
    }
}
