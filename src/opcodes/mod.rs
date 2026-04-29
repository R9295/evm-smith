mod resource;
#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
pub use resource::*;
pub mod requires;
pub use requires::*;
pub mod provides;
pub use provides::*;

use alloy_primitives::{Address, U256};
use fastrand::Rng;

use crate::machine::{DEFAULT_MEMORY_LENGTH_LIMIT, DEFAULT_MEMORY_OFFSET_LIMIT};

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

fn random_inclusive_u64(rng: &mut Rng, limit: u64) -> u64 {
    if limit == u64::MAX {
        rng.u64(..)
    } else {
        rng.u64(..limit + 1)
    }
}

fn random_memory_offset(rng: &mut Rng, memory_offset_limit: u64) -> u64 {
    random_inclusive_u64(rng, memory_offset_limit)
}

fn random_memory_length(rng: &mut Rng, memory_length_limit: u64) -> u64 {
    random_inclusive_u64(rng, memory_length_limit)
}

/// Random `(offset, length)` for ops that touch a memory range. Both limits are
/// configurable to bound memory expansion gas and per-byte charges.
fn random_memory_range(
    rng: &mut Rng,
    memory_offset_limit: u64,
    memory_length_limit: u64,
) -> (u64, u64) {
    (
        random_memory_offset(rng, memory_offset_limit),
        random_memory_length(rng, memory_length_limit),
    )
}

fn random_topic(rng: &mut Rng) -> U256 {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    U256::from_be_bytes(bytes)
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

fn random_copy_range(
    rng: &mut Rng,
    memory_offset_limit: u64,
    memory_length_limit: u64,
) -> (u64, u64, u64) {
    (
        random_memory_offset(rng, memory_offset_limit),
        random_memory_offset(rng, memory_offset_limit),
        random_memory_length(rng, memory_length_limit),
    )
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

    /// Returns a uniformly-random generated `Opcode` variant. For `Push*`
    /// variants the immediate-byte array is filled with random bytes from
    /// `rng`. Terminating ops that need explicit placement (`STOP`,
    /// `RETURN`, `SELFDESTRUCT`) are excluded.
    pub fn generate(rng: &mut Rng) -> Opcode {
        Self::generate_with_memory_limits(
            rng,
            DEFAULT_MEMORY_OFFSET_LIMIT,
            DEFAULT_MEMORY_LENGTH_LIMIT,
        )
    }

    /// Returns a uniformly-random generated `Opcode` variant, sampling memory
    /// offsets from `0..=memory_offset_limit`.
    pub fn generate_with_memory_offset_limit(rng: &mut Rng, memory_offset_limit: u64) -> Opcode {
        Self::generate_with_memory_limits(rng, memory_offset_limit, DEFAULT_MEMORY_LENGTH_LIMIT)
    }

    /// Returns a uniformly-random generated `Opcode` variant, sampling memory
    /// offsets from `0..=memory_offset_limit` and memory lengths from
    /// `0..=memory_length_limit`.
    pub fn generate_with_memory_limits(
        rng: &mut Rng,
        memory_offset_limit: u64,
        memory_length_limit: u64,
    ) -> Opcode {
        const VARIANT_COUNT: usize = 140;
        Self::nth_variant(
            rng.usize(0..VARIANT_COUNT),
            rng,
            memory_offset_limit,
            memory_length_limit,
        )
    }

    /// Returns a uniformly-random `Push*` variant with random immediate bytes.
    /// (Picks among Push1..Push32; Push0 is excluded.)
    pub fn generate_push(rng: &mut Rng) -> Opcode {
        const PUSH_OFFSET: usize = 56;
        const PUSH_COUNT: usize = 32;
        Self::nth_variant(
            PUSH_OFFSET + rng.usize(0..PUSH_COUNT),
            rng,
            DEFAULT_MEMORY_OFFSET_LIMIT,
            DEFAULT_MEMORY_LENGTH_LIMIT,
        )
    }
    #[cfg(feature = "arbitrary")]
    fn nth_variant<'a>(
        idx: usize,
        data: &'a mut Unstructured,
        memory_offset_limit: u64,
        memory_length_limit: u64,
    ) -> Opcode {
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
                let b = <[u8; 1]>::arbitrary(&mut u).unwrap();
                Opcode::Push1(b)
            }
            57 => {
                let b = <[u8; 2]>::arbitrary(&mut u).unwrap();
                Opcode::Push2(b)
            }
            58 => {
                let b = <[u8; 3]>::arbitrary(&mut u).unwrap();
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
                let offset = random_memory_offset(rng, memory_offset_limit);
                let mut value_bytes = [0u8; 32];
                rng.fill(&mut value_bytes);
                Opcode::MStore(offset, U256::from_be_bytes(value_bytes))
            }
            121 => {
                let offset = random_memory_offset(rng, memory_offset_limit);
                Opcode::MLoad(offset)
            }
            122 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log0(offset, length)
            }
            123 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log1(offset, length, random_topic(rng))
            }
            124 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log2(offset, length, random_topic(rng), random_topic(rng))
            }
            125 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log3(
                    offset,
                    length,
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                )
            }
            126 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log4(
                    offset,
                    length,
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                )
            }
            127 => Opcode::MStore8(random_memory_offset(rng, memory_offset_limit), rng.u8(..)),
            128 => {
                let (dest, src, length) =
                    random_copy_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::MCopy(dest, src, length)
            }
            129 => {
                let (dest, src, length) =
                    random_copy_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::CallDataCopy(dest, src, length)
            }
            130 => {
                let (dest, src, length) =
                    random_copy_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::CodeCopy(dest, src, length)
            }
            131 => {
                let (dest, src, length) =
                    random_copy_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::ExtCodeCopy(random_topic(rng), dest, src, length)
            }
            132 => Opcode::CallDataLoad(random_memory_offset(rng, memory_offset_limit)),
            133 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Keccak256(offset, length)
            }
            // Placeholder. Real init code is materialized by `Machine::ingest`
            // (which has access to outer gas + RNG) the first time this is
            // ingested; subsequent ingestions of the same value would re-use
            // the populated payload.
            134 => Opcode::Create(Vec::new()),
            // CREATE2 placeholder; salt is sampled now (it does not depend on
            // outer machine state), init code is materialized lazily.
            135 => Opcode::Create2(Vec::new(), random_topic(rng)),
            // CALL placeholder. Memory ranges are sampled now; gas and target
            // address are filled in by `Machine::ingest` (they depend on outer
            // state). The placeholder is detected by `address == Address::ZERO`.
            136 => {
                let (args_offset, args_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                let (ret_offset, ret_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
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
            137 => {
                let (args_offset, args_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                let (ret_offset, ret_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
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
                let (args_offset, args_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                let (ret_offset, ret_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
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
        }
    }
    #[cfg(not(feature = "arbitrary"))]
    fn nth_variant(
        idx: usize,
        rng: &mut Rng,
        memory_offset_limit: u64,
        memory_length_limit: u64,
    ) -> Opcode {
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
                let offset = random_memory_offset(rng, memory_offset_limit);
                let mut value_bytes = [0u8; 32];
                rng.fill(&mut value_bytes);
                Opcode::MStore(offset, U256::from_be_bytes(value_bytes))
            }
            121 => {
                let offset = random_memory_offset(rng, memory_offset_limit);
                Opcode::MLoad(offset)
            }
            122 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log0(offset, length)
            }
            123 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log1(offset, length, random_topic(rng))
            }
            124 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log2(offset, length, random_topic(rng), random_topic(rng))
            }
            125 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log3(
                    offset,
                    length,
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                )
            }
            126 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Log4(
                    offset,
                    length,
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                    random_topic(rng),
                )
            }
            127 => Opcode::MStore8(random_memory_offset(rng, memory_offset_limit), rng.u8(..)),
            128 => {
                let (dest, src, length) =
                    random_copy_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::MCopy(dest, src, length)
            }
            129 => {
                let (dest, src, length) =
                    random_copy_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::CallDataCopy(dest, src, length)
            }
            130 => {
                let (dest, src, length) =
                    random_copy_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::CodeCopy(dest, src, length)
            }
            131 => {
                let (dest, src, length) =
                    random_copy_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::ExtCodeCopy(random_topic(rng), dest, src, length)
            }
            132 => Opcode::CallDataLoad(random_memory_offset(rng, memory_offset_limit)),
            133 => {
                let (offset, length) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                Opcode::Keccak256(offset, length)
            }
            // Placeholder. Real init code is materialized by `Machine::ingest`
            // (which has access to outer gas + RNG) the first time this is
            // ingested; subsequent ingestions of the same value would re-use
            // the populated payload.
            134 => Opcode::Create(Vec::new()),
            // CREATE2 placeholder; salt is sampled now (it does not depend on
            // outer machine state), init code is materialized lazily.
            135 => Opcode::Create2(Vec::new(), random_topic(rng)),
            // CALL placeholder. Memory ranges are sampled now; gas and target
            // address are filled in by `Machine::ingest` (they depend on outer
            // state). The placeholder is detected by `address == Address::ZERO`.
            136 => {
                let (args_offset, args_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                let (ret_offset, ret_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
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
            137 => {
                let (args_offset, args_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                let (ret_offset, ret_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
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
                let (args_offset, args_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
                let (ret_offset, ret_size) =
                    random_memory_range(rng, memory_offset_limit, memory_length_limit);
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
/// top of the stack as RETURN expects.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_zero_memory_limits_force_zero_offsets_and_lengths() {
        let memory_variant_indices = [
            120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 136, 137, 138,
        ];

        for idx in memory_variant_indices {
            let mut rng = Rng::with_seed(idx as u64);
            let op = Opcode::nth_variant(idx, &mut rng, 0, 0);
            assert_memory_offsets_and_lengths(&op, 0, 0);
        }
    }

    #[test]
    fn generated_variants_exclude_manual_terminators() {
        let mut rng = Rng::with_seed(0);
        for idx in 0..140 {
            let op = Opcode::nth_variant(idx, &mut rng, 0, 0);
            assert!(!matches!(
                op,
                Opcode::Stop | Opcode::Return(..) | Opcode::SelfDestruct(..)
            ));
        }
    }

    fn assert_memory_offsets_and_lengths(op: &Opcode, expected_offset: u64, expected_length: u64) {
        match op {
            Opcode::MStore(offset, _)
            | Opcode::MLoad(offset)
            | Opcode::MStore8(offset, _)
            | Opcode::CallDataLoad(offset) => assert_eq!(*offset, expected_offset),
            Opcode::Log0(offset, length)
            | Opcode::Log1(offset, length, _)
            | Opcode::Log2(offset, length, _, _)
            | Opcode::Log3(offset, length, _, _, _)
            | Opcode::Log4(offset, length, _, _, _, _)
            | Opcode::Return(offset, length)
            | Opcode::Keccak256(offset, length) => {
                assert_eq!(*offset, expected_offset);
                assert_eq!(*length, expected_length);
            }
            Opcode::MCopy(dest, src, length)
            | Opcode::CallDataCopy(dest, src, length)
            | Opcode::CodeCopy(dest, src, length)
            | Opcode::ExtCodeCopy(_, dest, src, length) => {
                assert_eq!(*dest, expected_offset);
                assert_eq!(*src, expected_offset);
                assert_eq!(*length, expected_length);
            }
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
                assert_eq!(*args_offset, expected_offset);
                assert_eq!(*args_size, expected_length);
                assert_eq!(*ret_offset, expected_offset);
                assert_eq!(*ret_size, expected_length);
            }
            _ => panic!("unexpected opcode in memory limit test: {op:?}"),
        }
    }
}
