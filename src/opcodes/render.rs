use alloy_primitives::{Address, U256};

use crate::opcodes::Opcode;

pub trait Render {
    fn render(&self) -> Vec<u8>;
}

impl Render for Opcode {
    fn render(&self) -> Vec<u8> {
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
