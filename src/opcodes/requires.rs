use crate::{
    machine::{Machine, MachineSource},
    opcodes::{
        Opcode, Resource, copy_memory_size_dest, copy_memory_size_two, memory_range_size,
        round_up_to_word,
    },
};

pub trait Requires {
    fn requires<S: MachineSource>(&self, machine: &Machine<S>) -> Resource;
}

impl Requires for Opcode {
    fn requires<S: MachineSource>(&self, machine: &Machine<S>) -> Resource {
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
            // PUSH8 length (3) + PUSH8 offset (3) + RETURN (0 + memory expansion).
            // Peak rise = 2.
            Opcode::Return(offset, length) => {
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
                let mem_expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
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
                let mem_expansion =
                    memory_word_cost(needed).saturating_sub(memory_word_cost(machine.memory()));
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
}
/// EVM memory pricing: 3 * words + words^2 / 512, where words is the
/// number of 32-byte words required to cover `size_bytes`.
fn memory_word_cost(size_bytes: u64) -> u64 {
    let words = size_bytes.saturating_add(31) / 32;
    3u64.saturating_mul(words)
        .saturating_add(words.saturating_mul(words) / 512)
}

/// Per-word charge for *COPY / KECCAK256 style ops: 3 * ceil(length / 32).
fn copy_word_gas(length: u64) -> u64 {
    3u64.saturating_mul(length.saturating_add(31) / 32)
}
