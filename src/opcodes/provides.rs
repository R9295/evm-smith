use crate::{
    machine::{Machine, MachineSource},
    opcodes::{
        Opcode, Resource, copy_memory_size_dest, copy_memory_size_two, memory_range_size,
        round_up_to_word,
    },
};

pub trait Provides {
    fn provides<S: MachineSource>(&self, machine: &Machine<S>) -> Resource;
}
impl Provides for Opcode {
    fn provides<S: MachineSource>(&self, machine: &Machine<S>) -> Resource {
        match self {
            Opcode::Pop | Opcode::SStore | Opcode::TStore | Opcode::Stop => {
                Resource::builder().build()
            }
            // RETURN produces no stack output but may grow memory to cover
            // offset..offset+length.
            Opcode::Return(offset, length) => {
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
}
