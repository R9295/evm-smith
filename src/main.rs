mod machine;
mod opcodes;
mod error;

use crate::{machine::Machine, opcodes::{Opcode, ALL_OPCODES}};

use fastrand::Rng;
use std::time::SystemTime;

fn main() {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rand = fastrand::Rng::with_seed(seed.clone());
    let mut machine_rand = fastrand::Rng::with_seed(seed.clone());
    let gas = 1000;
    let mut machine = Machine::new(gas, machine_rand);
    loop {
        let op = get_next_op(&mut rand);
        let Ok(_) = machine.ingest(op) else {
            break;
        };
    };
    println!("{:?}",machine.bytecode);
}

fn get_next_op(rand: &mut Rng) -> &'static dyn Opcode {
    ALL_OPCODES[rand.usize(0..ALL_OPCODES.len())]
}
