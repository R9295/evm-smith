mod opcodes;
use std::time::SystemTime;

use crate::opcodes::ALL_OPCODES;

fn main() {
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rand = fastrand::Rng::with_seed(seed.clone());
    let op = ALL_OPCODES[rand.usize(0..ALL_OPCODES.len())];
    println!("{:?}", op);
}
