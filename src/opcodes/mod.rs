mod arith;
mod stack;
mod resource;
pub use resource::*;
pub use arith::*;
pub use stack::*;

pub trait Opcode: Sync + std::fmt::Debug {
    fn requires(&self) -> Resource;
    fn provides(&self) -> Resource;
}

pub static ALL_OPCODES: &[&dyn Opcode] = &[
    &Add,
    &Mul,
    &Sub,
    &Div,
    &SDiv,
    &Mod,
    &SMod,
    &AddMod,
    &MulMod,
    &Exp,
    &SignExtend,
    &Pop,
    &Push1,
    &Push2,
    &Push3,
    &Push4,
    &Push5,
    &Push6,
    &Push7,
    &Push8,
    &Push9,
    &Push10,
    &Push11,
    &Push12,
    &Push13,
    &Push14,
    &Push15,
    &Push16,
    &Push17,
    &Push18,
    &Push19,
    &Push20,
    &Push21,
    &Push22,
    &Push23,
    &Push24,
    &Push25,
    &Push26,
    &Push27,
    &Push28,
    &Push29,
    &Push30,
    &Push31,
    &Push32,
];
