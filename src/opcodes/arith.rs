use super::Opcode;

#[derive(Debug)]
pub struct Add;
#[derive(Debug)]
pub struct Mul;
#[derive(Debug)]
pub struct Sub;
#[derive(Debug)]
pub struct Div;
#[derive(Debug)]
pub struct SDiv;
#[derive(Debug)]
pub struct Mod;
#[derive(Debug)]
pub struct SMod;
#[derive(Debug)]
pub struct AddMod;
#[derive(Debug)]
pub struct MulMod;
#[derive(Debug)]
pub struct Exp;
#[derive(Debug)]
pub struct SignExtend;

impl Opcode for Add {}
impl Opcode for Mul {}
impl Opcode for Sub {}
impl Opcode for Div {}
impl Opcode for SDiv {}
impl Opcode for Mod {}
impl Opcode for SMod {}
impl Opcode for AddMod {}
impl Opcode for MulMod {}
impl Opcode for Exp {}
impl Opcode for SignExtend {}
