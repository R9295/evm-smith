mod resource;
pub use resource::*;

use fastrand::Rng;

#[derive(Debug, Clone, Copy)]
pub enum Opcode {
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
    Pop,
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
}

impl Opcode {
    pub fn requires(&self) -> Resource {
        match self {
            Opcode::Add | Opcode::Sub => Resource::builder().stack(2).gas(3).build(),
            Opcode::Mul
            | Opcode::Div
            | Opcode::SDiv
            | Opcode::Mod
            | Opcode::SMod
            | Opcode::SignExtend => Resource::builder().stack(2).gas(5).build(),
            Opcode::AddMod | Opcode::MulMod => Resource::builder().stack(3).gas(8).build(),
            // EIP-160: 10 + 50 * byte_size(exponent); worst case is a 32-byte exponent.
            Opcode::Exp => Resource::builder().stack(2).gas(10 + 50 * 32).build(),
            Opcode::Pop => Resource::builder().stack(1).gas(2).build(),
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
        }
    }

    pub fn provides(&self) -> Resource {
        match self {
            Opcode::Pop => Resource::builder().build(),
            _ => Resource::builder().stack(1).build(),
        }
    }

    /// Returns a uniformly-random `Opcode` variant. For `Push*` variants the
    /// immediate-byte array is filled with random bytes from `rng`.
    pub fn generate(rng: &mut Rng) -> Opcode {
        const VARIANT_COUNT: usize = 44;
        Self::nth_variant(rng.usize(0..VARIANT_COUNT), rng)
    }

    /// Returns a uniformly-random `Push*` variant with random immediate bytes.
    pub fn generate_push(rng: &mut Rng) -> Opcode {
        const PUSH_OFFSET: usize = 12;
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
            11 => Opcode::Pop,
            12 => { let mut b = [0u8; 1]; rng.fill(&mut b); Opcode::Push1(b) }
            13 => { let mut b = [0u8; 2]; rng.fill(&mut b); Opcode::Push2(b) }
            14 => { let mut b = [0u8; 3]; rng.fill(&mut b); Opcode::Push3(b) }
            15 => { let mut b = [0u8; 4]; rng.fill(&mut b); Opcode::Push4(b) }
            16 => { let mut b = [0u8; 5]; rng.fill(&mut b); Opcode::Push5(b) }
            17 => { let mut b = [0u8; 6]; rng.fill(&mut b); Opcode::Push6(b) }
            18 => { let mut b = [0u8; 7]; rng.fill(&mut b); Opcode::Push7(b) }
            19 => { let mut b = [0u8; 8]; rng.fill(&mut b); Opcode::Push8(b) }
            20 => { let mut b = [0u8; 9]; rng.fill(&mut b); Opcode::Push9(b) }
            21 => { let mut b = [0u8; 10]; rng.fill(&mut b); Opcode::Push10(b) }
            22 => { let mut b = [0u8; 11]; rng.fill(&mut b); Opcode::Push11(b) }
            23 => { let mut b = [0u8; 12]; rng.fill(&mut b); Opcode::Push12(b) }
            24 => { let mut b = [0u8; 13]; rng.fill(&mut b); Opcode::Push13(b) }
            25 => { let mut b = [0u8; 14]; rng.fill(&mut b); Opcode::Push14(b) }
            26 => { let mut b = [0u8; 15]; rng.fill(&mut b); Opcode::Push15(b) }
            27 => { let mut b = [0u8; 16]; rng.fill(&mut b); Opcode::Push16(b) }
            28 => { let mut b = [0u8; 17]; rng.fill(&mut b); Opcode::Push17(b) }
            29 => { let mut b = [0u8; 18]; rng.fill(&mut b); Opcode::Push18(b) }
            30 => { let mut b = [0u8; 19]; rng.fill(&mut b); Opcode::Push19(b) }
            31 => { let mut b = [0u8; 20]; rng.fill(&mut b); Opcode::Push20(b) }
            32 => { let mut b = [0u8; 21]; rng.fill(&mut b); Opcode::Push21(b) }
            33 => { let mut b = [0u8; 22]; rng.fill(&mut b); Opcode::Push22(b) }
            34 => { let mut b = [0u8; 23]; rng.fill(&mut b); Opcode::Push23(b) }
            35 => { let mut b = [0u8; 24]; rng.fill(&mut b); Opcode::Push24(b) }
            36 => { let mut b = [0u8; 25]; rng.fill(&mut b); Opcode::Push25(b) }
            37 => { let mut b = [0u8; 26]; rng.fill(&mut b); Opcode::Push26(b) }
            38 => { let mut b = [0u8; 27]; rng.fill(&mut b); Opcode::Push27(b) }
            39 => { let mut b = [0u8; 28]; rng.fill(&mut b); Opcode::Push28(b) }
            40 => { let mut b = [0u8; 29]; rng.fill(&mut b); Opcode::Push29(b) }
            41 => { let mut b = [0u8; 30]; rng.fill(&mut b); Opcode::Push30(b) }
            42 => { let mut b = [0u8; 31]; rng.fill(&mut b); Opcode::Push31(b) }
            43 => { let mut b = [0u8; 32]; rng.fill(&mut b); Opcode::Push32(b) }
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
            Opcode::Pop => vec![0x50],
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
        }
    }
}


fn render_push(opcode: u8, immediate: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + immediate.len());
    v.push(opcode);
    v.extend_from_slice(immediate);
    v
}
