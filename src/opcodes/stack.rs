use super::{Opcode, Resource};

#[derive(Debug)]
pub struct Pop;

#[derive(Debug)]
pub struct Push1;
#[derive(Debug)]
pub struct Push2;
#[derive(Debug)]
pub struct Push3;
#[derive(Debug)]
pub struct Push4;
#[derive(Debug)]
pub struct Push5;
#[derive(Debug)]
pub struct Push6;
#[derive(Debug)]
pub struct Push7;
#[derive(Debug)]
pub struct Push8;
#[derive(Debug)]
pub struct Push9;
#[derive(Debug)]
pub struct Push10;
#[derive(Debug)]
pub struct Push11;
#[derive(Debug)]
pub struct Push12;
#[derive(Debug)]
pub struct Push13;
#[derive(Debug)]
pub struct Push14;
#[derive(Debug)]
pub struct Push15;
#[derive(Debug)]
pub struct Push16;
#[derive(Debug)]
pub struct Push17;
#[derive(Debug)]
pub struct Push18;
#[derive(Debug)]
pub struct Push19;
#[derive(Debug)]
pub struct Push20;
#[derive(Debug)]
pub struct Push21;
#[derive(Debug)]
pub struct Push22;
#[derive(Debug)]
pub struct Push23;
#[derive(Debug)]
pub struct Push24;
#[derive(Debug)]
pub struct Push25;
#[derive(Debug)]
pub struct Push26;
#[derive(Debug)]
pub struct Push27;
#[derive(Debug)]
pub struct Push28;
#[derive(Debug)]
pub struct Push29;
#[derive(Debug)]
pub struct Push30;
#[derive(Debug)]
pub struct Push31;
#[derive(Debug)]
pub struct Push32;

impl Opcode for Pop {
    fn requires(&self) -> Resource {
        Resource::builder().stack(1).gas(2).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().build()
    }
    fn render(&self) -> Vec<u8> {
        vec![0x50]
    }
}

macro_rules! impl_push {
    ($($t:ty => $byte:expr, $len:expr),* $(,)?) => {
        $(
            impl Opcode for $t {
                fn requires(&self) -> Resource {
                    Resource::builder().gas(3).build()
                }
                fn provides(&self) -> Resource {
                    Resource::builder().stack(1).build()
                }
                fn render(&self) -> Vec<u8> {
                    let mut bytes = vec![0u8; $len + 1];
                    bytes[0] = $byte;
                    bytes[$len] = 0x01;
                    bytes
                }
            }
        )*
    };
}

impl_push!(
    Push1 => 0x60, 1,
    Push2 => 0x61, 2,
    Push3 => 0x62, 3,
    Push4 => 0x63, 4,
    Push5 => 0x64, 5,
    Push6 => 0x65, 6,
    Push7 => 0x66, 7,
    Push8 => 0x67, 8,
    Push9 => 0x68, 9,
    Push10 => 0x69, 10,
    Push11 => 0x6A, 11,
    Push12 => 0x6B, 12,
    Push13 => 0x6C, 13,
    Push14 => 0x6D, 14,
    Push15 => 0x6E, 15,
    Push16 => 0x6F, 16,
    Push17 => 0x70, 17,
    Push18 => 0x71, 18,
    Push19 => 0x72, 19,
    Push20 => 0x73, 20,
    Push21 => 0x74, 21,
    Push22 => 0x75, 22,
    Push23 => 0x76, 23,
    Push24 => 0x77, 24,
    Push25 => 0x78, 25,
    Push26 => 0x79, 26,
    Push27 => 0x7A, 27,
    Push28 => 0x7B, 28,
    Push29 => 0x7C, 29,
    Push30 => 0x7D, 30,
    Push31 => 0x7E, 31,
    Push32 => 0x7F, 32,
);
