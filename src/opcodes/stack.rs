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
}

macro_rules! impl_push {
    ($($t:ty),*) => {
        $(
            impl Opcode for $t {
                fn requires(&self) -> Resource {
                    Resource::builder().gas(3).build()
                }
                fn provides(&self) -> Resource {
                    Resource::builder().stack(1).build()
                }
            }
        )*
    };
}

impl_push!(
    Push1, Push2, Push3, Push4, Push5, Push6, Push7, Push8, Push9, Push10, Push11, Push12, Push13,
    Push14, Push15, Push16, Push17, Push18, Push19, Push20, Push21, Push22, Push23, Push24, Push25,
    Push26, Push27, Push28, Push29, Push30, Push31, Push32
);
