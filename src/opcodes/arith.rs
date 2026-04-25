use super::{Opcode, Resource};

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

impl Opcode for Add {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(3).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for Mul {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(5).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for Sub {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(3).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for Div {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(5).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for SDiv {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(5).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for Mod {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(5).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for SMod {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(5).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for AddMod {
    fn requires(&self) -> Resource {
        Resource::builder().stack(3).gas(8).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for MulMod {
    fn requires(&self) -> Resource {
        Resource::builder().stack(3).gas(8).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for Exp {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(10).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}

impl Opcode for SignExtend {
    fn requires(&self) -> Resource {
        Resource::builder().stack(2).gas(5).build()
    }
    fn provides(&self) -> Resource {
        Resource::builder().stack(1).build()
    }
}
