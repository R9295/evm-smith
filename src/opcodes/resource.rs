#[derive(Debug, Clone)]
pub struct Resource {
    stack: u8,
    gas: u32,
}

impl Resource {
    pub fn builder() -> ResourceBuilder {
        ResourceBuilder::default()
    }
}

#[derive(Debug, Default, Clone)]
pub struct ResourceBuilder {
    stack: u8,
    gas: u32,
}

impl ResourceBuilder {
    pub fn gas(mut self, gas: u32) -> Self {
        self.gas = gas;
        self
    }

    pub fn stack(mut self, stack: u8) -> Self {
        self.stack = stack;
        self
    }

    pub fn build(self) -> Resource {
        Resource {
            stack: self.stack,
            gas: self.gas,
        }
    }
}
