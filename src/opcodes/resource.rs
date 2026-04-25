#[derive(Debug, Clone)]
pub struct Resource {
    stack: isize,
    gas: u64,
}

impl Resource {
    pub fn builder() -> ResourceBuilder {
        ResourceBuilder::default()
    }
    pub fn set_stack(&mut self, stack: isize) {
        self.stack = stack;
    }
    pub fn gas(&self) -> u64 {
        self.gas
    }

    pub fn stack(&self) -> isize {
        self.stack
    }
}

#[derive(Debug, Default, Clone)]
pub struct ResourceBuilder {
    stack: isize,
    gas: u64,
}

impl ResourceBuilder {
    pub fn gas(mut self, gas: u64) -> Self {
        self.gas = gas;
        self
    }

    pub fn stack(mut self, stack: isize) -> Self {
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
