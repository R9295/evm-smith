#[derive(Debug, Clone)]
pub struct Resource {
    stack: isize,
    /// Free stack slots an op needs reserved during execution (i.e. the peak
    /// number of items the rendered region pushes above the entry stack
    /// before any internal pop). The constraint solver enforces this without
    /// synthesizing pushes — it only emits POPs when there isn't room.
    stack_reserved: usize,
    gas: u64,
    memory: u64,
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

    pub fn stack_reserved(&self) -> usize {
        self.stack_reserved
    }

    pub fn memory(&self) -> u64 {
        self.memory
    }
}

#[derive(Debug, Default, Clone)]
pub struct ResourceBuilder {
    stack: isize,
    stack_reserved: usize,
    gas: u64,
    memory: u64,
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

    pub fn stack_reserved(mut self, stack_reserved: usize) -> Self {
        self.stack_reserved = stack_reserved;
        self
    }

    pub fn memory(mut self, memory: u64) -> Self {
        self.memory = memory;
        self
    }

    pub fn build(self) -> Resource {
        Resource {
            stack: self.stack,
            stack_reserved: self.stack_reserved,
            gas: self.gas,
            memory: self.memory,
        }
    }
}
