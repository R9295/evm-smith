use alloy_primitives::Address;

/// Addresses used for the root transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionAddresses {
    pub caller: Address,
    pub contract: Address,
}

impl Default for ExecutionAddresses {
    fn default() -> Self {
        Self {
            caller: Address::from([0x11; 20]),
            contract: Address::from([0x42; 20]),
        }
    }
}

impl ExecutionAddresses {
    pub fn assert_valid(self) {
        assert_ne!(
            self.caller, self.contract,
            "caller and contract addresses must be distinct"
        );
    }
}
