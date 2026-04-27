#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OutOfGas,
    MaxInitCode,
    HaltConditionEncountered,
}
