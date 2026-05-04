use crate::opcodes::OpcodeSource;

pub const GENERATED_VARIANT_COUNT: usize = 140;
pub const PUSH_VARIANT_OFFSET: usize = 56;
pub const PUSH_VARIANT_COUNT: usize = 32;
pub const OPCODE_FAMILY_COUNT: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeFamily {
    Arithmetic,
    ComparisonBitwise,
    Environment,
    Stack,
    Push,
    Storage,
    Memory,
    Logs,
    CopyHash,
    Create,
    Calls,
}

impl OpcodeFamily {
    pub const ALL: [Self; OPCODE_FAMILY_COUNT] = [
        Self::Arithmetic,
        Self::ComparisonBitwise,
        Self::Environment,
        Self::Stack,
        Self::Push,
        Self::Storage,
        Self::Memory,
        Self::Logs,
        Self::CopyHash,
        Self::Create,
        Self::Calls,
    ];

    pub const fn variant_count(self) -> usize {
        match self {
            Self::Arithmetic => 12,
            Self::ComparisonBitwise => 14,
            Self::Environment => 25,
            Self::Stack => 33,
            Self::Push => 33,
            Self::Storage => 4,
            Self::Memory => 4,
            Self::Logs => 5,
            Self::CopyHash => 5,
            Self::Create => 2,
            Self::Calls => 3,
        }
    }

    pub const fn variant_index_at(self, offset: usize) -> usize {
        match self {
            Self::Arithmetic => {
                if offset < 11 {
                    offset
                } else {
                    139
                }
            }
            Self::ComparisonBitwise => 11 + offset,
            Self::Environment => {
                if offset < 22 {
                    25 + offset
                } else {
                    50 + (offset - 22)
                }
            }
            Self::Stack => {
                if offset == 0 {
                    47
                } else {
                    88 + (offset - 1)
                }
            }
            Self::Push => 55 + offset,
            Self::Storage => match offset {
                0 => 48,
                1 => 49,
                2 => 53,
                3 => 54,
                _ => unreachable!(),
            },
            Self::Memory => match offset {
                0 => 120,
                1 => 121,
                2 => 127,
                3 => 132,
                _ => unreachable!(),
            },
            Self::Logs => 122 + offset,
            Self::CopyHash => {
                if offset < 4 {
                    128 + offset
                } else {
                    133
                }
            }
            Self::Create => 134 + offset,
            Self::Calls => 136 + offset,
        }
    }
}

/// Family-level weights for generated opcodes. Selection is two-stage:
/// choose a family by weight, then choose uniformly among that family's
/// concrete opcode variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpcodeWeights {
    pub arithmetic: u32,
    pub comparison_bitwise: u32,
    pub environment: u32,
    pub stack: u32,
    pub push: u32,
    pub storage: u32,
    pub memory: u32,
    pub logs: u32,
    pub copy_hash: u32,
    pub create: u32,
    pub calls: u32,
}

impl OpcodeWeights {
    /// Balanced default that gives stateful, memory, create, and call opcodes
    /// much more opportunity than flat variant sampling.
    pub const fn balanced() -> Self {
        Self {
            arithmetic: 12,
            comparison_bitwise: 12,
            environment: 8,
            stack: 8,
            push: 4,
            storage: 12,
            memory: 14,
            logs: 8,
            copy_hash: 12,
            create: 8,
            calls: 10,
        }
    }

    /// Weights that reproduce the historical flat per-variant distribution.
    pub const fn uniform() -> Self {
        Self {
            arithmetic: OpcodeFamily::Arithmetic.variant_count() as u32,
            comparison_bitwise: OpcodeFamily::ComparisonBitwise.variant_count() as u32,
            environment: OpcodeFamily::Environment.variant_count() as u32,
            stack: OpcodeFamily::Stack.variant_count() as u32,
            push: OpcodeFamily::Push.variant_count() as u32,
            storage: OpcodeFamily::Storage.variant_count() as u32,
            memory: OpcodeFamily::Memory.variant_count() as u32,
            logs: OpcodeFamily::Logs.variant_count() as u32,
            copy_hash: OpcodeFamily::CopyHash.variant_count() as u32,
            create: OpcodeFamily::Create.variant_count() as u32,
            calls: OpcodeFamily::Calls.variant_count() as u32,
        }
    }

    /// Profile biased toward stateful and cross-frame behavior.
    pub const fn stateful() -> Self {
        Self {
            arithmetic: 6,
            comparison_bitwise: 6,
            environment: 4,
            stack: 8,
            push: 3,
            storage: 18,
            memory: 18,
            logs: 10,
            copy_hash: 14,
            create: 10,
            calls: 12,
        }
    }

    /// Empty profile useful with struct update syntax when a caller wants to
    /// enable only a few families. If every weight is zero, generation falls
    /// back to `uniform()`.
    pub const fn zero() -> Self {
        Self {
            arithmetic: 0,
            comparison_bitwise: 0,
            environment: 0,
            stack: 0,
            push: 0,
            storage: 0,
            memory: 0,
            logs: 0,
            copy_hash: 0,
            create: 0,
            calls: 0,
        }
    }

    fn weight(self, family: OpcodeFamily) -> u32 {
        match family {
            OpcodeFamily::Arithmetic => self.arithmetic,
            OpcodeFamily::ComparisonBitwise => self.comparison_bitwise,
            OpcodeFamily::Environment => self.environment,
            OpcodeFamily::Stack => self.stack,
            OpcodeFamily::Push => self.push,
            OpcodeFamily::Storage => self.storage,
            OpcodeFamily::Memory => self.memory,
            OpcodeFamily::Logs => self.logs,
            OpcodeFamily::CopyHash => self.copy_hash,
            OpcodeFamily::Create => self.create,
            OpcodeFamily::Calls => self.calls,
        }
    }

    fn total(self) -> u64 {
        OpcodeFamily::ALL
            .iter()
            .map(|family| self.weight(*family) as u64)
            .sum()
    }
}

impl Default for OpcodeWeights {
    fn default() -> Self {
        Self::balanced()
    }
}

pub(crate) fn weighted_variant_index<S: OpcodeSource>(
    source: &mut S,
    weights: &OpcodeWeights,
) -> Result<usize, S::Error> {
    let total = weights.total();
    if total == 0 {
        return Ok(source.u64_inclusive((GENERATED_VARIANT_COUNT - 1) as u64)? as usize);
    }

    let mut roll = source.u64_inclusive(total - 1)?;
    for family in OpcodeFamily::ALL {
        let weight = weights.weight(family) as u64;
        if weight == 0 {
            continue;
        }
        if roll < weight {
            let offset = source.u64_inclusive((family.variant_count() - 1) as u64)? as usize;
            return Ok(family.variant_index_at(offset));
        }
        roll -= weight;
    }

    unreachable!("weighted opcode selection roll escaped weight total")
}
