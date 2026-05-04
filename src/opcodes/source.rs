use fastrand::Rng;
#[cfg(feature = "rng")]
use std::convert::Infallible;

pub trait OpcodeSource {
    type Error;

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Self::Error>;
    fn u8(&mut self) -> Result<u8, Self::Error>;
    fn u64_inclusive(&mut self, limit: u64) -> Result<u64, Self::Error>;
}

#[cfg(feature = "rng")]
pub struct RngOpcodeSource<'a>(&'a mut Rng);
impl<'a> RngOpcodeSource<'a> {
    pub fn new(rng: &'a mut Rng) -> RngOpcodeSource<'a> {
        Self(rng)
    }
}

#[cfg(feature = "rng")]
impl OpcodeSource for RngOpcodeSource<'_> {
    type Error = Infallible;

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Self::Error> {
        let mut bytes = [0u8; N];
        self.0.fill(&mut bytes);
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, Self::Error> {
        Ok(self.0.u8(..))
    }

    fn u64_inclusive(&mut self, limit: u64) -> Result<u64, Self::Error> {
        if limit == u64::MAX {
            Ok(self.0.u64(..))
        } else {
            Ok(self.0.u64(..limit + 1))
        }
    }
}

#[cfg(feature = "arbitrary")]
pub struct ArbitraryOpcodeSource<'a, 'b>(&'a mut Unstructured<'b>);

#[cfg(feature = "arbitrary")]
impl OpcodeSource for ArbitraryOpcodeSource<'_, '_> {
    type Error = arbitrary::Error;

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Self::Error> {
        <[u8; N]>::arbitrary(self.0)
    }

    fn u8(&mut self) -> Result<u8, Self::Error> {
        u8::arbitrary(self.0)
    }

    fn u64_inclusive(&mut self, limit: u64) -> Result<u64, Self::Error> {
        self.0.int_in_range(0..=limit)
    }
}
