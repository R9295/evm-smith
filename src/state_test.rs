use alloy_primitives::{Address, keccak256};
use serde_json::{Value, json};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EvmByteBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl EvmByteBuffer {
    fn null() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }

    fn from_vec(bytes: Vec<u8>) -> Self {
        let mut bytes = bytes.into_boxed_slice();
        let out = Self {
            data: bytes.as_mut_ptr(),
            len: bytes.len(),
        };
        std::mem::forget(bytes);
        out
    }
}

#[cfg(feature = "arbitrary")]
pub fn arbitrary_state_test(data: Vec<u8>, gas: u64) -> Vec<u8> {
    use crate::{
        addresses::ExecutionAddresses,
        machine::{Config, Machine},
    };

    let sender_sk = DEFAULT_SENDER_SK;
    let sender = derive_sender(&sender_sk).unwrap();
    let mut config = Config::default();
    config.addresses = ExecutionAddresses {
        caller: sender,
        contract: ExecutionAddresses::default().contract,
    };
    let mut machine = Machine::new_arbitrary(gas, data, config);
    loop {
        if !machine.ingest_next().is_ok() {
            break;
        }
    }
    let st = build_state_test_json(&machine.bytecode(), sender, &sender_sk, gas);
    serde_json::to_vec(&st).unwrap()
}

#[cfg(feature = "arbitrary")]
#[unsafe(export_name = "arbitrary_state_test")]
pub unsafe extern "C" fn arbitrary_state_test_ffi(
    data: *const u8,
    len: usize,
    gas: u64,
) -> EvmByteBuffer {
    if data.is_null() && len != 0 {
        return EvmByteBuffer::null();
    }

    let input = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };

    std::panic::catch_unwind(|| EvmByteBuffer::from_vec(arbitrary_state_test(input, gas)))
        .unwrap_or_else(|_| EvmByteBuffer::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn evm_byte_buffer_free(buffer: EvmByteBuffer) {
    if buffer.data.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            buffer.data,
            buffer.len,
        )));
    }
}

pub fn build_state_test_json(
    bytecode: &[u8],
    sender: Address,
    sender_sk: &[u8; 32],
    _gas: u64,
) -> Value {
    let gas_limit = 167_77_216u32;
    json!({
        "evm-fuzz": {
            "env": {
                "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                "currentDifficulty": "0x020000",
                "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000",
                "currentGasLimit": "0xffffffffffffff",
                "currentNumber": "0x01",
                "currentTimestamp": "0x03e8",
                "currentBaseFee": "0x0a",
                "currentExcessBlobGas": "0x00",
                "previousHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6",
            },
            "pre": {
                hex0x(sender.as_slice()): {
                    // 1 ETH + u128::MAX, matching runner.rs:88.
                    "balance": "0x1000000000000000000ffffffffffffffff",
                    "code": "0x",
                    "nonce": "0x01",
                    "storage": {},
                },
                "0x4242424242424242424242424242424242424242": {
                    "balance": "0x00",
                    "code": hex0x(bytecode),
                    "nonce": "0x01",
                    "storage": {},
                },
            },
            "transaction": {
                "data": ["0x"],
                "gasLimit": [format!("{:#x}", gas_limit)],
                "gasPrice": "0x0a",
                "nonce": "0x01",
                "secretKey": hex0x(sender_sk),
                "to": "0x4242424242424242424242424242424242424242",
                "value": ["0xde0b6b3a7640000"],
            },
            "post": {
                FORK: [{
                    "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "logs": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "indexes": {"data": 0, "gas": 0, "value": 0},
                }]
            },
        }
    })
}

const FORK: &str = "Osaka";

pub fn hex0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn derive_sender(sk: &[u8; 32]) -> anyhow::Result<Address> {
    let secp = secp256k1::Secp256k1::new();
    let secret = secp256k1::SecretKey::from_byte_array(sk)
        .map_err(|e| anyhow::anyhow!("invalid sender secret key: {e}"))?;
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let serialized = pk.serialize_uncompressed();
    // serialize_uncompressed returns 65 bytes: leading 0x04 tag + 64 bytes of x||y.
    let hash = keccak256(&serialized[1..]);
    Ok(Address::from_slice(&hash[12..]))
}

/// Standard EEST test sender private key. Address: 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b.
pub const DEFAULT_SENDER_SK: [u8; 32] = [
    0x45, 0xa9, 0x15, 0xe4, 0xd0, 0x60, 0x14, 0x9e, 0xb4, 0x36, 0x59, 0x60, 0xe6, 0xa7, 0xa4, 0x5f,
    0x33, 0x43, 0x93, 0x09, 0x30, 0x61, 0x11, 0x6b, 0x19, 0x7e, 0x32, 0x40, 0x06, 0x5f, 0xf2, 0xd8,
];

#[cfg(all(test, feature = "arbitrary"))]
mod tests {
    use super::*;

    #[test]
    fn ffi_arbitrary_state_test_returns_owned_json() {
        let input = [0xAA, 0xBB, 0xCC, 0xDD];
        let buffer = unsafe { arbitrary_state_test_ffi(input.as_ptr(), input.len(), 100_000) };

        assert!(!buffer.data.is_null());
        assert!(buffer.len > 0);

        let bytes = unsafe { std::slice::from_raw_parts(buffer.data, buffer.len) };
        assert_eq!(bytes[0], b'{');

        unsafe { evm_byte_buffer_free(buffer) };
    }

    #[test]
    fn ffi_arbitrary_state_test_rejects_null_nonempty_input() {
        let buffer = unsafe { arbitrary_state_test_ffi(std::ptr::null(), 1, 100_000) };

        assert!(buffer.data.is_null());
        assert_eq!(buffer.len, 0);
    }
}
