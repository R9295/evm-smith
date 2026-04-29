use alloy_primitives::{keccak256, Address};
use serde_json::{json, Value};

pub fn build_state_test_json(
    bytecode: &[u8],
    sender: Address,
    sender_sk: &[u8; 32],
    _gas: u32,
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
