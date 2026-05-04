# evm-smith

evm-smith is a resource-aware EVM bytecode generator library. It builds final
runtime bytecode from either a deterministic RNG source or arbitrary input bytes.

To get bytecode, construct a `Machine`, call `ingest_next()` until generation
stops, then call `machine.bytecode()`.

## Table of contents

- [About](#about)
- [Usage](#usage)
  - [RNG generation](#rng-generation)
  - [Arbitrary-byte generation](#arbitrary-byte-generation)
- [Pipeline](#pipeline)
- [Input format](#input-format)
- [Output](#output)
- [Example](#example)
- [Donate](#donate)

# About

Naive random EVM bytecode usually dies before it reaches interesting execution:
stack underflows, immediate out-of-gas, impossible memory expansion, malformed
CREATE payloads, or recursive calls into unknown code. evm-smith keeps a
symbolic machine while it generates bytecode, tracking stack height, memory
growth, gas budget, created contract nonces, and safe call targets.

The generator covers arithmetic, comparison, bitwise, environment, block, stack,
storage, transient storage, memory, logs, copy/hash, CREATE, CREATE2, CALL,
STATICCALL, and DELEGATECALL families. CREATE and CREATE2 payloads are generated
by sub-machines and returned as empty runtime code so later calls can target
created contracts without recursively executing unknown generated code.

The library has two generation backends:

- `rng`: deterministic generation from a `fastrand::Rng`.
- `arbitrary`: generation from raw bytes.

Known limitation: sub-machines cannot call contracts they deploy themselves.
See [LIMITATIONS.md](LIMITATIONS.md) for the CREATE2 address-stability reason.

## Usage

The Cargo package is currently named `evm`. Enable either `rng` or `arbitrary`;
the crate intentionally refuses to compile without a generation source.

### RNG generation

```rust
use evm_smith::machine::{Config, Machine};

fn generate_bytecode(seed: u64, gas: u64) -> Vec<u8> {
    let config = Config::default();
    let rng = fastrand::Rng::with_seed(seed);
    let mut machine = Machine::new_rng(gas, rng, config);

    while machine.ingest_next().is_ok() {}

    machine.bytecode()
}
```

Build or test this path with:

```bash
cargo test --features rng
```

### Arbitrary-byte generation

```rust
use evm_smith::machine::{Config, Machine};

fn generate_bytecode(input: Vec<u8>, gas: u64) -> Vec<u8> {
    let config = Config::default();
    let mut machine = Machine::new_arbitrary(gas, input, config);

    while machine.ingest_next().is_ok() {}

    machine.bytecode()
}
```

Build or test this path with:

```bash
cargo test --features arbitrary
```

## Pipeline

```text
RNG seed or arbitrary input bytes
  |
  |- 1. Build Machine with gas, address, memory, and opcode-weight config
  |- 2. Draw opcodes from the selected generation backend
  |- 3. Reject or repair choices that violate stack, memory, gas, or init-code limits
  |- 4. Materialize CREATE/CREATE2 init code with generated sub-machines
  |- 5. Materialize CALL targets from known empty-code addresses
  `- 6. Render final bytecode
```

## Input format

evm-smith does not take bytecode templates. The input is generation data:

| Surface | Feature | Input |
|---------|---------|-------|
| RNG API | `rng` | `fastrand::Rng`, `Config`, and gas budget. |
| Arbitrary API | `arbitrary` | Raw byte buffer, `Config`, and gas budget. |

`Config` controls:

- root caller and contract addresses used for symbolic address accounting
- CREATE sub-call gas percentage
- termination behavior
- whether CREATE grows the known call-target set
- sampled memory offset and length limits
- family-level opcode weights

## Output

`Machine::bytecode()` returns the final rendered bytecode as `Vec<u8>`.

The returned bytecode includes a trailing `STOP` byte (`0x00`). Generated CREATE
and CREATE2 init-code payloads also append `RETURN(0, 0)`, so deployed contracts
have empty runtime code and remain safe call targets.

Convert to `0x` hex if your harness expects text:

```rust
fn hex0x(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
```

## Example

A minimal deterministic generator that writes raw bytecode:

```rust
use evm_smith::machine::{Config, Machine};

fn main() -> anyhow::Result<()> {
    let seed = 42;
    let gas = 3_000_000;
    let mut machine = Machine::new_rng(gas, fastrand::Rng::with_seed(seed), Config::default());

    while machine.ingest_next().is_ok() {}

    let bytecode = machine.bytecode();
    std::fs::write("/tmp/evm-smith.bin", &bytecode)?;

    println!("{}", hex0x(&bytecode));
    Ok(())
}

fn hex0x(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
```

# Donate

If this tool is useful to your work, consider funding development:

```text
0x466c0B6Ea71Bbc902514aba82E4C7e08f7e73CE4
```
