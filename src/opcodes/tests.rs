#[cfg(feature = "arbitrary")]
use arbitrary::Unstructured;
#[cfg(feature = "rng")]
use fastrand::Rng;

use crate::{
    machine::Config,
    opcodes::{GENERATED_VARIANT_COUNT, Opcode, OpcodeFamily, OpcodeWeights},
};

const MEMORY_VARIANT_INDICES: [usize; 17] = [
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 136, 137, 138,
];

#[cfg(feature = "rng")]
#[test]
fn rng_zero_memory_limits_force_zero_offsets_and_lengths() {
    let config = zero_memory_config();
    for idx in MEMORY_VARIANT_INDICES {
        let mut rng = Rng::with_seed(idx as u64);
        let op = Opcode::nth_variant_rng(idx, &mut rng, &config);
        assert_memory_offsets_and_lengths(&op, 0, 0);
    }
}

#[cfg(feature = "arbitrary")]
#[test]
fn arbitrary_zero_memory_limits_force_zero_offsets_and_lengths() {
    let config = zero_memory_config();
    let data = [0xAB; 512];
    for idx in MEMORY_VARIANT_INDICES {
        let mut u = Unstructured::new(&data);
        let op = Opcode::nth_variant_arbitrary(idx, &mut u, &config).unwrap();
        assert_memory_offsets_and_lengths(&op, 0, 0);
    }
}

#[cfg(feature = "rng")]
#[test]
fn rng_variants_exclude_manual_terminators() {
    let config = zero_memory_config();
    let mut rng = Rng::with_seed(0);
    for idx in 0..GENERATED_VARIANT_COUNT {
        let op = Opcode::nth_variant_rng(idx, &mut rng, &config);
        assert!(!matches!(
            op,
            Opcode::Stop | Opcode::Return(..) | Opcode::SelfDestruct(..)
        ));
    }
}

#[cfg(feature = "arbitrary")]
#[test]
fn arbitrary_variants_exclude_manual_terminators() {
    let config = zero_memory_config();
    let data = [0xCD; 512];
    for idx in 0..GENERATED_VARIANT_COUNT {
        let mut u = Unstructured::new(&data);
        let op = Opcode::nth_variant_arbitrary(idx, &mut u, &config).unwrap();
        assert!(!matches!(
            op,
            Opcode::Stop | Opcode::Return(..) | Opcode::SelfDestruct(..)
        ));
    }
}

#[test]
fn weighted_families_cover_every_generated_variant_once() {
    let mut seen = [0u8; GENERATED_VARIANT_COUNT];

    for family in OpcodeFamily::ALL {
        for offset in 0..family.variant_count() {
            let idx = family.variant_index_at(offset);
            assert!(idx < GENERATED_VARIANT_COUNT);
            seen[idx] = seen[idx].saturating_add(1);
        }
    }

    for (idx, count) in seen.iter().enumerate() {
        assert_eq!(*count, 1, "variant {idx} has family coverage count {count}");
    }
}

#[cfg(feature = "rng")]
#[test]
fn rng_weighted_generation_can_select_only_calls() {
    let config = calls_only_config();
    let mut rng = Rng::with_seed(0);

    for _ in 0..64 {
        let op = Opcode::generate_weighted(&mut rng, &config);
        assert!(matches!(
            op,
            Opcode::Call { .. } | Opcode::StaticCall { .. } | Opcode::DelegateCall { .. }
        ));
    }
}

#[cfg(feature = "arbitrary")]
#[test]
fn arbitrary_weighted_generation_can_select_only_calls() {
    let config = calls_only_config();
    let data = [0xEF; 2048];
    let mut u = Unstructured::new(&data);

    for _ in 0..16 {
        let op = Opcode::arbitrary_weighted(&mut u, &config).unwrap();
        assert!(matches!(
            op,
            Opcode::Call { .. } | Opcode::StaticCall { .. } | Opcode::DelegateCall { .. }
        ));
    }
}

fn zero_memory_config() -> Config {
    Config {
        memory_offset_limit: 0,
        memory_length_limit: 0,
        ..Config::default()
    }
}

fn calls_only_config() -> Config {
    Config {
        opcode_weights: OpcodeWeights {
            calls: 1,
            ..OpcodeWeights::zero()
        },
        memory_offset_limit: 0,
        memory_length_limit: 0,
        ..Config::default()
    }
}

fn assert_memory_offsets_and_lengths(op: &Opcode, expected_offset: u64, expected_length: u64) {
    match op {
        Opcode::MStore(offset, _)
        | Opcode::MLoad(offset)
        | Opcode::MStore8(offset, _)
        | Opcode::CallDataLoad(offset) => assert_eq!(*offset, expected_offset),
        Opcode::Log0(offset, length)
        | Opcode::Log1(offset, length, _)
        | Opcode::Log2(offset, length, _, _)
        | Opcode::Log3(offset, length, _, _, _)
        | Opcode::Log4(offset, length, _, _, _, _)
        | Opcode::Return(offset, length)
        | Opcode::Keccak256(offset, length) => {
            assert_eq!(*offset, expected_offset);
            assert_eq!(*length, expected_length);
        }
        Opcode::MCopy(dest, src, length)
        | Opcode::CallDataCopy(dest, src, length)
        | Opcode::CodeCopy(dest, src, length)
        | Opcode::ExtCodeCopy(_, dest, src, length) => {
            assert_eq!(*dest, expected_offset);
            assert_eq!(*src, expected_offset);
            assert_eq!(*length, expected_length);
        }
        Opcode::Call {
            args_offset,
            args_size,
            ret_offset,
            ret_size,
            ..
        }
        | Opcode::StaticCall {
            args_offset,
            args_size,
            ret_offset,
            ret_size,
            ..
        }
        | Opcode::DelegateCall {
            args_offset,
            args_size,
            ret_offset,
            ret_size,
            ..
        } => {
            assert_eq!(*args_offset, expected_offset);
            assert_eq!(*args_size, expected_length);
            assert_eq!(*ret_offset, expected_offset);
            assert_eq!(*ret_size, expected_length);
        }
        _ => panic!("unexpected opcode in memory limit test: {op:?}"),
    }
}
