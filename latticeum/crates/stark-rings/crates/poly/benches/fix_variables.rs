use ark_serialize::CanonicalDeserialize;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use stark_rings::cyclotomic_ring::models::goldilocks::{Fq, Fq3, RqNTT};
use stark_rings_poly::mle::{DenseMultilinearExtension, MultilinearExtension};

const POINTS_HEX: &[&str] = &[
    "62743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce6",
    "62743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce6",
    "62743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce6",
    "62743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce662743af35ef1deea40402ba26e8654cde8ff7bdb3d2d4ce6",
];

fn bench_fix_variables(c: &mut Criterion) {
    let points: Vec<RqNTT> = parse_captured_points();
    let base = deterministic_mle(18);
    let mut group = c.benchmark_group("fix_variables");

    for (idx, point) in points.iter().enumerate() {
        group.bench_with_input(BenchmarkId::from_parameter(idx), &idx, |b, _| {
            b.iter_batched(
                || base.clone(),
                |mut poly| {
                    poly.fix_variables(black_box(std::slice::from_ref(point)));
                    black_box(poly.evaluations.len())
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let hex = s.trim();
    assert!(hex.len() % 2 == 0, "hex input has odd length");
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex digit in capture");
        out.push(byte);
    }
    out
}

fn parse_captured_points() -> Vec<RqNTT> {
    let mut points = Vec::new();
    for hex in POINTS_HEX {
        let bytes = hex_to_bytes(hex);
        let base = Fq3::deserialize_compressed(bytes.as_slice())
            .expect("failed to deserialize Fq3 capture");
        points.push(RqNTT::from(base));
    }
    points
}

fn deterministic_mle(num_vars: usize) -> DenseMultilinearExtension<RqNTT> {
    let evals = (0..(1usize << num_vars))
        .map(|i| {
            let x = i as u64;
            let c0 = Fq::from(x.wrapping_mul(17).wrapping_add(3));
            let c1 = Fq::from(x.wrapping_mul(29).wrapping_add(5));
            let c2 = Fq::from(x.wrapping_mul(43).wrapping_add(7));
            RqNTT::from(Fq3::new(c0, c1, c2))
        })
        .collect::<Vec<_>>();
    DenseMultilinearExtension::from_evaluations_vec(num_vars, evals)
}

criterion_group!(benches, bench_fix_variables);
criterion_main!(benches);
