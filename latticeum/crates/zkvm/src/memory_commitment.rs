use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, PseudoCompressionFunction};
use rand::{SeedableRng, rngs::StdRng};
use vm::riscvm::inst::MemoryOperation;

pub fn mem_comm(previous_comm: u64, _mem_op: &MemoryOperation) -> u64 {
    previous_comm + 1
}

/// Lowest width for Goldilocks is 8
const WIDTH: usize = 8;
type PoseidonHash = Poseidon2Goldilocks<WIDTH>;

/// WIDTH is the same as in PoseidonHash
/// RATE is 4, because there are 4 inputs (previous_comm, cycle, address, value)
/// OUT number of output elements is 1
///
/// Capacity = WIDTH - RATE = 8 - 4 = 4
/// Security is (Capacity * field bits) / 2 = (4 * 64) / 2 = 128 bits of security
type PoseidonSponge = PaddingFreeSponge<PoseidonHash, WIDTH, 4, 1>;

type PoseidonCompression = CompressionFunctionFromHasher<PoseidonSponge, 4, 1>;

pub struct PoseidonHasher {
    compression: PoseidonCompression,
}

const RNG_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

impl PoseidonHasher {
    pub fn new() -> Self {
        let mut rng = StdRng::from_seed(RNG_SEED);
        let poseidon2 = PoseidonHash::new_from_rng_128(&mut rng);
        let sponge = PoseidonSponge::new(poseidon2);
        let compression = PoseidonCompression::new(sponge);
        Self { compression }
    }

    pub fn mem_comm(&self, previous_comm: Goldilocks, mem_op: &MemoryOperation) -> Goldilocks {
        let input = [
            [previous_comm],
            [Goldilocks::from_usize(mem_op.cycle)],
            [Goldilocks::from_u32(mem_op.address)],
            [Goldilocks::from_u32(mem_op.value)],
        ];

        self.compression.compress(input)[0]
    }
}
