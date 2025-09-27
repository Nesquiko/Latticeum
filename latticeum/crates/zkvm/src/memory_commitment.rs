use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use rand::{SeedableRng, rngs::StdRng};
use vm::riscvm::inst::MemoryOperation;

pub fn mem_comm(previous_comm: u64, _mem_op: &MemoryOperation) -> u64 {
    previous_comm + 1
}

const WIDTH: usize = 8;
type PoseidonHash = Poseidon2Goldilocks<WIDTH>;
type MemCommSponge = PaddingFreeSponge<PoseidonHash, WIDTH, 4, 1>;

pub struct PoseidonSponge {
    sponge: MemCommSponge,
}

impl PoseidonSponge {
    pub fn new() -> Self {
        let mut rng = StdRng::from_os_rng();
        let poseidon2 = PoseidonHash::new_from_rng_128(&mut rng);
        let sponge = MemCommSponge::new(poseidon2);
        Self { sponge }
    }

    pub fn poseidon_mem_comm(
        &self,
        previous_comm: Goldilocks,
        mem_op: &MemoryOperation,
    ) -> Goldilocks {
        self.sponge.hash_iter([
            previous_comm,
            Goldilocks::from_usize(mem_op.cycle),
            Goldilocks::from_u32(mem_op.address),
            Goldilocks::from_u32(mem_op.value),
        ])[0]
    }
}
