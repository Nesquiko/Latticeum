use configuration::N_REGS;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTree;
use p3_symmetric::{
    CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use vm::riscvm::{
    inst::{ExecutionTrace, MemoryOperation},
    vm::{Loaded, VM},
};

const RNG_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// Calculated with [ZkVmCommitter::vm_mem_comm] on empty memory
const ZERO_MEM_MERKLE_ROOT: u64 = 11048378538371949082;

/// Calculated with [ZkVmCommitter::vm_regs_comm] on empty regs
const ZERO_REGS_MERKLE_ROOT: u64 = 16244443006506064383;

/// Calculated with [ZkVmCommitter::mem_ops_vec_comm] on empty/zero args
const ZERO_MEM_OPS_VEC_COMM: u64 = 17155745924013818368;

/// Total state size of the Poseidon2 permutation for memory and registers
/// commitments (rate + capacity). The permutation operates on arrays of WIDTH
/// field elements.
const MEM_COMM_POSEIDON2_WIDTH: usize = 8;

/// Number of field elements that can be absorbed per permutation call. This is
/// the "input size" of the sponge construction. Higher rate = faster hashing,
/// but lower security.
const MEM_COMM_POSEIDON2_RATE: usize = 4;

/// Number of field elements in the output digest. This determines the size of
/// hash outputs and Merkle tree node digests.
const MEM_COMM_POSEIDON2_OUT: usize = 4;

type MemCommPoseidon2Perm = Poseidon2Goldilocks<MEM_COMM_POSEIDON2_WIDTH>;
type MemCommPoseidon2Sponge = PaddingFreeSponge<
    MemCommPoseidon2Perm,
    MEM_COMM_POSEIDON2_WIDTH,
    MEM_COMM_POSEIDON2_RATE,
    MEM_COMM_POSEIDON2_OUT,
>;
type MemCommPoseidon2Compression =
    TruncatedPermutation<MemCommPoseidon2Perm, 2, MEM_COMM_POSEIDON2_OUT, MEM_COMM_POSEIDON2_WIDTH>;

type MemOpsVecCommPoseidon2Compression =
    TruncatedPermutation<MemCommPoseidon2Perm, 4, 1, MEM_COMM_POSEIDON2_WIDTH>;

/// Total state size of the Poseidon2 permutation for state 0 commitment (rate + capacity).
/// The permutation operates on arrays of WIDTH field elements.
const STATE0_COMM_POSEIDON2_WIDTH: usize = 12;

/// Number of field elements that can be absorbed per permutation call. This is
/// the "input size" of the sponge construction. Higher rate = faster hashing,
/// but lower security. In order to keep 128 bits of security, subtract 4 from
/// the [STATE0_COMM_POSEIDON2_WIDTH]:
/// Security is (Capacity * field bits) / 2 = (4 * 64) / 2 = 128 bits of security
const STATE0_COMM_POSEIDON2_RATE: usize = STATE0_COMM_POSEIDON2_WIDTH - 4;

/// Number of field elements in the output digest. This determines the size of
/// hash outputs.
const STATE0_COMM_POSEIDON2_OUT: usize = 1;

type State0Poseidon2Perm = Poseidon2Goldilocks<STATE0_COMM_POSEIDON2_WIDTH>;
type State0Poseidon2Sponge = PaddingFreeSponge<
    State0Poseidon2Perm,
    STATE0_COMM_POSEIDON2_WIDTH,
    STATE0_COMM_POSEIDON2_RATE,
    STATE0_COMM_POSEIDON2_OUT,
>;

pub struct ZkVmCommitter {
    memory_hasher: MemCommPoseidon2Sponge,
    memory_compression: MemCommPoseidon2Compression,
    memory_ops_vec_compression: MemOpsVecCommPoseidon2Compression,
}

impl ZkVmCommitter {
    pub fn new() -> Self {
        let mut rng = StdRng::from_seed(RNG_SEED);
        let memory_perm = MemCommPoseidon2Perm::new_from_rng_128(&mut rng);
        let memory_hasher = MemCommPoseidon2Sponge::new(memory_perm.clone());
        let memory_compression = MemCommPoseidon2Compression::new(memory_perm.clone());
        let memory_ops_vec_compression = MemOpsVecCommPoseidon2Compression::new(memory_perm);

        Self {
            memory_hasher,
            memory_compression,
            memory_ops_vec_compression,
        }
    }

    pub fn state_i_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
        trace: &ExecutionTrace,
    ) -> Goldilocks {
        let commit_start = std::time::Instant::now();

        let pc = Goldilocks::from_usize(vm.pc);
        let regs_comm = self.vm_regs_comm(vm);

        if let Some(mem_op) = &trace.side_effects.memory_op {
            // TODO update the comm to mem
            // TODO update the comm to mem vec ops
        }

        tracing::trace!("commited to state_0 in {:?}", commit_start.elapsed());
        Goldilocks::ZERO
    }

    pub fn state_0_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
    ) -> Goldilocks {
        let commit_start = std::time::Instant::now();

        // 8 elements
        let code_comm = vm_code_comm(vm);
        let entrypoint = Goldilocks::from_usize(vm.elf().entry_point);
        let zero_mem_comm = Goldilocks::from_u64(ZERO_MEM_MERKLE_ROOT);
        let zero_regs_comm = Goldilocks::from_u64(ZERO_REGS_MERKLE_ROOT);
        let zero_mem_ops_vec_comm = Goldilocks::from_u64(ZERO_MEM_OPS_VEC_COMM);

        let mut rng = StdRng::from_seed(RNG_SEED);
        let perm = State0Poseidon2Perm::new_from_rng_128(&mut rng);
        let hasher = State0Poseidon2Sponge::new(perm);
        let comm = hasher.hash_iter([
            code_comm[0],
            code_comm[1],
            code_comm[2],
            code_comm[3],
            entrypoint,
            zero_mem_comm,
            zero_regs_comm,
            zero_mem_ops_vec_comm,
        ]);

        tracing::trace!("commited to state_0 in {:?}", commit_start.elapsed());
        comm[0]
    }

    /// Creates a Merkle tree commitment over the VM's registers
    fn vm_regs_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
    ) -> Goldilocks {
        let commit_start = std::time::Instant::now();

        let reg_elements: Vec<Goldilocks> = vm
            .regs
            .iter()
            .map(|&word| Goldilocks::from_u32(word))
            .collect();

        let matrix = RowMajorMatrix::new(reg_elements, N_REGS);
        let leaves = vec![matrix];

        let tree = MerkleTree::<
            Goldilocks,
            Goldilocks,
            RowMajorMatrix<Goldilocks>,
            MEM_COMM_POSEIDON2_OUT,
        >::new::<Goldilocks, Goldilocks, _, _>(
            &self.memory_hasher,
            &self.memory_compression,
            leaves,
        );

        let root_array: [Goldilocks; MEM_COMM_POSEIDON2_OUT] = tree.root().into();
        tracing::trace!("commited to vm's registers in {:?}", commit_start.elapsed());
        root_array[0]
    }

    /// Creates a Merkle tree commitment over the VM's memory using Poseidon2.
    /// Each page is hashed into a leaf, and the Merkle tree is built over all pages.
    fn vm_mem_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
    ) -> Goldilocks {
        let commit_start = std::time::Instant::now();

        let mut leaves = Vec::with_capacity(PAGE_COUNT);

        for page in vm.memory.iter() {
            let page_elements: Vec<Goldilocks> = page
                .iter()
                .map(|&word| Goldilocks::from_u32(word))
                .collect();

            let matrix = RowMajorMatrix::new(page_elements, WORDS_PER_PAGE);
            leaves.push(matrix);
        }

        let tree = MerkleTree::<
            Goldilocks,
            Goldilocks,
            RowMajorMatrix<Goldilocks>,
            MEM_COMM_POSEIDON2_OUT,
        >::new::<Goldilocks, Goldilocks, _, _>(
            &self.memory_hasher,
            &self.memory_compression,
            leaves,
        );

        let root_array: [Goldilocks; MEM_COMM_POSEIDON2_OUT] = tree.root().into();
        tracing::trace!("commited to vm's memory in {:?}", commit_start.elapsed());
        root_array[0]
    }

    fn vm_mem_ops_vec_comm(
        &self,
        previous_comm: Goldilocks,
        mem_op: &MemoryOperation,
    ) -> Goldilocks {
        let commit_start = std::time::Instant::now();

        let input = [
            [previous_comm],
            [Goldilocks::from_usize(mem_op.cycle)],
            [Goldilocks::from_u32(mem_op.address)],
            [Goldilocks::from_u32(mem_op.value)],
        ];

        let comm = self.memory_ops_vec_compression.compress(input)[0];
        tracing::trace!("commited to memory ops vec in {:?}", commit_start.elapsed());
        comm
    }
}

fn vm_code_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
    vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
) -> [Goldilocks; 4] {
    let commit_start = std::time::Instant::now();
    let program_code = vm.elf().raw_code.bytes.clone();
    let hasher = Keccak256Hash {};
    let program_comm = hasher.hash_iter(program_code);
    let mut rng = StdRng::from_seed(program_comm);

    let comm = [
        Goldilocks::from_u64(rng.random()),
        Goldilocks::from_u64(rng.random()),
        Goldilocks::from_u64(rng.random()),
        Goldilocks::from_u64(rng.random()),
    ];

    tracing::trace!("commited to vm's code in {:?}", commit_start.elapsed());
    comm
}
