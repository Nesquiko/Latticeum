use configuration::N_REGS;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_keccak::Keccak256Hash;
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_merkle_tree::{MerkleTree, MerkleTreeError, MerkleTreeMmcs};
use p3_symmetric::{
    CryptographicHasher, Hash, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use vm::riscvm::{
    inst::{ExecutionTrace, MemoryOperation},
    vm::{Loaded, VM, WORD_SIZE, physical_addr},
};

const RNG_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

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

pub type GoldilocksComm = [Goldilocks; MEM_COMM_POSEIDON2_OUT];

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
    TruncatedPermutation<MemCommPoseidon2Perm, 2, 4, MEM_COMM_POSEIDON2_WIDTH>;

type MemCommMerkleTree = MerkleTreeMmcs<
    Goldilocks,
    Goldilocks,
    MemCommPoseidon2Sponge,
    MemCommPoseidon2Compression,
    MEM_COMM_POSEIDON2_OUT,
>;

/// Total state size of the Poseidon2 permutation for state 0 commitment (rate + capacity).
/// The permutation operates on arrays of WIDTH field elements.
/// WIDTH = RATE + CAPACITY
const STATE0_COMM_POSEIDON2_WIDTH: usize = 16;

/// Number of field elements that can be absorbed per permutation call. This is
/// the "input size" of the sponge construction.
/// Higher rate = faster hashing, but lower security.
/// Security is (Capacity * field bits) / 2 = (4 * 64) / 2 = 128 bits of security
/// With CAPACITY=4 for 128-bit security, RATE = WIDTH - CAPACITY = 16 - 4 = 12
const STATE0_COMM_POSEIDON2_RATE: usize = 12;

/// Number of field elements in the output digest. This determines the size of
/// hash outputs.
const STATE_COMM_POSEIDON2_OUT: usize = 4;

type StatePoseidon2Perm = Poseidon2Goldilocks<STATE0_COMM_POSEIDON2_WIDTH>;
type StatePoseidon2Sponge = PaddingFreeSponge<
    StatePoseidon2Perm,
    STATE0_COMM_POSEIDON2_WIDTH,
    STATE0_COMM_POSEIDON2_RATE,
    STATE_COMM_POSEIDON2_OUT,
>;

/// Opening proof for a modified memory page.
pub struct MemoryPageComm<const WORDS_PER_PAGE: usize> {
    pub comm: GoldilocksComm,
    /// The page data that was opened
    pub page: [Goldilocks; WORDS_PER_PAGE],
    /// The Merkle proof for this page
    pub proof: Vec<GoldilocksComm>,
    /// The page index that was opened
    pub page_index: usize,
}

pub struct ZkVmCommitter {
    memory_hasher: MemCommPoseidon2Sponge,
    memory_compression: MemCommPoseidon2Compression,
    memory_ops_vec_compression: MemOpsVecCommPoseidon2Compression,
    memory_mmcs: MemCommMerkleTree,

    state_hasher: StatePoseidon2Sponge,
}

impl ZkVmCommitter {
    pub fn new() -> Self {
        let mut rng = StdRng::from_seed(RNG_SEED);
        let memory_perm = MemCommPoseidon2Perm::new_from_rng_128(&mut rng);
        let memory_hasher = MemCommPoseidon2Sponge::new(memory_perm.clone());
        let memory_compression = MemCommPoseidon2Compression::new(memory_perm.clone());
        let memory_ops_vec_compression = MemOpsVecCommPoseidon2Compression::new(memory_perm);
        let memory_mmcs = MemCommMerkleTree::new(memory_hasher.clone(), memory_compression.clone());

        let state_perm = StatePoseidon2Perm::new_from_rng_128(&mut rng);
        let state_hasher = StatePoseidon2Sponge::new(state_perm);

        Self {
            memory_hasher,
            memory_compression,
            memory_ops_vec_compression,
            memory_mmcs,
            state_hasher,
        }
    }

    /// Commits to state_i and generates opening proof for modified memory page
    pub fn state_i_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
        trace: &ExecutionTrace,
        previous_mem_comm: MemoryPageComm<WORDS_PER_PAGE>,
        previous_mem_ops_vec_comm: GoldilocksComm,
    ) -> (
        [Goldilocks; STATE_COMM_POSEIDON2_OUT],
        MemoryPageComm<WORDS_PER_PAGE>,
    ) {
        let commit_start = std::time::Instant::now();

        let pc = Goldilocks::from_usize(vm.pc);
        let regs_comm = self.vm_regs_comm(vm);

        let memory_comm = if let Some(mem_op) = &trace.side_effects.memory_op {
            self.vm_mem_comm_with_opening(vm, mem_op)
        } else {
            previous_mem_comm
        };

        let mem_ops_vec_comm = if let Some(mem_op) = &trace.side_effects.memory_op {
            self.vm_mem_ops_vec_comm(previous_mem_ops_vec_comm, mem_op)
        } else {
            previous_mem_ops_vec_comm
        };

        let comm = self.state_hasher.hash_iter([
            pc,
            regs_comm[0],
            regs_comm[1],
            regs_comm[2],
            regs_comm[3],
            memory_comm.comm[0],
            memory_comm.comm[1],
            memory_comm.comm[2],
            memory_comm.comm[3],
            mem_ops_vec_comm[0],
            mem_ops_vec_comm[1],
            mem_ops_vec_comm[2],
            mem_ops_vec_comm[3],
        ]);

        tracing::trace!("commited to state_i in {:?}", commit_start.elapsed());
        (comm, memory_comm)
    }

    pub fn state_0_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
    ) -> [Goldilocks; STATE_COMM_POSEIDON2_OUT] {
        let commit_start = std::time::Instant::now();

        let code_comm = vm_code_comm(vm);
        let entrypoint = Goldilocks::from_usize(vm.elf().entry_point);
        let zero_mem_comm = self.vm_mem_comm(vm);
        // calculated with [ZkVmCommitter::vm_mem_comm] on empty memory
        let const_zero_mem_merkle_root = [
            Goldilocks::from_u64(11048378538371949082),
            Goldilocks::from_u64(17790278716442129820),
            Goldilocks::from_u64(1567578095375187627),
            Goldilocks::from_u64(16514699081104724142),
        ];
        assert_eq!(zero_mem_comm, const_zero_mem_merkle_root);

        let zero_regs_comm = self.vm_regs_comm(vm);
        // calculated with [ZkVmCommitter::vm_regs_comm] on empty regs
        let const_zero_regs_merkle_root = [
            Goldilocks::from_u64(16244443006506064383),
            Goldilocks::from_u64(3940747969403026289),
            Goldilocks::from_u64(12218044832803549905),
            Goldilocks::from_u64(11889365038133828323),
        ];
        assert_eq!(zero_regs_comm, const_zero_regs_merkle_root);

        let zero_mem_ops_vec_comm = self.vm_mem_ops_vec_comm(
            [Goldilocks::ZERO; MEM_COMM_POSEIDON2_OUT],
            &MemoryOperation {
                cycle: 0,
                address: 0,
                value: 0,
                is_write: false,
            },
        );
        // calculated with [ZkVmCommitter::mem_ops_vec_comm] on empty/zero args
        let const_zero_mem_ops_vec_comm = [
            Goldilocks::from_u64(17155745924013818368),
            Goldilocks::from_u64(13273765924687100318),
            Goldilocks::from_u64(14983401559123317382),
            Goldilocks::from_u64(16003586692101738351),
        ];
        assert_eq!(zero_mem_ops_vec_comm, const_zero_mem_ops_vec_comm);

        let comm = self.state_hasher.hash_iter([
            code_comm[0],
            code_comm[1],
            code_comm[2],
            code_comm[3],
            entrypoint,
            zero_mem_comm[0],
            zero_mem_comm[1],
            zero_mem_comm[2],
            zero_mem_comm[3],
            zero_regs_comm[0],
            zero_regs_comm[1],
            zero_regs_comm[2],
            zero_regs_comm[3],
            zero_mem_ops_vec_comm[0],
            zero_mem_ops_vec_comm[1],
            zero_mem_ops_vec_comm[2],
            zero_mem_ops_vec_comm[3],
        ]);

        tracing::trace!("commited to state_0 in {:?}", commit_start.elapsed());
        comm
    }

    /// Creates a Merkle tree commitment over the VM's registers
    fn vm_regs_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
    ) -> GoldilocksComm {
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

        tracing::trace!("commited to vm's registers in {:?}", commit_start.elapsed());
        tree.root().into()
    }

    /// Creates a Merkle tree commitment over the VM's memory using Poseidon2.
    /// Each page is hashed into a leaf, and the Merkle tree is built over all pages.
    fn vm_mem_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
    ) -> GoldilocksComm {
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

        tracing::trace!("commited to vm's memory in {:?}", commit_start.elapsed());
        tree.root().into()
    }

    /// Creates a Merkle tree commitment over the VM's memory and generates an opening proof
    /// for the page that was modified by the memory operation.
    ///
    /// The memory is organized as a single matrix where:
    /// - Each row is a page (WORDS_PER_PAGE elements)
    /// - There are PAGE_COUNT rows
    /// - The Merkle tree has PAGE_COUNT leaves (one per page/row)
    fn vm_mem_comm_with_opening<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
        mem_op: &MemoryOperation,
    ) -> MemoryPageComm<WORDS_PER_PAGE> {
        let commit_start = std::time::Instant::now();

        let (page_index, _) =
            physical_addr::<WORD_SIZE, WORDS_PER_PAGE, PAGE_COUNT>(mem_op.address as usize);

        let mut all_pages = Vec::with_capacity(PAGE_COUNT * WORDS_PER_PAGE);
        for page in vm.memory.iter() {
            for &word in page.iter() {
                all_pages.push(Goldilocks::from_u32(word));
            }
        }

        let memory_matrix = RowMajorMatrix::new(all_pages, WORDS_PER_PAGE);
        let (commitment, merkle_tree) = self.memory_mmcs.commit(vec![memory_matrix]);

        let batch_opening: BatchOpening<Goldilocks, MemCommMerkleTree> =
            self.memory_mmcs.open_batch(page_index, &merkle_tree);

        // there should be log2(PAGE_COUNT) elements in merkle proof
        assert_eq!(
            PAGE_COUNT.trailing_zeros() as usize,
            batch_opening.opening_proof.len(),
            "Expected {} proof elements for {} pages, got {}",
            PAGE_COUNT.trailing_zeros(),
            PAGE_COUNT,
            batch_opening.opening_proof.len()
        );

        let comm = MemoryPageComm::<WORDS_PER_PAGE> {
            comm: commitment.into(),
            page: batch_opening.opened_values[0]
                .clone()
                .try_into()
                .expect("failed to convert page data"),
            proof: batch_opening.opening_proof,
            page_index,
        };
        tracing::trace!(
            "commited to vm's memory with opening for page {} in {:?}",
            page_index,
            commit_start.elapsed()
        );
        comm
    }

    /// Verifies a memory page opening proof against a commitment.
    pub fn verify_memory_opening<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        comm: &MemoryPageComm<WORDS_PER_PAGE>,
    ) -> Result<(), MerkleTreeError> {
        let commitment_array = Hash::from(comm.comm);

        let dimensions = vec![Dimensions {
            width: WORDS_PER_PAGE,
            height: PAGE_COUNT,
        }];

        let batch_opening_ref = BatchOpeningRef {
            opened_values: &[comm.page.to_vec()],
            opening_proof: &comm.proof,
        };

        self.memory_mmcs.verify_batch(
            &commitment_array,
            &dimensions,
            comm.page_index,
            batch_opening_ref,
        )
    }

    fn vm_mem_ops_vec_comm(
        &self,
        previous_comm: GoldilocksComm,
        mem_op: &MemoryOperation,
    ) -> GoldilocksComm {
        let commit_start = std::time::Instant::now();

        let input = [
            previous_comm,
            [
                Goldilocks::from_usize(mem_op.cycle),
                Goldilocks::from_u32(mem_op.address),
                Goldilocks::from_u32(mem_op.value),
                Goldilocks::ZERO,
            ],
        ];

        let comm = self.memory_ops_vec_compression.compress(input);
        tracing::trace!("commited to memory ops vec in {:?}", commit_start.elapsed());
        comm
    }
}

fn vm_code_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
    vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
) -> GoldilocksComm {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use vm::riscvm::{
        inst::MemoryOperation,
        vm::{dummy_loaded_vm_1mb, new_vm_1mb},
    };

    use crate::commitments::ZkVmCommitter;

    #[test]
    fn page_commitment_and_verification() {
        const WORDS_PER_PAGE: usize = 256;
        const PAGE_COUNT: usize = 1024;

        let commiter = ZkVmCommitter::new();
        let mut vm = dummy_loaded_vm_1mb();

        //                   __ppppwwwwwwwwii
        let virt_addr: u32 = 0b00011000000100; // page 1, word 129
        let value = 1;

        vm.write_mem(virt_addr as usize, value);
        let memory_op = MemoryOperation {
            cycle: 0,
            address: virt_addr,
            value: value,
            is_write: true,
        };
        let comm = commiter.vm_mem_comm_with_opening(&vm, &memory_op);

        commiter
            .verify_memory_opening::<WORDS_PER_PAGE, PAGE_COUNT>(&comm)
            .expect("commitment opening wan't valid");
    }

    #[test]
    fn state_0_comm_on_fibonacci() {
        let vm = new_vm_1mb();
        let program = PathBuf::from(
            "/home/nesquiko/fiit/dp/latticeum/target/riscv32imac-unknown-none-elf/release/fibonacci",
        );
        let vm = vm.load_elf(program).expect("failed to load fibonacci elf");

        let commiter = ZkVmCommitter::new();
        let comm = commiter.state_0_comm(&vm);

        let expected = [
            Goldilocks::from_u64(3265770228178860056),
            Goldilocks::from_u64(5178827264030412874),
            Goldilocks::from_u64(3467290198855439401),
            Goldilocks::from_u64(11781120981098105746),
        ];

        assert_eq!(expected, comm);
    }
}
