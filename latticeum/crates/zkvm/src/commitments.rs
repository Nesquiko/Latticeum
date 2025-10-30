use std::sync::LazyLock;

use configuration::N_REGS;
use cyclotomic_rings::rings::{GoldilocksRingNTT, GoldilocksRingPoly};
use latticefold::arith::LCCCS;
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
use stark_rings::{
    PolyRing,
    cyclotomic_ring::{ICRT, models::goldilocks::Fq},
};
use tracing::{Level, instrument};
use vm::riscvm::{
    inst::{ExecutionTrace, MemoryOperation},
    vm::{Loaded, Memory, Registers, VM, WORD_SIZE, physical_addr},
};

const RNG_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// number of field elements in the output digest
const POSEIDON2_OUT: usize = 4;

pub type GoldilocksComm = [Goldilocks; POSEIDON2_OUT];

pub const ZERO_GOLDILOCKS_COMM: GoldilocksComm = [Goldilocks::ZERO; 4];

/// Total state size of the Poseidon2 permutation for memory and registers
/// commitments (rate + capacity). The permutation operates on arrays of WIDTH
/// field elements.
const POSEIDON2_WIDTH: usize = 8;

/// Number of field elements that can be absorbed per permutation call. This is
/// the "input size" of the sponge construction. Higher rate = faster hashing,
/// but lower security.
const POSEIDON2_RATE: usize = 4;

type Poseidon2Perm = Poseidon2Goldilocks<POSEIDON2_WIDTH>;
type Poseidon2Sponge =
    PaddingFreeSponge<Poseidon2Perm, POSEIDON2_WIDTH, POSEIDON2_RATE, POSEIDON2_OUT>;
type Poseidon2Compression = TruncatedPermutation<Poseidon2Perm, 2, POSEIDON2_OUT, POSEIDON2_WIDTH>;

type MemOpsVecCommPoseidon2Compression = TruncatedPermutation<Poseidon2Perm, 2, 4, POSEIDON2_WIDTH>;

type Poseidon2MerkleTree =
    MerkleTreeMmcs<Goldilocks, Goldilocks, Poseidon2Sponge, Poseidon2Compression, POSEIDON2_OUT>;

/// Total state size of the Poseidon2 permutation for state 0 commitment (rate + capacity).
/// The permutation operates on arrays of WIDTH field elements.
/// WIDTH = RATE + CAPACITY
const WIDE_POSEIDON2_WIDTH: usize = 16;

/// Number of field elements that can be absorbed per permutation call. This is
/// the "input size" of the sponge construction.
/// Higher rate = faster hashing, but lower security.
/// Security is (Capacity * field bits) / 2 = (4 * 64) / 2 = 128 bits of security
/// With CAPACITY=4 for 128-bit security, RATE = WIDTH - CAPACITY = 16 - 4 = 12
const WIDE_POSEIDON2_RATE: usize = 12;

type WidePoseidon2Perm = Poseidon2Goldilocks<WIDE_POSEIDON2_WIDTH>;
type WidePoseidon2Sponge =
    PaddingFreeSponge<WidePoseidon2Perm, WIDE_POSEIDON2_WIDTH, WIDE_POSEIDON2_RATE, POSEIDON2_OUT>;

/// Opening proof for a modified memory page.
#[derive(Debug, Clone)]
pub struct MemoryPageComm<const WORDS_PER_PAGE: usize> {
    pub comm: GoldilocksComm,
    /// The page data that was opened
    pub page: [Goldilocks; WORDS_PER_PAGE],
    /// The Merkle proof for this page
    pub proof: Vec<GoldilocksComm>,
    /// The page index that was opened
    pub page_index: usize,
}

impl<const WORDS_PER_PAGE: usize> Default for MemoryPageComm<WORDS_PER_PAGE> {
    fn default() -> Self {
        Self {
            comm: Default::default(),
            page: [Goldilocks::ZERO; WORDS_PER_PAGE],
            proof: Default::default(),
            page_index: Default::default(),
        }
    }
}

pub struct ZkVmCommitter {
    hasher: Poseidon2Sponge,
    compression: Poseidon2Compression,
    memory_ops_vec_compression: MemOpsVecCommPoseidon2Compression,
    merkle_tree: Poseidon2MerkleTree,

    wide_hasher: WidePoseidon2Sponge,
}

/// calculated with [ZkVmCommitter::vm_mem_comm] on empty memory
pub static CONST_ZERO_MEM_MERKLE_ROOT: LazyLock<GoldilocksComm> = LazyLock::new(|| {
    [
        Goldilocks::from_u64(11048378538371949082),
        Goldilocks::from_u64(17790278716442129820),
        Goldilocks::from_u64(1567578095375187627),
        Goldilocks::from_u64(16514699081104724142),
    ]
});

/// calculated with [ZkVmCommitter::vm_regs_comm] on empty regs
pub static CONST_ZERO_REGS_COMM: LazyLock<GoldilocksComm> = LazyLock::new(|| {
    [
        Goldilocks::from_u64(13273899974993439638),
        Goldilocks::from_u64(9036831037010425586),
        Goldilocks::from_u64(16810440461374211854),
        Goldilocks::from_u64(4302830597023040269),
    ]
});

/// calculated with [ZkVmCommitter::vm_mem_ops_vec_comm] on empty/zero args
pub static CONST_ZERO_MEM_OPS_VEC_COMM: LazyLock<GoldilocksComm> = LazyLock::new(|| {
    [
        Goldilocks::from_u64(17155745924013818368),
        Goldilocks::from_u64(13273765924687100318),
        Goldilocks::from_u64(14983401559123317382),
        Goldilocks::from_u64(16003586692101738351),
    ]
});

impl ZkVmCommitter {
    pub fn new() -> Self {
        let mut rng = StdRng::from_seed(RNG_SEED);
        let perm = Poseidon2Perm::new_from_rng_128(&mut rng);
        let hasher = Poseidon2Sponge::new(perm.clone());
        let compression = Poseidon2Compression::new(perm.clone());
        let memory_ops_vec_compression = MemOpsVecCommPoseidon2Compression::new(perm);
        let merkle_tree = Poseidon2MerkleTree::new(hasher.clone(), compression.clone());

        let wide_perm = WidePoseidon2Perm::new_from_rng_128(&mut rng);
        let wide_hasher = WidePoseidon2Sponge::new(wide_perm);

        Self {
            hasher,
            compression,
            memory_ops_vec_compression: memory_ops_vec_compression,
            merkle_tree,
            wide_hasher,
        }
    }

    /// `h_i` public poseidon2 commitment to the state of the IVC step `i`.
    /// Preimage contains:
    /// - `i`
    /// - state 0 commitment (calculated with [Self::state_0_comm])
    /// - state i commitment (calculated with [Self::state_i_comm])
    /// - accumulator i commitment ([Self::acc_comm])
    #[instrument(skip_all, level = Level::TRACE)]
    pub fn ivc_step_comm(
        &self,
        i: Goldilocks,
        state_0_comm: GoldilocksComm,
        state_i_comm: GoldilocksComm,
        acc_comm: GoldilocksComm,
    ) -> GoldilocksComm {
        self.wide_hasher.hash_iter([
            i,
            state_0_comm[0],
            state_0_comm[1],
            state_0_comm[2],
            state_0_comm[3],
            state_i_comm[0],
            state_i_comm[1],
            state_i_comm[2],
            state_i_comm[3],
            acc_comm[0],
            acc_comm[1],
            acc_comm[2],
            acc_comm[3],
        ])
    }

    /// Returns commtiment to state_i, memory commitment (new if a memory
    /// operation happened, or previous one if not), and memory ops vec commitment
    /// (new if a memory operation happened, or previous one if not).
    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn state_i_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm_memory: &Memory<WORDS_PER_PAGE, PAGE_COUNT>,
        vm_regs: &Registers,
        trace: &ExecutionTrace,
        memory_comm: &MemoryPageComm<WORDS_PER_PAGE>,
        mem_ops_vec_comm: GoldilocksComm,
    ) -> GoldilocksComm {
        let pc = Goldilocks::from_usize(trace.output.pc);
        let regs_comm = self.vm_regs_comm(vm_regs);

        self.wide_hasher.hash_iter([
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
        ])
    }

    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn acc_comm(&self, acc: &LCCCS<GoldilocksRingNTT>) -> GoldilocksComm {
        let LCCCS::<GoldilocksRingNTT> {
            // sumcheck challenge vector, s = log₂(m) where m is the number of rows in CCS matrices
            r,
            // evaluation of linearized CCS commitment at r
            v,
            // ajtai commitment to the B-decomposed witness, length is the commitment scheme's KAPPA parameter
            cm,
            // evaluations of MLEs of {M_j * z} at r, ccs.t is the number of matrices in the CCS
            u,
            // public IO (CCS statement) of size ccs.l
            x_w,
            // constant term of GoldilocksRingNTT::one()
            h,
        } = acc;

        let r_flat = flatten(r);
        debug_assert_eq!(r_flat.len(), 216);
        let v_flat = flatten(v);
        debug_assert_eq!(v_flat.len(), 72);
        let cm_flat = flatten(cm.as_ref());
        debug_assert_eq!(cm_flat.len(), 96);
        let u_flat = flatten(u);
        debug_assert_eq!(u_flat.len(), 360);
        let x_w_flat = flatten(x_w);
        debug_assert_eq!(x_w_flat.len(), 96);
        let h_flat = flatten(&[*h]);
        debug_assert_eq!(h_flat.len(), 24);

        let mut acc_goldilocks: Vec<Goldilocks> = Vec::new();
        acc_goldilocks.extend_from_slice(&r_flat);
        acc_goldilocks.extend_from_slice(&v_flat);
        acc_goldilocks.extend_from_slice(&cm_flat);
        acc_goldilocks.extend_from_slice(&u_flat);
        acc_goldilocks.extend_from_slice(&x_w_flat);
        acc_goldilocks.extend_from_slice(&h_flat);

        self.wide_hasher.hash_iter(acc_goldilocks)
    }

    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn state_0_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
    ) -> GoldilocksComm {
        let code_comm = vm_code_comm(vm);
        let entrypoint = Goldilocks::from_usize(vm.elf().entry_point);
        let zero_mem_comm = self.vm_mem_comm(vm);
        debug_assert_eq!(zero_mem_comm, *CONST_ZERO_MEM_MERKLE_ROOT);

        let zero_regs_comm = self.vm_regs_comm(&vm.regs);
        debug_assert_eq!(zero_regs_comm, *CONST_ZERO_REGS_COMM);

        let zero_mem_ops_vec_comm = self.vm_mem_ops_vec_comm(
            [Goldilocks::ZERO; POSEIDON2_OUT],
            &MemoryOperation {
                cycle: 0,
                address: 0,
                value: 0,
                is_write: false,
            },
        );
        debug_assert_eq!(zero_mem_ops_vec_comm, *CONST_ZERO_MEM_OPS_VEC_COMM);

        self.wide_hasher.hash_iter([
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
        ])
    }

    /// Creates a poseidon2 commitment over the VM's registers
    #[instrument(skip_all, level = Level::DEBUG)]
    fn vm_regs_comm(&self, vm_regs: &Registers) -> GoldilocksComm {
        let reg_elements: [Goldilocks; N_REGS] = vm_regs
            .iter()
            .map(|&word| Goldilocks::from_u32(word))
            .collect::<Vec<Goldilocks>>()
            .try_into()
            .expect("how can there be more then 32 regs?");

        self.wide_hasher.hash_iter(reg_elements)
    }

    /// Creates a Merkle tree commitment over the VM's memory using Poseidon2.
    /// Each page is hashed into a leaf, and the Merkle tree is built over all pages.
    #[instrument(skip_all, level = Level::DEBUG)]
    fn vm_mem_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
    ) -> GoldilocksComm {
        let mut leaves = Vec::with_capacity(PAGE_COUNT);

        for page in vm.memory.iter() {
            let page_elements: Vec<Goldilocks> = page
                .iter()
                .map(|&word| Goldilocks::from_u32(word))
                .collect();

            let matrix = RowMajorMatrix::new(page_elements, WORDS_PER_PAGE);
            leaves.push(matrix);
        }

        let tree =
            MerkleTree::<Goldilocks, Goldilocks, RowMajorMatrix<Goldilocks>, POSEIDON2_OUT>::new::<
                Goldilocks,
                Goldilocks,
                _,
                _,
            >(&self.hasher, &self.compression, leaves);

        tree.root().into()
    }

    /// Creates a Merkle tree commitment over the VM's memory and generates an opening proof
    /// for the page that was modified by the memory operation.
    ///
    /// The memory is organized as a single matrix where:
    /// - Each row is a page (WORDS_PER_PAGE elements)
    /// - There are PAGE_COUNT rows
    /// - The Merkle tree has PAGE_COUNT leaves (one per page/row)
    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn vm_mem_comm_with_opening<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm_memory: &Memory<WORDS_PER_PAGE, PAGE_COUNT>,
        mem_op: &MemoryOperation,
    ) -> MemoryPageComm<WORDS_PER_PAGE> {
        let (page_index, _) =
            physical_addr::<WORD_SIZE, WORDS_PER_PAGE, PAGE_COUNT>(mem_op.address as usize);

        let mut all_pages = Vec::with_capacity(PAGE_COUNT * WORDS_PER_PAGE);
        for page in vm_memory.iter() {
            for &word in page.iter() {
                all_pages.push(Goldilocks::from_u32(word));
            }
        }

        let memory_matrix = RowMajorMatrix::new(all_pages, WORDS_PER_PAGE);
        let (commitment, merkle_tree) = self.merkle_tree.commit(vec![memory_matrix]);

        let batch_opening: BatchOpening<Goldilocks, Poseidon2MerkleTree> =
            self.merkle_tree.open_batch(page_index, &merkle_tree);

        // there should be log2(PAGE_COUNT) elements in merkle proof
        debug_assert_eq!(
            PAGE_COUNT.trailing_zeros() as usize,
            batch_opening.opening_proof.len(),
            "Expected {} proof elements for {} pages, got {}",
            PAGE_COUNT.trailing_zeros(),
            PAGE_COUNT,
            batch_opening.opening_proof.len()
        );

        MemoryPageComm::<WORDS_PER_PAGE> {
            comm: commitment.into(),
            page: batch_opening.opened_values[0]
                .clone()
                .try_into()
                .expect("failed to convert page data"),
            proof: batch_opening.opening_proof,
            page_index,
        }
    }

    /// Verifies a memory page opening proof against a commitment.
    #[instrument(skip_all, level = Level::DEBUG)]
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

        self.merkle_tree.verify_batch(
            &commitment_array,
            &dimensions,
            comm.page_index,
            batch_opening_ref,
        )
    }

    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn vm_mem_ops_vec_comm(
        &self,
        previous_comm: GoldilocksComm,
        mem_op: &MemoryOperation,
    ) -> GoldilocksComm {
        let input = [
            previous_comm,
            [
                Goldilocks::from_usize(mem_op.cycle),
                Goldilocks::from_u32(mem_op.address),
                Goldilocks::from_u32(mem_op.value),
                Goldilocks::ZERO,
            ],
        ];

        self.memory_ops_vec_compression.compress(input)
    }
}

fn vm_code_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
    vm: &VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>,
) -> GoldilocksComm {
    let program_code = vm.elf().raw_code.bytes.clone();
    let hasher = Keccak256Hash {};
    let program_comm = hasher.hash_iter(program_code);
    let mut rng = StdRng::from_seed(program_comm);

    [
        Goldilocks::from_u64(rng.random()),
        Goldilocks::from_u64(rng.random()),
        Goldilocks::from_u64(rng.random()),
        Goldilocks::from_u64(rng.random()),
    ]
}

fn fq_to_plonky3_goldilocks(fq: &Fq) -> Goldilocks {
    debug_assert_eq!(1, fq.0.0.len());
    let num = fq.0.0[0];
    Goldilocks::from_u64(num)
}

fn flatten(vec: &[GoldilocksRingNTT]) -> Vec<Goldilocks> {
    vec.iter()
        .flat_map(|&ring_elem| {
            let coeff_form = ICRT::icrt(ring_elem);
            debug_assert_eq!(GoldilocksRingPoly::dimension(), coeff_form.coeffs().len());
            coeff_form
                .coeffs()
                .iter()
                .map(fq_to_plonky3_goldilocks)
                .collect::<Vec<_>>()
        })
        .collect()
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
        let comm = commiter.vm_mem_comm_with_opening(&vm.memory, &memory_op);

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
            Goldilocks::from_u64(1895765705522452637),
            Goldilocks::from_u64(8128224917819805318),
            Goldilocks::from_u64(15816178864278320395),
            Goldilocks::from_u64(6438867417431175243),
        ];

        assert_eq!(expected, comm);
    }
}
