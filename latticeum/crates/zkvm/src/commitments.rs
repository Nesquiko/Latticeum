use configuration::N_REGS;
use cyclotomic_rings::rings::{GoldilocksRingNTT, GoldilocksRingPoly};
use latticefold::arith::LCCCS;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::{Dimensions, dense::RowMajorMatrix};
use p3_merkle_tree::{MerkleTree, MerkleTreeError, MerkleTreeMmcs};
use p3_symmetric::{Hash, PseudoCompressionFunction, TruncatedPermutation};
use stark_rings::{
    PolyRing,
    cyclotomic_ring::{ICRT, models::goldilocks::Fq},
};
use std::usize;
use tracing::{Level, instrument};
use vm::riscvm::{
    inst::MemoryOperation,
    vm::{Memory, Registers, WORD_SIZE, physical_addr},
};

use crate::{
    crypto_consts::internal_constants_len_22,
    poseidon2::{
        GoldilocksComm, IntermediateStates, POSEIDON2_OUT, POSEIDON2_WIDTH, Poseidon2Compression,
        Poseidon2Perm, Poseidon2Sponge, WIDTH_8_EXTERNAL_INITIAL_CONSTS,
        WIDTH_16_EXTERNAL_INITIAL_CONSTS, WideZkVMPoseidon2,
    },
};

type MemOpsVecCommPoseidon2Compression = TruncatedPermutation<Poseidon2Perm, 2, 4, POSEIDON2_WIDTH>;

type Poseidon2MerkleTree =
    MerkleTreeMmcs<Goldilocks, Goldilocks, Poseidon2Sponge, Poseidon2Compression, POSEIDON2_OUT>;

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

pub struct ZkVmCommitter {
    hasher: Poseidon2Sponge,
    compression: Poseidon2Compression,
    memory_ops_vec_compression: MemOpsVecCommPoseidon2Compression,
    merkle_tree: Poseidon2MerkleTree,

    wide_hasher: WideZkVMPoseidon2,
}

impl ZkVmCommitter {
    pub fn new() -> Self {
        let internal_consts = internal_constants_len_22();
        let perm = Poseidon2Perm::new(
            WIDTH_8_EXTERNAL_INITIAL_CONSTS.clone(),
            internal_consts.clone(),
        );

        let hasher = Poseidon2Sponge::new(perm.clone());
        let compression = Poseidon2Compression::new(perm.clone());
        let memory_ops_vec_compression = MemOpsVecCommPoseidon2Compression::new(perm);
        let merkle_tree = Poseidon2MerkleTree::new(hasher.clone(), compression.clone());

        let wide_hasher =
            WideZkVMPoseidon2::new(WIDTH_16_EXTERNAL_INITIAL_CONSTS.clone(), internal_consts);

        Self {
            hasher,
            compression,
            memory_ops_vec_compression,
            merkle_tree,
            wide_hasher,
        }
    }

    /// `h_i` public poseidon2 commitment to the state of the IVC step `i`.
    /// Preimage contains:
    /// - `i`
    /// - state 0 commitment (calculated with [Self::state_i_comm])
    /// - state i commitment (calculated with [Self::state_i_comm])
    /// - accumulator i commitment ([Self::acc_comm])
    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn ivc_step_comm(
        &self,
        i: Goldilocks,
        state_0_comm: GoldilocksComm,
        state_i_comm: GoldilocksComm,
        acc_comm: GoldilocksComm,
    ) -> (GoldilocksComm, IntermediateStates) {
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

    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn state_i_comm(
        &self,
        vm_regs: &Registers,
        program_code: &Box<[u8]>,
        pc: usize,
        memory_comm: GoldilocksComm,
        mem_ops_vec_comm: GoldilocksComm,
    ) -> GoldilocksComm {
        let code_comm = self.vm_code_comm(program_code);
        let pc = Goldilocks::from_usize(pc);
        let regs_comm = self.vm_regs_comm(vm_regs);

        self.wide_hasher
            .hash_iter([
                code_comm[0],
                code_comm[1],
                code_comm[2],
                code_comm[3],
                pc,
                memory_comm[0],
                memory_comm[1],
                memory_comm[2],
                memory_comm[3],
                regs_comm[0],
                regs_comm[1],
                regs_comm[2],
                regs_comm[3],
                mem_ops_vec_comm[0],
                mem_ops_vec_comm[1],
                mem_ops_vec_comm[2],
                mem_ops_vec_comm[3],
            ])
            .0
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
        let v_flat = flatten(v);
        let cm_flat = flatten(cm.as_ref());
        let u_flat = flatten(u);
        let x_w_flat = flatten(x_w);
        let h_flat = flatten(&[*h]);

        let mut acc_goldilocks: Vec<Goldilocks> = Vec::new();
        acc_goldilocks.extend_from_slice(&r_flat);
        acc_goldilocks.extend_from_slice(&v_flat);
        acc_goldilocks.extend_from_slice(&cm_flat);
        acc_goldilocks.extend_from_slice(&u_flat);
        acc_goldilocks.extend_from_slice(&x_w_flat);
        acc_goldilocks.extend_from_slice(&h_flat);

        assert_eq!(r_flat.len(), 264);
        assert_eq!(v_flat.len(), 72);
        assert_eq!(cm_flat.len(), 96);
        assert_eq!(u_flat.len(), 456);
        assert_eq!(x_w_flat.len(), 96);
        assert_eq!(h_flat.len(), 24);
        assert_eq!(acc_goldilocks.len(), 264 + 72 + 96 + 456 + 96 + 24);

        self.wide_hasher.hash_iter(acc_goldilocks).0
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

        self.wide_hasher.hash_iter(reg_elements).0
    }

    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn vm_mem_comm<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>(
        &self,
        vm_memory: &Memory<WORDS_PER_PAGE, PAGE_COUNT>,
    ) -> GoldilocksComm {
        let mut leaves = Vec::with_capacity(PAGE_COUNT);

        for page in vm_memory.iter() {
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
        assert_eq!(
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

    /// Creates a Merkle tree commitment to the VM's program code.
    /// For RISC-V IMAC extensions, instructions can be either:
    /// - 16-bit (compressed instructions)
    /// - 32-bit (standard instructions)
    #[instrument(skip_all, level = Level::DEBUG)]
    fn vm_code_comm(&self, program_code: &Box<[u8]>) -> GoldilocksComm {
        // convert bytes to 16-bit half-words (little-endian), pad with zeros if the code size is odd
        let mut halfwords = Vec::with_capacity((program_code.len() + 1) / 2);
        for chunk in program_code.chunks(2) {
            let halfword = if chunk.len() == 2 {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                // odd byte at the end, pad with zero
                u16::from_le_bytes([chunk[0], 0])
            };
            // Convert u16 to u64 then to Goldilocks field element
            halfwords.push(Goldilocks::from_u16(halfword));
        }
        assert!(!halfwords.is_empty());

        let leaves = RowMajorMatrix::new(halfwords, 1);

        let tree =
            MerkleTree::<Goldilocks, Goldilocks, RowMajorMatrix<Goldilocks>, POSEIDON2_OUT>::new::<
                Goldilocks,
                Goldilocks,
                _,
                _,
            >(&self.hasher, &self.compression, vec![leaves]);

        tree.root().into()
    }
}

fn fq_to_plonky3_goldilocks(fq: &Fq) -> Goldilocks {
    assert_eq!(1, fq.0.0.len());
    let num = fq.0.0[0];
    Goldilocks::from_u64(num)
}

fn flatten(vec: &[GoldilocksRingNTT]) -> Vec<Goldilocks> {
    vec.iter()
        .flat_map(|&ring_elem| {
            let coeff_form = ICRT::icrt(ring_elem);
            assert_eq!(GoldilocksRingPoly::dimension(), coeff_form.coeffs().len());
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
    use crate::{
        commitments::{MemoryPageComm, ZkVmCommitter},
        poseidon2::ZERO_GOLDILOCKS_COMM,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use std::path::PathBuf;
    use vm::riscvm::{
        inst::MemoryOperation,
        vm::{dummy_loaded_vm_1mb, new_vm_1mb},
    };

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
        let vm_memory_comm = MemoryPageComm {
            comm: commiter.vm_mem_comm(&vm.memory),
            page_index: 0,
            page: vm.memory[0].map(|el| Goldilocks::from_u32(el)),
            proof: Default::default(),
        };

        let comm = commiter.state_i_comm(
            &vm.regs,
            &vm.elf().raw_code.bytes,
            vm.pc,
            vm_memory_comm.comm,
            ZERO_GOLDILOCKS_COMM,
        );

        let expected = [
            Goldilocks::from_u64(13458558136629279646),
            Goldilocks::from_u64(11917569669020208757),
            Goldilocks::from_u64(3145715386209370042),
            Goldilocks::from_u64(17331705705982545631),
        ];

        assert_eq!(expected, comm);
    }
}
