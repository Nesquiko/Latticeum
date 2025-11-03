use crate::ccs::CCSLayout;
use ark_std::log2;
use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::arith::CCS;
use num_traits::identities::One;
use stark_rings_linalg::SparseMatrix;
use std::ops::Neg;

pub type Ring = GoldilocksRingNTT;

#[derive(Debug)]
pub struct CCSBuilder<'a> {
    /// number of constraints = number of rows in matrices[i]
    m: usize,
    /// layout of the witness vector, also used to derive `n` = number of variables
    layout: &'a CCSLayout,
    /// vector of selector matrices (otherwise known as `M`)
    matrices: Vec<SparseMatrix<Ring>>,
    /// vector of multisets which signal which matrices to use in constraint (otherwise known as `S`)
    multisets: Vec<Vec<usize>>,
    /// vector of coefficients to be used in constraint (otherwise known as `c`)
    coeffs: Vec<Ring>,
}

impl<'a> CCSBuilder<'a> {
    fn new<const W: usize>(layout: &'a CCSLayout) -> Self {
        Self {
            m: W,
            layout,
            matrices: Vec::new(),
            multisets: Vec::new(),
            coeffs: Vec::new(),
        }
    }

    pub fn create_riscv_ccs<const W: usize>(layout: &'a CCSLayout) -> CCS<Ring> {
        let mut builder = Self::new::<W>(layout);

        builder.pc_non_branching_constraint();

        builder.add_constraint();
        builder.jal_constraint();
        builder.jalr_constraint();
        builder.bne_constraint();
        builder.auipc_constraint();
        builder.lui_constraint();

        builder.build()
    }

    /// Adds an ADD constraint that handles 32-bit overflow:
    /// z[IS_ADD] * (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[VAL_RS1] - z[VAL_RS2]) = 0
    fn add_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_ADD]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[ADD_CONSTR].push((Ring::one(), self.layout.is_add_idx));

        // Matrix B: selects (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[VAL_RS1] - z[VAL_RS2])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[ADD_CONSTR].push((Ring::from(1u64 << 32), self.layout.has_overflown_idx)); // +2^32 * has_overflown
        m_b.coeffs[ADD_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx)); // +val_rd_out
        m_b.coeffs[ADD_CONSTR].push((Ring::one().neg(), self.layout.val_rs1_idx)); // -val_rs1
        m_b.coeffs[ADD_CONSTR].push((Ring::one().neg(), self.layout.val_rs2_idx)); // -val_rs2

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a PC constraint for non-branching instructions:
    /// (1 - z[IS_BRANCHING]) * (z[PC_OUT] - z[PC_IN] - z[INST_SIZE]) = 0
    fn pc_non_branching_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects (1 - z[IS_BRANCHING])
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[PC_NON_BRANCH_CONSTR].push((Ring::one(), self.layout.const_1_idx));
        m_a.coeffs[PC_NON_BRANCH_CONSTR].push((Ring::one().neg(), self.layout.is_branching_idx));

        // Matrix B: selects (z[PC_OUT] - z[PC_IN] - z[INSTRUCTION_SIZE])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[PC_NON_BRANCH_CONSTR].push((Ring::one(), self.layout.pc_out_idx));
        m_b.coeffs[PC_NON_BRANCH_CONSTR].push((Ring::one().neg(), self.layout.pc_in_idx));
        m_b.coeffs[PC_NON_BRANCH_CONSTR]
            .push((Ring::one().neg(), self.layout.instruction_size_idx));

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a JAL constraint that ensures the return address is written correctly:
    /// z[IS_JAL] * (z[VAL_RD_OUT] - (z[PC_IN] + z[INSTRUCTION_SIZE])) = 0
    fn jal_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_JAL]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[JAL_CONSTR].push((Ring::one(), self.layout.is_jal_idx));

        // Matrix B: selects (z[VAL_RD_OUT] - z[PC_IN] - z[INSTRUCTION_SIZE])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[JAL_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx));
        m_b.coeffs[JAL_CONSTR].push((Ring::one().neg(), self.layout.pc_in_idx));
        m_b.coeffs[JAL_CONSTR].push((Ring::one().neg(), self.layout.instruction_size_idx));

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a JALR constraint that ensures the return address is written correctly:
    /// z[IS_JALR] * (z[VAL_RD_OUT] - (z[PC_IN] + z[INSTRUCTION_SIZE])) = 0
    fn jalr_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_JALR]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[JALR_CONSTR].push((Ring::one(), self.layout.is_jalr_idx));

        // Matrix B: selects (z[VAL_RD_OUT] - z[PC_IN] - z[INSTRUCTION_SIZE])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[JALR_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx));
        m_b.coeffs[JALR_CONSTR].push((Ring::one().neg(), self.layout.pc_in_idx));
        m_b.coeffs[JALR_CONSTR].push((Ring::one().neg(), self.layout.instruction_size_idx));

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a BNE constraint that ensures the branch condition is correct:
    /// z[IS_BNE] * (1 - z[IS_BRANCHING]) * (z[VAL_RS1] - z[VAL_RS2]) = 0
    ///
    /// This constraint ensures that:
    /// - If is_branching = 0 (branch not taken), then rs1 - rs2 = 0, so rs1 = rs2
    /// - If is_branching = 1 (branch taken), then rs1 - rs2 != 0 and constraint becomes 0 * (...) = 0
    ///
    /// Since the Goldilocks field is used and it is proving a 32-bit machine,
    /// the rs1 - rs2 = 0 can be directly constrained.
    fn bne_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_BNE]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[BNE_CONSTR].push((Ring::one(), self.layout.is_bne_idx));

        // Matrix B: selects (1 - z[IS_BRANCHING])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[BNE_CONSTR].push((Ring::one(), 0)); // constant 1 is at() index 0() in z-vector
        m_b.coeffs[BNE_CONSTR].push((Ring::one().neg(), self.layout.is_branching_idx));

        // Matrix C: selects (z[VAL_RS1] - z[VAL_RS2])
        let mut m_c = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_c.coeffs[BNE_CONSTR].push((Ring::one(), self.layout.val_rs1_idx));
        m_c.coeffs[BNE_CONSTR].push((Ring::one().neg(), self.layout.val_rs2_idx));

        self.matrices.push(m_a);
        self.matrices.push(m_b);
        self.matrices.push(m_c);

        // Multiset: A * B * C = IS_BNE * (1 - IS_BRANCHING) * (RS1 - RS2)
        self.multisets.push(vec![
            matrix_base_idx,
            matrix_base_idx + 1,
            matrix_base_idx + 2,
        ]);
        self.coeffs.push(Ring::one());
    }

    /// Adds an AUIPC constraint that handles 32-bit overflow:
    /// z[IS_AUIPC] * (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[PC_IN] - (z[IMM] * 2^12)) = 0
    ///
    /// AUIPC computes: rd = pc + (imm << 12) with 32-bit wrapping
    /// The constraint ensures this computation is performed correctly, including overflow handling.
    pub fn auipc_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_AUIPC]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[AUIPC_CONSTR].push((Ring::one(), self.layout.is_auipc_idx));

        // Matrix B: selects (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[PC_IN] - (z[IMM] * 2^12))
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[AUIPC_CONSTR].push((Ring::from(1u64 << 32), self.layout.has_overflown_idx)); // +2^32 * has_overflown
        m_b.coeffs[AUIPC_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx)); // +rd_out
        m_b.coeffs[AUIPC_CONSTR].push((Ring::one().neg(), self.layout.pc_in_idx)); // -pc_in
        m_b.coeffs[AUIPC_CONSTR].push((Ring::from(1u64 << 12).neg(), self.layout.imm_idx)); // -(imm * 2^12)

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a LUI constraint that ensures the computation is correct:
    /// z[IS_LUI] * (z[VAL_RD_OUT] - (z[IMM] * 2^12)) = 0
    ///
    /// LUI computes: rd = imm << 12 (load upper immediate)
    /// where z[IMM] contains the unshifted immediate value
    /// and the constraint performs the shift by multiplying by 2^12
    fn lui_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_LUI]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[LUI_CONSTR].push((Ring::one(), self.layout.is_lui_idx));

        // Matrix B: selects (z[VAL_RD_OUT] - (z[IMM] * 2^12))
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[LUI_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx)); // +rd_out
        m_b.coeffs[LUI_CONSTR].push((Ring::from(1u64 << 12).neg(), self.layout.imm_idx)); // -(imm * 2^12)

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    pub fn build(self) -> CCS<Ring> {
        let mut ccs = CCS::<Ring> {
            m: self.m,
            n: self.layout.z_vector_size(), // z-vector structure: [x_ccs(1), 1, w_ccs(layout.size)] = layout.size + 2 total
            l: CCSLayout::X_ELEMS_SIZE,     // Number of public inputs (memory commitment)
            t: self.matrices.len(),
            q: self.multisets.len(),
            d: self.multisets.iter().map(|s| s.len()).max().unwrap_or(1),
            s: log2(self.m) as usize,
            s_prime: log2(self.layout.z_vector_size()) as usize,
            M: self.matrices,
            S: self.multisets,
            c: self.coeffs,
        };

        // The latticefold library will apply additional padding based on the formula:
        // len = max((n - l - 1) * L, m).next_power_of_two()
        // With our values: n=layout.size+1, l=0, L=1, m=original_m
        // This gives: len = max(layout.size, original_m).next_power_of_two()
        // So we need to set our dimensions to match this expected padding
        let latticefold_padded_size =
            usize::max((ccs.n - ccs.l - 1) * 1, self.m).next_power_of_two();

        ccs.m = latticefold_padded_size;
        ccs.s = log2(latticefold_padded_size) as usize;
        ccs.M.iter_mut().for_each(|mat| {
            mat.pad_rows(latticefold_padded_size);
        });

        ccs
    }
}

fn empty_sparse_matrix(m: usize, n: usize) -> SparseMatrix<GoldilocksRingNTT> {
    SparseMatrix {
        nrows: m,
        ncols: n,
        coeffs: vec![vec![]; m],
    }
}

// Indices of the constraints
const ADD_CONSTR: usize = 0;
const PC_NON_BRANCH_CONSTR: usize = 1;
const JAL_CONSTR: usize = 2;
const JALR_CONSTR: usize = 3;
const BNE_CONSTR: usize = 4;
const AUIPC_CONSTR: usize = 5;
const LUI_CONSTR: usize = 6;

#[cfg(feature = "debug")]
use crate::ivc::IVCStepInput;
#[cfg(feature = "debug")]
use latticefold::arith::Arith;
#[cfg(feature = "debug")]
use tracing::{Level, instrument};
#[cfg(feature = "debug")]
use vm::riscvm::riscv_isa::Instruction;

#[cfg(feature = "debug")]
#[instrument(skip_all, level = Level::DEBUG)]
pub fn check_relation_debug(
    ccs: &CCS<GoldilocksRingNTT>,
    z: &Vec<GoldilocksRingNTT>,
    ivc_step: &IVCStepInput,
) {
    let inst = ivc_step.trace.instruction.inst;

    match inst {
        Instruction::ADD { .. }
        | Instruction::ADDI { .. }
        | Instruction::BNE { .. }
        | Instruction::LUI { .. }
        | Instruction::AUIPC { .. }
        | Instruction::JAL { .. }
        | Instruction::JALR { .. }
        | Instruction::SW { .. } => {
            ccs.check_relation(z).unwrap_or_else(|e| {
                panic!("CCS relation failed for {:?}: {:?}", inst, e);
            });
        }
        inst => {
            panic!("unchecked instruction {:?}", inst);
        }
    }
}
