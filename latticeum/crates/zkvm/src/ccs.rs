use std::ops::Range;

use configuration::N_REGS;
use latticefold::decomposition_parameters::DecompositionParams;
use vm::riscvm::{inst::ExecutionTrace, riscv_isa::Instruction};

#[derive(Clone, Copy)]
pub struct GoldiLocksDP;

// Default params from latticefold examples
impl DecompositionParams for GoldiLocksDP {
    const B: u128 = 1 << 15;
    /// Ring modulus is GoldiLocks (little less than 2^64), thus GoldiLocks modulus < B^L
    const L: usize = 5;
    /// Standard binary decomposition
    const B_SMALL: usize = 2;
    /// log₂(B)
    const K: usize = 15;
}

pub const CCS_LAYOUT: CCSLayout = CCSLayout::new();
/// Length of Ajtai commitment vectors (rows in commitment matrix)
pub const KAPPA: usize = 4;
/// Number of columns in the Ajtai commitment matrix
pub const N: usize = CCS_LAYOUT.w_size * GoldiLocksDP::L;

/// This struct holds the *indices* for CCS layout. It doesn't hold the data itself,
/// just the indexes/layout map.
///
/// CCS/Z-vector structure: `[x_ccs..., 1, w_ccs...]`
#[derive(Debug)]
pub struct CCSLayout {
    pub const_1_idx: usize,
    // input state
    pc_in_idx: usize,
    regs_in_idx: Range<usize>,

    // instruction & decoding
    instruction_size_idx: usize,
    is_branching_idx: usize,
    branched_to_idx: usize,

    // opcode selectors
    is_add_idx: usize,
    is_addi_idx: usize,

    is_sw_idx: usize,

    is_auipc_idx: usize,
    is_lui_idx: usize,

    is_bne_idx: usize,
    is_jal_idx: usize,
    is_jalr_idx: usize,

    // operands
    val_rs1_idx: usize,
    val_rs2_idx: usize,
    imm_idx: usize,

    // alu
    has_overflown_idx: usize,

    // output State
    pc_out_idx: usize,
    regs_out_idx: Range<usize>,
    val_rd_out_idx: usize,

    /// Size of the private witness
    pub w_size: usize,
}

impl CCSLayout {
    pub const X_ELEMS_SIZE: usize = 4; // memory commitment as public input
    pub const CONST_ELEMS_SIZE: usize = 1;
    pub const W_IDX_DELTA: usize = Self::X_ELEMS_SIZE + Self::CONST_ELEMS_SIZE;

    pub const fn new() -> Self {
        let const_1_idx = Self::X_ELEMS_SIZE;
        let mut w_cursor = CCSLayout::W_IDX_DELTA;

        let pc_in_idx = w_cursor;
        w_cursor += 1;

        let regs_in_start = w_cursor;
        w_cursor += N_REGS;
        let regs_in_idx = regs_in_start..w_cursor;

        let instruction_size_idx = w_cursor;
        w_cursor += 1;
        let is_branching_idx = w_cursor;
        w_cursor += 1;
        let branched_to_idx = w_cursor;
        w_cursor += 1;

        let imm_idx = w_cursor;
        w_cursor += 1;

        let is_add_idx = w_cursor;
        w_cursor += 1;
        let is_addi_idx = w_cursor;
        w_cursor += 1;
        let is_bne_idx = w_cursor;
        w_cursor += 1;
        let is_lui_idx = w_cursor;
        w_cursor += 1;
        let is_auipc_idx = w_cursor;
        w_cursor += 1;
        let is_jal_idx = w_cursor;
        w_cursor += 1;
        let is_jalr_idx = w_cursor;
        w_cursor += 1;
        let is_sw_idx = w_cursor;
        w_cursor += 1;

        let val_rs1_idx = w_cursor;
        w_cursor += 1;
        let val_rs2_idx = w_cursor;
        w_cursor += 1;

        let has_overflown_idx = w_cursor;
        w_cursor += 1;

        let pc_out_idx = w_cursor;
        w_cursor += 1;

        let regs_out_start = w_cursor;
        w_cursor += N_REGS;
        let regs_out_idx = regs_out_start..w_cursor;

        let val_rd_out_idx = w_cursor;
        w_cursor += 1;

        Self {
            const_1_idx,
            pc_in_idx,
            regs_in_idx,
            instruction_size_idx,
            is_branching_idx,
            branched_to_idx,
            imm_idx,
            is_add_idx,
            is_addi_idx,
            is_bne_idx,
            is_lui_idx,
            is_auipc_idx,
            is_jal_idx,
            is_jalr_idx,
            is_sw_idx,
            val_rs1_idx,
            val_rs2_idx,
            has_overflown_idx,
            pc_out_idx,
            regs_out_idx,
            val_rd_out_idx,
            w_size: w_cursor - CCSLayout::W_IDX_DELTA,
        }
    }

    /// Returns the total size needed for the CCS constraint system z-vector.
    ///
    /// The z-vector in the CCS has the structure: [x_ccs, 1, w_ccs]
    /// where:
    /// - x_ccs: public inputs (memory commitment in our case, so l=1)
    /// - 1: constant element (always 1) at index 1
    /// - w_ccs: private witness elements starting at index 2
    ///
    /// This is the 'n' parameter in the CCS structure.
    pub const fn z_vector_size(&self) -> usize {
        Self::X_ELEMS_SIZE + Self::CONST_ELEMS_SIZE + self.w_size
    }

    // Getter functions that return the z-vector indices
    pub const fn pc_in(&self) -> usize {
        self.pc_in_idx
    }
    pub fn regs_in(&self) -> Range<usize> {
        self.regs_in_idx.clone()
    }
    pub const fn instruction_size(&self) -> usize {
        self.instruction_size_idx
    }
    pub const fn is_branching(&self) -> usize {
        self.is_branching_idx
    }
    pub const fn branched_to(&self) -> usize {
        self.branched_to_idx
    }
    pub const fn is_add(&self) -> usize {
        self.is_add_idx
    }
    pub const fn is_addi(&self) -> usize {
        self.is_addi_idx
    }
    pub const fn is_sw(&self) -> usize {
        self.is_sw_idx
    }
    pub const fn is_auipc(&self) -> usize {
        self.is_auipc_idx
    }
    pub const fn is_lui(&self) -> usize {
        self.is_lui_idx
    }
    pub const fn is_bne(&self) -> usize {
        self.is_bne_idx
    }
    pub const fn is_jal(&self) -> usize {
        self.is_jal_idx
    }
    pub const fn is_jalr(&self) -> usize {
        self.is_jalr_idx
    }
    pub const fn val_rs1(&self) -> usize {
        self.val_rs1_idx
    }
    pub const fn val_rs2(&self) -> usize {
        self.val_rs2_idx
    }
    pub const fn imm(&self) -> usize {
        self.imm_idx
    }
    pub const fn has_overflown(&self) -> usize {
        self.has_overflown_idx
    }
    pub const fn pc_out(&self) -> usize {
        self.pc_out_idx
    }
    pub fn regs_out(&self) -> Range<usize> {
        self.regs_out_idx.clone()
    }
    pub const fn val_rd_out(&self) -> usize {
        self.val_rd_out_idx
    }

    // Witness index functions that return indices in the private witness part (w_ccs)
    pub const fn w_pc_in(&self) -> usize {
        self.pc_in_idx - Self::W_IDX_DELTA
    }
    pub fn w_regs_in(&self) -> Range<usize> {
        let start = self.regs_in_idx.start - Self::W_IDX_DELTA;
        let end = self.regs_in_idx.end - Self::W_IDX_DELTA;
        start..end
    }
    pub const fn w_instruction_size(&self) -> usize {
        self.instruction_size_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_branching(&self) -> usize {
        self.is_branching_idx - Self::W_IDX_DELTA
    }
    pub const fn w_branched_to(&self) -> usize {
        self.branched_to_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_add(&self) -> usize {
        self.is_add_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_addi(&self) -> usize {
        self.is_addi_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_sw(&self) -> usize {
        self.is_sw_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_auipc(&self) -> usize {
        self.is_auipc_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_lui(&self) -> usize {
        self.is_lui_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_bne(&self) -> usize {
        self.is_bne_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_jal(&self) -> usize {
        self.is_jal_idx - Self::W_IDX_DELTA
    }
    pub const fn w_is_jalr(&self) -> usize {
        self.is_jalr_idx - Self::W_IDX_DELTA
    }
    pub const fn w_val_rs1(&self) -> usize {
        self.val_rs1_idx - Self::W_IDX_DELTA
    }
    pub const fn w_val_rs2(&self) -> usize {
        self.val_rs2_idx - Self::W_IDX_DELTA
    }
    pub const fn w_imm(&self) -> usize {
        self.imm_idx - Self::W_IDX_DELTA
    }
    pub const fn w_has_overflown(&self) -> usize {
        self.has_overflown_idx - Self::W_IDX_DELTA
    }
    pub const fn w_pc_out(&self) -> usize {
        self.pc_out_idx - Self::W_IDX_DELTA
    }
    pub fn w_regs_out(&self) -> Range<usize> {
        let start = self.regs_out_idx.start - Self::W_IDX_DELTA;
        let end = self.regs_out_idx.end - Self::W_IDX_DELTA;
        start..end
    }
    pub const fn w_val_rd_out(&self) -> usize {
        self.val_rd_out_idx - Self::W_IDX_DELTA
    }
}

/// Returns only private witness vector `w_ccs`
pub fn to_raw_witness(trace: &ExecutionTrace, layout: &CCSLayout) -> Vec<u32> {
    // The witness vector contains only the private witness elements
    let mut z = vec![0u32; layout.w_size];

    z[layout.w_pc_in()] = trace
        .input
        .pc
        .try_into()
        .expect("can't fit input pc: usize to u32");
    for (i, z_idx) in layout.w_regs_in().enumerate() {
        z[z_idx] = trace.input.regs[i];
    }

    z[layout.w_instruction_size()] = trace.instruction.size as u32;

    match trace.instruction.inst {
        Instruction::LUI { rd, imm } => {
            z[layout.w_is_lui()] = 1;
            z[layout.w_imm()] = imm;
            z[layout.w_val_rd_out()] = trace.output.regs[rd as usize];
        }
        Instruction::AUIPC { rd, imm } => {
            z[layout.w_is_auipc()] = 1;
            z[layout.w_imm()] = imm;
            z[layout.w_val_rd_out()] = trace.output.regs[rd as usize];
            z[layout.w_has_overflown()] = trace.side_effects.has_overflown.into();
        }
        Instruction::JAL { rd, offset } => {
            z[layout.w_is_jal()] = 1;
            z[layout.w_imm()] = offset as u32;
            z[layout.w_val_rd_out()] = trace.output.regs[rd as usize];
            z[layout.w_is_branching()] = 1;
            z[layout.w_branched_to()] = trace.side_effects.branched_to.expect("JAL must branch");
        }
        Instruction::JALR { rd, rs1, offset } => {
            z[layout.w_is_jalr()] = 1;
            z[layout.w_val_rs1()] = trace.input.regs[rs1 as usize];
            z[layout.w_imm()] = offset as u32;
            z[layout.w_val_rd_out()] = trace.output.regs[rd as usize];
            z[layout.w_is_branching()] = 1;
            z[layout.w_branched_to()] = trace.side_effects.branched_to.expect("JALR must branch");
        }
        Instruction::BNE { rs1, rs2, offset } => {
            z[layout.w_is_bne()] = 1;
            z[layout.w_val_rs1()] = trace.input.regs[rs1 as usize];
            z[layout.w_val_rs2()] = trace.input.regs[rs2 as usize];
            z[layout.w_imm()] = offset as u32;
            z[layout.w_is_branching()] = trace.side_effects.branched_to.is_some().into();
            z[layout.w_branched_to()] = trace.side_effects.branched_to.unwrap_or(0);
        }
        Instruction::SW { rs1, rs2, offset } => {
            z[layout.w_is_sw()] = 1;
            z[layout.w_val_rs1()] = trace.input.regs[rs1 as usize];
            z[layout.w_val_rs2()] = trace.input.regs[rs2 as usize];
            z[layout.w_imm()] = offset as u32;
        }
        Instruction::ADDI { rd, rs1, imm } => {
            z[layout.w_is_addi()] = 1;

            z[layout.w_val_rs1()] = trace.input.regs[rs1 as usize];
            z[layout.w_imm()] = imm as u32;
            z[layout.w_val_rd_out()] = trace.output.regs[rd as usize];

            z[layout.w_has_overflown()] = trace.side_effects.has_overflown.into();
        }
        Instruction::ADD { rd, rs1, rs2 } => {
            z[layout.w_is_add()] = 1;

            z[layout.w_val_rs1()] = trace.input.regs[rs1 as usize];
            z[layout.w_val_rs2()] = trace.input.regs[rs2 as usize];
            z[layout.w_val_rd_out()] = trace.output.regs[rd as usize];

            z[layout.w_has_overflown()] = trace.side_effects.has_overflown.into();
        }
        _ => panic!("unsupported instruction: {:?}", trace.instruction.inst),
    };

    z[layout.w_pc_out()] = trace
        .output
        .pc
        .try_into()
        .expect("can't fit output pc: usize to u32");
    for (i, z_idx) in layout.w_regs_out().enumerate() {
        z[z_idx] = trace.output.regs[i];
    }

    z
}
