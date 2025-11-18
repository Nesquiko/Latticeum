use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use std::{ops::Range, usize};
use tracing::{Level, instrument};

use configuration::N_REGS;
use latticefold::decomposition_parameters::DecompositionParams;
use vm::riscvm::{inst::ExecutionTrace, riscv_isa::Instruction};

use crate::{
    crypto_consts::PARTIAL_ROUNDS,
    ivc::IVCStepInput,
    poseidon2::{POSEIDON2_OUT, WIDE_POSEIDON2_WIDTH},
};

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
    pub ivc_h_i_idx: [usize; POSEIDON2_OUT],
    pub const_1_idx: usize,

    pub wide_poseidon2_external_initial_consts_idx:
        [usize; WIDE_POSEIDON2_WIDTH * PARTIAL_ROUNDS / 2],
    pub wide_poseidon2_external_terminal_consts_idx:
        [usize; WIDE_POSEIDON2_WIDTH * PARTIAL_ROUNDS / 2],

    // h_i (public input 0) preimage parts
    pub ivc_h_i_step_idx: usize,
    pub ivc_h_i_state_0_comm_idx: [usize; POSEIDON2_OUT],
    pub ivc_h_i_state_i_comm_idx: [usize; POSEIDON2_OUT],
    pub ivc_h_i_acc_i_comm_idx: [usize; POSEIDON2_OUT],

    /// Intermediate 2 states (because there are 2 sponge passes on 13 preimage elements of the
    /// ivc_h_i commitment) after applying MDS in the first operation in external rounds
    pub ivc_h_i_after_mds_idx: [usize; 2 * WIDE_POSEIDON2_WIDTH],

    // input state
    pub pc_in_idx: usize,
    pub regs_in_idx: Range<usize>,

    // instruction & decoding
    pub instruction_size_idx: usize,
    pub is_branching_idx: usize,
    pub branched_to_idx: usize,

    // opcode selectors
    pub is_add_idx: usize,
    pub is_addi_idx: usize,

    pub is_sw_idx: usize,

    pub is_auipc_idx: usize,
    pub is_lui_idx: usize,

    pub is_bne_idx: usize,
    pub is_jal_idx: usize,
    pub is_jalr_idx: usize,

    // operands
    pub val_rs1_idx: usize,
    pub val_rs2_idx: usize,
    pub imm_idx: usize,

    // alu
    pub has_overflown_idx: usize,

    // output State
    pub pc_out_idx: usize,
    pub regs_out_idx: Range<usize>,
    pub val_rd_out_idx: usize,

    /// Size of the private witness
    pub w_size: usize,
}

impl CCSLayout {
    pub const X_ELEMS_SIZE: usize = 4; // memory commitment as public input
    pub const CONST_ELEMS_SIZE: usize = 1;
    pub const W_IDX_DELTA: usize = Self::X_ELEMS_SIZE + Self::CONST_ELEMS_SIZE;

    pub const fn new() -> Self {
        let w_cursor = 0;
        let (ivc_h_i_idx, mut w_cursor) = indices_with_new_cursor(w_cursor);

        let const_1_idx = w_cursor;
        w_cursor += 1;

        let (wide_poseidon2_external_initial_consts_idx, w_cursor) =
            indices_with_new_cursor::<{ WIDE_POSEIDON2_WIDTH * PARTIAL_ROUNDS / 2 }>(w_cursor);

        let (wide_poseidon2_external_terminal_consts_idx, mut w_cursor) =
            indices_with_new_cursor::<{ WIDE_POSEIDON2_WIDTH * PARTIAL_ROUNDS / 2 }>(w_cursor);

        let ivc_h_i_step_idx = w_cursor;
        w_cursor += 1;

        let (ivc_h_i_state_0_comm_idx, w_cursor) = indices_with_new_cursor(w_cursor);

        let (ivc_h_i_state_i_comm_idx, w_cursor) = indices_with_new_cursor(w_cursor);

        let (ivc_h_i_acc_i_comm_idx, w_cursor) = indices_with_new_cursor(w_cursor);

        // there are 13 elements in the ivc h_i comm, and rate is 12, so 2 sponge passes
        let (ivc_h_i_after_mds_idx, mut w_cursor) =
            indices_with_new_cursor::<{ 2 * WIDE_POSEIDON2_WIDTH }>(w_cursor);

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
            ivc_h_i_idx,
            const_1_idx,
            wide_poseidon2_external_initial_consts_idx,
            wide_poseidon2_external_terminal_consts_idx,
            ivc_h_i_step_idx,
            ivc_h_i_state_0_comm_idx,
            ivc_h_i_state_i_comm_idx,
            ivc_h_i_acc_i_comm_idx,
            ivc_h_i_after_mds_idx,
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
}

#[instrument(skip_all, level = Level::DEBUG)]
pub fn set_ivc_witness(z: &mut Vec<usize>, input: &IVCStepInput, layout: &CCSLayout) {
    for (i, &z_idx) in layout
        .wide_poseidon2_external_initial_consts_idx
        .iter()
        .enumerate()
    {
        // z[z_idx] =
        //     input.poseidon2_external_consts.get_initial_constants()[i].as_canonical_u64() as usize;
    }

    z[layout.ivc_h_i_step_idx] = input.ivc_step.as_canonical_u64() as usize;

    for (i, &z_idx) in layout.ivc_h_i_state_0_comm_idx.iter().enumerate() {
        z[z_idx] = input.state_0_comm[i].as_canonical_u64() as usize;
    }

    for (i, &z_idx) in layout.ivc_h_i_state_i_comm_idx.iter().enumerate() {
        z[z_idx] = input.state_comm[i].as_canonical_u64() as usize;
    }

    for (i, &z_idx) in layout.ivc_h_i_acc_i_comm_idx.iter().enumerate() {
        z[z_idx] = input.acc_comm[i].as_canonical_u64() as usize;
    }

    assert_eq!(2, input.ivc_step_comm.1.perm_states.len());
    let after_mds_sponge_passes: [Goldilocks; 2 * WIDE_POSEIDON2_WIDTH] = input
        .ivc_step_comm
        .1
        .perm_states
        .iter()
        .flat_map(|states| states.after_external_initial_mds)
        .collect::<Vec<Goldilocks>>()
        .try_into()
        .expect("failed to convert permutation states into sponge passes");

    for (i, &z_idx) in layout.ivc_h_i_after_mds_idx.iter().enumerate() {
        z[z_idx] = after_mds_sponge_passes[i].as_canonical_u64() as usize;
    }
}

#[instrument(skip_all, level = Level::DEBUG)]
pub fn set_trace_witness(z: &mut Vec<usize>, trace: &ExecutionTrace, layout: &CCSLayout) {
    z[layout.pc_in_idx] = trace
        .input
        .pc
        .try_into()
        .expect("can't fit input pc: usize to u32");
    for (i, z_idx) in layout.regs_in_idx.clone().enumerate() {
        z[z_idx] = trace.input.regs[i] as usize;
    }

    z[layout.instruction_size_idx] = trace.instruction.size;

    match trace.instruction.inst {
        Instruction::LUI { rd, imm } => {
            z[layout.is_lui_idx] = 1;
            z[layout.imm_idx] = imm as usize;
            z[layout.val_rd_out_idx] = trace.output.regs[rd as usize] as usize;
        }
        Instruction::AUIPC { rd, imm } => {
            z[layout.is_auipc_idx] = 1;
            z[layout.imm_idx] = imm as usize;
            z[layout.val_rd_out_idx] = trace.output.regs[rd as usize] as usize;
            z[layout.has_overflown_idx] = trace.side_effects.has_overflown.into();
        }
        Instruction::JAL { rd, offset } => {
            z[layout.is_jal_idx] = 1;
            z[layout.imm_idx] = offset as usize;
            z[layout.val_rd_out_idx] = trace.output.regs[rd as usize] as usize;
            z[layout.is_branching_idx] = 1;
            z[layout.branched_to_idx] =
                trace.side_effects.branched_to.expect("JAL must branch") as usize;
        }
        Instruction::JALR { rd, rs1, offset } => {
            z[layout.is_jalr_idx] = 1;
            z[layout.val_rs1_idx] = trace.input.regs[rs1 as usize] as usize;
            z[layout.imm_idx] = offset as usize;
            z[layout.val_rd_out_idx] = trace.output.regs[rd as usize] as usize;
            z[layout.is_branching_idx] = 1;
            z[layout.branched_to_idx] =
                trace.side_effects.branched_to.expect("JALR must branch") as usize;
        }
        Instruction::BNE { rs1, rs2, offset } => {
            z[layout.is_bne_idx] = 1;
            z[layout.val_rs1_idx] = trace.input.regs[rs1 as usize] as usize;
            z[layout.val_rs2_idx] = trace.input.regs[rs2 as usize] as usize;
            z[layout.imm_idx] = offset as usize;
            z[layout.is_branching_idx] = trace.side_effects.branched_to.is_some().into();
            z[layout.branched_to_idx] = trace.side_effects.branched_to.unwrap_or(0) as usize;
        }
        Instruction::SW { rs1, rs2, offset } => {
            z[layout.is_sw_idx] = 1;
            z[layout.val_rs1_idx] = trace.input.regs[rs1 as usize] as usize;
            z[layout.val_rs2_idx] = trace.input.regs[rs2 as usize] as usize;
            z[layout.imm_idx] = offset as usize;
        }
        Instruction::ADDI { rd, rs1, imm } => {
            z[layout.is_addi_idx] = 1;

            z[layout.val_rs1_idx] = trace.input.regs[rs1 as usize] as usize;
            z[layout.imm_idx] = imm as usize;
            z[layout.val_rd_out_idx] = trace.output.regs[rd as usize] as usize;

            z[layout.has_overflown_idx] = trace.side_effects.has_overflown.into();
        }
        Instruction::ADD { rd, rs1, rs2 } => {
            z[layout.is_add_idx] = 1;

            z[layout.val_rs1_idx] = trace.input.regs[rs1 as usize] as usize;
            z[layout.val_rs2_idx] = trace.input.regs[rs2 as usize] as usize;
            z[layout.val_rd_out_idx] = trace.output.regs[rd as usize] as usize;

            z[layout.has_overflown_idx] = trace.side_effects.has_overflown.into();
        }
        _ => panic!("unsupported instruction: {:?}", trace.instruction.inst),
    };

    z[layout.pc_out_idx] = trace
        .output
        .pc
        .try_into()
        .expect("can't fit output pc: usize to u32");
    for (i, z_idx) in layout.regs_out_idx.clone().enumerate() {
        z[z_idx] = trace.output.regs[i] as usize;
    }
}

const fn indices_array<const SIZE: usize>(start: usize) -> [usize; SIZE] {
    let mut arr = [0; SIZE];
    let mut i = 0;
    while i < SIZE {
        arr[i] = start + i;
        i += 1;
    }
    arr
}

const fn indices_with_new_cursor<const SIZE: usize>(start: usize) -> ([usize; SIZE], usize) {
    let mut arr = [0; SIZE];
    let mut i = 0;
    while i < SIZE {
        arr[i] = start + i;
        i += 1;
    }
    (arr, arr[i - 1] + 1)
}
