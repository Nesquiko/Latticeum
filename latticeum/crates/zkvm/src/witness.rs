use std::ops::Range;

use configuration::N_REGS;
use vm::riscvm::{inst::ExectionTrace, riscv_isa::Instruction};

/// This struct holds the *indices* for witness vector z. It doesn't hold the
/// data itself, just the indexes/layout map.
#[derive(Debug)]
pub struct ZVectorLayout {
    // input state
    pub pc_in: usize,
    pub regs_in: Range<usize>,

    // instruction & decoding
    pub instruction_size: usize,
    pub is_branching: usize,
    pub branched_to: usize,

    // opcode selectors
    pub is_add: usize,
    pub is_addi: usize,

    pub is_sw: usize,

    pub is_auipc: usize,
    pub is_lui: usize,

    pub is_bne: usize,
    pub is_jal: usize,
    pub is_jalr: usize,

    // operands
    pub val_rs1: usize,
    pub val_rs2: usize,
    pub imm: usize,

    // alu
    pub has_overflown: usize,

    // constants
    pub one_constant: usize,

    // output State
    pub pc_out: usize,
    pub regs_out: Range<usize>,
    pub val_rd_out: usize,

    // total size of the vector
    pub size: usize,
}

impl ZVectorLayout {
    pub const fn new() -> Self {
        let mut cursor = 0;

        let pc_in = cursor;
        cursor += 1;

        let regs_in_start = cursor;
        cursor += N_REGS;
        let regs_in = regs_in_start..cursor;

        let instruction_size = cursor;
        cursor += 1;
        let is_branching = cursor;
        cursor += 1;
        let branched_to = cursor;
        cursor += 1;

        let imm = cursor;
        cursor += 1;

        let is_add = cursor;
        cursor += 1;
        let is_addi = cursor;
        cursor += 1;
        let is_bne = cursor;
        cursor += 1;
        let is_lui = cursor;
        cursor += 1;
        let is_auipc = cursor;
        cursor += 1;
        let is_jal = cursor;
        cursor += 1;
        let is_jalr = cursor;
        cursor += 1;
        let is_sw = cursor;
        cursor += 1;

        let val_rs1 = cursor;
        cursor += 1;
        let val_rs2 = cursor;
        cursor += 1;

        let has_overflown = cursor;
        cursor += 1;

        let one_constant = cursor;
        cursor += 1;

        let pc_out = cursor;
        cursor += 1;

        let regs_out_start = cursor;
        cursor += N_REGS;
        let regs_out = regs_out_start..cursor;

        let val_rd_out = cursor;
        cursor += 1;

        Self {
            pc_in,
            regs_in,
            instruction_size,
            is_branching,
            branched_to,
            imm,
            is_add,
            is_addi,
            is_bne,
            is_lui,
            is_auipc,
            is_jal,
            is_jalr,
            is_sw,
            val_rs1,
            val_rs2,
            has_overflown,
            one_constant,
            pc_out,
            regs_out,
            val_rd_out,
            size: cursor,
        }
    }
}

pub fn to_witness(trace: &ExectionTrace, z_layout: &ZVectorLayout) -> Vec<u32> {
    let mut z = vec![0u32; z_layout.size];

    z[z_layout.one_constant] = 1;

    z[z_layout.pc_in] = trace
        .input
        .pc
        .try_into()
        .expect("can't fit input pc: usize to u32");
    for (i, z_idx) in z_layout.regs_in.clone().enumerate() {
        z[z_idx] = trace.input.regs[i];
    }

    z[z_layout.instruction_size] = trace.instruction.size as u32;

    match trace.instruction.inst {
        Instruction::LUI { rd, imm } => {
            z[z_layout.is_lui] = 1;
            z[z_layout.imm] = imm;
            z[z_layout.val_rd_out] = trace.output.regs[rd as usize];
        }
        Instruction::AUIPC { rd, imm } => {
            z[z_layout.is_auipc] = 1;
            z[z_layout.imm] = imm;
            z[z_layout.val_rd_out] = trace.output.regs[rd as usize];
            z[z_layout.has_overflown] = trace.side_effects.has_overflown.into();
        }
        Instruction::JAL { rd, offset } => {
            z[z_layout.is_jal] = 1;
            z[z_layout.imm] = offset as u32;
            z[z_layout.val_rd_out] = trace.output.regs[rd as usize];
            z[z_layout.is_branching] = 1;
            z[z_layout.branched_to] = trace.side_effects.branched_to.expect("JAL must branch");
        }
        Instruction::JALR { rd, rs1, offset } => {
            z[z_layout.is_jalr] = 1;
            z[z_layout.val_rs1] = trace.input.regs[rs1 as usize];
            z[z_layout.imm] = offset as u32;
            z[z_layout.val_rd_out] = trace.output.regs[rd as usize];
            z[z_layout.is_branching] = 1;
            z[z_layout.branched_to] = trace.side_effects.branched_to.expect("JALR must branch");
        }
        Instruction::BNE { rs1, rs2, offset } => {
            z[z_layout.is_bne] = 1;
            z[z_layout.val_rs1] = trace.input.regs[rs1 as usize];
            z[z_layout.val_rs2] = trace.input.regs[rs2 as usize];
            z[z_layout.imm] = offset as u32;
            z[z_layout.is_branching] = trace.side_effects.branched_to.is_some().into();
            z[z_layout.branched_to] = trace.side_effects.branched_to.unwrap_or(0);
        }
        Instruction::SW { rs1, rs2, offset } => {
            z[z_layout.is_sw] = 1;
            z[z_layout.val_rs1] = trace.input.regs[rs1 as usize];
            z[z_layout.val_rs2] = trace.input.regs[rs2 as usize];
            z[z_layout.imm] = offset as u32;
        }
        Instruction::ADDI { rd, rs1, imm } => {
            z[z_layout.is_addi] = 1;

            z[z_layout.val_rs1] = trace.input.regs[rs1 as usize];
            z[z_layout.imm] = imm as u32;
            z[z_layout.val_rd_out] = trace.output.regs[rd as usize];

            z[z_layout.has_overflown] = trace.side_effects.has_overflown.into();
        }
        Instruction::ADD { rd, rs1, rs2 } => {
            z[z_layout.is_add] = 1;

            z[z_layout.val_rs1] = trace.input.regs[rs1 as usize];
            z[z_layout.val_rs2] = trace.input.regs[rs2 as usize];
            z[z_layout.val_rd_out] = trace.output.regs[rd as usize];

            z[z_layout.has_overflown] = trace.side_effects.has_overflown.into();
        }
        _ => panic!("unsupported instruction: {:?}", trace.instruction.inst),
    };

    z[z_layout.pc_out] = trace
        .output
        .pc
        .try_into()
        .expect("can't fit output pc: usize to u32");
    for (i, z_idx) in z_layout.regs_out.clone().enumerate() {
        z[z_idx] = trace.output.regs[i];
    }

    z
}
