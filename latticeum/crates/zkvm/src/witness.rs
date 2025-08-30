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
    pub is_compressed: usize,

    // opcode selectors
    pub is_add: usize,
    pub is_addi: usize,
    pub is_bne: usize,
    pub is_lui: usize,
    pub is_auipc: usize,
    pub is_jal: usize,
    pub is_jalr: usize,
    pub is_sw: usize,

    // operands
    pub val_rs1: usize,
    pub val_rs2: usize,
    pub imm: usize,

    // alu
    pub has_overflown: usize,
    pub has_branched: usize,

    // output State
    pub pc_out: usize,
    pub regs_out: Range<usize>,
    pub val_rd_out: usize,

    // total size of the vector
    pub size: usize,
}

impl ZVectorLayout {
    // This is a compile-time function that builds the layout.
    pub const fn new() -> Self {
        let mut cursor = 0;

        let pc_in = cursor;
        cursor += 1;

        let regs_in_start = cursor;
        cursor += N_REGS;
        let regs_in = regs_in_start..cursor;

        // let inst_word = cursor;
        // cursor += 1;
        let is_compressed = cursor;
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
        let has_branched = cursor;
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
            // inst_word,
            is_compressed,
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
            has_branched,
            pc_out,
            regs_out,
            val_rd_out,
            size: cursor,
        }
    }
}

const Z_LAYOUT: ZVectorLayout = ZVectorLayout::new();

pub fn to_witness(trace: &ExectionTrace) -> (Vec<u32>, ZVectorLayout) {
    let mut z = vec![0u32; Z_LAYOUT.size];

    z[Z_LAYOUT.pc_in] = trace
        .input
        .pc
        .try_into()
        .expect("can't fit input pc: usize to u32");
    for (i, z_idx) in Z_LAYOUT.regs_in.enumerate() {
        z[z_idx] = trace.input.regs[i];
    }

    // z[Z_LAYOUT.inst_word] = trace.instruction.raw_word;
    z[Z_LAYOUT.is_compressed] = if trace.instruction.size == 2 { 1 } else { 0 };

    match trace.instruction.inst {
        Instruction::LUI { rd, imm } => {
            z[Z_LAYOUT.is_lui] = 1;
            z[Z_LAYOUT.imm] = imm;
            z[Z_LAYOUT.val_rd_out] = trace.output.regs[rd as usize];
        }
        Instruction::AUIPC { rd, imm } => {
            z[Z_LAYOUT.is_auipc] = 1;
            z[Z_LAYOUT.imm] = imm;
            z[Z_LAYOUT.val_rd_out] = trace.output.regs[rd as usize];
        }
        Instruction::JAL { rd, offset } => {
            z[Z_LAYOUT.is_jal] = 1;
            z[Z_LAYOUT.imm] = offset as u32;
            z[Z_LAYOUT.val_rd_out] = trace.output.regs[rd as usize];
            z[Z_LAYOUT.has_branched] = trace.side_effects.has_branched as u32;
        }
        Instruction::JALR { rd, rs1, offset } => {
            z[Z_LAYOUT.is_jalr] = 1;
            z[Z_LAYOUT.val_rs1] = trace.input.regs[rs1 as usize];
            z[Z_LAYOUT.imm] = offset as u32;
            z[Z_LAYOUT.val_rd_out] = trace.output.regs[rd as usize];
        }
        Instruction::BNE { rs1, rs2, offset } => {
            z[Z_LAYOUT.is_bne] = 1;
            z[Z_LAYOUT.val_rs1] = trace.input.regs[rs1 as usize];
            z[Z_LAYOUT.val_rs2] = trace.input.regs[rs2 as usize];
            z[Z_LAYOUT.imm] = offset as u32;
            z[Z_LAYOUT.has_branched] = trace.side_effects.has_branched.into();
        }
        Instruction::SW { rs1, rs2, offset } => {
            z[Z_LAYOUT.is_sw] = 1;
            z[Z_LAYOUT.val_rs1] = trace.input.regs[rs1 as usize];
            z[Z_LAYOUT.val_rs2] = trace.input.regs[rs2 as usize];
            z[Z_LAYOUT.imm] = offset as u32;
        }
        Instruction::ADDI { rd, rs1, imm } => {
            z[Z_LAYOUT.is_addi] = 1;

            z[Z_LAYOUT.val_rs1] = trace.input.regs[rs1 as usize];
            z[Z_LAYOUT.imm] = imm as u32;
            z[Z_LAYOUT.val_rd_out] = trace.output.regs[rd as usize];

            z[Z_LAYOUT.has_overflown] = trace.side_effects.has_overflown.into();
        }
        Instruction::ADD { rd, rs1, rs2 } => {
            z[Z_LAYOUT.is_add] = 1;

            z[Z_LAYOUT.val_rs1] = trace.input.regs[rs1 as usize];
            z[Z_LAYOUT.val_rs2] = trace.input.regs[rs2 as usize];
            z[Z_LAYOUT.val_rd_out] = trace.output.regs[rd as usize];

            z[Z_LAYOUT.has_overflown] = trace.side_effects.has_overflown.into();
        }
        _ => panic!("unsupported instruction: {:?}", trace.instruction.inst),
    };

    z[Z_LAYOUT.pc_out] = trace
        .output
        .pc
        .try_into()
        .expect("can't fit output pc: usize to u32");
    for (i, z_idx) in Z_LAYOUT.regs_out.enumerate() {
        z[z_idx] = trace.output.regs[i];
    }

    (z, Z_LAYOUT)
}
