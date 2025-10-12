use crate::riscvm::{
    inst_decoder::{DecodedInstruction, Instruction},
    vm::{Loaded, VM},
};

#[derive(Debug)]
struct RTypeArgs {
    rd: u32,
    rs1: u32,
    rs2: u32,
}
#[derive(Debug)]
struct ITypeArgs {
    rd: u32,
    rs1: u32,
    imm: i32,
}
#[derive(Debug)]
struct STypeArgs {
    rs1: u32,
    rs2: u32,
    offset: i32,
}
#[derive(Debug)]
struct BTypeArgs {
    rs1: u32,
    rs2: u32,
    offset: i32,
}
#[derive(Debug)]
struct UTypeArgs {
    rd: u32,
    imm: u32,
}
#[derive(Debug)]
struct JTypeArgs {
    rd: u32,
    offset: i32,
}
#[derive(Debug)]
struct JalrArgs {
    rd: u32,
    rs1: u32,
    offset: i32,
}

#[derive(Debug)]
pub struct ExecutionTrace {
    pub cycle: usize,
    pub input: ExecutionSnapshot,
    pub output: ExecutionSnapshot,
    pub instruction: DecodedInstruction,
    pub side_effects: SideEffects,
}

#[derive(Debug)]
pub struct ExecutionSnapshot {
    pub pc: usize,
    pub regs: [u32; 32],
}

#[derive(Debug, Default)]
pub struct SideEffects {
    pub has_overflown: bool,

    pub branched_to: Option<u32>,
    pub memory_op: Option<MemoryOperation>,
}

#[derive(Debug, Default, Clone)]
pub struct MemoryOperation {
    pub cycle: usize,
    pub address: u32,
    pub value: u32,
    pub is_write: bool,
}

impl<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize> VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded> {
    pub fn execute_step(&mut self, inst: &DecodedInstruction, cycle: usize) -> ExecutionTrace {
        let mut trace = ExecutionTrace {
            cycle,
            input: ExecutionSnapshot {
                pc: self.pc,
                regs: self.regs.clone(),
            },
            output: ExecutionSnapshot {
                pc: 0,
                regs: [0; 32],
            },
            instruction: inst.clone(),
            side_effects: SideEffects::default(),
        };

        tracing::trace!("executing {:#0x} - {}", self.pc, inst);

        match inst.inst {
            // Implemented RV32I instructions
            Instruction::LUI { rd, imm } => self.inst_lui(UTypeArgs { rd, imm }),
            Instruction::AUIPC { rd, imm } => {
                self.inst_auipc(UTypeArgs { rd, imm }, &mut trace.side_effects)
            }
            Instruction::JAL { rd, offset } => {
                self.inst_jal(JTypeArgs { rd, offset }, inst.size, &mut trace.side_effects)
            }
            Instruction::JALR { rd, rs1, offset } => self.inst_jalr(
                JalrArgs { rd, rs1, offset },
                inst.size,
                &mut trace.side_effects,
            ),
            Instruction::BNE { rs1, rs2, offset } => self.inst_bne(
                BTypeArgs { rs1, rs2, offset },
                inst.size,
                &mut trace.side_effects,
            ),
            Instruction::SW { rs1, rs2, offset } => {
                self.inst_sw(STypeArgs { rs1, rs2, offset }, &mut trace)
            }
            Instruction::ADDI { rd, rs1, imm } => {
                self.inst_addi(ITypeArgs { rd, rs1, imm }, &mut trace.side_effects)
            }
            Instruction::ADD { rd, rs1, rs2 } => {
                self.inst_add(RTypeArgs { rd, rs1, rs2 }, &mut trace.side_effects)
            }

            _ => panic!("unsupported instruction: {:?}", inst),
        };

        if !inst.inst.branch() {
            self.pc = self.pc.wrapping_add(inst.size);
            tracing::trace!(
                "non branching instruction incrementing pc {:#0x} to {:#0x}",
                trace.input.pc,
                self.pc
            );
        }
        trace.output.pc = self.pc;
        trace.output.regs = self.regs.clone();
        self.write_reg(0, 0);

        trace
    }

    fn inst_lui(&mut self, UTypeArgs { rd, imm }: UTypeArgs) {
        self.write_reg(rd, imm << 12);
    }

    fn inst_auipc(&mut self, UTypeArgs { rd, imm }: UTypeArgs, side_effects: &mut SideEffects) {
        let (val, has_overflown) = TryInto::<u32>::try_into(self.pc)
            .expect("can't convert pc to u32")
            .overflowing_add(imm << 12);
        self.write_reg(rd, val);
        side_effects.has_overflown = has_overflown;
        tracing::trace!("\tAUIPC value {:#0x}", val);
    }

    fn inst_jal(
        &mut self,
        JTypeArgs { rd, offset }: JTypeArgs,
        inst_len: usize,
        side_effects: &mut SideEffects,
    ) {
        let link = self.pc.wrapping_add(inst_len) as u32;
        let new_pc = self.pc.wrapping_add(offset as usize);

        self.write_reg(rd, link);
        self.pc = new_pc;
        side_effects.branched_to = Some(new_pc as u32);

        tracing::trace!("\tJAL link {:#0x}, new pc {:#0x}", link, new_pc);
    }

    fn inst_jalr(
        &mut self,
        JalrArgs { rd, rs1, offset }: JalrArgs,
        inst_len: usize,
        side_effects: &mut SideEffects,
    ) {
        let rs1_data = self.read_reg(rs1);
        let link = self.pc.wrapping_add(inst_len) as u32;

        let new_pc = (rs1_data.wrapping_add(offset as u32)) & !1; // clear bit 0 to enforce 2-byte alignment

        self.pc = new_pc as usize;
        self.write_reg(rd, link);
        side_effects.branched_to = Some(new_pc);

        tracing::trace!("\tJALR link {:#0x}, new pc {:#0x}", link, new_pc);
    }

    fn inst_bne(
        &mut self,
        BTypeArgs { rs1, rs2, offset }: BTypeArgs,
        inst_len: usize,
        side_effects: &mut SideEffects,
    ) {
        let rs1_data = self.read_reg(rs1);
        let rs2_data = self.read_reg(rs2);
        if rs1_data != rs2_data {
            let new_pc = self.pc.wrapping_add(offset as usize);
            tracing::trace!("\tBNE branching from pc {:#0x} to {:#0x}", self.pc, new_pc);
            self.pc = new_pc;
            side_effects.branched_to = Some(new_pc as u32);
        } else {
            let new_pc = self.pc.wrapping_add(inst_len);
            tracing::trace!(
                "\tBNE not equal, continuing pc {:#0x} to {:#0x}",
                self.pc,
                new_pc
            );
            self.pc = new_pc;
        }
    }

    fn inst_sw(&mut self, STypeArgs { rs1, rs2, offset }: STypeArgs, trace: &mut ExecutionTrace) {
        let rs1_data = self.read_reg(rs1) as i32;
        let rs2_data = self.read_reg(rs2);
        let addr = rs1_data.wrapping_add(offset) as u32;
        self.write_mem(addr as usize, rs2_data);

        trace.side_effects.memory_op = Some(MemoryOperation {
            cycle: trace.cycle,
            address: addr,
            value: rs2_data,
            is_write: true,
        });

        tracing::trace!("\tSW addr {:#0x} - value {:#0x}", addr, rs2_data);
    }

    fn inst_addi(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs, side_effects: &mut SideEffects) {
        let rs1_data = self.read_reg(rs1) as i32;
        let (value, has_overflown) = rs1_data.overflowing_add(imm);
        self.write_reg(rd, value as u32);
        side_effects.has_overflown = has_overflown;
        tracing::trace!("\tADDI value {:#0x}", value);
    }

    fn inst_add(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs, side_effects: &mut SideEffects) {
        let rs1_data = self.read_reg(rs1);
        let rs2_data = self.read_reg(rs2);
        let (value, has_overflown) = rs1_data.overflowing_add(rs2_data);
        self.write_reg(rd, value);
        side_effects.has_overflown = has_overflown;

        tracing::trace!("\tADD {:#0x} + {:#0x} = {:#0x} ", rs1_data, rs2_data, value);
    }
}
