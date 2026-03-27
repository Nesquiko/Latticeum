use crate::riscvm::{
    inst_decoder::{DecodedInstruction, Instruction},
    vm::{Loaded, VM},
};

#[derive(Debug)]
pub(crate) struct RTypeArgs {
    pub rd: u32,
    pub rs1: u32,
    pub rs2: u32,
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
struct ShiftITypeArgs {
    rd: u32,
    rs1: u32,
    shamt: u32,
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
            Instruction::BEQ { rs1, rs2, offset } => self.inst_beq(
                BTypeArgs { rs1, rs2, offset },
                inst.size,
                &mut trace.side_effects,
            ),
            Instruction::BLTU { rs1, rs2, offset } => self.inst_bltu(
                BTypeArgs { rs1, rs2, offset },
                inst.size,
                &mut trace.side_effects,
            ),
            Instruction::BGEU { rs1, rs2, offset } => self.inst_bgeu(
                BTypeArgs { rs1, rs2, offset },
                inst.size,
                &mut trace.side_effects,
            ),
            Instruction::BLT { rs1, rs2, offset } => self.inst_blt(
                BTypeArgs { rs1, rs2, offset },
                inst.size,
                &mut trace.side_effects,
            ),
            Instruction::BGE { rs1, rs2, offset } => self.inst_bge(
                BTypeArgs { rs1, rs2, offset },
                inst.size,
                &mut trace.side_effects,
            ),
            Instruction::LW { rd, rs1, offset } => self.inst_lw(ITypeArgs {
                rd,
                rs1,
                imm: offset,
            }),
            Instruction::LB { rd, rs1, offset } => self.inst_lb(ITypeArgs {
                rd,
                rs1,
                imm: offset,
            }),
            Instruction::LBU { rd, rs1, offset } => self.inst_lbu(ITypeArgs {
                rd,
                rs1,
                imm: offset,
            }),
            Instruction::LH { rd, rs1, offset } => self.inst_lh(ITypeArgs {
                rd,
                rs1,
                imm: offset,
            }),
            Instruction::LHU { rd, rs1, offset } => self.inst_lhu(ITypeArgs {
                rd,
                rs1,
                imm: offset,
            }),
            Instruction::SW { rs1, rs2, offset } => {
                self.inst_sw(STypeArgs { rs1, rs2, offset }, &mut trace)
            }
            Instruction::SB { rs1, rs2, offset } => {
                self.inst_sb(STypeArgs { rs1, rs2, offset }, &mut trace)
            }
            Instruction::SH { rs1, rs2, offset } => {
                self.inst_sh(STypeArgs { rs1, rs2, offset }, &mut trace)
            }
            Instruction::ADDI { rd, rs1, imm } => {
                self.inst_addi(ITypeArgs { rd, rs1, imm }, &mut trace.side_effects)
            }
            Instruction::SLTI { rd, rs1, imm } => self.inst_slti(ITypeArgs { rd, rs1, imm }),
            Instruction::SLTIU { rd, rs1, imm } => self.inst_sltiu(ITypeArgs { rd, rs1, imm }),
            Instruction::XORI { rd, rs1, imm } => self.inst_xori(ITypeArgs { rd, rs1, imm }),
            Instruction::ANDI { rd, rs1, imm } => self.inst_andi(ITypeArgs { rd, rs1, imm }),
            Instruction::ORI { rd, rs1, imm } => self.inst_ori(ITypeArgs { rd, rs1, imm }),
            Instruction::SLLI { rd, rs1, shamt } => {
                self.inst_slli(ShiftITypeArgs { rd, rs1, shamt })
            }
            Instruction::SRLI { rd, rs1, shamt } => {
                self.inst_srli(ShiftITypeArgs { rd, rs1, shamt })
            }
            Instruction::SRAI { rd, rs1, shamt } => {
                self.inst_srai(ShiftITypeArgs { rd, rs1, shamt })
            }
            Instruction::ADD { rd, rs1, rs2 } => {
                self.inst_add(RTypeArgs { rd, rs1, rs2 }, &mut trace.side_effects)
            }
            Instruction::SUB { rd, rs1, rs2 } => self.inst_sub(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SLL { rd, rs1, rs2 } => self.inst_sll(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SLT { rd, rs1, rs2 } => self.inst_slt(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SLTU { rd, rs1, rs2 } => self.inst_sltu(RTypeArgs { rd, rs1, rs2 }),
            Instruction::XOR { rd, rs1, rs2 } => self.inst_xor(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SRL { rd, rs1, rs2 } => self.inst_srl(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SRA { rd, rs1, rs2 } => self.inst_sra(RTypeArgs { rd, rs1, rs2 }),
            Instruction::OR { rd, rs1, rs2 } => self.inst_or(RTypeArgs { rd, rs1, rs2 }),
            Instruction::AND { rd, rs1, rs2 } => self.inst_and(RTypeArgs { rd, rs1, rs2 }),
            Instruction::MUL { rd, rs1, rs2 } => self.inst_mul(RTypeArgs { rd, rs1, rs2 }),
            Instruction::MULHU { rd, rs1, rs2 } => self.inst_mulhu(RTypeArgs { rd, rs1, rs2 }),
            Instruction::DIVU { rd, rs1, rs2 } => self.inst_divu(RTypeArgs { rd, rs1, rs2 }),
            Instruction::REMU { rd, rs1, rs2 } => self.inst_remu(RTypeArgs { rd, rs1, rs2 }),
            Instruction::FENCE { .. } => {}
            Instruction::LR_W { rd, rs1, .. } => self.inst_lr_w(ITypeArgs { rd, rs1, imm: 0 }),
            Instruction::SC_W { rd, rs1, rs2, .. } => self.inst_sc_w(RTypeArgs { rd, rs1, rs2 }),
            Instruction::AMOADD_W { rd, rs1, rs2, .. } => {
                self.inst_amoadd_w(RTypeArgs { rd, rs1, rs2 })
            }
            Instruction::ECALL => self.inst_ecall(),
            Instruction::UNIMP => panic!(
                "hit UNIMP at pc={:#x}, cycle={}, regs={:08x?}",
                self.pc, cycle, self.regs
            ),

            _ => panic!(
                "unsupported instruction at pc={:#x}, cycle={}, inst={:?}, regs={:08x?}",
                self.pc, cycle, inst, self.regs
            ),
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

    fn inst_beq(
        &mut self,
        BTypeArgs { rs1, rs2, offset }: BTypeArgs,
        inst_len: usize,
        side_effects: &mut SideEffects,
    ) {
        let rs1_data = self.read_reg(rs1);
        let rs2_data = self.read_reg(rs2);
        if rs1_data == rs2_data {
            let new_pc = self.pc.wrapping_add(offset as usize);
            self.pc = new_pc;
            side_effects.branched_to = Some(new_pc as u32);
        } else {
            self.pc = self.pc.wrapping_add(inst_len);
        }
    }

    fn inst_bltu(
        &mut self,
        BTypeArgs { rs1, rs2, offset }: BTypeArgs,
        inst_len: usize,
        side_effects: &mut SideEffects,
    ) {
        if self.read_reg(rs1) < self.read_reg(rs2) {
            let new_pc = self.pc.wrapping_add(offset as usize);
            self.pc = new_pc;
            side_effects.branched_to = Some(new_pc as u32);
        } else {
            self.pc = self.pc.wrapping_add(inst_len);
        }
    }

    fn inst_bgeu(
        &mut self,
        BTypeArgs { rs1, rs2, offset }: BTypeArgs,
        inst_len: usize,
        side_effects: &mut SideEffects,
    ) {
        if self.read_reg(rs1) >= self.read_reg(rs2) {
            let new_pc = self.pc.wrapping_add(offset as usize);
            self.pc = new_pc;
            side_effects.branched_to = Some(new_pc as u32);
        } else {
            self.pc = self.pc.wrapping_add(inst_len);
        }
    }

    fn inst_blt(
        &mut self,
        BTypeArgs { rs1, rs2, offset }: BTypeArgs,
        inst_len: usize,
        side_effects: &mut SideEffects,
    ) {
        if (self.read_reg(rs1) as i32) < (self.read_reg(rs2) as i32) {
            let new_pc = self.pc.wrapping_add(offset as usize);
            self.pc = new_pc;
            side_effects.branched_to = Some(new_pc as u32);
        } else {
            self.pc = self.pc.wrapping_add(inst_len);
        }
    }

    fn inst_bge(
        &mut self,
        BTypeArgs { rs1, rs2, offset }: BTypeArgs,
        inst_len: usize,
        side_effects: &mut SideEffects,
    ) {
        if (self.read_reg(rs1) as i32) >= (self.read_reg(rs2) as i32) {
            let new_pc = self.pc.wrapping_add(offset as usize);
            self.pc = new_pc;
            side_effects.branched_to = Some(new_pc as u32);
        } else {
            self.pc = self.pc.wrapping_add(inst_len);
        }
    }

    fn load_byte(&self, addr: usize) -> u8 {
        let word_addr = addr & !0b11;
        let shift = (addr & 0b11) * 8;
        ((self.read_mem(word_addr) >> shift) & 0xff) as u8
    }

    fn load_halfword(&self, addr: usize) -> u16 {
        let lo = self.load_byte(addr) as u16;
        let hi = self.load_byte(addr + 1) as u16;
        lo | (hi << 8)
    }

    fn store_byte(&mut self, addr: usize, value: u8) {
        let word_addr = addr & !0b11;
        let shift = (addr & 0b11) * 8;
        let mask = !(0xff_u32 << shift);
        let word = (self.read_mem(word_addr) & mask) | ((value as u32) << shift);
        self.write_mem(word_addr, word);
    }

    fn store_halfword(&mut self, addr: usize, value: u16) {
        self.store_byte(addr, value as u8);
        self.store_byte(addr + 1, (value >> 8) as u8);
    }

    fn inst_lw(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        let addr = (self.read_reg(rs1) as i32).wrapping_add(imm) as usize;
        self.write_reg(rd, self.read_mem(addr));
    }

    fn inst_lb(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        let addr = (self.read_reg(rs1) as i32).wrapping_add(imm) as usize;
        self.write_reg(rd, self.load_byte(addr) as i8 as i32 as u32);
    }

    fn inst_lbu(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        let addr = (self.read_reg(rs1) as i32).wrapping_add(imm) as usize;
        self.write_reg(rd, self.load_byte(addr) as u32);
    }

    fn inst_lh(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        let addr = (self.read_reg(rs1) as i32).wrapping_add(imm) as usize;
        self.write_reg(rd, self.load_halfword(addr) as i16 as i32 as u32);
    }

    fn inst_lhu(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        let addr = (self.read_reg(rs1) as i32).wrapping_add(imm) as usize;
        self.write_reg(rd, self.load_halfword(addr) as u32);
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

    fn inst_sb(&mut self, STypeArgs { rs1, rs2, offset }: STypeArgs, trace: &mut ExecutionTrace) {
        let addr = (self.read_reg(rs1) as i32).wrapping_add(offset) as u32;
        let value = self.read_reg(rs2) as u8;
        self.store_byte(addr as usize, value);
        trace.side_effects.memory_op = Some(MemoryOperation {
            cycle: trace.cycle,
            address: addr,
            value: value as u32,
            is_write: true,
        });
    }

    fn inst_sh(&mut self, STypeArgs { rs1, rs2, offset }: STypeArgs, trace: &mut ExecutionTrace) {
        let addr = (self.read_reg(rs1) as i32).wrapping_add(offset) as u32;
        let value = self.read_reg(rs2) as u16;
        self.store_halfword(addr as usize, value);
        trace.side_effects.memory_op = Some(MemoryOperation {
            cycle: trace.cycle,
            address: addr,
            value: value as u32,
            is_write: true,
        });
    }

    fn inst_addi(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs, side_effects: &mut SideEffects) {
        let rs1_data = self.read_reg(rs1) as i32;
        let (value, has_overflown) = rs1_data.overflowing_add(imm);
        self.write_reg(rd, value as u32);
        side_effects.has_overflown = has_overflown;
        tracing::trace!("\tADDI value {:#0x}", value);
    }

    fn inst_sltiu(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        self.write_reg(rd, (self.read_reg(rs1) < imm as u32) as u32);
    }

    fn inst_slti(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        self.write_reg(rd, ((self.read_reg(rs1) as i32) < imm) as u32);
    }

    fn inst_xori(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) ^ (imm as u32));
    }

    fn inst_andi(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) & (imm as u32));
    }

    fn inst_ori(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) | (imm as u32));
    }

    fn inst_slli(&mut self, ShiftITypeArgs { rd, rs1, shamt }: ShiftITypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) << shamt);
    }

    fn inst_srli(&mut self, ShiftITypeArgs { rd, rs1, shamt }: ShiftITypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) >> shamt);
    }

    fn inst_srai(&mut self, ShiftITypeArgs { rd, rs1, shamt }: ShiftITypeArgs) {
        self.write_reg(rd, ((self.read_reg(rs1) as i32) >> shamt) as u32);
    }

    fn inst_add(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs, side_effects: &mut SideEffects) {
        let rs1_data = self.read_reg(rs1);
        let rs2_data = self.read_reg(rs2);
        let (value, has_overflown) = rs1_data.overflowing_add(rs2_data);
        self.write_reg(rd, value);
        side_effects.has_overflown = has_overflown;

        tracing::trace!("\tADD {:#0x} + {:#0x} = {:#0x} ", rs1_data, rs2_data, value);
    }

    fn inst_sub(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(rd, self.read_reg(rs1).wrapping_sub(self.read_reg(rs2)));
    }

    fn inst_sll(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) << (self.read_reg(rs2) & 0x1f));
    }

    fn inst_slt(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(
            rd,
            ((self.read_reg(rs1) as i32) < (self.read_reg(rs2) as i32)) as u32,
        );
    }

    fn inst_sltu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(rd, (self.read_reg(rs1) < self.read_reg(rs2)) as u32);
    }

    pub(crate) fn inst_xor(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) ^ self.read_reg(rs2));
    }

    fn inst_srl(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) >> (self.read_reg(rs2) & 0x1f));
    }

    fn inst_sra(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(
            rd,
            ((self.read_reg(rs1) as i32) >> (self.read_reg(rs2) & 0x1f)) as u32,
        );
    }

    pub(crate) fn inst_or(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) | self.read_reg(rs2));
    }

    pub(crate) fn inst_and(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(rd, self.read_reg(rs1) & self.read_reg(rs2));
    }

    pub(crate) fn inst_mul(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        self.write_reg(rd, self.read_reg(rs1).wrapping_mul(self.read_reg(rs2)));
    }

    pub(crate) fn inst_mulhu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        let lhs = self.read_reg(rs1) as u64;
        let rhs = self.read_reg(rs2) as u64;
        self.write_reg(rd, ((lhs * rhs) >> 32) as u32);
    }

    pub(crate) fn inst_divu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        let divisor = self.read_reg(rs2);
        self.write_reg(
            rd,
            if divisor == 0 {
                u32::MAX
            } else {
                self.read_reg(rs1) / divisor
            },
        );
    }

    pub(crate) fn inst_remu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        let divisor = self.read_reg(rs2);
        self.write_reg(
            rd,
            if divisor == 0 {
                self.read_reg(rs1)
            } else {
                self.read_reg(rs1) % divisor
            },
        );
    }

    fn inst_ecall(&mut self) {
        const SYSCALL_ALLOC_ALIGNED: u32 = 1;

        match self.read_reg(17) {
            SYSCALL_ALLOC_ALIGNED => {
                let size = self.read_reg(10) as usize;
                let align = self.read_reg(11) as usize;
                let ptr = self.heap.alloc_aligned(size, align).unwrap_or(0) as u32;
                self.write_reg(10, ptr);
            }
            n => panic!("unsupported syscall number: {n}"),
        }
    }

    fn inst_lr_w(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        let addr = (self.read_reg(rs1) as i32).wrapping_add(imm) as usize;
        self.reserved_word_addr = Some(addr);
        self.write_reg(rd, self.read_mem(addr));
    }

    fn inst_sc_w(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        let addr = self.read_reg(rs1) as usize;
        if self.reserved_word_addr == Some(addr) {
            self.write_mem(addr, self.read_reg(rs2));
            self.write_reg(rd, 0);
        } else {
            self.write_reg(rd, 1);
        }
        self.reserved_word_addr = None;
    }

    fn inst_amoadd_w(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        let addr = self.read_reg(rs1) as usize;
        let old = self.read_mem(addr);
        let new = old.wrapping_add(self.read_reg(rs2));
        self.write_mem(addr, new);
        self.write_reg(rd, old);
        self.reserved_word_addr = None;
    }
}
