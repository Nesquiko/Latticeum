use crate::riscvm::{
    inst_decoder::{DecodedInstruction, Instruction},
    vm::{Loaded, VM},
};

// These structs represent the common argument patterns for RISC-V instructions.
// Deriving `Debug` allows them to be printed for inspection.
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
struct IShiftArgs {
    rd: u32,
    rs1: u32,
    shamt: u32,
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
struct LoadArgs {
    rd: u32,
    rs1: u32,
    offset: i32,
}
#[derive(Debug)]
struct FenceArgs {
    pred: u8,
    succ: u8,
}
#[derive(Debug)]
struct LrArgs {
    rd: u32,
    rs1: u32,
    rl: u32,
    aq: u32,
}
#[derive(Debug)]
struct AmoArgs {
    rd: u32,
    rs1: u32,
    rs2: u32,
    rl: u32,
    aq: u32,
}

#[derive(Debug)]
pub struct ExectionTrace {
    pub input: ExectionSnapshot,
    pub output: ExectionSnapshot,
    pub instruction: DecodedInstruction,
}

#[derive(Debug)]
pub struct ExectionSnapshot {
    pub pc: usize,
    pub regs: [u32; 32],
}

impl VM<Loaded> {
    /// Dispatches the given instruction to the appropriate handler function.
    /// Also mutates `pc`.
    ///
    /// Only handles instructions from the RV32IMAC set.
    pub fn execute_step(&mut self, inst: &DecodedInstruction) -> ExectionTrace {
        let mut trace = ExectionTrace {
            input: ExectionSnapshot {
                pc: self.pc,
                regs: self.regs.clone(),
            },
            output: ExectionSnapshot {
                pc: 0,
                regs: [0; 32],
            },
            instruction: inst.clone(),
        };

        tracing::trace!("executing 0x{:x} - {}", self.pc, inst);

        match inst.inst {
            // --- RV32I: Base Integer Instructions ---
            Instruction::LUI { rd, imm } => self.inst_lui(UTypeArgs { rd, imm }),
            Instruction::AUIPC { rd, imm } => self.inst_auipc(UTypeArgs { rd, imm }),
            Instruction::JAL { rd, offset } => self.inst_jal(JTypeArgs { rd, offset }, inst.size),
            Instruction::JALR { rd, rs1, offset } => {
                self.inst_jalr(JalrArgs { rd, rs1, offset }, inst.size)
            }
            Instruction::BEQ { rs1, rs2, offset } => self.inst_beq(BTypeArgs { rs1, rs2, offset }),
            Instruction::BNE { rs1, rs2, offset } => {
                self.inst_bne(BTypeArgs { rs1, rs2, offset }, inst.size)
            }
            Instruction::BLT { rs1, rs2, offset } => self.inst_blt(BTypeArgs { rs1, rs2, offset }),
            Instruction::BGE { rs1, rs2, offset } => self.inst_bge(BTypeArgs { rs1, rs2, offset }),
            Instruction::BLTU { rs1, rs2, offset } => {
                self.inst_bltu(BTypeArgs { rs1, rs2, offset })
            }
            Instruction::BGEU { rs1, rs2, offset } => {
                self.inst_bgeu(BTypeArgs { rs1, rs2, offset })
            }
            Instruction::LB { rd, rs1, offset } => self.inst_lb(LoadArgs { rd, rs1, offset }),
            Instruction::LH { rd, rs1, offset } => self.inst_lh(LoadArgs { rd, rs1, offset }),
            Instruction::LW { rd, rs1, offset } => self.inst_lw(LoadArgs { rd, rs1, offset }),
            Instruction::LBU { rd, rs1, offset } => self.inst_lbu(LoadArgs { rd, rs1, offset }),
            Instruction::LHU { rd, rs1, offset } => self.inst_lhu(LoadArgs { rd, rs1, offset }),
            Instruction::SB { rs1, rs2, offset } => self.inst_sb(STypeArgs { rs1, rs2, offset }),
            Instruction::SH { rs1, rs2, offset } => self.inst_sh(STypeArgs { rs1, rs2, offset }),
            Instruction::SW { rs1, rs2, offset } => self.inst_sw(STypeArgs { rs1, rs2, offset }),
            Instruction::ADDI { rd, rs1, imm } => self.inst_addi(ITypeArgs { rd, rs1, imm }),
            Instruction::SLTI { rd, rs1, imm } => self.inst_slti(ITypeArgs { rd, rs1, imm }),
            Instruction::SLTIU { rd, rs1, imm } => self.inst_sltiu(ITypeArgs { rd, rs1, imm }),
            Instruction::XORI { rd, rs1, imm } => self.inst_xori(ITypeArgs { rd, rs1, imm }),
            Instruction::ORI { rd, rs1, imm } => self.inst_ori(ITypeArgs { rd, rs1, imm }),
            Instruction::ANDI { rd, rs1, imm } => self.inst_andi(ITypeArgs { rd, rs1, imm }),
            Instruction::SLLI { rd, rs1, shamt } => self.inst_slli(IShiftArgs { rd, rs1, shamt }),
            Instruction::SRLI { rd, rs1, shamt } => self.inst_srli(IShiftArgs { rd, rs1, shamt }),
            Instruction::SRAI { rd, rs1, shamt } => self.inst_srai(IShiftArgs { rd, rs1, shamt }),
            Instruction::ADD { rd, rs1, rs2 } => self.inst_add(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SUB { rd, rs1, rs2 } => self.inst_sub(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SLL { rd, rs1, rs2 } => self.inst_sll(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SLT { rd, rs1, rs2 } => self.inst_slt(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SLTU { rd, rs1, rs2 } => self.inst_sltu(RTypeArgs { rd, rs1, rs2 }),
            Instruction::XOR { rd, rs1, rs2 } => self.inst_xor(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SRL { rd, rs1, rs2 } => self.inst_srl(RTypeArgs { rd, rs1, rs2 }),
            Instruction::SRA { rd, rs1, rs2 } => self.inst_sra(RTypeArgs { rd, rs1, rs2 }),
            Instruction::OR { rd, rs1, rs2 } => self.inst_or(RTypeArgs { rd, rs1, rs2 }),
            Instruction::AND { rd, rs1, rs2 } => self.inst_and(RTypeArgs { rd, rs1, rs2 }),
            Instruction::FENCE { pred, succ } => {
                self.inst_fence(FenceArgs {
                    pred: pred.to_string().parse::<u8>().expect(
                        "riscv_isa doesn't export the Iorw type, so I must do it like this",
                    ),
                    succ: succ.to_string().parse::<u8>().expect(
                        "riscv_isa doesn't export the Iorw type, so I must do it like this",
                    ),
                })
            }
            Instruction::ECALL => self.inst_ecall(),
            Instruction::EBREAK => self.inst_ebreak(),
            Instruction::UNIMP => self.inst_unimp(),

            // --- M Standard Extension ---
            Instruction::MUL { rd, rs1, rs2 } => self.inst_mul(RTypeArgs { rd, rs1, rs2 }),
            Instruction::MULH { rd, rs1, rs2 } => self.inst_mulh(RTypeArgs { rd, rs1, rs2 }),
            Instruction::MULHSU { rd, rs1, rs2 } => self.inst_mulhsu(RTypeArgs { rd, rs1, rs2 }),
            Instruction::MULHU { rd, rs1, rs2 } => self.inst_mulhu(RTypeArgs { rd, rs1, rs2 }),
            Instruction::DIV { rd, rs1, rs2 } => self.inst_div(RTypeArgs { rd, rs1, rs2 }),
            Instruction::DIVU { rd, rs1, rs2 } => self.inst_divu(RTypeArgs { rd, rs1, rs2 }),
            Instruction::REM { rd, rs1, rs2 } => self.inst_rem(RTypeArgs { rd, rs1, rs2 }),
            Instruction::REMU { rd, rs1, rs2 } => self.inst_remu(RTypeArgs { rd, rs1, rs2 }),

            // --- A Standard Extension ---
            Instruction::LR_W { rd, rs1, rl, aq } => self.inst_lr_w(LrArgs { rd, rs1, rl, aq }),
            Instruction::SC_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_sc_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOSWAP_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amoswap_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOADD_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amoadd_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOXOR_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amoxor_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOAND_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amoand_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOOR_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amoor_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOMIN_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amomin_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOMAX_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amomax_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOMINU_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amominu_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),
            Instruction::AMOMAXU_W {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            } => self.inst_amomaxu_w(AmoArgs {
                rd,
                rs1,
                rs2,
                rl,
                aq,
            }),

            _ => panic!("unsupported instruction: {:?}", inst),
        };

        if !inst.inst.branch() {
            self.pc = self.pc.wrapping_add(inst.size);
            tracing::trace!(
                "non branching instruction incrementing pc 0x{:x} to 0x{:x}",
                trace.input.pc,
                self.pc
            );
        }
        trace.output.pc = self.pc;
        trace.output.regs = self.regs.clone();
        self.write_reg(0, 0);

        trace
    }

    // --- RV32I Instruction Implementations ---
    fn inst_lui(&mut self, UTypeArgs { rd, imm }: UTypeArgs) {
        self.write_reg(rd, imm << 12);
    }
    fn inst_auipc(&mut self, UTypeArgs { rd, imm }: UTypeArgs) {
        let val = TryInto::<u32>::try_into(self.pc)
            .expect("can't convert pc to u32")
            .wrapping_add(imm);
        self.write_reg(rd, val);
        tracing::trace!("\tAUIPC value 0x{:x}", val);
    }
    fn inst_jal(&mut self, JTypeArgs { rd, offset }: JTypeArgs, inst_len: usize) {
        let link = self.pc.wrapping_add(inst_len) as u32;
        let new_pc = self.pc.wrapping_add(offset as usize);

        self.write_reg(rd, link);
        self.pc = new_pc;

        tracing::trace!("\tJAL link 0x{:x}, new pc 0x{:x}", link, new_pc);
    }
    fn inst_jalr(&mut self, JalrArgs { rd, rs1, offset }: JalrArgs, inst_len: usize) {
        let rs1_data = self.read_reg(rs1);
        let link = self
            .pc
            .wrapping_add(inst_len)
            .try_into()
            .expect("can't convert usize to u32");

        let new_pc = (rs1_data.wrapping_add(offset as u32)) & !1;

        self.pc = new_pc as usize;
        self.write_reg(rd, link);
        tracing::trace!("\tJALR link 0x{:x}, new pc 0x{:x}", link, new_pc);
    }
    fn inst_beq(&mut self, BTypeArgs { rs1, rs2, offset }: BTypeArgs) {
        println!("BEQ: rs1={}, rs2={}, offset={}", rs1, rs2, offset);
    }
    fn inst_bne(&mut self, BTypeArgs { rs1, rs2, offset }: BTypeArgs, inst_len: usize) {
        // if rs1 != rs2 then pc += offset else pc += inst_len
        let rs1_data = self.read_reg(rs1);
        let rs2_data = self.read_reg(rs2);
        if rs1_data != rs2_data {
            let new_pc = self.pc.wrapping_add(offset as usize);
            tracing::trace!("\tBNE branching from pc 0x{:x} to 0x{:x}", self.pc, new_pc);
            self.pc = new_pc;
        } else {
            let new_pc = self.pc.wrapping_add(inst_len);
            tracing::trace!(
                "\tBNE not equal, continuing pc 0x{:x} to 0x{:x}",
                self.pc,
                new_pc
            );
            self.pc = new_pc;
        }
    }
    fn inst_blt(&mut self, BTypeArgs { rs1, rs2, offset }: BTypeArgs) {
        println!("BLT: rs1={}, rs2={}, offset={}", rs1, rs2, offset);
    }
    fn inst_bge(&mut self, BTypeArgs { rs1, rs2, offset }: BTypeArgs) {
        println!("BGE: rs1={}, rs2={}, offset={}", rs1, rs2, offset);
    }
    fn inst_bltu(&mut self, BTypeArgs { rs1, rs2, offset }: BTypeArgs) {
        println!("BLTU: rs1={}, rs2={}, offset={}", rs1, rs2, offset);
    }
    fn inst_bgeu(&mut self, BTypeArgs { rs1, rs2, offset }: BTypeArgs) {
        println!("BGEU: rs1={}, rs2={}, offset={}", rs1, rs2, offset);
    }
    fn inst_lb(&mut self, LoadArgs { rd, rs1, offset }: LoadArgs) {
        println!("LB: rd={}, rs1={}, offset={}", rd, rs1, offset);
    }
    fn inst_lh(&mut self, LoadArgs { rd, rs1, offset }: LoadArgs) {
        println!("LH: rd={}, rs1={}, offset={}", rd, rs1, offset);
    }
    fn inst_lw(&mut self, LoadArgs { rd, rs1, offset }: LoadArgs) {
        println!("LW: rd={}, rs1={}, offset={}", rd, rs1, offset);
    }
    fn inst_lbu(&mut self, LoadArgs { rd, rs1, offset }: LoadArgs) {
        println!("LBU: rd={}, rs1={}, offset={}", rd, rs1, offset);
    }
    fn inst_lhu(&mut self, LoadArgs { rd, rs1, offset }: LoadArgs) {
        println!("LHU: rd={}, rs1={}, offset={}", rd, rs1, offset);
    }
    fn inst_sb(&mut self, STypeArgs { rs1, rs2, offset }: STypeArgs) {
        println!("SB: rs1={}, rs2={}, offset={}", rs1, rs2, offset);
    }
    fn inst_sh(&mut self, STypeArgs { rs1, rs2, offset }: STypeArgs) {
        println!("SH: rs1={}, rs2={}, offset={}", rs1, rs2, offset);
    }
    fn inst_sw(&mut self, STypeArgs { rs1, rs2, offset }: STypeArgs) {
        // M[rs1+offset] = reg[rs2]
        let rs1_data = self.read_reg(rs1) as i32;
        let rs2_data = self.read_reg(rs2);
        let addr = rs1_data.wrapping_add(offset) as u32;
        self.write_mem(addr, rs2_data);

        tracing::trace!("\tSW addr 0x{:x} - value 0x{:x}", addr, rs2_data);
    }
    fn inst_addi(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        let rs1_data = self.read_reg(rs1) as i32;
        let value = rs1_data.wrapping_add(imm);
        self.write_reg(rd, value as u32);
        tracing::trace!("\tADDI value 0x{:x}", value);
    }
    fn inst_slti(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        println!("SLTI: rd={}, rs1={}, imm={}", rd, rs1, imm);
    }
    fn inst_sltiu(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        println!("SLTIU: rd={}, rs1={}, imm={}", rd, rs1, imm);
    }
    fn inst_xori(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        println!("XORI: rd={}, rs1={}, imm={}", rd, rs1, imm);
    }
    fn inst_ori(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        println!("ORI: rd={}, rs1={}, imm={}", rd, rs1, imm);
    }
    fn inst_andi(&mut self, ITypeArgs { rd, rs1, imm }: ITypeArgs) {
        println!("ANDI: rd={}, rs1={}, imm={}", rd, rs1, imm);
    }
    fn inst_slli(&mut self, IShiftArgs { rd, rs1, shamt }: IShiftArgs) {
        println!("SLLI: rd={}, rs1={}, shamt={}", rd, rs1, shamt);
    }
    fn inst_srli(&mut self, IShiftArgs { rd, rs1, shamt }: IShiftArgs) {
        println!("SRLI: rd={}, rs1={}, shamt={}", rd, rs1, shamt);
    }
    fn inst_srai(&mut self, IShiftArgs { rd, rs1, shamt }: IShiftArgs) {
        println!("SRAI: rd={}, rs1={}, shamt={}", rd, rs1, shamt);
    }
    fn inst_add(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        //  regs[rd] = regs[rs1] + regs[rs2]
        let rs1_data = self.read_reg(rs1) as i32;
        let rs2_data = self.read_reg(rs2) as i32;
        let value = rs1_data.wrapping_add(rs2_data);
        self.write_reg(rd, value as u32);

        tracing::trace!("\tADD 0x{:x} + 0x{:x} = 0x{:x} ", rs1_data, rs2_data, value);
    }
    fn inst_sub(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("SUB: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_sll(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("SLL: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_slt(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("SLT: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_sltu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("SLTU: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_xor(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("XOR: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_srl(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("SRL: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_sra(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("SRA: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_or(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("OR: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_and(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("AND: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_fence(&mut self, FenceArgs { pred, succ }: FenceArgs) {
        println!("FENCE: pred={}, succ={}", pred, succ);
    }
    fn inst_ecall(&mut self) {
        println!("ECALL");
    }
    fn inst_ebreak(&mut self) {
        println!("EBREAK");
    }
    fn inst_unimp(&mut self) {
        println!("UNIMP");
    }

    // --- M Extension Instruction Implementations ---
    fn inst_mul(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("MUL: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_mulh(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("MULH: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_mulhsu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("MULHSU: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_mulhu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("MULHU: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_div(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("DIV: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_divu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("DIVU: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_rem(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("REM: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }
    fn inst_remu(&mut self, RTypeArgs { rd, rs1, rs2 }: RTypeArgs) {
        println!("REMU: rd={}, rs1={}, rs2={}", rd, rs1, rs2);
    }

    // --- A Extension Instruction Implementations ---
    fn inst_lr_w(&mut self, LrArgs { rd, rs1, rl, aq }: LrArgs) {
        println!("LR.W: rd={}, rs1={}, rl={}, aq={}", rd, rs1, rl, aq);
    }
    fn inst_sc_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "SC.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amoswap_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOSWAP.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amoadd_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOADD.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amoxor_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOXOR.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amoand_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOAND.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amoor_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOOR.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amomin_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOMIN.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amomax_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOMAX.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amominu_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOMINU.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
    fn inst_amomaxu_w(
        &mut self,
        AmoArgs {
            rd,
            rs1,
            rs2,
            rl,
            aq,
        }: AmoArgs,
    ) {
        println!(
            "AMOMAXU.W: rd={}, rs1={}, rs2={}, rl={}, aq={}",
            rd, rs1, rs2, rl, aq
        );
    }
}
