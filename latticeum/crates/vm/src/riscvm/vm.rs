use std::{
    fmt::{Debug, Display},
    path::PathBuf,
};

use crate::riscvm::{
    consts::MAX_MEM,
    elf::{Elf, ElfLoadingError},
    inst_decoder::{DecodedInstruction, Decoder},
};

pub trait VmState {}

struct Uninitialized {}
impl VmState for Uninitialized {}

pub(crate) struct ProgramLoaded {
    elf: Elf,
}
impl VmState for ProgramLoaded {}

#[derive(Debug)]
pub struct VM<State: VmState> {
    /// 32 general-purpose registers of width T.
    /// RISC-Vs calling convention https://riscv.org/wp-content/uploads/2024/12/riscv-calling.pdf:
    /// Register | ABI Name | Description                        | Saver
    /// -------- | -------- | ---------------------------------- | -----
    /// x0       | zero     | Hard-wired zero                    | -
    /// x1       | ra       | Return address                     | Caller
    /// x2       | sp       | Stack pointer                      | Callee
    /// x3       | gp       | Global pointer                     | -
    /// x4       | tp       | Thread pointer                     | -
    /// x5–7     | t0–2     | Temporaries                        | Caller
    /// x8       | s0/fp    | Saved register/frame pointer       | Callee
    /// x9       | s1       | Saved register                     | Callee
    /// x10–11   | a0–1     | Function arguments/return values   | Caller
    /// x12–17   | a2–7     | Function arguments                 | Caller
    /// x18–27   | s2–11    | Saved registers                    | Callee
    /// x28–31   | t3–6     | Temporaries                        | Caller
    regs: [u32; 32],

    /// The program counter of width 32 bits.
    pc: u32,

    /// The main memory of the VM.
    memory: Vec<u8>,

    program: State,
}

impl VM<Uninitialized> {
    pub fn new() -> Self {
        VM {
            regs: [0; 32],
            pc: 0,
            memory: vec![0; MAX_MEM as usize],
            program: Uninitialized {},
        }
    }

    pub fn load_elf(self, path: PathBuf) -> Result<VM<ProgramLoaded>, ElfLoadingError> {
        let program = Elf::load(path)?;
        let initialized = VM {
            regs: self.regs,
            pc: self.pc,
            memory: self.memory,
            program: ProgramLoaded { elf: program },
        };
        Ok(initialized)
    }
}

impl VM<ProgramLoaded> {
    fn instructions(&self) -> Vec<DecodedInstruction> {
        Decoder::decode(&self.program.elf.raw_code)
    }

    fn run(&mut self) {
        self.instructions()
            .iter()
            .for_each(|inst| self.execute_step(inst.0));
    }
}

impl Display for VM<ProgramLoaded> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== RISC-V VM State ===")?;
        writeln!(f, "Registers:")?;

        // Display registers in a nice 4-column format with ABI names
        #[rustfmt::skip]
        let abi_names = [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
            "s0/fp", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
            "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
        ];

        for i in (0..32).step_by(4) {
            write!(f, "  ")?;
            for j in 0..4 {
                if i + j < 32 {
                    let reg_idx = i + j;
                    write!(
                        f,
                        "x{:2}({:>5}): 0x{:08x}  ",
                        reg_idx, abi_names[reg_idx], self.regs[reg_idx]
                    )?;
                }
            }
            writeln!(f)?;
        }

        writeln!(f, "\nProgram Counter:")?;
        writeln!(f, "  pc: 0x{:08x}", self.pc)?;

        let program = &self.program.elf;
        writeln!(f, "\nProgram Information:")?;
        writeln!(f, "  Image size: {} words", program.image.len())?;
        writeln!(f, "  Raw code size: {} bytes", program.raw_code.len())?;

        if !program.raw_code.is_empty() {
            writeln!(f, "\nDisassembled Code:")?;
            let instructions = self.instructions();

            let mut addr = program.entry_point;

            for (instruction, len) in instructions.iter() {
                writeln!(f, "  0x{:08x}: {}", addr, instruction)?;
                addr += len;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::riscvm::{
        reg,
        vm::{Uninitialized, VM},
    };
    use riscv_isa::Instruction;
    use std::path::PathBuf;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    #[rustfmt::skip]
    fn fibonacci_instructions() {
        let vm = VM::<Uninitialized>::new();

        let program = PathBuf::from("samples/fibonacci");
        let vm = match vm.load_elf(program) {
            Ok(vm) => vm,
            Err(e) => panic!("failed to loaed samples/fibonacci elf, {}", e),
        };

        let instructions = vm.instructions();

        assert_eq!(17, instructions.len());
        // init code
        assert_eq!(instructions[0], (Instruction::AUIPC { rd: reg::X3, imm: 0xfffff }, 4));
        assert_eq!(instructions[1], (Instruction::ADDI { rd: reg::X3, rs1: reg::X3, imm: 1836 }, 4));
        assert_eq!(instructions[2], (Instruction::LUI { rd: reg::X2, imm: 0x300 }, 4));
        assert_eq!(instructions[3], (Instruction::AUIPC { rd: reg::X1, imm: 0x0 }, 4));
        assert_eq!(instructions[4], (Instruction::JALR { rd: reg::X1, rs1: reg::X1, offset: 8 } , 4));

        // fibonacci code
        assert_eq!(instructions[5], (Instruction::ADDI { rd: reg::X10, rs1: reg::X0, imm: 0 }, 2));
        assert_eq!(instructions[6], (Instruction::ADDI { rd: reg::X11, rs1: reg::X0, imm: 1 }, 2));
        assert_eq!(instructions[7], (Instruction::LUI { rd: reg::X12, imm: 0x18 }, 2));
        assert_eq!(instructions[8], (Instruction::ADDI { rd: reg::X12, rs1: reg::X12, imm: 1695 }, 4));
        assert_eq!(instructions[9], (Instruction::ADD { rd: 13, rs1: 0, rs2: 11 }, 2));
        assert_eq!(instructions[10], (Instruction::ADDI { rd: reg::X12, rs1: reg::X12, imm: -1 }, 2));
        assert_eq!(instructions[11], (Instruction::ADD { rd: reg::X11, rs1: reg::X11, rs2: reg::X10 }, 2));
        assert_eq!(instructions[12], (Instruction::ADD { rd: reg::X10, rs1: reg::X0, rs2: reg::X13 }, 2));
        assert_eq!(instructions[13], (Instruction::BNE { rs1: reg::X12, rs2: reg::X0, offset: -8 }, 2));
        assert_eq!(instructions[14], (Instruction::LUI { rd: reg::X10, imm: 0x300 }, 4));
        assert_eq!(instructions[15], (Instruction::SW { rs1: reg::X10, rs2: reg::X11, offset: 4 }, 2));
        assert_eq!(instructions[16], (Instruction::JAL { rd: reg::X0, offset: 0 }, 2));
    }

    #[test]
    #[traced_test]
    fn run() {
        let vm = VM::<Uninitialized>::new();

        let program = PathBuf::from("samples/fibonacci");
        let mut vm = match vm.load_elf(program) {
            Ok(vm) => vm,
            Err(e) => panic!("failed to loaed samples/fibonacci elf, {}", e),
        };

        vm.run();
    }
}
