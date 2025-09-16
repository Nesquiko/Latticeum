use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    path::PathBuf,
};

use configuration::RESULT_ADDRESS;
use thiserror::Error;

use crate::riscvm::{
    elf::{Elf, ElfLoadingError},
    inst::ExecutionTrace,
    inst_decoder::{DecodedInstruction, Decoder},
};

pub trait VmProgram {}

pub struct Uninitialized {}

impl VmProgram for Uninitialized {}

pub struct Loaded {
    elf: Elf,
    instructions: HashMap<usize, DecodedInstruction>,
}

impl VmProgram for Loaded {}

#[derive(Debug)]
pub struct VM<Program: VmProgram> {
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
    pub(crate) regs: [u32; 32],

    /// The program counter of width 32 bits.
    pub(crate) pc: usize,

    /// The main memory of the VM.
    memory: HashMap<usize, u32>,

    program: Program,
}

pub fn new_vm() -> VM<Uninitialized> {
    VM::<Uninitialized>::new()
}

impl<Program: VmProgram> VM<Program> {
    pub(crate) fn read_reg(&self, i: u32) -> u32 {
        self.regs[i as usize]
    }

    pub(crate) fn write_reg(&mut self, i: u32, data: u32) {
        self.regs[i as usize] = data
    }

    pub(crate) fn write_mem(&mut self, addr: u32, data: u32) {
        self.memory.insert(addr as usize, data);
    }
}

impl VM<Uninitialized> {
    pub fn new() -> Self {
        VM {
            regs: [0; 32],
            pc: 0,
            memory: HashMap::new(),
            program: Uninitialized {},
        }
    }

    pub fn load_elf(self, path: PathBuf) -> Result<VM<Loaded>, ElfLoadingError> {
        let elf = Elf::load(path)?;

        let mut instructions = HashMap::new();
        let mut addr = elf.raw_code.start;

        for inst in Decoder::from_le_bytes(&elf.raw_code.bytes, elf.raw_code.size) {
            let size = inst.size;
            instructions.insert(addr, inst);
            addr += size;
        }

        let initialized = VM {
            regs: self.regs,
            pc: elf.entry_point,
            memory: self.memory,
            program: Loaded { elf, instructions },
        };
        Ok(initialized)
    }
}

impl VM<Loaded> {
    /// Runs the VM's execution loop
    pub fn run(&mut self, intercept: impl Fn(ExecutionTrace) -> ()) {
        let mut cycle: usize = 0;
        loop {
            match self.fetch_execute(cycle) {
                Ok((ExecutionState::Continue, trace)) => intercept(trace),
                Ok((ExecutionState::Halt, trace)) => {
                    tracing::info!("execution halted");
                    intercept(trace);
                    break;
                }
                Err(err) => {
                    tracing::error!("error in fetch_execute: {}", err);
                    break;
                }
            }
            cycle += 1;
        }
    }

    pub fn result(&self) -> u32 {
        let result_addr = RESULT_ADDRESS as usize;
        assert!(self.memory.contains_key(&result_addr));
        self.memory[&result_addr]
    }

    /// Fetches instruction pointed at by `pc`, executes it and updates `pc`.
    fn fetch_execute(
        &mut self,
        cycle: usize,
    ) -> Result<(ExecutionState, ExecutionTrace), ExecutionError> {
        let inst = match self.program.instructions.get(&self.pc) {
            Some(inst) => inst.clone(),
            None => {
                tracing::error!(
                    "HALTING execution, PC 0x{:x} is not a valid instruction address",
                    self.pc
                );
                return Err(ExecutionError::InvalidPC(self.pc));
            }
        };

        let trace = self.execute_step(&inst, cycle);

        // halt when program enters an infinite loop by jumping to itself
        if trace.input.pc == trace.output.pc {
            tracing::trace!("halting on instruction {} at 0x{:x}", inst, trace.input.pc);
            return Ok((ExecutionState::Halt, trace));
        }

        Ok((ExecutionState::Continue, trace))
    }
}

enum ExecutionState {
    Continue,
    Halt,
}

#[derive(Error, Debug)]
enum ExecutionError {
    #[error("invalid instruction address in PC 0x{0:x}")]
    InvalidPC(usize),
}

impl Display for VM<Loaded> {
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
        writeln!(f, "  Entry point: 0x{:x}", program.entry_point)?;
        writeln!(f, "  Image size: 0x{:x} words", program.image.len())?;
        writeln!(f, "  Raw code start: 0x{:x}", program.raw_code.start)?;
        writeln!(
            f,
            "  Raw code size: 0x{:x} bytes",
            program.raw_code.bytes.len()
        )?;

        if !self.program.instructions.is_empty() {
            writeln!(f, "\nDisassembled Code:")?;
            let mut addrs: Vec<_> = self.program.instructions.keys().collect();
            addrs.sort();

            for addr in addrs {
                let inst = self
                    .program
                    .instructions
                    .get(addr)
                    .expect("got the key from the map itself");
                writeln!(f, "  0x{:08x}: {}", addr, inst.inst)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::riscvm::{
        inst_decoder::DecodedInstruction,
        reg,
        vm::{Uninitialized, VM},
    };
    use configuration::RESULT_ADDRESS;
    use riscv_isa::Instruction;
    use std::path::PathBuf;
    use test_log::test;

    #[test]
    fn fibonacci_instructions() {
        let vm = VM::<Uninitialized>::new();

        let program = PathBuf::from("samples/fibonacci");
        let vm = match vm.load_elf(program) {
            Ok(vm) => vm,
            Err(e) => panic!("failed to loaed samples/fibonacci elf, {}", e),
        };

        let insts = vm.program.instructions;

        assert_eq!(24, insts.len());

        // The main code is first. Linker can reorders sections in `.text` segment.
        assert_eq!(
            insts[&vm.program.elf.raw_code.start],
            DecodedInstruction {
                inst: Instruction::ADDI {
                    rd: reg::X11,
                    rs1: reg::X0,
                    imm: 0x0
                },
                size: 2,
                raw_word: 0x4581
            }
        );
        assert_eq!(
            insts[&0x110d6],
            DecodedInstruction {
                inst: Instruction::ADDI {
                    rd: reg::X10,
                    rs1: reg::X0,
                    imm: 0x1
                },
                size: 2,
                raw_word: 0x4505
            }
        );
        assert_eq!(
            insts[&0x110d8],
            DecodedInstruction {
                inst: Instruction::LUI {
                    rd: reg::X12,
                    imm: 0x18
                },
                size: 2,
                raw_word: 0x6661
            }
        );
        assert_eq!(
            insts[&0x110da],
            DecodedInstruction {
                inst: Instruction::ADDI {
                    rd: reg::X12,
                    rs1: reg::X12,
                    imm: 1695
                },
                size: 4,
                raw_word: 0x69f60613
            }
        );
        assert_eq!(
            insts[&0x110de],
            DecodedInstruction {
                inst: Instruction::ADD {
                    rd: reg::X13,
                    rs1: reg::X0,
                    rs2: reg::X10
                },
                size: 2,
                raw_word: 0x86aa
            }
        );
        assert_eq!(
            insts[&0x110e0],
            DecodedInstruction {
                inst: Instruction::ADDI {
                    rd: reg::X12,
                    rs1: reg::X12,
                    imm: -1
                },
                size: 2,
                raw_word: 0x167d
            }
        );
        assert_eq!(
            insts[&0x110e2],
            DecodedInstruction {
                inst: Instruction::ADD {
                    rd: reg::X10,
                    rs1: reg::X10,
                    rs2: reg::X11
                },
                size: 2,
                raw_word: 0x952e
            }
        );
        assert_eq!(
            insts[&0x110e4],
            DecodedInstruction {
                inst: Instruction::ADD {
                    rd: reg::X11,
                    rs1: reg::X0,
                    rs2: reg::X13
                },
                size: 2,
                raw_word: 0x85b6
            }
        );
        assert_eq!(
            insts[&0x110e6],
            DecodedInstruction {
                inst: Instruction::BNE {
                    rs1: reg::X12,
                    rs2: reg::X0,
                    offset: -8
                },
                size: 2,
                raw_word: 0xfe65
            }
        );
        assert_eq!(
            insts[&0x110e8],
            DecodedInstruction {
                inst: Instruction::AUIPC {
                    rd: reg::X6,
                    imm: 0x0
                },
                size: 4,
                raw_word: 0x00000317
            }
        );
        assert_eq!(
            insts[&0x110ec],
            DecodedInstruction {
                inst: Instruction::JALR {
                    rd: reg::X0,
                    rs1: reg::X6,
                    offset: 42
                },
                size: 4,
                raw_word: 0x02a30067
            }
        );

        // _start function
        assert_eq!(
            insts[&0x110f0],
            DecodedInstruction {
                inst: Instruction::AUIPC {
                    rd: reg::X3,
                    imm: 0xfffff
                },
                size: 4,
                raw_word: 0xfffff197
            }
        );
        assert_eq!(
            insts[&0x110f4],
            DecodedInstruction {
                inst: Instruction::ADDI {
                    rd: reg::X3,
                    rs1: reg::X3,
                    imm: 1808
                },
                size: 4,
                raw_word: 0x71018193
            }
        );
        assert_eq!(
            insts[&0x110f8],
            DecodedInstruction {
                inst: Instruction::LUI {
                    rd: reg::X2,
                    imm: 0x300
                },
                size: 4,
                raw_word: 0x00300137
            }
        );
        assert_eq!(
            insts[&0x110fc],
            DecodedInstruction {
                inst: Instruction::AUIPC {
                    rd: reg::X1,
                    imm: 0
                },
                size: 4,
                raw_word: 0x00000097
            }
        );
        assert_eq!(
            insts[&0x11100],
            DecodedInstruction {
                inst: Instruction::JALR {
                    rd: reg::X1,
                    rs1: reg::X1,
                    offset: 8
                },
                size: 4,
                raw_word: 0x008080e7
            }
        );

        // rust_main function
        assert_eq!(
            insts[&0x11104],
            DecodedInstruction {
                inst: Instruction::ADDI {
                    rd: reg::X2,
                    rs1: reg::X2,
                    imm: -16
                },
                size: 2,
                raw_word: 0x1141
            }
        );
        assert_eq!(
            insts[&0x11106],
            DecodedInstruction {
                inst: Instruction::SW {
                    rs1: reg::X2,
                    rs2: reg::X1,
                    offset: 12
                },
                size: 2,
                raw_word: 0xc606
            }
        );
        assert_eq!(
            insts[&0x11108],
            DecodedInstruction {
                inst: Instruction::AUIPC {
                    rd: reg::X1,
                    imm: 0
                },
                size: 4,
                raw_word: 0x00000097
            }
        );
        assert_eq!(
            insts[&0x1110c],
            DecodedInstruction {
                inst: Instruction::JALR {
                    rd: reg::X1,
                    rs1: reg::X1,
                    offset: -52
                },
                size: 4,
                raw_word: 0xfcc080e7
            }
        );
        assert_eq!(
            insts[&0x11110],
            DecodedInstruction {
                inst: Instruction::JAL {
                    rd: reg::X0,
                    offset: 0
                },
                size: 2,
                raw_word: 0xa001
            }
        );

        // link to the configuration crate
        assert_eq!(
            insts[&0x11112],
            DecodedInstruction {
                inst: Instruction::LUI {
                    rd: reg::X11,
                    imm: 0xff000
                },
                size: 4,
                raw_word: 0xff0005b7
            }
        );
        assert_eq!(
            insts[&0x11116],
            DecodedInstruction {
                inst: Instruction::SW {
                    rs1: reg::X11,
                    rs2: reg::X10,
                    offset: 0
                },
                size: 2,
                raw_word: 0xc188
            }
        );
        assert_eq!(
            insts[&0x11118],
            DecodedInstruction {
                inst: Instruction::JALR {
                    rd: reg::X0,
                    rs1: reg::X1,
                    offset: 0
                },
                size: 2,
                raw_word: 0x8082
            }
        );
    }

    #[test]
    fn run() {
        let vm = VM::<Uninitialized>::new();

        let program = PathBuf::from("samples/fibonacci");
        let mut vm = match vm.load_elf(program) {
            Ok(vm) => vm,
            Err(e) => panic!("failed to loaed samples/fibonacci elf, {}", e),
        };

        vm.run(|_| {});

        let result_addr = RESULT_ADDRESS as usize;
        let expected_value = 0x34164a7b;
        assert!(vm.memory.contains_key(&result_addr));
        assert_eq!(vm.memory[&result_addr], expected_value);
    }
}
