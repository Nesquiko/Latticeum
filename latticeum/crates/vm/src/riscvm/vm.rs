use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    path::PathBuf,
};

use configuration::{N_REGS, RESULT_ADDRESS, STACK_TOP};
use thiserror::Error;

use crate::riscvm::{
    elf::{Code, Elf, ElfLoadingError},
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

pub const WORD_SIZE: usize = size_of::<u32>();

pub type Memory<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize> =
    Box<[[u32; WORDS_PER_PAGE]; PAGE_COUNT]>;

pub type Registers = [u32; N_REGS];

#[derive(Debug, Clone, Copy)]
pub struct HeapState {
    pub start: usize,
    pub end: usize,
    pub next: usize,
}

impl HeapState {
    pub fn new(start: usize, end: usize) -> Self {
        assert!(start <= end, "heap start must not exceed heap end");
        Self {
            start,
            end,
            next: start,
        }
    }

    pub fn alloc_aligned(&mut self, size: usize, align: usize) -> Option<usize> {
        if align == 0 || !align.is_power_of_two() {
            return None;
        }

        let aligned = self.next.checked_add(align - 1)? & !(align - 1);
        let new_next = aligned.checked_add(size)?;
        if new_next > self.end {
            return None;
        }

        self.next = new_next;
        Some(aligned)
    }
}

#[derive(Debug)]
/// WORDS_PER_PAGE is the number words in one page
/// PAGE_COUNT is the number of such pages
pub struct VM<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize, Program: VmProgram> {
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
    pub regs: Registers,

    /// The program counter of width 32 bits.
    pub pc: usize,

    /// The main memory of the VM.
    pub memory: Memory<WORDS_PER_PAGE, PAGE_COUNT>,

    /// Monotonic heap allocator state used by guest allocation syscalls.
    pub heap: HeapState,

    /// Reservation for LR/SC emulation.
    pub reserved_word_addr: Option<usize>,

    program: Program,
}

pub(crate) const WORDS_PER_PAGE_256: usize = 256;
pub(crate) const PAGE_COUNT_1024: usize = 1024;
pub(crate) const PAGE_COUNT_4096: usize = 4096;
pub(crate) const PAGE_COUNT_8192: usize = 8192;
pub(crate) const HEAP_START_1MB: usize = 0x0002_0000;
pub(crate) const HEAP_END_1MB: usize = 0x000f_0000;
pub(crate) const STACK_GUARD_BYTES: usize = 0x0000_8000;

pub fn new_vm_1mb() -> VM<WORDS_PER_PAGE_256, PAGE_COUNT_1024, Uninitialized> {
    VM::<_, _, _>::new()
}

pub fn new_vm_4mb() -> VM<WORDS_PER_PAGE_256, PAGE_COUNT_4096, Uninitialized> {
    VM::<_, _, _>::new()
}

pub fn new_vm_8mb() -> VM<WORDS_PER_PAGE_256, PAGE_COUNT_8192, Uninitialized> {
    VM::<_, _, _>::new()
}

pub fn dummy_loaded_vm_1mb() -> VM<WORDS_PER_PAGE_256, PAGE_COUNT_1024, Loaded> {
    VM {
        regs: [0; 32],
        pc: 0,
        memory: unsafe {
            Box::<[[u32; WORDS_PER_PAGE_256]; PAGE_COUNT_1024]>::new_zeroed().assume_init()
        },
        heap: HeapState::new(HEAP_START_1MB, HEAP_END_1MB),
        reserved_word_addr: None,
        program: Loaded {
            elf: Elf {
                image: HashMap::new(),
                entry_point: 0x0,
                raw_code: Code {
                    start: 0x0,
                    size: 0x0,
                    bytes: Box::new([]),
                },
            },
            instructions: HashMap::new(),
        },
    }
}

impl<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize, Program: VmProgram>
    VM<WORDS_PER_PAGE, PAGE_COUNT, Program>
{
    pub fn read_reg(&self, i: u32) -> u32 {
        self.regs[i as usize]
    }

    pub fn write_reg(&mut self, i: u32, data: u32) {
        self.regs[i as usize] = data
    }

    pub fn read_mem(&self, addr: usize) -> u32 {
        let (page_index, word_index) = physical_addr::<WORD_SIZE, WORDS_PER_PAGE, PAGE_COUNT>(addr);
        self.memory[page_index][word_index]
    }

    pub fn write_mem(&mut self, addr: usize, data: u32) {
        let (page_index, word_index) = physical_addr::<WORD_SIZE, WORDS_PER_PAGE, PAGE_COUNT>(addr);
        self.memory[page_index][word_index] = data;
    }
}

impl<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize>
    VM<WORDS_PER_PAGE, PAGE_COUNT, Uninitialized>
{
    pub fn new() -> Self {
        VM {
            regs: [0; 32],
            pc: 0,
            memory: unsafe {
                Box::<[[u32; WORDS_PER_PAGE]; PAGE_COUNT]>::new_zeroed().assume_init()
            },
            heap: HeapState::new(HEAP_START_1MB, HEAP_END_1MB),
            reserved_word_addr: None,
            program: Uninitialized {},
        }
    }

    pub fn load_elf(
        mut self,
        path: PathBuf,
    ) -> Result<VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>, ElfLoadingError> {
        let elf = Elf::load(path)?;

        for (addr, word) in &elf.image {
            self.write_mem(*addr, *word);
        }

        let image_end = elf
            .image
            .keys()
            .copied()
            .max()
            .map(|addr| addr + WORD_SIZE)
            .unwrap_or(0);
        let heap_start = (image_end + 0xf) & !0xf;
        let max_mem = WORD_SIZE * WORDS_PER_PAGE * PAGE_COUNT;
        let heap_end = if (STACK_TOP as usize) <= max_mem {
            (STACK_TOP as usize).saturating_sub(STACK_GUARD_BYTES)
        } else {
            max_mem
        };
        self.heap = HeapState::new(heap_start.min(heap_end), heap_end);

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
            heap: self.heap,
            reserved_word_addr: self.reserved_word_addr,
            program: Loaded { elf, instructions },
        };
        Ok(initialized)
    }
}

pub struct InterceptArgs<'a, const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize> {
    pub trace: ExecutionTrace,
    pub vm_memory: &'a Memory<WORDS_PER_PAGE, PAGE_COUNT>,
    pub vm_regs: &'a Registers,
    pub vm_raw_code: &'a Box<[u8]>,
}

impl<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize> VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded> {
    /// Runs the VM's execution loop
    pub fn run(
        &mut self,
        mut intercept: impl FnMut(InterceptArgs<WORDS_PER_PAGE, PAGE_COUNT>) -> (),
    ) {
        let mut cycle: usize = 0;
        loop {
            match self.fetch_execute(cycle) {
                Ok((ExecutionState::Continue, trace)) => intercept(InterceptArgs {
                    trace,
                    vm_memory: &self.memory,
                    vm_regs: &self.regs,
                    vm_raw_code: &self.elf().raw_code.bytes,
                }),
                Ok((ExecutionState::Halt, trace)) => {
                    tracing::info!("execution halted");
                    intercept(InterceptArgs {
                        trace,
                        vm_memory: &self.memory,
                        vm_regs: &self.regs,
                        vm_raw_code: &self.elf().raw_code.bytes,
                    });
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
        self.read_mem(result_addr)
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
                    "HALTING execution, PC {:#0x} is not a valid instruction address",
                    self.pc
                );
                return Err(ExecutionError::InvalidPC(self.pc));
            }
        };

        let trace = self.execute_step(&inst, cycle);

        // halt when program enters an infinite loop by jumping to itself
        if trace.input.pc == trace.output.pc {
            tracing::trace!("halting on instruction {} at {:#0x}", inst, trace.input.pc);
            return Ok((ExecutionState::Halt, trace));
        }

        Ok((ExecutionState::Continue, trace))
    }

    pub fn elf(&self) -> &Elf {
        &self.program.elf
    }
}

enum ExecutionState {
    Continue,
    Halt,
}

#[derive(Error, Debug)]
enum ExecutionError {
    #[error("invalid instruction address in PC {0:#0x}")]
    InvalidPC(usize),
}

impl<const WORDS_PER_PAGE: usize, const PAGE_COUNT: usize> Display
    for VM<WORDS_PER_PAGE, PAGE_COUNT, Loaded>
{
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

        for i in (0..N_REGS).step_by(4) {
            write!(f, "  ")?;
            for j in 0..4 {
                if i + j < 32 {
                    let reg_idx = i + j;
                    write!(
                        f,
                        "x{:2}({:>5}): {:#08x}  ",
                        reg_idx, abi_names[reg_idx], self.regs[reg_idx]
                    )?;
                }
            }
            writeln!(f)?;
        }

        writeln!(f, "\nMemory:")?;
        writeln!(
            f,
            "  Size {:#0x} bytes",
            WORD_SIZE * WORDS_PER_PAGE * PAGE_COUNT
        )?;

        writeln!(f, "\nProgram Counter:")?;
        writeln!(f, "  pc: {:#08x}", self.pc)?;

        let program = &self.program.elf;
        writeln!(f, "\nProgram Information:")?;
        writeln!(f, "  Entry point: {:#0x}", program.entry_point)?;
        writeln!(f, "  Image size: {:#0x} words", program.image.len())?;
        writeln!(f, "  Raw code start: {:#0x}", program.raw_code.start)?;
        writeln!(
            f,
            "  Raw code size: {:#0x} bytes",
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
                writeln!(f, "  {:#08x}: {}", addr, inst.inst)?;
            }
        }

        Ok(())
    }
}

pub fn physical_addr<
    const WORD_SIZE: usize,
    const WORDS_PER_PAGE: usize,
    const PAGE_COUNT: usize,
>(
    virt_addr: usize,
) -> (usize, usize) {
    // bits in the virtual address, not how many bits does the thing have
    let word_bits: usize = WORD_SIZE.trailing_zeros() as usize;
    let word_in_page_bits: usize = WORDS_PER_PAGE.trailing_zeros() as usize;

    let max_addr = WORDS_PER_PAGE * PAGE_COUNT * WORD_SIZE;
    assert!(
        virt_addr < max_addr,
        "Memory access out of bounds, virtual address {:#0x}, max address {:#0x}",
        virt_addr,
        max_addr
    );
    assert!(
        virt_addr % WORD_SIZE == 0,
        "Unaligned memory access, virtual address {}",
        virt_addr
    );

    // upper bits of the address determine the page
    let page_index = virt_addr >> (word_in_page_bits + word_bits);
    // middle bits of the address determine the word's index within the page
    let word_index = (virt_addr >> word_bits) & (WORDS_PER_PAGE - 1);

    (page_index, word_index)
}

#[cfg(test)]
mod tests {
    use crate::riscvm::{
        inst_decoder::DecodedInstruction,
        reg,
        vm::{
            dummy_loaded_vm_1mb, new_vm_1mb, new_vm_8mb, physical_addr, HEAP_START_1MB,
            PAGE_COUNT_1024, WORDS_PER_PAGE_256, WORD_SIZE,
        },
    };
    use configuration::{RESULT_ADDRESS, STACK_TOP};
    use riscv_isa::Instruction;
    use std::path::PathBuf;
    use test_log::test;

    fn run_inst(
        vm: &mut crate::riscvm::vm::VM<
            WORDS_PER_PAGE_256,
            PAGE_COUNT_1024,
            crate::riscvm::vm::Loaded,
        >,
        inst: Instruction,
        size: usize,
    ) -> crate::riscvm::inst::ExecutionTrace {
        vm.execute_step(
            &DecodedInstruction {
                raw_word: 0,
                inst,
                size,
            },
            0,
        )
    }

    #[test]
    fn physical_addr_32bit_vm() {
        assert_eq!(WORD_SIZE, 4);

        //              __ppppwwwwwwwwii
        let virt_addr = 0b00011000000100;
        // WORD_SIZE shifts by 2 bits, PAGE_SIZE_1024 by 8 bits
        let (page_index, word_index) =
            physical_addr::<WORD_SIZE, WORDS_PER_PAGE_256, PAGE_COUNT_1024>(virt_addr);
        assert_eq!(0b1, page_index);
        assert_eq!(0b10000001, word_index);
    }

    #[test]
    fn fibonacci_instructions() {
        let vm = new_vm_1mb();

        let program = PathBuf::from("samples/fibonacci_100_000");
        let vm = match vm.load_elf(program) {
            Ok(vm) => vm,
            Err(e) => panic!("failed to load samples/fibonacci elf, {}", e),
        };

        let insts = vm.program.instructions;

        assert_eq!(23, insts.len());
        assert_eq!(0x110f0, vm.program.elf.entry_point);

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
                    imm: 0x100
                },
                size: 4,
                raw_word: 0x00100137
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
                inst: Instruction::SW {
                    rs1: reg::X0,
                    rs2: reg::X10,
                    offset: 0
                },
                size: 4,
                raw_word: 0x00a02023
            }
        );
        assert_eq!(
            insts[&0x11116],
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
    fn fibonacci_100000th_element() {
        let vm = new_vm_1mb();

        let program = PathBuf::from("samples/fibonacci_100_000");
        let mut vm = match vm.load_elf(program) {
            Ok(vm) => vm,
            Err(e) => panic!("failed to load samples/fibonacci elf, {}", e),
        };

        vm.run(|_| {});

        let result_addr = RESULT_ADDRESS as usize;
        let expected_value = 0x34164a7b;
        assert_eq!(vm.read_mem(result_addr), expected_value);
    }

    #[test]
    fn mulhu_matches_riscv_semantics() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 0xffff_fffe);
        vm.write_reg(6, 0x8000_0003);

        vm.inst_mulhu(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });

        assert_eq!(
            vm.read_reg(7),
            (((0xffff_fffe_u64) * (0x8000_0003_u64)) >> 32) as u32
        );
    }

    #[test]
    fn divu_matches_riscv_semantics() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 17);
        vm.write_reg(6, 5);
        vm.inst_divu(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });
        assert_eq!(vm.read_reg(7), 3);

        vm.write_reg(6, 0);
        vm.inst_divu(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });
        assert_eq!(vm.read_reg(7), u32::MAX);
    }

    #[test]
    fn remu_matches_riscv_semantics() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 17);
        vm.write_reg(6, 5);
        vm.inst_remu(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });
        assert_eq!(vm.read_reg(7), 2);

        vm.write_reg(6, 0);
        vm.inst_remu(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });
        assert_eq!(vm.read_reg(7), 17);
    }

    #[test]
    fn mul_matches_riscv_semantics() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 0xffff_fffe);
        vm.write_reg(6, 0x8000_0003);
        vm.inst_mul(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });
        assert_eq!(vm.read_reg(7), 0xffff_fffe_u32.wrapping_mul(0x8000_0003));
    }

    #[test]
    fn xor_matches_riscv_semantics() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 0xdead_beef);
        vm.write_reg(6, 0x1234_5678);
        vm.inst_xor(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });
        assert_eq!(vm.read_reg(7), 0xdead_beef ^ 0x1234_5678);
    }

    #[test]
    fn or_matches_riscv_semantics() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 0xdead_beef);
        vm.write_reg(6, 0x1234_5678);
        vm.inst_or(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });
        assert_eq!(vm.read_reg(7), 0xdead_beef | 0x1234_5678);
    }

    #[test]
    fn and_matches_riscv_semantics() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 0xdead_beef);
        vm.write_reg(6, 0x1234_5678);
        vm.inst_and(crate::riscvm::inst::RTypeArgs {
            rd: 7,
            rs1: 5,
            rs2: 6,
        });
        assert_eq!(vm.read_reg(7), 0xdead_beef & 0x1234_5678);
    }

    #[test]
    fn control_flow_and_immediates_work() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.pc = 0x100;

        run_inst(
            &mut vm,
            Instruction::LUI {
                rd: 5,
                imm: 0x12345,
            },
            4,
        );
        assert_eq!(vm.read_reg(5), 0x12345 << 12);

        vm.pc = 0x100;
        run_inst(&mut vm, Instruction::AUIPC { rd: 6, imm: 0x2 }, 4);
        assert_eq!(vm.read_reg(6), 0x100 + (0x2 << 12));

        vm.pc = 0x100;
        run_inst(&mut vm, Instruction::JAL { rd: 1, offset: 12 }, 4);
        assert_eq!(vm.read_reg(1), 0x104);
        assert_eq!(vm.pc, 0x10c);

        vm.pc = 0x200;
        vm.write_reg(5, 0x320);
        run_inst(
            &mut vm,
            Instruction::JALR {
                rd: 1,
                rs1: 5,
                offset: 5,
            },
            4,
        );
        assert_eq!(vm.read_reg(1), 0x204);
        assert_eq!(vm.pc, 0x324);

        vm.pc = 0x300;
        vm.write_reg(5, 9);
        vm.write_reg(6, 8);
        run_inst(
            &mut vm,
            Instruction::BNE {
                rs1: 5,
                rs2: 6,
                offset: 8,
            },
            4,
        );
        assert_eq!(vm.pc, 0x308);

        vm.pc = 0x300;
        run_inst(
            &mut vm,
            Instruction::BEQ {
                rs1: 5,
                rs2: 5,
                offset: 8,
            },
            4,
        );
        assert_eq!(vm.pc, 0x308);

        vm.pc = 0x300;
        vm.write_reg(5, 1);
        vm.write_reg(6, 2);
        run_inst(
            &mut vm,
            Instruction::BLTU {
                rs1: 5,
                rs2: 6,
                offset: 8,
            },
            4,
        );
        assert_eq!(vm.pc, 0x308);

        vm.pc = 0x300;
        run_inst(
            &mut vm,
            Instruction::BGEU {
                rs1: 6,
                rs2: 5,
                offset: 8,
            },
            4,
        );
        assert_eq!(vm.pc, 0x308);

        vm.pc = 0x300;
        vm.write_reg(5, (-2_i32) as u32);
        vm.write_reg(6, 1);
        run_inst(
            &mut vm,
            Instruction::BLT {
                rs1: 5,
                rs2: 6,
                offset: 8,
            },
            4,
        );
        assert_eq!(vm.pc, 0x308);

        vm.pc = 0x300;
        vm.write_reg(5, 4);
        vm.write_reg(6, (-1_i32) as u32);
        run_inst(
            &mut vm,
            Instruction::BGE {
                rs1: 5,
                rs2: 6,
                offset: 8,
            },
            4,
        );
        assert_eq!(vm.pc, 0x308);

        vm.pc = 0x400;
        vm.write_reg(5, 10);
        run_inst(
            &mut vm,
            Instruction::ADDI {
                rd: 7,
                rs1: 5,
                imm: -3,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 7);
        run_inst(
            &mut vm,
            Instruction::SLTI {
                rd: 7,
                rs1: 5,
                imm: 20,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 1);
        run_inst(
            &mut vm,
            Instruction::SLTIU {
                rd: 7,
                rs1: 5,
                imm: 9,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0);
        run_inst(
            &mut vm,
            Instruction::XORI {
                rd: 7,
                rs1: 5,
                imm: 0xff,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 10 ^ 0xff);
        run_inst(
            &mut vm,
            Instruction::ANDI {
                rd: 7,
                rs1: 5,
                imm: 0x6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 10 & 0x6);
        run_inst(
            &mut vm,
            Instruction::ORI {
                rd: 7,
                rs1: 5,
                imm: 0x6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 10 | 0x6);
        run_inst(
            &mut vm,
            Instruction::SLLI {
                rd: 7,
                rs1: 5,
                shamt: 3,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 80);
        run_inst(
            &mut vm,
            Instruction::SRLI {
                rd: 7,
                rs1: 7,
                shamt: 2,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 20);
        vm.write_reg(5, (-16_i32) as u32);
        run_inst(
            &mut vm,
            Instruction::SRAI {
                rd: 7,
                rs1: 5,
                shamt: 2,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), (-4_i32) as u32);
    }

    #[test]
    fn loads_and_stores_work() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 0x100);
        vm.write_reg(6, 0xaabb_ccdd);

        run_inst(
            &mut vm,
            Instruction::SW {
                rs1: 5,
                rs2: 6,
                offset: 0,
            },
            4,
        );
        assert_eq!(vm.read_mem(0x100), 0xaabb_ccdd);
        run_inst(
            &mut vm,
            Instruction::LW {
                rd: 7,
                rs1: 5,
                offset: 0,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xaabb_ccdd);

        vm.write_reg(6, 0x1122_3344);
        run_inst(
            &mut vm,
            Instruction::SB {
                rs1: 5,
                rs2: 6,
                offset: 1,
            },
            4,
        );
        assert_eq!(vm.read_mem(0x100), 0xaabb_44dd);
        run_inst(
            &mut vm,
            Instruction::LBU {
                rd: 7,
                rs1: 5,
                offset: 1,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0x44);

        vm.write_reg(6, 0x0000_eeff);
        run_inst(
            &mut vm,
            Instruction::SH {
                rs1: 5,
                rs2: 6,
                offset: 2,
            },
            4,
        );
        assert_eq!(vm.read_mem(0x100), 0xeeff_44dd);
        run_inst(
            &mut vm,
            Instruction::LHU {
                rd: 7,
                rs1: 5,
                offset: 2,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xeeff);

        vm.write_mem(0x104, 0x80ff_7f01);
        run_inst(
            &mut vm,
            Instruction::LB {
                rd: 7,
                rs1: 5,
                offset: 4,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 1);
        run_inst(
            &mut vm,
            Instruction::LB {
                rd: 7,
                rs1: 5,
                offset: 5,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0x7f);
        run_inst(
            &mut vm,
            Instruction::LB {
                rd: 7,
                rs1: 5,
                offset: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), (-1_i32) as u32);
        run_inst(
            &mut vm,
            Instruction::LH {
                rd: 7,
                rs1: 5,
                offset: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), (-32513_i32) as u32);
    }

    #[test]
    fn register_arithmetic_and_system_ops_work() {
        let mut vm = dummy_loaded_vm_1mb();
        vm.write_reg(5, 0xdead_beef);
        vm.write_reg(6, 0x1234_5678);

        run_inst(
            &mut vm,
            Instruction::ADD {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xdead_beef_u32.wrapping_add(0x1234_5678));
        run_inst(
            &mut vm,
            Instruction::SUB {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xdead_beef_u32.wrapping_sub(0x1234_5678));
        run_inst(
            &mut vm,
            Instruction::SLL {
                rd: 7,
                rs1: 6,
                rs2: 5,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0x1234_5678 << (0xdead_beef_u32 & 0x1f));
        run_inst(
            &mut vm,
            Instruction::SLT {
                rd: 7,
                rs1: 6,
                rs2: 5,
            },
            4,
        );
        assert_eq!(
            vm.read_reg(7),
            ((0x1234_5678_i32) < (-559038737_i32)) as u32
        );
        run_inst(
            &mut vm,
            Instruction::SLTU {
                rd: 7,
                rs1: 6,
                rs2: 5,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), (0x1234_5678_u32 < 0xdead_beef_u32) as u32);
        run_inst(
            &mut vm,
            Instruction::XOR {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xdead_beef ^ 0x1234_5678);
        run_inst(
            &mut vm,
            Instruction::SRL {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xdead_beef >> (0x1234_5678 & 0x1f));
        run_inst(
            &mut vm,
            Instruction::SRA {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(
            vm.read_reg(7),
            ((0xdead_beef_u32 as i32) >> (0x1234_5678 & 0x1f)) as u32
        );
        run_inst(
            &mut vm,
            Instruction::OR {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xdead_beef | 0x1234_5678);
        run_inst(
            &mut vm,
            Instruction::AND {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xdead_beef & 0x1234_5678);
        run_inst(
            &mut vm,
            Instruction::MUL {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0xdead_beef_u32.wrapping_mul(0x1234_5678));
        run_inst(
            &mut vm,
            Instruction::MULHU {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(
            vm.read_reg(7),
            (((0xdead_beef_u64) * (0x1234_5678_u64)) >> 32) as u32
        );

        vm.write_reg(5, 17);
        vm.write_reg(6, 5);
        run_inst(
            &mut vm,
            Instruction::DIVU {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 3);
        run_inst(
            &mut vm,
            Instruction::REMU {
                rd: 7,
                rs1: 5,
                rs2: 6,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 2);

        vm.pc = 0x500;
        run_inst(
            &mut vm,
            Instruction::FENCE {
                pred: 0b10_u8.into(),
                succ: 0b11_u8.into(),
            },
            4,
        );
        assert_eq!(vm.pc, 0x504);

        vm.write_reg(5, 0x100);
        vm.write_mem(0x100, 41);
        run_inst(
            &mut vm,
            Instruction::LR_W {
                rd: 7,
                rs1: 5,
                aq: 1,
                rl: 0,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 41);
        vm.write_reg(6, 99);
        run_inst(
            &mut vm,
            Instruction::SC_W {
                rd: 7,
                rs1: 5,
                rs2: 6,
                aq: 0,
                rl: 1,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 0);
        assert_eq!(vm.read_mem(0x100), 99);

        vm.write_mem(0x100, 10);
        vm.write_reg(6, 5);
        run_inst(
            &mut vm,
            Instruction::AMOADD_W {
                rd: 7,
                rs1: 5,
                rs2: 6,
                aq: 0,
                rl: 0,
            },
            4,
        );
        assert_eq!(vm.read_reg(7), 10);
        assert_eq!(vm.read_mem(0x100), 15);

        vm.write_reg(10, 32);
        vm.write_reg(11, 8);
        vm.write_reg(17, 1);
        let before = vm.heap.next;
        run_inst(&mut vm, Instruction::ECALL, 4);
        assert_eq!(vm.read_reg(10) as usize, before);
        assert_eq!(vm.heap.next, before + 32);
    }

    #[test]
    fn evm_guest_runs() {
        let vm = new_vm_8mb();

        let program = PathBuf::from("../../target/riscv32imac-unknown-none-elf/release/evm");
        let mut vm = match vm.load_elf(program) {
            Ok(vm) => vm,
            Err(e) => panic!("failed to load evm elf, {}", e),
        };

        vm.run(|_| {});

        assert_eq!(vm.read_mem(RESULT_ADDRESS as usize), 56);
    }

    #[test]
    fn evm_elf_data_segments_are_loaded_into_memory() {
        let vm = new_vm_8mb();
        let elf = crate::riscvm::elf::Elf::load(PathBuf::from(
            "../../target/riscv32imac-unknown-none-elf/release/evm",
        ))
        .unwrap();

        let program = PathBuf::from("../../target/riscv32imac-unknown-none-elf/release/evm");
        let vm = match vm.load_elf(program) {
            Ok(vm) => vm,
            Err(e) => panic!("failed to load evm elf, {}", e),
        };

        let (&addr, &word) = elf
            .image
            .iter()
            .find(|(addr, _)| **addr < elf.raw_code.start)
            .expect("expected rodata word below text segment");
        assert_eq!(vm.read_mem(addr), word);
    }

    #[test]
    fn evm_elf_fits_below_static_stack_top() {
        let elf = crate::riscvm::elf::Elf::load(PathBuf::from(
            "../../target/riscv32imac-unknown-none-elf/release/evm",
        ))
        .unwrap();

        let max_loaded_addr = elf.image.keys().copied().max().unwrap() + 4;

        assert!(max_loaded_addr > HEAP_START_1MB);
        assert!(max_loaded_addr < STACK_TOP as usize);
    }
}
