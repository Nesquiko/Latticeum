use std::{fmt::Debug, path::PathBuf};

use crate::riscvm::{
    consts::MAX_MEM,
    elf::{Elf, ElfLoadingError},
};

#[derive(Debug, Clone)]
pub struct VM {
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

    /// The program counter of width T.
    pc: u32,

    /// The main memory of the VM. Memory is always byte-addressable.
    memory: Vec<u8>,
}

impl VM {
    pub fn new(memory_size: usize) -> VM {
        if memory_size > MAX_MEM as usize {
            panic!(
                "memory_size ({}) can't be bigger than the max value of associated type ({})",
                memory_size, MAX_MEM
            )
        }

        VM {
            regs: [0; 32],
            pc: 0,
            memory: vec![0; memory_size],
        }
    }

    pub fn load_elf(&mut self, path: PathBuf) -> Result<(), ElfLoadingError> {
        let elf = Elf::load(path)?;

        let mut image: Vec<(&usize, &u32)> = elf.image.iter().filter(|x| *x.0 >= 0x110d4).collect();
        image.sort_by(|x1, x2| x1.0.cmp(x2.0));

        // for ins in image.iter() {
        //     tracing::info!("0x{:x} - {:032b}", ins.0, ins.1);
        // }
        for ins in image.iter() {
            tracing::info!(
                "0x{:x} - {:025b} {:07b}",
                ins.0,
                ins.1 >> 7,
                ins.1 & 0b1111111
            );
        }

        Ok(())
    }
}
