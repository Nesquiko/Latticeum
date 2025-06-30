use elf::{ElfBytes, endian::LittleEndian, file::Class};
use std::{collections::HashMap, path::PathBuf, usize};
use thiserror::Error;

use crate::riscvm::consts::{HALF_WORD_SIZE, MAX_MEM, is_compressed};

pub struct Elf {
    pub instructions: Vec<u32>,
    pub image: HashMap<usize, u32>,
}

#[derive(Error, Debug)]
pub enum ElfLoadingError {
    #[error("failed to open elf file")]
    FileOpen(#[from] std::io::Error),
    #[error("failed to parse elf file")]
    ElfParse(#[from] elf::ParseError),
    #[error("elf file falidation failed, {0}")]
    ElfValidation(String),
    #[error("failed to number to u32")]
    EntryConvert(#[from] std::num::TryFromIntError),
}

impl Elf {
    pub fn load(path: PathBuf) -> Result<Elf, ElfLoadingError> {
        tracing::trace!("loading program at {:?}", path);

        let file_data = std::fs::read(path)?;
        let slice = file_data.as_slice();
        let elf_file = ElfBytes::<LittleEndian>::minimal_parse(slice)?;

        if elf_file.ehdr.class != Class::ELF32 {
            return Err(ElfLoadingError::ElfValidation(
                "elf file has wrong class, expected 32bit".to_owned(),
            ));
        } else if elf_file.ehdr.e_machine != elf::abi::EM_RISCV {
            return Err(ElfLoadingError::ElfValidation(
                "elf file has wrong machine type, expected RISC-V".to_owned(),
            ));
        }

        let entry_point: u32 = elf_file.ehdr.e_entry.try_into()?;
        tracing::trace!("entry_point is 0x{:x}", entry_point);

        if (entry_point as usize) % HALF_WORD_SIZE != 0 {
            return Err(ElfLoadingError::ElfValidation(
                "entry_point is not divisible by word size".to_owned(),
            ));
        } else if entry_point == MAX_MEM {
            return Err(ElfLoadingError::ElfValidation(
                "entry_point is set as max memory size".to_owned(),
            ));
        }

        let segments = match elf_file.segments() {
            Some(segs) => segs,
            None => {
                return Err(ElfLoadingError::ElfValidation(
                    "no segments in elf file".to_owned(),
                ));
            }
        };

        let mut instructions = vec![];
        let mut image = HashMap::<usize, u32>::new(); // address to word
        let pt_load_segments = segments.iter().filter(|s| s.p_type == elf::abi::PT_LOAD);
        for segment in pt_load_segments.into_iter() {
            let vaddr = segment.p_vaddr as usize;
            let offset = segment.p_offset as usize;
            let is_text = segment.p_flags & elf::abi::PF_X != 0;

            let mut first_inst_half: Option<u16> = None;
            for i in (0..segment.p_memsz as usize).step_by(HALF_WORD_SIZE) {
                let mut addr = vaddr + i;

                let b0 = file_data[offset + i];
                let b1 = file_data[offset + i + 1];
                let half_word = u16::from_le_bytes([b0, b1]);
                let instruction: u32;

                if let Some(half) = first_inst_half {
                    // the previous read was half of a 32bit instruction, join them
                    // and create one full 32 bit one

                    instruction = (half_word as u32) << 16 | half as u32;
                    first_inst_half = None;
                    // the whole 32 bit instruction begain
                    // HALF_WORD_SIZE previous
                    addr = addr - HALF_WORD_SIZE;
                } else if is_compressed(half_word) {
                    // process compressed instruction
                    // TODO decompress it https://hackmd.io/@kaeteyaruyo/risc-v-rvc#Instruction-Decompression, then map opcodes and print them
                    instruction = half_word as u32;
                } else {
                    // first half of a 32 bit instruction
                    first_inst_half = Some(half_word);
                    continue;
                }

                image.insert(addr, instruction);
                if is_text {
                    instructions.push(instruction);
                }
            }
        }

        Ok(Elf {
            instructions: instructions,
            image: image,
        })
    }
}
