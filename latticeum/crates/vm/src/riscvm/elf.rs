use elf::{ElfBytes, endian::LittleEndian, file::Class};
use std::{collections::HashMap, path::PathBuf, usize};
use thiserror::Error;

use crate::riscvm::consts::{MAX_MEM, WORD_SIZE};

#[derive(Debug)]
pub struct Elf {
    pub image: HashMap<usize, u32>,
    pub entry_point: usize,
    pub raw_code: Box<[u8]>,
}

#[derive(Error, Debug)]
pub enum ElfLoadingError {
    #[error("failed to open elf file")]
    FileOpen(#[from] std::io::Error),
    #[error("failed to parse elf file")]
    ElfParse(#[from] elf::ParseError),
    #[error("elf file falidation failed, {0}")]
    ElfValidation(String),
}

impl Elf {
    pub fn load(path: PathBuf) -> Result<Elf, ElfLoadingError> {
        tracing::trace!("loading elf program at {:?}", path);

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

        let entry_point = elf_file.ehdr.e_entry as usize;
        tracing::trace!("entry_point is 0x{:x}", entry_point);

        if (entry_point as usize) % WORD_SIZE != 0 {
            return Err(ElfLoadingError::ElfValidation(
                "entry_point is not divisible by word size".to_owned(),
            ));
        } else if entry_point == MAX_MEM as usize {
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

        let mut raw_code = vec![];
        let mut image = HashMap::<usize, u32>::new(); // address to word
        let pt_load_segments = segments.iter().filter(|s| s.p_type == elf::abi::PT_LOAD);
        let mut pt_load_segments_count = 0;

        for segment in pt_load_segments.into_iter() {
            pt_load_segments_count += 1;
            let vaddr = segment.p_vaddr as usize;
            let offset = segment.p_offset as usize;
            let is_text = segment.p_flags & elf::abi::PF_X != 0;
            tracing::trace!(
                "parsing segment at vaddr 0x{:x}, offset 0x{:x}, is .text = {}",
                vaddr,
                offset,
                is_text
            );

            for i in (0..segment.p_memsz as usize).step_by(WORD_SIZE) {
                let b0 = file_data[offset + i];
                let b1 = file_data[offset + i + 1];
                let b2 = file_data[offset + i + 2];
                let b3 = file_data[offset + i + 3];
                let bytes = [b0, b1, b2, b3];
                let word = u32::from_le_bytes(bytes);

                let addr = vaddr + i;
                image.insert(addr, word);
                if is_text {
                    raw_code.extend_from_slice(&bytes);
                }
            }
        }

        tracing::trace!(
            "parsed {} pt_load segment, image size {} words, raw code size {} bytes",
            pt_load_segments_count,
            image.len(),
            raw_code.len()
        );

        Ok(Elf {
            image,
            entry_point,
            raw_code: raw_code.into_boxed_slice(),
        })
    }
}
