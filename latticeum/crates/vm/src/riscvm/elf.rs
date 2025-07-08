use elf::{ElfBytes, endian::LittleEndian, file::Class};
use std::{collections::HashMap, path::PathBuf, usize};
use thiserror::Error;

use crate::riscvm::consts::{MAX_MEM, WORD_SIZE};

#[derive(Debug)]
pub struct Elf {
    pub image: HashMap<usize, u32>,
    pub entry_point: usize,
    pub raw_code: Code,
}

#[derive(Debug)]
pub struct Code {
    pub start: usize,
    pub size: usize,
    pub bytes: Box<[u8]>,
}

#[derive(Error, Debug)]
pub enum ElfLoadingError {
    #[error("failed to open elf file")]
    FileOpen(#[from] std::io::Error),
    #[error("failed to parse elf file")]
    ElfParse(#[from] elf::ParseError),
    #[error("elf file falidation failed, {0}")]
    ElfValidation(String),
    #[error("elf segment is invalid: {0}")]
    InvalidSegment(String),
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

        let mut raw_code_start = 0;
        let mut raw_code_size = 0;
        let mut raw_code = vec![];

        let mut image = HashMap::<usize, u32>::new(); // address to word
        let pt_load_segments = segments.iter().filter(|s| s.p_type == elf::abi::PT_LOAD);
        let mut pt_load_segments_count = 0;

        for segment in pt_load_segments.into_iter() {
            pt_load_segments_count += 1;

            let vaddr = segment.p_vaddr as usize;
            let offset = segment.p_offset as usize;
            let file_size = segment.p_filesz as usize;
            let mem_size = segment.p_memsz as usize;
            let is_text = (segment.p_flags & elf::abi::PF_X) != 0;

            tracing::trace!(
                "parsing segment at vaddr 0x{:x}, offset 0x{:x}, file_size 0x{:x}, mem_size 0x{:x}, is .text = {}",
                vaddr,
                offset,
                file_size,
                mem_size,
                is_text
            );

            if file_size > mem_size {
                return Err(ElfLoadingError::InvalidSegment(format!(
                    "segment at vaddr 0x{:x} has file_size > mem_size",
                    vaddr
                )));
            }
            if offset + file_size > file_data.len() {
                return Err(ElfLoadingError::InvalidSegment(format!(
                    "segment at vaddr 0x{:x} reads past end of file",
                    vaddr
                )));
            }

            if is_text {
                raw_code_start = vaddr;
                raw_code_size = file_size;
                raw_code.reserve(mem_size);
            }

            let segment_file_data = &file_data[offset..offset + file_size];
            let mut current_addr = vaddr;
            let mut bytes_processed = 0;

            while bytes_processed + WORD_SIZE <= segment_file_data.len() {
                let chunk = &segment_file_data[bytes_processed..bytes_processed + WORD_SIZE];
                let word_bytes: [u8; WORD_SIZE] =
                    chunk.try_into().expect("slice with incorrect length");
                let word = u32::from_le_bytes(word_bytes);
                tracing::trace!("0x{:x} - 0x{:08x}", current_addr, word);

                image.insert(current_addr, word);
                if is_text {
                    raw_code.extend_from_slice(&word_bytes);
                }

                current_addr += WORD_SIZE;
                bytes_processed += WORD_SIZE;
            }

            let remainder = &segment_file_data[bytes_processed..];
            if !remainder.is_empty() {
                tracing::trace!("=== remainder ===");
                let mut temp_word_bytes = [0u8; WORD_SIZE];
                temp_word_bytes[..remainder.len()].copy_from_slice(remainder);
                let word = u32::from_le_bytes(temp_word_bytes);

                tracing::trace!("0x{:x} - 0x{:08x}", current_addr, word);

                image.insert(current_addr, word);
                if is_text {
                    raw_code.extend_from_slice(&temp_word_bytes);
                }
            }

            let zero_fill_start = vaddr + file_size;
            let zero_fill_end = vaddr + mem_size;

            if zero_fill_start != zero_fill_end {
                tracing::trace!(
                    "zero filling from 0x{:x} to 0x{:x}",
                    zero_fill_start,
                    zero_fill_end
                );
                let next_word_aligned_addr = (zero_fill_start + WORD_SIZE - 1) & !(WORD_SIZE - 1);
                for addr in (next_word_aligned_addr..zero_fill_end).step_by(WORD_SIZE) {
                    image.entry(addr).or_insert(0);
                    if is_text {
                        raw_code.extend_from_slice(&[0, 0, 0, 0]);
                    }
                }
            }
        }

        tracing::trace!(
            "parsed {} pt_load segment, image size 0x{:x} words, raw code size 0x{:x} bytes",
            pt_load_segments_count,
            image.len(),
            raw_code.len()
        );

        assert!(raw_code_start != 0, "raw_code_start didn't change");
        assert!(raw_code_size != 0, "raw_code_size didn't change");

        Ok(Elf {
            image,
            entry_point,
            raw_code: Code {
                start: raw_code_start,
                size: raw_code_size,
                bytes: raw_code.into_boxed_slice(),
            },
        })
    }
}
