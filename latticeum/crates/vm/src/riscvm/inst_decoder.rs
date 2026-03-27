use std::fmt::Display;

pub use riscv_isa::Instruction;
use riscv_isa::Target;

const RV32IMAC: &str = "RV32IMAC";

pub struct Decoder<'a> {
    /// RISC-V ISA target in format RVXX..., where XX is machine size and ... are extensions, see RV32IMAC
    target: Target,
    /// word aligned array of bytes
    bytes: &'a [u8],
    /// Indicates valid size of the instruction bytes, used to handle when last
    /// instruction is compressed, so the other half of word contains zeroes.
    valid_size: usize,
}

/// A struct containing a raw word, decoded RISC-V instruction and its length in bytes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DecodedInstruction {
    pub raw_word: u32,
    pub inst: Instruction,
    pub size: usize,
}

impl Display for DecodedInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}, size {}", self.inst, self.size)
    }
}

impl<'a> Decoder<'a> {
    pub fn from_le_bytes(bytes: &'a [u8], valid_size: usize) -> Decoder<'a> {
        let target = riscv_isa::Target::from_str_strict(RV32IMAC).expect("invalid target");
        Decoder {
            target,
            bytes,
            valid_size,
        }
    }

    fn decode_known_compressed_fallback(raw: u16) -> Option<Instruction> {
        let quadrant = raw & 0b11;
        let funct3 = (raw >> 13) & 0b111;

        if quadrant != 0b01 || funct3 != 0b100 {
            return None;
        }

        let bit12 = (raw >> 12) & 0b1;
        let bits11_10 = (raw >> 10) & 0b11;
        let bits6_5 = (raw >> 5) & 0b11;
        let rd = (((raw >> 7) & 0b111) as u32) + 8;
        let rs2 = (((raw >> 2) & 0b111) as u32) + 8;

        match (bit12, bits11_10, bits6_5) {
            (0, 0b11, 0b00) => Some(Instruction::SUB { rd, rs1: rd, rs2 }),
            (0, 0b11, 0b01) => Some(Instruction::XOR { rd, rs1: rd, rs2 }),
            (0, 0b11, 0b10) => Some(Instruction::OR { rd, rs1: rd, rs2 }),
            (0, 0b11, 0b11) => Some(Instruction::AND { rd, rs1: rd, rs2 }),
            _ => None,
        }
    }
}

impl Iterator for Decoder<'_> {
    type Item = DecodedInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        // If the previous instruction was compressed, and there are no more
        // expected instructions end interation.
        if self.valid_size == 0 {
            return None;
        }

        let (mut inst, size) = riscv_isa::decode_le_bytes(self.bytes, &self.target)?;
        self.valid_size -= size;

        let (raw_inst, _) = self
            .bytes
            .split_at_checked(size)
            .expect("bytes should have enough size");

        let raw_word = if size == 2 {
            let raw: [u8; 2] = raw_inst.try_into().expect("there should be 2 elements");
            let full_word: [u8; 4] = [raw, [0, 0]]
                .concat()
                .try_into()
                .expect("there should be 2 elements in `raw`");
            u32::from_le_bytes(full_word)
        } else {
            let raw: [u8; 4] = raw_inst
                .try_into()
                .expect("conversion to array of size 4 failed");
            u32::from_le_bytes(raw)
        };

        if size == 2 && matches!(inst, Instruction::UNIMP) {
            let raw: [u8; 2] = raw_inst.try_into().expect("there should be 2 elements");
            if let Some(fallback) = Self::decode_known_compressed_fallback(u16::from_le_bytes(raw))
            {
                inst = fallback;
            }
        }

        self.bytes = &self.bytes[size..];
        Some(DecodedInstruction {
            raw_word,
            inst,
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Decoder, Instruction};

    #[test]
    fn decodes_compressed_and() {
        let bytes = [0xe9, 0x8e];
        let mut decoder = Decoder::from_le_bytes(&bytes, bytes.len());
        let inst = decoder.next().unwrap();

        assert_eq!(inst.size, 2);
        assert_eq!(inst.raw_word, 0x8ee9);
        assert_eq!(
            inst.inst,
            Instruction::AND {
                rd: 13,
                rs1: 13,
                rs2: 10
            }
        );
    }
}
