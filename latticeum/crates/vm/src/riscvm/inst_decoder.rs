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
}

impl Iterator for Decoder<'_> {
    type Item = DecodedInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        // If the previous instruction was compressed, and there are no more
        // expected instructions end interation.
        if self.valid_size == 0 {
            return None;
        }

        let (inst, size) = riscv_isa::decode_le_bytes(self.bytes, &self.target)?;
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

        self.bytes = &self.bytes[size..];
        Some(DecodedInstruction {
            raw_word,
            inst,
            size,
        })
    }
}
