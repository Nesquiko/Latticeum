pub use riscv_isa::Instruction;
use riscv_isa::Target;

const RV32IMAC: &str = "RV32IMAC";

pub struct Decoder<'a> {
    target: Target,
    bytes: &'a [u8],
}

/// A tuple containing a decoded RISC-V instruction and its length in bytes.
pub type DecodedInstruction = (Instruction, usize);

impl<'a> Decoder<'a> {
    pub fn decode(bytes: &'a [u8]) -> Vec<DecodedInstruction> {
        let target = riscv_isa::Target::from_str_strict(RV32IMAC).expect("invalid target");
        let decoder = Decoder::from_le_bytes(target, bytes);
        decoder.collect()
    }

    pub fn from_le_bytes(target: Target, bytes: &'a [u8]) -> Decoder<'a> {
        Decoder { target, bytes }
    }
}

impl Iterator for Decoder<'_> {
    type Item = DecodedInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        let (insn, len) = riscv_isa::decode_le_bytes(self.bytes, &self.target)?;
        self.bytes = &self.bytes[len..];
        Some((insn, len))
    }
}
