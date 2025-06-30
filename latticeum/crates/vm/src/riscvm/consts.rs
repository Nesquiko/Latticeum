pub const MAX_MEM: u32 = u32::MAX;
pub const WORD_SIZE: usize = 4;
pub const HALF_WORD_SIZE: usize = WORD_SIZE / 2;
pub const UNCOMPRESED_INST: u16 = 0b11;

pub const fn is_compressed(half_word: u16) -> bool {
    (half_word & UNCOMPRESED_INST) != UNCOMPRESED_INST
}
