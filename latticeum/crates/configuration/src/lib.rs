#![no_std]

pub static STACK_TOP: u32 = 0x0010_0000;
pub const RESULT_ADDRESS: *mut u32 = 0x0000_0000 as *mut u32;

pub const N_REGS: usize = 32;
