/// Represents the hard-wired zero register (x0).
pub const X0: u32 = 0;
/// Represents the return address register (x1 / ra).
pub const X1: u32 = 1;
/// Represents the stack pointer register (x2 / sp).
pub const X2: u32 = 2;
/// Represents the global pointer register (x3 / gp).
pub const X3: u32 = 3;
/// Represents the thread pointer register (x4 / tp).
pub const X4: u32 = 4;
/// Represents the temporary register (x5 / t0).
pub const X5: u32 = 5;
/// Represents the temporary register (x6 / t1).
pub const X6: u32 = 6;
/// Represents the temporary register (x7 / t2).
pub const X7: u32 = 7;
/// Represents the saved register / frame pointer (x8 / s0/fp).
pub const X8: u32 = 8;
/// Represents the saved register (x9 / s1).
pub const X9: u32 = 9;
/// Represents the function argument / return value register (x10 / a0).
pub const X10: u32 = 10;
/// Represents the function argument / return value register (x11 / a1).
pub const X11: u32 = 11;
/// Represents the function argument register (x12 / a2).
pub const X12: u32 = 12;
/// Represents the function argument register (x13 / a3).
pub const X13: u32 = 13;
/// Represents the function argument register (x14 / a4).
pub const X14: u32 = 14;
/// Represents the function argument register (x15 / a5).
pub const X15: u32 = 15;
/// Represents the function argument register (x16 / a6).
pub const X16: u32 = 16;
/// Represents the function argument register (x17 / a7).
pub const X17: u32 = 17;
/// Represents the saved register (x18 / s2).
pub const X18: u32 = 18;
/// Represents the saved register (x19 / s3).
pub const X19: u32 = 19;
/// Represents the saved register (x20 / s4).
pub const X20: u32 = 20;
/// Represents the saved register (x21 / s5).
pub const X21: u32 = 21;
/// Represents the saved register (x22 / s6).
pub const X22: u32 = 22;
/// Represents the saved register (x23 / s7).
pub const X23: u32 = 23;
/// Represents the saved register (x24 / s8).
pub const X24: u32 = 24;
/// Represents the saved register (x25 / s9).
pub const X25: u32 = 25;
/// Represents the saved register (x26 / s10).
pub const X26: u32 = 26;
/// Represents the saved register (x27 / s11).
pub const X27: u32 = 27;
/// Represents the temporary register (x28 / t3).
pub const X28: u32 = 28;
/// Represents the temporary register (x29 / t4).
pub const X29: u32 = 29;
/// Represents the temporary register (x30 / t5).
pub const X30: u32 = 30;
/// Represents the temporary register (x31 / t6).
pub const X31: u32 = 31;

// --- How to use them ---
fn main() {
    // You can directly use the constants:
    let register_index_for_ra = X1;
    println!("The index for RA is: {}", register_index_for_ra); // Output: The index for RA is: 1

    // For array indexing, you'd typically cast them to usize:
    let mut registers: [u32; 32] = [0; 32];
    registers[X10 as usize] = 100; // Set register x10 to 100
    println!("Value in registers[x10]: {}", registers[X10 as usize]); // Output: Value in registers[x10]: 100

    // You can still get the ABI names if you have a helper function:
    fn get_abi_name(reg_index: u32) -> Option<&'static str> {
        match reg_index {
            X0 => Some("zero"),
            X1 => Some("ra"),
            X2 => Some("sp"),
            X3 => Some("gp"),
            X4 => Some("tp"),
            X5 => Some("t0"),
            X6 => Some("t1"),
            X7 => Some("t2"),
            X8 => Some("s0/fp"),
            X9 => Some("s1"),
            X10 => Some("a0"),
            X11 => Some("a1"),
            X12 => Some("a2"),
            X13 => Some("a3"),
            X14 => Some("a4"),
            X15 => Some("a5"),
            X16 => Some("a6"),
            X17 => Some("a7"),
            X18 => Some("s2"),
            X19 => Some("s3"),
            X20 => Some("s4"),
            X21 => Some("s5"),
            X22 => Some("s6"),
            X23 => Some("s7"),
            X24 => Some("s8"),
            X25 => Some("s9"),
            X26 => Some("s10"),
            X27 => Some("s11"),
            X28 => Some("t3"),
            X29 => Some("t4"),
            X30 => Some("t5"),
            X31 => Some("t6"),
            _ => None,
        }
    }

    println!("ABI name for X1: {}", get_abi_name(X1).unwrap_or("unknown")); // Output: ABI name for X1: ra
}
