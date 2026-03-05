#![no_main]
#![no_std]

#[cfg(target_arch = "riscv32")]
use configuration::STACK_TOP;

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(
    ".section .text._start",
    ".globl _start",
    "_start:",
    "   .option push",
    "   .option norelax",
    "   la gp, __global_pointer$",
    "   .option pop",
    "    li sp, {stack_top}",
    "    call rust_main",
    stack_top = const STACK_TOP,
);

#[cfg(not(target_arch = "riscv32"))]
#[allow(dead_code)]
pub fn guest_target_guard() {
    panic!("guest crate must be compiled for riscv32 target");
}

#[macro_export]
macro_rules! guest_main {
    ($path:path) => {
        const GUEST_MAIN: fn() = $path;

        mod guest_generated_main {
            #[unsafe(no_mangle)]
            fn main() {
                super::GUEST_MAIN()
            }
        }
    };
}

#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
extern "C" fn rust_main() -> ! {
    {
        unsafe extern "C" {
            fn main();
        }
        unsafe { main() }
    }

    loop {}
}

pub fn write_result(word: u32) {
    unsafe {
        core::ptr::write_volatile(configuration::RESULT_ADDRESS, word);
    }
}

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic_impl(_panic_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
