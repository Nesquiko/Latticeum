#![no_main]
#![no_std]

use configuration::STACK_TOP;

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

#[panic_handler]
fn panic_impl(_panic_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
