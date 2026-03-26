#![no_main]
#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};

#[cfg(target_arch = "riscv32")]
use configuration::STACK_TOP;

#[cfg(target_arch = "riscv32")]
pub mod syscalls {
    pub const SYSCALL_ALLOC_ALIGNED: usize = 1;

    #[inline]
    pub unsafe fn sys_alloc_aligned(size: usize, align: usize) -> *mut u8 {
        let ptr: usize;
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a0") size,
                in("a1") align,
                in("a7") SYSCALL_ALLOC_ALIGNED,
                lateout("a0") ptr,
            );
        }
        ptr as *mut u8
    }
}

struct SimpleAlloc;

unsafe impl GlobalAlloc for SimpleAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(target_arch = "riscv32")]
        {
            unsafe { syscalls::sys_alloc_aligned(layout.size(), layout.align()) }
        }

        #[cfg(not(target_arch = "riscv32"))]
        {
            let _ = layout;
            core::ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static HEAP: SimpleAlloc = SimpleAlloc;

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

#[cfg(target_arch = "riscv32")]
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    loop {}
}
