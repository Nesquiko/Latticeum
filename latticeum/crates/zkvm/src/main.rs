use std::path::PathBuf;

use cyclotomic_rings::rings::GoldilocksRingNTT;
use vm::riscvm::{inst::ExectionTrace, vm::new_vm};

fn main() {
    tracing_subscriber::fmt::init();

    let vm = new_vm();
    let program = PathBuf::from("../vm/samples/fibonacci");
    let mut vm = match vm.load_elf(program) {
        Ok(vm) => vm,
        Err(e) => panic!("failed to loaed samples/fibonacci elf, {}", e),
    };

    vm.run(trace_step);

    let expected_value = 0x34164a7b;
    println!("expected: 0x{:x}, got 0x{:x}", expected_value, vm.result());
    assert_eq!(expected_value, vm.result());
}

fn trace_step(trace: &ExectionTrace) {
    let ccs = arithmetize(trace);
}

fn arithmetize(trace: &ExectionTrace) {
    // also written as `z`
    let witness: Vec<GoldilocksRingNTT> = vec![];
    // TODO populating z, look at the new note
}
