mod constraints;
mod witness;

use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::arith::{CCS, r1cs::to_F_vec};
use stark_rings_linalg::SparseMatrix;
use std::{path::PathBuf, usize};
use witness::to_witness;

use vm::riscvm::{inst::ExectionTrace, vm::new_vm};

use crate::constraints::CCSBuilder;

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
    // TODO its time for folding
}

fn arithmetize(trace: &ExectionTrace) -> CCS<GoldilocksRingNTT> {
    let (raw_z, z_layout) = to_witness(trace);
    let z: Vec<GoldilocksRingNTT> = to_F_vec(raw_z.iter().map(|&x| x as usize).collect());

    CCSBuilder::create_riscv_ccs(&z_layout)
}
