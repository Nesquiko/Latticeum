mod constraints;
mod witness;

use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::arith::{Arith, CCS, r1cs::to_F_vec};
use std::{path::PathBuf, usize};
use witness::to_witness;

use vm::riscvm::{inst::ExectionTrace, riscv_isa::Instruction, vm::new_vm};

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
    // TODO transform z let wit_acc = Witness::from_w_ccs::<DP>(rand_w_ccs);

    let ccs = CCSBuilder::create_riscv_ccs(&z_layout);

    #[cfg(feature = "debug")]
    {
        check_relation_debug(&ccs, &z, trace);
    }

    ccs
}

#[cfg(feature = "debug")]
pub fn check_relation_debug(
    ccs: &CCS<GoldilocksRingNTT>,
    z: &Vec<GoldilocksRingNTT>,
    trace: &ExectionTrace,
) {
    match trace.instruction.inst {
        Instruction::ADD { .. }
        | Instruction::ADDI { .. }
        | Instruction::BNE { .. }
        | Instruction::LUI { .. }
        | Instruction::AUIPC { .. }
        | Instruction::JAL { .. }
        | Instruction::JALR { .. }
        | Instruction::SW { .. } => {
            ccs.check_relation(z).unwrap_or_else(|e| {
                panic!(
                    "❌ CCS relation failed for {:?}: {:?}",
                    trace.instruction.inst, e
                );
            });
        }
        _ => {}
    }
}
