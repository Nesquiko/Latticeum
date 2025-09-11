mod constraints;
mod witness;

use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{Arith, CCCS, CCS, LCCCS, Witness, r1cs::to_F_vec},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::linearization::{LFLinearizationProver, LinearizationProver},
    transcript::poseidon::PoseidonTranscript,
};
use num_traits::identities::Zero;
use std::{path::PathBuf, usize};
use witness::to_witness;

use vm::riscvm::{inst::ExectionTrace, riscv_isa::Instruction, vm::new_vm};

use crate::{
    constraints::{CCSBuilder, Ring},
    witness::ZVectorLayout,
};

const Z_LAYOUT: ZVectorLayout = ZVectorLayout::new();
const C: usize = 4;
const W: usize = Z_LAYOUT.size; // Match the actual witness size from ZVectorLayout

fn main() {
    tracing_subscriber::fmt::init();

    let vm = new_vm();
    let program = PathBuf::from("/home/nesquiko/fiit/dp/latticeum/crates/vm/samples/fibonacci");
    let mut vm = match vm.load_elf(program) {
        Ok(vm) => vm,
        Err(e) => panic!("failed to load samples/fibonacci elf, {}", e),
    };

    // Define the universal CCS for a single RISC-V step.
    let ccs = CCSBuilder::create_riscv_ccs(&Z_LAYOUT);

    // Create the Ajtai commitment scheme.
    // The constants C and W need to be defined based on your CCS and witness size.
    let mut rng = ark_std::test_rng();
    let scheme: AjtaiCommitmentScheme<C, W, GoldilocksRingNTT> =
        AjtaiCommitmentScheme::rand(&mut rng);

    let (mut acc, mut w_acc) = initialize_accumulator(&ccs, &scheme);

    vm.run(|trace| trace_step(trace, &Z_LAYOUT, &ccs));

    let expected_value = 0x34164a7b;
    println!("expected: 0x{:x}, got 0x{:x}", expected_value, vm.result());
    assert_eq!(expected_value, vm.result());
}

#[derive(Clone, Copy)]
pub struct GoldiLocksDP;

impl DecompositionParams for GoldiLocksDP {
    const B: u128 = 4;
    const L: usize = 1;
    const B_SMALL: usize = 2;
    const K: usize = 2;
}

fn initialize_accumulator<const C: usize, const W: usize>(
    ccs: &CCS<GoldilocksRingNTT>,
    scheme: &AjtaiCommitmentScheme<C, W, GoldilocksRingNTT>,
) -> (LCCCS<C, GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    // Create witness with private witness part only
    // The z-vector structure is [x_ccs(0), 1, w_ccs(z_layout.size)] = z_layout.size + 1 total
    // So the private witness (w_ccs) should be z_layout.size elements
    let dummy_w_ccs = vec![GoldilocksRingNTT::zero(); ccs.n - ccs.l - 1];
    tracing::info!(
        "Creating witness with w_ccs.len={}, ccs.n={}, ccs.l={}",
        dummy_w_ccs.len(),
        ccs.n,
        ccs.l
    );

    let dummy_wit = Witness::from_w_ccs::<GoldiLocksDP>(dummy_w_ccs.clone());
    tracing::info!("CCS: m={}, n={}, l={}, t={}", ccs.m, ccs.n, ccs.l, ccs.t);
    tracing::info!(
        "Z_LAYOUT.size={}, dummy_w_ccs.len={}",
        Z_LAYOUT.size,
        ccs.n - ccs.l
    );

    // Let's manually calculate the expected size
    let expected_size =
        1 + 32 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1;
    tracing::info!(
        "Expected Z_LAYOUT.size: {}, actual: {}",
        expected_size,
        Z_LAYOUT.size
    );

    // Debug the witness creation
    tracing::info!("dummy_w_ccs input length: {}", dummy_w_ccs.len());
    // Let's check what the witness looks like after creation
    tracing::info!("dummy_wit created, checking its internal structure...");
    let dummy_x_ccs = vec![GoldilocksRingNTT::zero(); ccs.l];

    let dummy_cm_i = CCCS {
        cm: dummy_wit
            .commit::<C, W, GoldiLocksDP>(scheme)
            .expect("didn't commit to dummy witness"),
        x_ccs: dummy_x_ccs,
    };

    let mut transcript = PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();
    let (acc, _) = LFLinearizationProver::<
        _,
        PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
    >::prove(&dummy_cm_i, &dummy_wit, &mut transcript, ccs)
    .expect("failed to create initial accumulator");

    (acc, dummy_wit)
}

fn trace_step(trace: &ExectionTrace, z_layout: &ZVectorLayout, ccs: &CCS<GoldilocksRingNTT>) {
    arithmetize(trace, z_layout, ccs);
}

fn arithmetize(trace: &ExectionTrace, z_layout: &ZVectorLayout, ccs: &CCS<GoldilocksRingNTT>) {
    let raw_z = to_witness(trace, z_layout);

    // Convert raw witness to proper z-vector structure: [x_ccs, 1, w_ccs]
    let mut z_vec = Vec::new();
    // x_ccs: public inputs (empty since ccs.l = 0)
    // (no elements to add)

    // Add constant 1
    z_vec.push(1usize);

    // w_ccs: witness elements
    z_vec.extend(raw_z.iter().map(|&x| x as usize));

    let z: Vec<GoldilocksRingNTT> = to_F_vec(z_vec);

    #[cfg(feature = "debug")]
    {
        check_relation_debug(&ccs, &z, trace);
    }
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
