mod ccs;
mod constraints;

use ccs::to_witness;
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

use vm::riscvm::{
    inst::{ExectionTrace, MemoryOperation},
    riscv_isa::Instruction,
    vm::new_vm,
};

use crate::{ccs::CCSLayout, constraints::CCSBuilder};

#[derive(Clone, Copy)]
pub struct GoldiLocksDP;

impl DecompositionParams for GoldiLocksDP {
    const B: u128 = 1 << 32;
    /// Ring modulus is GoldiLocks (little less than 2^64), thus GoldiLocks modulus < B^L
    const L: usize = 2;
    /// Standard binary decomposition
    const B_SMALL: usize = 2;
    /// Log(B) (base 2 log)
    const K: usize = 32;
}

const CCS_LAYOUT: CCSLayout = CCSLayout::new();
/// Length of Ajtai commitment vectors (rows in commitment matrix)
const C: usize = 4;
/// Number of columns in the Ajtai commitment matrix
const W: usize = CCS_LAYOUT.w_size * GoldiLocksDP::L;

fn main() {
    tracing_subscriber::fmt::init();

    let vm = new_vm();
    let program = PathBuf::from("/home/nesquiko/fiit/dp/latticeum/crates/vm/samples/fibonacci");
    let mut vm = match vm.load_elf(program) {
        Ok(vm) => vm,
        Err(e) => panic!("failed to load samples/fibonacci elf, {}", e),
    };

    // Define the universal CCS for a single RISC-V step.
    let ccs = CCSBuilder::create_riscv_ccs::<W>(&CCS_LAYOUT);

    // Create the Ajtai commitment scheme.
    // The constants C and W need to be defined based on your CCS and witness size.
    let mut rng = ark_std::test_rng();
    let scheme: AjtaiCommitmentScheme<C, W, GoldilocksRingNTT> =
        AjtaiCommitmentScheme::rand(&mut rng);

    let (mut acc, mut w_acc) = initialize_accumulator(&ccs, &CCS_LAYOUT, &scheme);

    vm.run(|trace| {
        trace_step(trace, &CCS_LAYOUT, &ccs, &scheme);
    });

    let expected_value = 0x34164a7b;
    println!("expected: 0x{:x}, got 0x{:x}", expected_value, vm.result());
    assert_eq!(expected_value, vm.result());
}

fn trace_step(
    trace: &ExectionTrace,
    layout: &CCSLayout,
    ccs: &CCS<GoldilocksRingNTT>,
    scheme: &AjtaiCommitmentScheme<C, W, GoldilocksRingNTT>,
) {
    arithmetize(trace, layout, ccs, scheme);
}

fn arithmetize(
    trace: &ExectionTrace,
    layout: &CCSLayout,
    ccs: &CCS<GoldilocksRingNTT>,
    scheme: &AjtaiCommitmentScheme<C, W, GoldilocksRingNTT>,
) -> (CCCS<C, GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    let raw_z = to_witness(trace, layout);
    // convert raw z to proper z-vector structure: [x_ccs, 1, w_ccs]
    let mut z_vec = Vec::new();
    // x_ccs: public inputs (empty since ccs.l = 0)
    // (no elements to add)

    // Add constant 1
    z_vec.push(1usize);

    // w_ccs: witness elements
    z_vec.extend(raw_z.iter().map(|&x| x as usize));

    // 1. generate the full witness vector `z` as before
    let z_as_ring: Vec<GoldilocksRingNTT> = to_F_vec(z_vec);

    // 2. split the z vector into public IO (x_ccs) and private witness (w_ccs)
    let x_ccs = z_as_ring[0..ccs.l].to_vec();
    let w_ccs = z_as_ring[ccs.l + 1..].to_vec(); // +1 to skip the constant '1'

    // 3. create the Witness struct
    let wit = Witness::from_w_ccs::<GoldiLocksDP>(w_ccs);

    // // 4. create the CCCS (Committed CCS) instance.
    let cm = wit
        .commit::<C, W, GoldiLocksDP>(scheme)
        .expect("failed to commit");
    let cccs_instance = CCCS { cm, x_ccs };

    #[cfg(feature = "debug")]
    check_relation_debug(&ccs, &z_as_ring, trace);

    (cccs_instance, wit)
}

fn initialize_accumulator<const C: usize, const W: usize>(
    ccs: &CCS<GoldilocksRingNTT>,
    layout: &CCSLayout,
    scheme: &AjtaiCommitmentScheme<C, W, GoldilocksRingNTT>,
) -> (LCCCS<C, GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    // Create witness with private witness part only
    // The z-vector structure is [x_ccs(0), 1, w_ccs(layout.size)] = layout.size + 1 total
    // So the private witness (w_ccs) should be layout.size elements
    debug_assert_eq!(ccs.n - ccs.l - 1, layout.w_size);
    let zero_w_ccs = vec![GoldilocksRingNTT::zero(); layout.w_size];

    let zero_wit = Witness::from_w_ccs::<GoldiLocksDP>(zero_w_ccs.clone());
    let zero_x_ccs = vec![GoldilocksRingNTT::zero(); ccs.l];

    let zero_cm_i = CCCS {
        cm: zero_wit
            .commit::<C, W, GoldiLocksDP>(scheme)
            .expect("didn't commit to zero witness"),
        x_ccs: zero_x_ccs,
    };

    let mut transcript = PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();
    let (acc, _) = LFLinearizationProver::<
        _,
        PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
    >::prove(&zero_cm_i, &zero_wit, &mut transcript, ccs)
    .expect("failed to create initial accumulator");

    (acc, zero_wit)
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
