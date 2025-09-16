mod ccs;
mod constraints;

use ccs::to_witness;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
#[cfg(feature = "debug")]
use latticefold::arith::Arith;
use latticefold::{
    arith::{r1cs::to_F_vec, Witness, CCCS, CCS, LCCCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::{
        linearization::{LFLinearizationProver, LinearizationProver}, NIFSProver,
        NIFSVerifier,
    },
    transcript::poseidon::PoseidonTranscript,
};
#[cfg(feature = "debug")]
use vm::riscvm::riscv_isa::Instruction;

use num_traits::identities::Zero;
use std::{path::PathBuf, sync::Mutex, usize};

use vm::riscvm::{inst::ExectionTrace, vm::new_vm};

use crate::{ccs::CCSLayout, constraints::CCSBuilder};

#[derive(Clone, Copy)]
pub struct GoldiLocksDP;

// Default params from latticefold examples
impl DecompositionParams for GoldiLocksDP {
    const B: u128 = 1 << 15;
    /// Ring modulus is GoldiLocks (little less than 2^64), thus GoldiLocks modulus < B^L
    const L: usize = 5;
    /// Standard binary decomposition
    const B_SMALL: usize = 2;
    /// log₂(B)
    const K: usize = 15;
}

const CCS_LAYOUT: CCSLayout = CCSLayout::new();
/// Length of Ajtai commitment vectors (rows in commitment matrix)
const C: usize = 4;
/// Number of columns in the Ajtai commitment matrix
const W: usize = CCS_LAYOUT.w_size * GoldiLocksDP::L;

// TODO then finally memory ops and poseidon CCS
fn main() {
    tracing_subscriber::fmt::init();

    tracing::info!(
        "Starting zkVM with decomposition params: B={}, L={}, B_SMALL={}, K={}",
        GoldiLocksDP::B,
        GoldiLocksDP::L,
        GoldiLocksDP::B_SMALL,
        GoldiLocksDP::K
    );

    let vm = new_vm();
    let program = PathBuf::from(
        "/home/nesquiko/fiit/dp/latticeum/target/riscv32imac-unknown-none-elf/release/fibonacci",
    );
    let mut vm = match vm.load_elf(program) {
        Ok(vm) => vm,
        Err(e) => panic!("failed to load `fibonacci` elf, {}", e),
    };

    // Define the universal CCS for a single RISC-V step.
    let ccs = CCSBuilder::create_riscv_ccs::<W>(&CCS_LAYOUT);

    // Create the Ajtai commitment scheme.
    let mut rng = ark_std::test_rng();
    let scheme: AjtaiCommitmentScheme<C, W, GoldilocksRingNTT> =
        AjtaiCommitmentScheme::rand(&mut rng);

    tracing::info!("initializing accumulator...");
    let (mut acc, mut w_acc) = initialize_accumulator(&ccs, &CCS_LAYOUT, &scheme);
    tracing::info!("accumulator initialized, starting VM execution...");

    let start_vm_run = std::time::Instant::now();

    // collect all traces first, then process them
    let traces = Mutex::new(Vec::new());
    vm.run(|trace| {
        traces.lock().unwrap().push(trace);
    });
    let traces = traces.into_inner().unwrap();
    let step_count = traces.len() as u32;

    // process each trace and fold into accumulator
    for trace in &traces {
        let (cm_i, w_i) = arithmetize(trace, &CCS_LAYOUT, &ccs, &scheme);

        let mut prover_transcript =
            PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();

        let (folded_acc, folded_w_acc, _) = NIFSProver::<
            C,
            W,
            GoldilocksRingNTT,
            GoldiLocksDP,
            PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
        >::prove(
            &acc,
            &w_acc,
            &cm_i,
            &w_i,
            &mut prover_transcript,
            &ccs,
            &scheme,
        )
        .expect("NIFS proving failed for a step");

        acc = folded_acc;
        w_acc = folded_w_acc;
    }

    let vm_run_time = start_vm_run.elapsed();
    tracing::info!(
        "VM execution completed: {:?} ({} steps, avg {:?}/step)",
        vm_run_time,
        step_count,
        vm_run_time / step_count
    );

    let expected_value = 0xc594bfc3;
    tracing::info!("expected: 0x{:x}, got 0x{:x}", expected_value, vm.result());
    assert_eq!(expected_value, vm.result());

    tracing::info!("generating final folding proof...");
    let start_final_proof = std::time::Instant::now();

    // create a dummy CCCS instance to fold with the final accumulator
    // This demonstrates the final proof generation similar to goldilocks.rs
    let zero_w_ccs = vec![GoldilocksRingNTT::zero(); CCS_LAYOUT.w_size];
    let dummy_wit = Witness::from_w_ccs::<GoldiLocksDP>(zero_w_ccs);
    let dummy_cm = CCCS {
        cm: dummy_wit
            .commit::<C, W, GoldiLocksDP>(&scheme)
            .expect("failed to commit dummy witness"),
        x_ccs: vec![GoldilocksRingNTT::zero(); ccs.l],
    };

    let mut final_prover_transcript =
        PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();
    let mut final_verifier_transcript =
        PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();

    let (_final_acc, _final_wit, final_proof) = NIFSProver::<
        C,
        W,
        GoldilocksRingNTT,
        GoldiLocksDP,
        PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
    >::prove(
        &acc,
        &w_acc,
        &dummy_cm,
        &dummy_wit,
        &mut final_prover_transcript,
        &ccs,
        &scheme,
    )
    .expect("Final NIFS proving failed");

    let final_proof_time = start_final_proof.elapsed();
    tracing::info!("final proof generated: {:?}", final_proof_time);

    tracing::info!("verifying final proof...");
    let start_verification = std::time::Instant::now();

    NIFSVerifier::<
        C,
        GoldilocksRingNTT,
        GoldiLocksDP,
        PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
    >::verify(
        &acc,
        &dummy_cm,
        &final_proof,
        &mut final_verifier_transcript,
        &ccs,
    )
    .expect("Final proof verification failed");

    let verification_time = start_verification.elapsed();
    tracing::info!("final proof verified: {:?}", verification_time);

    tracing::info!(
        "zkVM execution summary: {} steps in {:?} (avg {:?}/step), proof: {:?}, verify: {:?}",
        step_count,
        vm_run_time,
        vm_run_time / step_count.max(1),
        final_proof_time,
        verification_time
    );
}

fn arithmetize(
    trace: &ExectionTrace,
    layout: &CCSLayout,
    ccs: &CCS<GoldilocksRingNTT>,
    scheme: &AjtaiCommitmentScheme<C, W, GoldilocksRingNTT>,
) -> (CCCS<C, GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    let start_witness_creation = std::time::Instant::now();

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

    tracing::debug!(
        "witness creation: {:?} (size: {} elements)",
        start_witness_creation.elapsed(),
        layout.w_size
    );

    // 4. create the CCCS (Committed CCS) instance.
    let start_commitment = std::time::Instant::now();
    let cm = wit
        .commit::<C, W, GoldiLocksDP>(scheme)
        .expect("failed to commit");
    let cccs_instance = CCCS { cm, x_ccs };

    tracing::debug!(
        "commitment: {:?} (C={}, W={}, B={}, L={})",
        start_commitment.elapsed(),
        C,
        W,
        GoldiLocksDP::B,
        GoldiLocksDP::L
    );

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
