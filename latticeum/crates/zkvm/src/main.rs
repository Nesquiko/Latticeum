mod ccs;
mod constraints;
mod memory_commitment;

use ccs::to_raw_witness;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT};
use latticefold::{
    arith::{CCCS, CCS, LCCCS, Witness, r1cs::to_F_vec},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::{
        NIFSProver, NIFSVerifier,
        linearization::{LFLinearizationProver, LinearizationProver},
    },
    transcript::poseidon::PoseidonTranscript,
};

use num_traits::identities::Zero;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use stark_rings::Ring;
use std::{path::PathBuf, usize};

use vm::riscvm::{inst::ExecutionTrace, vm::new_vm};

#[cfg(feature = "debug")]
use crate::constraints::check_relation_debug;
use crate::{
    ccs::CCSLayout,
    constraints::CCSBuilder,
    memory_commitment::{PoseidonHasher, mem_comm},
};

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

fn main() {
    tracing_subscriber::fmt::init();

    tracing::debug!(
        "starting zkVM with decomposition params: B={}, L={}, B_SMALL={}, K={}",
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

    let ccs = CCSBuilder::create_riscv_ccs::<W>(&CCS_LAYOUT);

    let mut rng = ark_std::test_rng();
    let poseidon = PoseidonHasher::new();

    let scheme: AjtaiCommitmentScheme<C, W, GoldilocksRingNTT> =
        AjtaiCommitmentScheme::rand(&mut rng);

    tracing::debug!("initializing accumulator");
    let (mut acc, mut w_acc, mut current_mem_comm) =
        initialize_accumulator(&ccs, &CCS_LAYOUT, &scheme);
    tracing::debug!("accumulator initialized, starting VM execution");

    let start_vm_run = std::time::Instant::now();

    let mut memory_ops = Vec::new();
    let mut cycles: usize = 0;

    vm.run(|trace| {
        cycles = trace.cycle;
        let mem_comm_in = current_mem_comm;
        let mut mem_comm_out = current_mem_comm;

        if let Some(memory_op) = trace.side_effects.memory_op.clone() {
            mem_comm_out = poseidon.mem_comm(current_mem_comm, &memory_op);
            memory_ops.push(memory_op);
        }

        let z = arithmetize(&trace, &CCS_LAYOUT, mem_comm_in, mem_comm_out);

        #[cfg(feature = "debug")]
        check_relation_debug(&ccs, &z, &trace);

        let (cm_i, w_i) = commit(z, &ccs, &scheme);
        (acc, w_acc) = fold(FoldingArgs {
            ccs: &ccs,
            scheme: &scheme,
            acc: &acc,
            w_acc: &w_acc,
            cm_i: &cm_i,
            w_i: &w_i,
        });

        current_mem_comm = mem_comm_out;
    });

    let expected_value = 0xc594bfc3; // 100th fibonacci
    assert_eq!(expected_value, vm.result());

    tracing::info!(
        "folded {} execution traces and commited to {} memory operations",
        cycles,
        memory_ops.len()
    );

    let vm_run_time = start_vm_run.elapsed();
    tracing::info!("folding completed in {:?} ({} cycles)", vm_run_time, cycles,);

    // tracing::info!("generating final folding proof...");
    // let start_final_proof = std::time::Instant::now();
    //
    // // create a zero CCCS instance to fold with the final accumulator
    // // This demonstrates the final proof generation similar to goldilocks.rs
    // let zero_w_ccs = vec![GoldilocksRingNTT::zero(); CCS_LAYOUT.w_size];
    // let dummy_wit = Witness::from_w_ccs::<GoldiLocksDP>(zero_w_ccs);
    // let dummy_cm = CCCS {
    //     cm: dummy_wit
    //         .commit::<C, W, GoldiLocksDP>(&scheme)
    //         .expect("failed to commit dummy witness"),
    //     x_ccs: vec![GoldilocksRingNTT::from(final_memory_commitment); ccs.l],
    // };
    //
    // let mut final_prover_transcript =
    //     PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();
    // let mut final_verifier_transcript =
    //     PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();
    //
    // let (_final_acc, _final_wit, final_proof) = NIFSProver::<
    //     C,
    //     W,
    //     GoldilocksRingNTT,
    //     GoldiLocksDP,
    //     PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
    // >::prove(
    //     &acc,
    //     &w_acc,
    //     &dummy_cm,
    //     &dummy_wit,
    //     &mut final_prover_transcript,
    //     &ccs,
    //     &scheme,
    // )
    // .expect("Final NIFS proving failed");
    //
    // let final_proof_time = start_final_proof.elapsed();
    // tracing::info!("final proof generated: {:?}", final_proof_time);
    //
    // tracing::info!("verifying final proof...");
    // let start_verification = std::time::Instant::now();
    //
    // NIFSVerifier::<
    //     C,
    //     GoldilocksRingNTT,
    //     GoldiLocksDP,
    //     PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
    // >::verify(
    //     &acc,
    //     &dummy_cm,
    //     &final_proof,
    //     &mut final_verifier_transcript,
    //     &ccs,
    // )
    // .expect("Final proof verification failed");
    //
    // let verification_time = start_verification.elapsed();
    // tracing::info!("final proof verified: {:?}", verification_time);
    //
    // tracing::info!(
    //     "zkVM execution summary: {} steps in {:?} (avg {:?}/step), proof: {:?}, verify: {:?}",
    //     step_count,
    //     vm_run_time,
    //     vm_run_time / step_count.max(1),
    //     final_proof_time,
    //     verification_time
    // );
}

const INITIAL_MEM_COMM: Goldilocks = Goldilocks::ZERO;

fn initialize_accumulator<const C: usize, const W: usize>(
    ccs: &CCS<GoldilocksRingNTT>,
    layout: &CCSLayout,
    scheme: &AjtaiCommitmentScheme<C, W, GoldilocksRingNTT>,
) -> (
    LCCCS<C, GoldilocksRingNTT>,
    Witness<GoldilocksRingNTT>,
    Goldilocks,
) {
    // Create witness with private witness part only
    // The z-vector structure is [x_ccs, 1, w_ccs] = layout.size + 1 total
    // So the private witness (w_ccs) should be layout.size elements
    debug_assert_eq!(ccs.n - ccs.l - 1, layout.w_size);
    let zero_w_ccs = vec![GoldilocksRingNTT::zero(); layout.w_size];

    let zero_wit = Witness::from_w_ccs::<GoldiLocksDP>(zero_w_ccs);
    // initialize public inputs and output to memory comm in and memory comm out
    let zero_x_ccs = vec![
        GoldilocksRingNTT::from(INITIAL_MEM_COMM.as_canonical_u64()),
        GoldilocksRingNTT::from(INITIAL_MEM_COMM.as_canonical_u64()),
    ];

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

    (acc, zero_wit, INITIAL_MEM_COMM)
}

fn arithmetize(
    trace: &ExecutionTrace,
    layout: &CCSLayout,
    mem_comm_in: Goldilocks,
    mem_comm_out: Goldilocks,
) -> Vec<GoldilocksRingNTT> {
    let start_witness_creation = std::time::Instant::now();

    let raw_z = to_raw_witness(trace, layout);
    // convert raw z to proper z-vector structure: [x_ccs, 1, w_ccs]
    let mut z_vec = Vec::new();

    // x_ccs: public inputs - memory commitment in and out
    z_vec.push(mem_comm_in.as_canonical_u64() as usize);
    z_vec.push(mem_comm_out.as_canonical_u64() as usize);

    // Add constant 1
    z_vec.push(1usize);

    // w_ccs: witness elements
    z_vec.extend(raw_z.iter().map(|&x| x as usize));

    // generate the full witness vector `z`
    let z_as_ring: Vec<GoldilocksRingNTT> = to_F_vec(z_vec);

    tracing::debug!(
        "witness creation: {:?} (size: {} elements, mem_comm_in: {}, mem_comm_out: {})",
        start_witness_creation.elapsed(),
        layout.w_size,
        mem_comm_in,
        mem_comm_out,
    );

    z_as_ring
}

/// returns CCS witness commitment and the private witness
fn commit(
    z_as_ring: Vec<GoldilocksRingNTT>,
    ccs: &CCS<GoldilocksRingNTT>,
    scheme: &AjtaiCommitmentScheme<C, W, GoldilocksRingNTT>,
) -> (CCCS<C, GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    let start_commitment = std::time::Instant::now();
    // split the z vector into public IO (x_ccs) and private witness (w_ccs)
    let x_ccs = z_as_ring[0..ccs.l].to_vec(); // contains memory commitment (l=1)
    let w_ccs = z_as_ring[ccs.l + 1..].to_vec(); // +1 to skip the constant '1'

    // create the Witness struct from private w_ccs
    let wit = Witness::from_w_ccs::<GoldiLocksDP>(w_ccs);

    // create the CCCS (Committed CCS) instance.
    let cm = wit
        .commit::<C, W, GoldiLocksDP>(scheme)
        .expect("failed to commit");
    let cccs_instance = CCCS { cm, x_ccs };

    tracing::debug!(
        "commited to witnes in {:?} (C={}, W={}, B={}, L={})",
        start_commitment.elapsed(),
        C,
        W,
        GoldiLocksDP::B,
        GoldiLocksDP::L
    );

    (cccs_instance, wit)
}

struct FoldingArgs<'a> {
    ccs: &'a CCS<GoldilocksRingNTT>,
    scheme: &'a AjtaiCommitmentScheme<C, W, GoldilocksRingNTT>,

    acc: &'a LCCCS<C, GoldilocksRingNTT>,
    w_acc: &'a Witness<GoldilocksRingNTT>,
    cm_i: &'a CCCS<C, GoldilocksRingNTT>,
    w_i: &'a Witness<GoldilocksRingNTT>,
}

fn fold(
    FoldingArgs {
        ccs,
        scheme,
        acc,
        w_acc,
        cm_i,
        w_i,
    }: FoldingArgs,
) -> (LCCCS<C, GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    let folding_start = std::time::Instant::now();
    let mut prover_transcript =
        PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();

    // the folding proof is ignored here, because there needs to be just one
    // at the end of the whole folding
    let (folded_acc, folded_w_acc, folding_proof) =
        NIFSProver::<
            C,
            W,
            GoldilocksRingNTT,
            GoldiLocksDP,
            PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
        >::prove(acc, w_acc, cm_i, w_i, &mut prover_transcript, ccs, scheme)
        .expect("NIFS proving failed for a step");

    tracing::debug!("folded in {:?}", folding_start.elapsed());

    #[cfg(feature = "debug")]
    {
        use latticefold::nifs::NIFSVerifier;

        let verifying_start = std::time::Instant::now();
        let mut final_verifier_transcript =
            PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();
        NIFSVerifier::<
            C,
            GoldilocksRingNTT,
            GoldiLocksDP,
            PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
        >::verify(
            &acc,
            &cm_i,
            &folding_proof,
            &mut final_verifier_transcript,
            &ccs,
        )
        .expect("Final proof verification failed");

        tracing::debug!("verified folding in {:?}", verifying_start.elapsed());
    }

    (folded_acc, folded_w_acc)
}
