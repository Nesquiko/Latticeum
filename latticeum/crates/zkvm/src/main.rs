mod ccs;
mod commitments;
mod constraints;
mod crypto_consts;
mod ivc;
mod poseidon2;

use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT, GoldilocksRingPoly};
use latticefold::{
    arith::{CCCS, CCS, LCCCS, Witness},
    commitment::AjtaiCommitmentScheme,
    nifs::{
        LFProof, NIFSProver,
        linearization::{LFLinearizationProver, LinearizationProver},
    },
    transcript::poseidon::PoseidonTranscript,
};

use num_traits::identities::Zero;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use stark_rings::PolyRing;
use std::path::PathBuf;
use tracing::{Level, instrument};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use vm::riscvm::vm::{InterceptArgs, new_vm_1mb};

#[cfg(feature = "debug")]
use crate::constraints::check_relation_debug;

use crate::{
    ccs::{CCS_LAYOUT, CCSLayout, GoldiLocksDP, KAPPA, N},
    commitments::{MemoryPageComm, ZkVmCommitter},
    constraints::CCSBuilder,
    ivc::{IVCStepInput, IVCStepOutput, arithmetize},
    poseidon2::{GoldilocksComm, ZERO_GOLDILOCKS_COMM},
};

fn main() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("debug"))
        .add_directive("p3_merkle_tree=off".parse().expect("invalid directive"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let program_path =
        "/home/nesquiko/fiit/dp/latticeum/target/riscv32imac-unknown-none-elf/release/fibonacci";
    let program = PathBuf::from(program_path);

    tracing::info!("proving program '{}'", program_path);

    let vm = new_vm_1mb();
    let mut vm = match vm.load_elf(program) {
        Ok(vm) => vm,
        Err(e) => panic!("failed to load '{}' elf, {}", program_path, e),
    };

    let start_zkvm_run = std::time::Instant::now();

    let ccs = CCSBuilder::create_riscv_ccs::<N>(&CCS_LAYOUT);

    let mut rng = ark_std::test_rng();
    let scheme: AjtaiCommitmentScheme<GoldilocksRingNTT> =
        AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let zkvm_commiter = ZkVmCommitter::new();

    let mut memory_ops = Vec::new();
    let mut vm_memory_comm = MemoryPageComm {
        comm: zkvm_commiter.vm_mem_comm(&vm.memory),
        page_index: 0,
        page: vm.memory[0].map(|el| Goldilocks::from_u32(el)),
        proof: Default::default(),
    };

    let mut vm_memory_ops_vec_comm = ZERO_GOLDILOCKS_COMM;
    let z_0_comm = zkvm_commiter.state_i_comm(
        &vm.regs,
        &vm.elf().raw_code.bytes,
        vm.pc,
        vm_memory_comm.comm,
        vm_memory_ops_vec_comm,
    );

    let mut step: Goldilocks = Goldilocks::ZERO;
    let (acc, w_acc) = initialize_accumulator(&ccs, &CCS_LAYOUT, &scheme, ZERO_GOLDILOCKS_COMM);
    let acc_0_comm = zkvm_commiter.acc_comm(&acc);
    let ivc_step_0_comm = zkvm_commiter.ivc_step_comm(step, z_0_comm, z_0_comm, acc_0_comm);

    let mut ivc_output = IVCStepOutput {
        ivc_step_comm: ivc_step_0_comm,
        ivc_step: step,
        z_0_comm,
        z_i_comm: z_0_comm,
        acc_comm: acc_0_comm,
        acc,
        w_acc,
        folding_proof: None,
    };

    vm.run(
        |InterceptArgs {
             trace,
             vm_memory,
             vm_regs,
             vm_raw_code,
         }| {
            // IVC starts at step 0, which is the empty state, cycle starts at 0,
            // in order to match add 1.
            step = Goldilocks::from_usize(trace.cycle + 1);

            if let Some(memory_op) = trace.side_effects.memory_op.clone() {
                vm_memory_comm = zkvm_commiter.vm_mem_comm_with_opening(vm_memory, &memory_op);
                vm_memory_ops_vec_comm =
                    zkvm_commiter.vm_mem_ops_vec_comm(vm_memory_ops_vec_comm, &memory_op);
                memory_ops.push(memory_op);
            }

            let ivc_input = IVCStepInput {
                // these prove correct IVC transition from step `i - 1`
                ivc_step_comm: ivc_output.ivc_step_comm.clone(),
                ivc_step: step - Goldilocks::ONE,
                state_0_comm: ivc_output.z_0_comm,
                state_comm: ivc_output.z_i_comm,
                acc_comm: ivc_output.acc_comm,
                acc: &ivc_output.acc,
                // these are used to prove correct folding in step `i - 1`
                folding_proof: ivc_output.folding_proof.as_ref(),
                w_acc: &ivc_output.w_acc,

                // this is used to prove the RISC-V execution
                trace: &trace,
            };

            let z = arithmetize(&ivc_input, &CCS_LAYOUT);

            #[cfg(feature = "debug")]
            check_relation_debug(&ccs, &z, &ivc_input);

            let (cm_i, w_i) = commit(z, &ccs, &scheme);
            let (folded_acc, folded_w_acc, folding_proof) = fold(FoldingArgs {
                ccs: &ccs,
                scheme: &scheme,
                acc: &ivc_output.acc,
                w_acc: &ivc_output.w_acc,
                cm_i: &cm_i,
                w_i: &w_i,
            });

            let state_i_comm = zkvm_commiter.state_i_comm(
                vm_regs,
                vm_raw_code,
                trace.output.pc,
                vm_memory_comm.comm,
                vm_memory_ops_vec_comm,
            );

            let acc_comm = zkvm_commiter.acc_comm(&folded_acc);
            let ivc_step_comm = zkvm_commiter.ivc_step_comm(step, z_0_comm, state_i_comm, acc_comm);

            ivc_output = IVCStepOutput {
                ivc_step_comm: ivc_step_comm,
                ivc_step: ivc_input.ivc_step,
                z_0_comm,
                z_i_comm: state_i_comm,
                acc_comm: acc_comm,
                acc: folded_acc,
                w_acc: folded_w_acc,
                folding_proof: Some(folding_proof),
            };

            assert_eq!(ccs.s, ivc_output.acc.r.len());
            assert_eq!(
                GoldilocksRingPoly::dimension() / GoldilocksRingNTT::dimension(),
                ivc_output.acc.v.len()
            );
            assert_eq!(KAPPA, ivc_output.acc.cm.len());
            assert_eq!(ccs.t, ivc_output.acc.u.len());
            assert_eq!(ccs.l, ivc_output.acc.x_w.len());
        },
    );

    assert_eq!(0xc594bfc3 /* 100th fibonacci */, vm.result());

    tracing::info!(
        "folded {} execution traces and commited to {} memory operations",
        step,
        memory_ops.len()
    );

    let vm_run_time = start_zkvm_run.elapsed();
    tracing::info!("folding completed in {:?} ({} cycles)", vm_run_time, step,);
}

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
#[instrument(skip_all, level = Level::DEBUG)]
fn initialize_accumulator(
    ccs: &CCS<GoldilocksRingNTT>,
    layout: &CCSLayout,
    scheme: &AjtaiCommitmentScheme<GoldilocksRingNTT>,
    initial_ivc_step_comm: GoldilocksComm,
) -> (LCCCS<GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    // create witness with private witness part only
    // the z-vector structure is [x_ccs, 1, w_ccs] = layout.size + 1 total
    // so the private witness (w_ccs) should be layout.w_size elements
    assert_eq!(ccs.n - ccs.l - CCSLayout::CONST_ELEMS_SIZE, layout.w_size);
    let zero_w_ccs = vec![GoldilocksRingNTT::zero(); layout.w_size];

    let zero_wit = Witness::from_w_ccs::<GoldiLocksDP>(zero_w_ccs);
    // empty public input representing the ivc step commitment
    let zero_x_ccs = vec![
        GoldilocksRingNTT::from(initial_ivc_step_comm[0].as_canonical_u64()),
        GoldilocksRingNTT::from(initial_ivc_step_comm[1].as_canonical_u64()),
        GoldilocksRingNTT::from(initial_ivc_step_comm[2].as_canonical_u64()),
        GoldilocksRingNTT::from(initial_ivc_step_comm[3].as_canonical_u64()),
    ];

    let zero_cm_i = CCCS {
        cm: zero_wit
            .commit::<GoldiLocksDP>(scheme)
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

/// returns CCS witness commitment and the private witness
#[instrument(skip_all, level = Level::DEBUG)]
fn commit(
    z_as_ring: Vec<GoldilocksRingNTT>,
    ccs: &CCS<GoldilocksRingNTT>,
    scheme: &AjtaiCommitmentScheme<GoldilocksRingNTT>,
) -> (CCCS<GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    // split the z vector into public IO (x_ccs) and private witness (w_ccs)
    let x_ccs = z_as_ring[0..ccs.l].to_vec(); // contains memory commitment (l=1)
    let w_ccs = z_as_ring[ccs.l + 1..].to_vec(); // +1 to skip the constant '1'

    // create the Witness struct from private w_ccs
    let wit = Witness::from_w_ccs::<GoldiLocksDP>(w_ccs);

    // create the CCCS (Committed CCS) instance.
    let cm = wit
        .commit::<GoldiLocksDP>(scheme)
        .expect("failed to commit");
    let cccs_instance = CCCS { cm, x_ccs };

    (cccs_instance, wit)
}

struct FoldingArgs<'a> {
    ccs: &'a CCS<GoldilocksRingNTT>,
    scheme: &'a AjtaiCommitmentScheme<GoldilocksRingNTT>,

    acc: &'a LCCCS<GoldilocksRingNTT>,
    w_acc: &'a Witness<GoldilocksRingNTT>,
    cm_i: &'a CCCS<GoldilocksRingNTT>,
    w_i: &'a Witness<GoldilocksRingNTT>,
}

#[instrument(skip_all, level = Level::DEBUG)]
fn fold(
    FoldingArgs {
        ccs,
        scheme,
        acc,
        w_acc,
        cm_i,
        w_i,
    }: FoldingArgs,
) -> (
    LCCCS<GoldilocksRingNTT>,
    Witness<GoldilocksRingNTT>,
    LFProof<GoldilocksRingNTT>,
) {
    let mut prover_transcript =
        PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();

    let (folded_acc, folded_w_acc, folding_proof) =
        NIFSProver::<
            GoldilocksRingNTT,
            GoldiLocksDP,
            PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
        >::prove(acc, w_acc, cm_i, w_i, &mut prover_transcript, ccs, scheme)
        .expect("NIFS proving failed for a step");

    #[cfg(feature = "debug")]
    verify_folding(&acc, &cm_i, &folding_proof, &ccs);

    (folded_acc, folded_w_acc, folding_proof)
}

#[cfg(feature = "debug")]
#[instrument(skip_all, level = Level::DEBUG)]
fn verify_folding(
    acc: &LCCCS<GoldilocksRingNTT>,
    cm_i: &CCCS<GoldilocksRingNTT>,
    folding_proof: &LFProof<GoldilocksRingNTT>,
    ccs: &CCS<GoldilocksRingNTT>,
) {
    use latticefold::nifs::NIFSVerifier;

    let mut verifier_transcript =
        PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();

    NIFSVerifier::<
        GoldilocksRingNTT,
        GoldiLocksDP,
        PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
    >::verify(&acc, &cm_i, &folding_proof, &mut verifier_transcript, &ccs)
    .expect("Final proof verification failed");
}
