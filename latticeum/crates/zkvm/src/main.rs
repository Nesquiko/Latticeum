mod ccs;
mod commitments;
mod constraints;

use ccs::to_raw_witness;
use cyclotomic_rings::rings::{GoldilocksChallengeSet, GoldilocksRingNTT, GoldilocksRingPoly};
use latticefold::{
    arith::{CCCS, CCS, LCCCS, Witness, r1cs::to_F_vec},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
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
use std::{path::PathBuf, usize};

use vm::riscvm::{inst::ExecutionTrace, vm::new_vm_1mb};

#[cfg(feature = "debug")]
use crate::constraints::check_relation_debug;
use crate::{
    ccs::{CCS_LAYOUT, CCSLayout, GoldiLocksDP, KAPPA, N},
    commitments::{GoldilocksComm, ZkVmCommitter},
    constraints::CCSBuilder,
};

fn main() {
    tracing_subscriber::fmt::init();

    tracing::debug!(
        "starting zkVM with decomposition params: B={}, L={}, B_SMALL={}, K={}",
        GoldiLocksDP::B,
        GoldiLocksDP::L,
        GoldiLocksDP::B_SMALL,
        GoldiLocksDP::K
    );

    let vm = new_vm_1mb();
    let program = PathBuf::from(
        "/home/nesquiko/fiit/dp/latticeum/target/riscv32imac-unknown-none-elf/release/fibonacci",
    );
    let mut vm = match vm.load_elf(program) {
        Ok(vm) => vm,
        Err(e) => panic!("failed to load `fibonacci` elf, {}", e),
    };

    let zkvm_commiter = ZkVmCommitter::new();
    let state_0_comm = zkvm_commiter.state_0_comm(&vm);

    let ccs = CCSBuilder::create_riscv_ccs::<N>(&CCS_LAYOUT);

    let mut rng = ark_std::test_rng();

    let scheme: AjtaiCommitmentScheme<GoldilocksRingNTT> =
        AjtaiCommitmentScheme::rand(KAPPA, N, &mut rng);

    let (mut acc, mut w_acc, mut current_mem_ops_comm) =
        initialize_accumulator(&ccs, &CCS_LAYOUT, &scheme);
    let mut folding_proof: Option<LFProof<GoldilocksRingNTT>> = None;

    let start_vm_run = std::time::Instant::now();

    let mut memory_ops = Vec::new();
    let mut cycles: usize = 0;
    let mut state_comm: GoldilocksComm = [Default::default(); 4];

    vm.run(|trace| {
        cycles = trace.cycle;

        zkvm_commiter.acc_comm(&acc);

        if let Some(memory_op) = trace.side_effects.memory_op.clone() {
            memory_ops.push(memory_op);
        }

        // let ivc_step = IVCStepInput {
        //     ivc_step_comm: todo!(),
        //     ivc_step: Goldilocks::from_usize(trace.cycle - 1),
        //     state_0_comm,
        //     state_comm,
        //     acc_comm: todo!(),
        //     trace: &trace,
        //     acc: &acc,
        //     folding_proof: folding_proof.as_ref(),
        //     w_acc: &w_acc,
        // };

        // let z = arithmetize(&trace, &CCS_LAYOUT, state_0_comm, state_comm);

        #[cfg(feature = "debug")]
        check_relation_debug(&ccs, &z, &trace);

        // let (cm_i, w_i) = commit(z, &ccs, &scheme);
        // (acc, w_acc, folding_proof) = fold(FoldingArgs {
        //     ccs: &ccs,
        //     scheme: &scheme,
        //     acc: &acc,
        //     w_acc: &w_acc,
        //     cm_i: &cm_i,
        //     w_i: &w_i,
        // });

        assert_eq!(ccs.s, acc.r.len());
        assert_eq!(
            GoldilocksRingPoly::dimension() / GoldilocksRingNTT::dimension(),
            acc.v.len()
        );
        assert_eq!(KAPPA, acc.cm.len());
        assert_eq!(ccs.t, acc.u.len());
        assert_eq!(ccs.l, acc.x_w.len());
    });

    assert_eq!(0xc594bfc3 /* 100th fibonacci */, vm.result());

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

const INITIAL_VM_COMM: GoldilocksComm = [Goldilocks::ZERO; 4];

fn initialize_accumulator(
    ccs: &CCS<GoldilocksRingNTT>,
    layout: &CCSLayout,
    scheme: &AjtaiCommitmentScheme<GoldilocksRingNTT>,
) -> (
    LCCCS<GoldilocksRingNTT>,
    Witness<GoldilocksRingNTT>,
    GoldilocksComm,
) {
    // create witness with private witness part only
    // the z-vector structure is [x_ccs, 1, w_ccs] = layout.size + 1 total
    // so the private witness (w_ccs) should be layout.w_size elements
    debug_assert_eq!(ccs.n - ccs.l - 1, layout.w_size);
    let zero_w_ccs = vec![GoldilocksRingNTT::zero(); layout.w_size];

    let zero_wit = Witness::from_w_ccs::<GoldiLocksDP>(zero_w_ccs);
    // initialize public inputs and output to memory comm in and memory comm out
    let zero_x_ccs = vec![
        GoldilocksRingNTT::from(INITIAL_VM_COMM[0].as_canonical_u64()),
        GoldilocksRingNTT::from(INITIAL_VM_COMM[1].as_canonical_u64()),
        GoldilocksRingNTT::from(INITIAL_VM_COMM[2].as_canonical_u64()),
        GoldilocksRingNTT::from(INITIAL_VM_COMM[3].as_canonical_u64()),
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

    (acc, zero_wit, INITIAL_VM_COMM)
}

// TODO needs the merkle opening of the VMs memory and also other things needed
// for verifying the folding proof.
struct IVCStepInput<'a> {
    /// `h_{i - 1}` public poseidon2 commitment to the state of previous IVC step.
    /// Preimage contains:
    /// - `i - 1`
    /// - state 0 commitment ([Self::state_0_comm])
    /// - state i - 1 commitment ([Self::state_comm])
    /// - accumulator at i - 1 commitment ([Self::acc_comm])
    ivc_step_comm: GoldilocksComm,

    // ###############################################
    // ## [Self::ivc_step_comm] preimage components ##
    // ###############################################
    /// `i - 1`, the number of the previous step
    ivc_step: Goldilocks,

    /// poseidon2 commitment to the initial state of VM, doesn't need to be
    /// verified inside the CCS, because all preimage parts are public.
    state_0_comm: GoldilocksComm,

    /// poseidon2 commitment to state_{i-1} (or z_{i-1}). Preimage contains:
    /// - `pc`
    /// - merkle root of VM's memory
    /// - merkle root of VM's registers
    /// - poseidon2 of accumulated memory ops vector
    state_comm: GoldilocksComm,

    /// poseidon2 commitment to the accumulated instance as of previous IVC step,
    /// preimage contains all the fields of [LCCCS<GoldilocksRingNTT>].
    acc_comm: GoldilocksComm,

    /// contains `pc` registers needed in preimage of [Self::state_comm],
    /// and also needed to prove correct execution of VM step.
    trace: &'a ExecutionTrace,

    /// preimage of [Self::acc_comm]
    acc: &'a LCCCS<GoldilocksRingNTT>,

    /// folding proof needed to verify correct IVC step inside the CCS.
    /// When arithmetizing first step, there is not folding proof.
    folding_proof: Option<&'a LFProof<GoldilocksRingNTT>>,
    /// needed in verifying [Self::folding_proof] inside the CCS.
    w_acc: &'a Witness<GoldilocksRingNTT>,
}

fn arithmetize(
    IVCStepInput {
        ivc_step_comm,
        ivc_step,
        state_0_comm,
        state_comm,
        acc_comm,
        trace,
        acc,
        folding_proof,
        w_acc,
    }: IVCStepInput,
    layout: &CCSLayout,
) -> Vec<GoldilocksRingNTT> {
    let start_witness_creation = std::time::Instant::now();

    // TODO put all the things into the to_raw_witness
    let raw_z = to_raw_witness(trace, layout);
    // convert raw z to proper z-vector structure [x_ccs, 1, w_ccs]
    let mut z_vec = Vec::new();

    // public inputs (x_ccs) = `h_{i - 1}` = ivc step commitment
    z_vec.push(ivc_step_comm[0].as_canonical_u64() as usize);
    z_vec.push(ivc_step_comm[1].as_canonical_u64() as usize);
    z_vec.push(ivc_step_comm[2].as_canonical_u64() as usize);
    z_vec.push(ivc_step_comm[3].as_canonical_u64() as usize);

    // constant 1
    z_vec.push(1usize);

    // witness elements (w_ccs)
    z_vec.extend(raw_z.iter().map(|&x| x as usize));

    let z_as_ring: Vec<GoldilocksRingNTT> = to_F_vec(z_vec);

    tracing::trace!(
        "witness creation: {:?} (size: {} elements)",
        start_witness_creation.elapsed(),
        layout.w_size,
    );

    z_as_ring
}

/// returns CCS witness commitment and the private witness
fn commit(
    z_as_ring: Vec<GoldilocksRingNTT>,
    ccs: &CCS<GoldilocksRingNTT>,
    scheme: &AjtaiCommitmentScheme<GoldilocksRingNTT>,
) -> (CCCS<GoldilocksRingNTT>, Witness<GoldilocksRingNTT>) {
    let start_commitment = std::time::Instant::now();
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

    tracing::trace!(
        "commited to witnes in {:?} (C={}, W={}, B={}, L={})",
        start_commitment.elapsed(),
        KAPPA,
        N,
        GoldiLocksDP::B,
        GoldiLocksDP::L
    );

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
    let folding_start = std::time::Instant::now();
    let mut prover_transcript =
        PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();

    // the folding proof is ignored here, because there needs to be just one
    // at the end of the whole folding
    let (folded_acc, folded_w_acc, folding_proof) =
        NIFSProver::<
            GoldilocksRingNTT,
            GoldiLocksDP,
            PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
        >::prove(acc, w_acc, cm_i, w_i, &mut prover_transcript, ccs, scheme)
        .expect("NIFS proving failed for a step");

    tracing::trace!("folded in {:?}", folding_start.elapsed());

    #[cfg(feature = "debug")]
    {
        use latticefold::nifs::NIFSVerifier;

        let verifying_start = std::time::Instant::now();
        let mut verifier_transcript =
            PoseidonTranscript::<GoldilocksRingNTT, GoldilocksChallengeSet>::default();
        NIFSVerifier::<
            GoldilocksRingNTT,
            GoldiLocksDP,
            PoseidonTranscript<GoldilocksRingNTT, GoldilocksChallengeSet>,
        >::verify(&acc, &cm_i, &folding_proof, &mut verifier_transcript, &ccs)
        .expect("Final proof verification failed");

        tracing::trace!("verified folding in {:?}", verifying_start.elapsed());
    }

    (folded_acc, folded_w_acc, folding_proof)
}
