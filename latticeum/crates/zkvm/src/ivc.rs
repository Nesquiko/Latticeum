use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::{
    arith::{LCCCS, Witness, r1cs::to_F_vec},
    nifs::LFProof,
};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_poseidon2::ExternalLayerConstants;
use tracing::{Level, instrument};
use vm::riscvm::inst::ExecutionTrace;

use crate::{
    ccs::{CCSLayout, set_ivc_witness, set_trace_witness},
    poseidon2::{GoldilocksComm, IntermediateStates, WIDE_POSEIDON2_WIDTH},
};

/// Holds the complete public and private state at the end of a single IVC step.
/// The data from this struct is used to construct the `IVCStepInput` for the *next* step.
pub struct IVCStepOutput {
    /// `h_i` public Poseidon2 commitment that seals the state of the completed IVC step `i`.
    /// this becomes the `ivc_step_comm` for step `i+1`.
    pub ivc_step_comm: (GoldilocksComm, IntermediateStates),

    /// `i` the number of the step that was just completed. Becomes `ivc_step` for step `i+1`.
    pub ivc_step: Goldilocks,

    /// The Poseidon2 commitment to the initial VM state before first step.
    /// It has different structure. It is a constant, its preimage is publicly
    /// known.
    pub z_0_comm: GoldilocksComm,

    /// The Poseidon2 commitment to the VM state `z_i` at the end of this step.
    /// Becomes `state_comm` for step `i+1`.
    pub z_i_comm: GoldilocksComm,

    /// The Poseidon2 commitment to the accumulator `U_i` at the end of this step.
    /// Becomes `acc_comm` for step `i+1`.
    pub acc_comm: GoldilocksComm,

    /// The new running accumulator `U_i`. Becomes `acc` for step `i+1`.
    pub acc: LCCCS<GoldilocksRingNTT>,

    /// The witness for the new running accumulator `U_i`. Becomes `w_acc` for step `i+1`.
    pub w_acc: Witness<GoldilocksRingNTT>,

    /// The folding proof `π_i` that was generated during this step.
    /// Becomes `folding_proof` for step `i+1`.
    pub folding_proof: Option<LFProof<GoldilocksRingNTT>>,
}

pub struct IVCStepInput<'a> {
    /// `h_{i - 1}` public poseidon2 commitment to the state of previous IVC step,
    /// and the poseidon2 intermediate states needed to enforce it in CCS.
    /// Preimage contains:
    /// - `i - 1`
    /// - state 0 commitment ([Self::state_0_comm])
    /// - state i - 1 commitment ([Self::state_comm])
    /// - accumulator at i - 1 commitment ([Self::acc_comm])
    pub ivc_step_comm: (GoldilocksComm, IntermediateStates),

    // ###############################################
    // ## [Self::ivc_step_comm] preimage components ##
    // ###############################################
    /// `i - 1`, the number of the previous step
    pub ivc_step: Goldilocks,

    /// poseidon2 commitment to the initial state of VM, doesn't need to be
    /// verified inside the CCS, because all preimage parts are public.
    pub state_0_comm: GoldilocksComm,

    /// poseidon2 commitment to state_{i-1} (or z_{i-1}). Preimage contains:
    /// - `pc`
    /// - merkle root of VM's memory
    /// - merkle root of VM's registers
    /// - poseidon2 of accumulated memory ops vector
    pub state_comm: GoldilocksComm,

    /// poseidon2 commitment to the accumulated instance as of previous IVC step,
    /// preimage contains all the fields of [LCCCS<GoldilocksRingNTT>].
    pub acc_comm: GoldilocksComm,

    /// preimage of [Self::acc_comm], accumulator as of `i - 1` and also
    /// needed to prove [Self::folding_proof].
    pub acc: &'a LCCCS<GoldilocksRingNTT>,

    /// folding proof needed to verify correct IVC step `i - 1` inside the CCS.
    /// When arithmetizing first step, there is not folding proof.
    pub folding_proof: Option<&'a LFProof<GoldilocksRingNTT>>,
    /// needed in verifying [Self::folding_proof] inside the CCS.
    pub w_acc: &'a Witness<GoldilocksRingNTT>,

    /// contains `pc` registers needed in preimage of [Self::state_comm],
    /// and also needed to prove correct execution of VM step.
    pub trace: &'a ExecutionTrace,

    /// poseidon2 width 16 external initial consts
    pub poseidon2_external_consts: &'a ExternalLayerConstants<Goldilocks, WIDE_POSEIDON2_WIDTH>,
}

#[instrument(skip_all, level = Level::DEBUG)]
pub fn arithmetize(input: &IVCStepInput, layout: &CCSLayout) -> Vec<GoldilocksRingNTT> {
    let mut z_vec = vec![0usize; layout.z_vector_size()];

    for i in layout.ivc_h_i_idx.clone() {
        z_vec[i] = input.ivc_step_comm.0[i].as_canonical_u64() as usize;
    }

    z_vec[layout.const_1_idx] = 1usize;

    set_ivc_witness(&mut z_vec, input, layout);
    set_trace_witness(&mut z_vec, input.trace, layout);

    to_F_vec(z_vec)
}
