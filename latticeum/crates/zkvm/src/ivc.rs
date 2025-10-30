use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::{
    arith::{LCCCS, Witness, r1cs::to_F_vec},
    nifs::LFProof,
};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use tracing::{Level, instrument};
use vm::riscvm::inst::ExecutionTrace;

use crate::{
    ccs::{CCSLayout, to_raw_witness},
    commitments::{GoldilocksComm, MemoryPageComm},
};

/// Holds the complete public and private state at the end of a single IVC step.
/// The data from this struct is used to construct the `IVCStepInput` for the *next* step.
pub struct IVCStepOutput {
    /// `h_i` public Poseidon2 commitment that seals the state of the completed IVC step `i`.
    /// this becomes the `ivc_step_comm` for step `i+1`.
    pub ivc_step_comm: GoldilocksComm,

    /// `i` the number of the step that was just completed. Becomes `ivc_step` for step `i+1`.
    pub ivc_step: Goldilocks,

    /// The Poseidon2 commitment to the VM state `z_i` at the end of this step.
    /// Becomes `state_comm` for step `i+1`.
    pub state_comm: GoldilocksComm,

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

// TODO needs the merkle opening of the VMs memory and also other things needed
// for verifying the folding proof, but that can wait a little.
pub struct IVCStepInput<'a> {
    /// `h_{i - 1}` public poseidon2 commitment to the state of previous IVC step.
    /// Preimage contains:
    /// - `i - 1`
    /// - state 0 commitment ([Self::state_0_comm])
    /// - state i - 1 commitment ([Self::state_comm])
    /// - accumulator at i - 1 commitment ([Self::acc_comm])
    pub ivc_step_comm: GoldilocksComm,

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
}

#[instrument(skip_all, level = Level::DEBUG)]
pub fn arithmetize(
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
    }: &IVCStepInput,
    layout: &CCSLayout,
) -> Vec<GoldilocksRingNTT> {
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

    to_F_vec(z_vec)
}
