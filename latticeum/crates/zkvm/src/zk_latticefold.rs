use ark_ff::{Field, PrimeField};
use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::decomposition_parameters::DecompositionParams;
use latticefold::nifs::decomposition::DecompositionProver;
use latticefold::nifs::decomposition::LFDecompositionProver;
use latticefold::nifs::folding::FoldingProver;
use latticefold::nifs::folding::LFFoldingProver;
use latticefold::nifs::linearization::LFLinearizationProver;
use latticefold::nifs::linearization::LinearizationProver;
use latticefold::{
    arith::{CCCS, CCS, LCCCS, Witness, error::CSError},
    commitment::AjtaiCommitmentScheme,
    nifs::{LFProof, error::LatticefoldError},
    transcript::Transcript,
};
use stark_rings::cyclotomic_ring::models::goldilocks::Fq3;

use crate::{ccs::GoldiLocksDP, fiat_shamir::Poseidon2Transcript};

/// Modified version of latticefold's NIFSProver::prove to better accomodate
/// collection of variables needed to check folding proof inside CCS
pub fn zk_latticefold_prove(
    acc: &LCCCS<GoldilocksRingNTT>,
    w_acc: &Witness<GoldilocksRingNTT>,
    cm_i: &CCCS<GoldilocksRingNTT>,
    w_i: &Witness<GoldilocksRingNTT>,
    transcript: &mut Poseidon2Transcript,
    ccs: &CCS<GoldilocksRingNTT>,
    scheme: &AjtaiCommitmentScheme<GoldilocksRingNTT>,
) -> Result<
    (
        LCCCS<GoldilocksRingNTT>,
        Witness<GoldilocksRingNTT>,
        LFProof<GoldilocksRingNTT>,
    ),
    LatticefoldError<GoldilocksRingNTT>,
> {
    sanity_check(ccs)?;

    absorb_public_input(acc, cm_i, transcript);
    // TODO collect absorbtions here from transcript

    let (linearized_cm_i, linearization_proof) =
        LFLinearizationProver::<_, Poseidon2Transcript>::prove(cm_i, w_i, transcript, ccs)?;

    let (mz_mles_l, decomposed_lcccs_l, decomposed_wit_l, decomposition_proof_l) =
        LFDecompositionProver::<_, Poseidon2Transcript>::prove::<GoldiLocksDP>(
            acc, w_acc, transcript, ccs, scheme,
        )?;
    let (mz_mles_r, decomposed_lcccs_r, decomposed_wit_r, decomposition_proof_r) =
        LFDecompositionProver::<_, Poseidon2Transcript>::prove::<GoldiLocksDP>(
            &linearized_cm_i,
            w_i,
            transcript,
            ccs,
            scheme,
        )?;

    let (mz_mles, lcccs, wit_s) = {
        let mut lcccs = decomposed_lcccs_l;
        let mut lcccs_r = decomposed_lcccs_r;
        lcccs.append(&mut lcccs_r);

        let mut wit_s = decomposed_wit_l;
        let mut wit_s_r = decomposed_wit_r;
        wit_s.append(&mut wit_s_r);

        let mut mz_mles = mz_mles_l;
        let mut mz_mles_r = mz_mles_r;
        mz_mles.append(&mut mz_mles_r);
        (mz_mles, lcccs, wit_s)
    };

    let (folded_lcccs, wit, folding_proof) = LFFoldingProver::<_, Poseidon2Transcript>::prove::<
        GoldiLocksDP,
    >(&lcccs, wit_s, transcript, ccs, &mz_mles)?;

    Ok((
        folded_lcccs,
        wit,
        LFProof {
            linearization_proof,
            decomposition_proof_l,
            decomposition_proof_r,
            folding_proof,
        },
    ))
}

/// Modified version of the sanity_check from latticefold library, because it isn't
/// exposed as public.
fn sanity_check(ccs: &CCS<GoldilocksRingNTT>) -> Result<(), LatticefoldError<GoldilocksRingNTT>> {
    if ccs.m != usize::max((ccs.n - ccs.l - 1) * GoldiLocksDP::L, ccs.m).next_power_of_two() {
        return Err(CSError::InvalidSizeBounds(ccs.m, ccs.n, GoldiLocksDP::L).into());
    }

    Ok(())
}

/// Modified version of the absorb_public_input from latticefold library, because it isn't
/// exposed as public.
fn absorb_public_input(
    acc: &LCCCS<GoldilocksRingNTT>,
    cm_i: &CCCS<GoldilocksRingNTT>,
    transcript: &mut Poseidon2Transcript,
) {
    transcript.absorb_field_element(&<Fq3 as Field>::from_base_prime_field(
        <Fq3 as Field>::BasePrimeField::from_be_bytes_mod_order(b"acc"),
    ));

    transcript.absorb_slice(&acc.r);
    transcript.absorb_slice(&acc.v);
    transcript.absorb_slice(acc.cm.as_ref());
    transcript.absorb_slice(&acc.u);
    transcript.absorb_slice(&acc.x_w);
    transcript.absorb(&acc.h);

    transcript.absorb_field_element(&<Fq3 as Field>::from_base_prime_field(
        <Fq3 as Field>::BasePrimeField::from_be_bytes_mod_order(b"cm_i"),
    ));

    transcript.absorb_slice(cm_i.cm.as_ref());
    transcript.absorb_slice(&cm_i.x_ccs);
}
