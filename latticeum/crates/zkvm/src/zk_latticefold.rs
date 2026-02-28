use ark_ff::{Field, PrimeField};
use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::commitment::Commitment;
use latticefold::decomposition_parameters::DecompositionParams;
use latticefold::nifs::decomposition::LFDecompositionProver;
use latticefold::nifs::decomposition::{DecompositionProof, DecompositionProver};
use latticefold::nifs::folding::FoldingProver;
use latticefold::nifs::folding::LFFoldingProver;
use latticefold::nifs::linearization::LFLinearizationProver;
use latticefold::nifs::linearization::LFLinearizationVerifier;
use latticefold::nifs::linearization::LinearizationProof;
use latticefold::nifs::linearization::LinearizationProver;
use latticefold::utils::sumcheck::IPForMLSumcheck;
use latticefold::utils::sumcheck::utils::EqEvalHelperVars;
use latticefold::utils::sumcheck::utils::zk_eq_eval;
use latticefold::utils::sumcheck::verifier::zk_interpolate_uni_poly;
use latticefold::{
    arith::{CCCS, CCS, LCCCS, Witness, error::CSError},
    commitment::AjtaiCommitmentScheme,
    nifs::{LFProof, error::LatticefoldError},
    transcript::Transcript,
};
use num_traits::Zero;
use stark_rings::Ring;
use stark_rings::cyclotomic_ring::models::goldilocks::Fq3;

use crate::poseidon2::GOLDILOCKS_S_BOX_DEGREE;
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

pub struct FoldingProofWitnessVars {
    pub linearization_vars: LinearizationVars,
    pub decomp_vars: DecompositionVars,
}

pub fn generate_verification_witness_vars(
    acc: &LCCCS<GoldilocksRingNTT>,
    cm_i: &CCCS<GoldilocksRingNTT>,
    proof: &LFProof<GoldilocksRingNTT>,
    ccs: &CCS<GoldilocksRingNTT>,
) -> FoldingProofWitnessVars {
    let mut transcript = Poseidon2Transcript::default();
    absorb_public_input(acc, cm_i, &mut transcript);

    let (linearized_cm_i, linearization_vars) =
        collect_linearization_vars(cm_i, &proof.linearization_proof, ccs, &mut transcript);

    let (decomposed_acc, decomp_vars) =
        collect_decomposition_vars(acc, &proof.decomposition_proof_l, &mut transcript);

    FoldingProofWitnessVars {
        linearization_vars,
        decomp_vars,
    }
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

// Collect (on ring element is 8 vectors of 3 u64s)
//  - linearization_proof.u (vector of ring elements)

pub struct LinearizationVars {
    pub beta_s: Vec<GoldilocksRingNTT>,
    pub evaluation_polynomials: Vec<Vec<GoldilocksRingNTT>>,
    pub claimed_sums: Vec<GoldilocksRingNTT>,
    pub claimed_sums_subterms: Vec<GoldilocksRingNTT>,

    /// in paper, or in latticefold lib `r`
    pub evaluation_point: Vec<GoldilocksRingNTT>,
    pub expected_evaluation: GoldilocksRingNTT,
    pub linearization_proof_u: Vec<GoldilocksRingNTT>,
    pub inner: GoldilocksRingNTT,
    pub inner_product_per_multiset: Vec<GoldilocksRingNTT>,
    pub e_helper_vars: EqEvalHelperVars<GoldilocksRingNTT>,
}

fn collect_linearization_vars(
    cm_i: &CCCS<GoldilocksRingNTT>,
    lin_proof: &LinearizationProof<GoldilocksRingNTT>,
    ccs: &CCS<GoldilocksRingNTT>,
    transcript: &mut Poseidon2Transcript,
) -> (LCCCS<GoldilocksRingNTT>, LinearizationVars) {
    let beta_s = transcript.squeeze_beta_challenges(ccs.s);

    let lin_sumcheck_vars = collect_linearization_sumcheck_vars(lin_proof, transcript, ccs);

    #[cfg(feature = "debug")]
    {
        use latticefold::nifs::linearization::LFLinearizationVerifier;

        let linearization_claim =
        LFLinearizationVerifier::<GoldilocksRingNTT, Poseidon2Transcript>::verify_evaluation_claim(
            &beta_s,
            &lin_sumcheck_vars.evaluation_point,
            lin_sumcheck_vars.expected_evaluation,
            lin_proof,
            ccs,
        );
        if let Err(err) = linearization_claim {
            tracing::error!("verification of linearization failed, error: {:?}", err);
            panic!("verification of linearization failed");
        }
    }
    let (_, e_helper_vars) = zk_eq_eval(&lin_sumcheck_vars.evaluation_point, &beta_s);

    assert_eq!(ccs.S.len(), ccs.c.len());
    let (inner, products_per_multiset) = ccs.c.iter().enumerate().fold(
        (GoldilocksRingNTT::ZERO, Vec::with_capacity(ccs.S.len())),
        |(inner, mut products), (i, &c)| {
            let multiset = &ccs.S[i];
            assert!(multiset.iter().all(|&j| j < lin_proof.u.len()));

            let multiset_product = multiset
                .iter()
                .map(|&j| lin_proof.u[j])
                .product::<GoldilocksRingNTT>();
            products.push(multiset_product);
            (inner + c * multiset_product, products)
        },
    );

    transcript.absorb_slice(&lin_proof.v);
    transcript.absorb_slice(&lin_proof.u);

    let lcccs = LFLinearizationVerifier::<_, Poseidon2Transcript>::prepare_verifier_output(
        cm_i,
        lin_sumcheck_vars.evaluation_point,
        lin_proof,
    );

    let vars = LinearizationVars {
        beta_s,
        evaluation_polynomials: lin_sumcheck_vars.polynomials,
        claimed_sums: lin_sumcheck_vars.claimed_sums,
        claimed_sums_subterms: lin_sumcheck_vars.claimed_sums_subterms,
        evaluation_point: lcccs.r.clone(),
        expected_evaluation: lin_sumcheck_vars.expected_evaluation,
        linearization_proof_u: lin_proof.u.clone(),
        inner,
        inner_product_per_multiset: products_per_multiset,
        e_helper_vars,
    };

    (lcccs, vars)
}

struct LinearizationSumcheckVars {
    polynomials: Vec<Vec<GoldilocksRingNTT>>,
    claimed_sums: Vec<GoldilocksRingNTT>,
    claimed_sums_subterms: Vec<GoldilocksRingNTT>,

    evaluation_point: Vec<GoldilocksRingNTT>,
    expected_evaluation: GoldilocksRingNTT,
}

/// Modified version of the LFLinearizationVerifier::verify_sumcheck_proof,
/// because it is private...
fn collect_linearization_sumcheck_vars(
    proof: &LinearizationProof<GoldilocksRingNTT>,
    transcript: &mut Poseidon2Transcript,
    ccs: &CCS<GoldilocksRingNTT>,
) -> LinearizationSumcheckVars {
    let linearization_expected_sum = GoldilocksRingNTT::zero();
    // The polynomial has degree <= ccs.d + 1 and log_m (ccs.s) vars.
    let nvars = ccs.s;
    let degree = ccs.d + 1;
    assert_eq!(degree, GOLDILOCKS_S_BOX_DEGREE + 1);

    transcript.absorb(&GoldilocksRingNTT::from(nvars as u128));
    transcript.absorb(&GoldilocksRingNTT::from(degree as u128));

    let mut verifier_state =
        IPForMLSumcheck::<GoldilocksRingNTT, Poseidon2Transcript>::verifier_init(nvars, degree);
    let lin_proof = &proof.linearization_sumcheck;

    let mut claimed_sum = linearization_expected_sum.clone();
    let mut eval_point = Vec::with_capacity(nvars);

    let mut claimed_sums = Vec::with_capacity(nvars + 1);
    let mut claimed_sums_subterms = Vec::with_capacity(nvars * ccs.s);
    claimed_sums.push(claimed_sum.clone());

    for i in 0..nvars {
        let prover_msg = lin_proof.0.get(i).expect("proof is incomplete");
        transcript.absorb_slice(&prover_msg.evaluations);

        let verifier_msg =
            IPForMLSumcheck::verify_round(prover_msg.clone(), &mut verifier_state, transcript);
        eval_point.push(verifier_msg.randomness);

        let interpolated =
            zk_interpolate_uni_poly(&prover_msg.evaluations, verifier_msg.randomness);
        claimed_sum = interpolated.0;
        claimed_sums_subterms.extend(interpolated.1);
        claimed_sums.push(claimed_sum.clone());

        transcript.absorb(&verifier_msg.randomness.into());
    }
    // populated in the verify_round, it comes from the prover evaluations
    let polynomials_received = verifier_state.polynomials_received.clone();

    #[cfg(feature = "debug")]
    {
        let subclaim =
            IPForMLSumcheck::<GoldilocksRingNTT, Poseidon2Transcript>::check_and_generate_subclaim(
                verifier_state,
                linearization_expected_sum,
            );

        match subclaim {
            Err(err) => {
                tracing::error!("check_and_generate_subclaim returned an error: {:?}", err);
                panic!("there was an error in check_and_generate_subclaim");
            }
            Ok(_subc) => {}
        };
    }

    LinearizationSumcheckVars {
        polynomials: polynomials_received,
        claimed_sums,
        claimed_sums_subterms,
        evaluation_point: eval_point.into_iter().map(|x| x.into()).collect(),
        expected_evaluation: claimed_sum,
    }
}

pub struct DecompositionVars {
    /// Commitment to `f`, where `f` is the witness after B-base decomposition
    /// of the original CCS witness (`w_ccs -> f` with params `B, L`).
    pub cm: Commitment<GoldilocksRingNTT>,

    /// Commitments to the `K` small-base limbs `f_i` from the second decomposition step
    /// (`f -> {f_i}` with base `B_SMALL`), expected to satisfy:
    /// `cm == sum_i (B_SMALL^i * y_s[i])`.
    pub y_s: Vec<Commitment<GoldilocksRingNTT>>,

    /// The evaluation of the linearized CCS commitment at `r`.
    pub v: Vec<GoldilocksRingNTT>,

    /// Evaluation claims about rows of $\hat{f}$-matrices of decomposed witnesses.
    ///
    /// After a run of the decomposition subprotocol prover this field contains `K` vectors of length 3
    pub v_s: Vec<Vec<GoldilocksRingNTT>>,

    /// The evaluation of the MLEs of {M_j z} at r.
    pub u: Vec<GoldilocksRingNTT>,

    /// Evaluation claims about decomposed witnesses for u.
    pub u_s: Vec<Vec<GoldilocksRingNTT>>,

    /// Statement part x_w from LCCCS.
    pub x_w: Vec<GoldilocksRingNTT>,

    /// Constant term h from LCCCS.
    pub h: GoldilocksRingNTT,

    /// Decomposed x vectors (each is x_w || h).
    pub x_s: Vec<Vec<GoldilocksRingNTT>>,
}

fn collect_decomposition_vars(
    cm_i: &LCCCS<GoldilocksRingNTT>,
    decomp_proof: &DecompositionProof<GoldilocksRingNTT>,
    transcript: &mut Poseidon2Transcript,
) -> (Vec<LCCCS<GoldilocksRingNTT>>, DecompositionVars) {
    let mut lcccs_s = Vec::<LCCCS<GoldilocksRingNTT>>::with_capacity(GoldiLocksDP::K);

    for (((x, y), u), v) in decomp_proof
        .x_s
        .iter()
        .zip(&decomp_proof.y_s)
        .zip(&decomp_proof.u_s)
        .zip(&decomp_proof.v_s)
    {
        transcript.absorb_slice(x);
        transcript.absorb_slice(y.as_ref());
        transcript.absorb_slice(u);
        transcript.absorb_slice(v);

        let h = x.last().cloned().expect("x_s is empty");
        lcccs_s.push(LCCCS {
            r: cm_i.r.clone(),
            v: v.clone(),
            cm: y.clone(),
            u: u.clone(),
            x_w: x[0..x.len() - 1].to_vec(),
            h,
        });
    }

    (
        lcccs_s,
        DecompositionVars {
            cm: cm_i.cm.clone(),
            y_s: decomp_proof.y_s.clone(),
            v: cm_i.v.clone(),
            v_s: decomp_proof.v_s.clone(),
            u: cm_i.u.clone(),
            u_s: decomp_proof.u_s.clone(),
            x_w: cm_i.x_w.clone(),
            h: cm_i.h,
            x_s: decomp_proof.x_s.clone(),
        },
    )
}
