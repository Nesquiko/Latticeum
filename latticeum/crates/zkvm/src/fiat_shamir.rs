use crate::poseidon2::{
    INTERNAL_CONSTS, WIDE_POSEIDON2_RATE, WIDE_POSEIDON2_WIDTH, WIDTH_16_EXTERNAL_CONSTS,
    WideZkVMPoseidon2Perm,
};
use ark_ff::Field;
use ark_ff::PrimeField;
use cyclotomic_rings::{
    challenge_set::LatticefoldChallengeSet,
    rings::{GoldilocksChallengeSet, GoldilocksRingNTT, GoldilocksRingPoly},
};
use latticefold::transcript::{Transcript, TranscriptWithShortChallenges};
use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_poseidon2::ExternalLayerConstants;
use stark_rings::{
    PolyRing,
    cyclotomic_ring::models::goldilocks::{Fq, Fq3},
};

type Poseidon2Sponge =
    DuplexChallenger<Goldilocks, WideZkVMPoseidon2Perm, WIDE_POSEIDON2_WIDTH, WIDE_POSEIDON2_RATE>;

#[derive(Clone)]
pub struct Poseidon2Transcript {
    sponge: Poseidon2Sponge,

    pub absorbtions: Vec<Vec<GoldilocksRingNTT>>,
}

impl Default for Poseidon2Transcript {
    fn default() -> Self {
        Self::new(&(WIDTH_16_EXTERNAL_CONSTS.clone(), INTERNAL_CONSTS.clone()))
    }
}

impl Transcript<GoldilocksRingNTT> for Poseidon2Transcript {
    type TranscriptConfig = (
        ExternalLayerConstants<Goldilocks, WIDE_POSEIDON2_WIDTH>,
        Vec<Goldilocks>,
    );

    fn new(config: &Self::TranscriptConfig) -> Self {
        let perm = WideZkVMPoseidon2Perm::new(config.0.clone(), config.1.clone());
        let sponge = Poseidon2Sponge::new(perm);
        Self {
            sponge,
            absorbtions: Vec::new(),
        }
    }

    fn absorb(&mut self, v: &GoldilocksRingNTT) {
        for coeff in v.coeffs().iter() {
            let base_elems: Vec<Fq> = coeff.to_base_prime_field_elements().collect();
            for elem in base_elems.iter() {
                let u64_val = elem.0.0[0];
                let goldilocks_elem = Goldilocks::from_u64(u64_val);
                self.sponge.observe(goldilocks_elem);
            }
        }
    }

    fn absorb_slice(&mut self, v: &[GoldilocksRingNTT]) {
        self.absorbtions.push(v.to_vec());
        for ring in v {
            self.absorb(ring);
        }
    }

    fn get_challenge(&mut self) -> Fq3 {
        // sample 3 base field elements for Fq3 degree-3 extension
        let c0: Goldilocks = self.sponge.sample();
        let c1: Goldilocks = self.sponge.sample();
        let c2: Goldilocks = self.sponge.sample();

        self.sponge.observe(c0);
        self.sponge.observe(c1);
        self.sponge.observe(c2);

        // convert from p3_goldilocks::Goldilocks to arkworks Fq
        let fq0 = Fq::from(c0.as_canonical_u64());
        let fq1 = Fq::from(c1.as_canonical_u64());
        let fq2 = Fq::from(c2.as_canonical_u64());

        Fq3::from_base_prime_field_elems(&[fq0, fq1, fq2])
            .expect("Fq3 requires exactly 3 base field elements")
    }

    fn squeeze_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(n);
        let mut remaining = n;

        while remaining > 0 {
            let sample: Goldilocks = self.sponge.sample();
            let val = sample.as_canonical_u64();
            let sample_bytes: [u8; 8] = val.to_le_bytes();
            let to_take = remaining.min(8);
            bytes.extend_from_slice(&sample_bytes[..to_take]);
            remaining -= to_take;
        }

        bytes
    }
}

impl TranscriptWithShortChallenges<GoldilocksRingNTT> for Poseidon2Transcript {
    type ChallengeSet = GoldilocksChallengeSet;

    fn get_short_challenge(&mut self) -> GoldilocksRingPoly {
        let random_bytes = self.squeeze_bytes(Self::ChallengeSet::BYTES_NEEDED);

        Self::ChallengeSet::short_challenge_from_random_bytes(&random_bytes)
            .expect("not enough bytes to get a small challenge")
    }
}

impl Poseidon2Transcript {
    /// Modified squeeze_beta_challenges from latticefold's SqueezeBeta trait,
    /// which is crate private...
    pub fn squeeze_beta_challenges(&mut self, n: usize) -> Vec<GoldilocksRingNTT> {
        self.absorb_field_element(&<Fq3 as Field>::from_base_prime_field(
            <Fq3 as Field>::BasePrimeField::from_be_bytes_mod_order(b"beta_s"),
        ));

        self.get_challenges(n)
            .into_iter()
            .map(|x| x.into())
            .collect()
    }
}
