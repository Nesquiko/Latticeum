use crate::poseidon2::{
    INTERNAL_CONSTS, WIDE_POSEIDON2_RATE, WIDE_POSEIDON2_WIDTH, WIDTH_16_EXTERNAL_CONSTS,
    WideZkVMPoseidon2Perm,
};
use ark_ff::{Field, PrimeField};
use cyclotomic_rings::{
    challenge_set::LatticefoldChallengeSet,
    rings::{GoldilocksChallengeSet, GoldilocksRingNTT, GoldilocksRingPoly},
};
use latticefold::transcript::{Transcript, TranscriptWithShortChallenges};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use stark_rings::{
    PolyRing,
    cyclotomic_ring::models::goldilocks::{Fq, Fq3},
};

#[derive(Clone)]
pub struct Poseidon2Transcript {
    /// The sponge state: 16 Goldilocks field elements
    /// state[0..4] = capacity (never directly modified by absorption)
    /// state[4..16] = rate (12 elements where absorption occurs)
    state: [Goldilocks; WIDE_POSEIDON2_WIDTH],
    /// Current position in the rate portion (0..WIDE_POSEIDON2_RATE)
    absorb_index: usize,
    /// Buffer for squeezed bytes that haven't been consumed yet
    bytes_buffer: Vec<u8>,
}

impl Default for Poseidon2Transcript {
    fn default() -> Self {
        Self::new(&())
    }
}

impl Transcript<GoldilocksRingNTT> for Poseidon2Transcript {
    type TranscriptConfig = ();

    fn new(_config: &Self::TranscriptConfig) -> Self {
        Self {
            state: [Goldilocks::default(); WIDE_POSEIDON2_WIDTH],
            absorb_index: 0,
            bytes_buffer: Vec::new(),
        }
    }

    fn absorb(&mut self, v: &GoldilocksRingNTT) {
        // Convert ring element coefficients to base field elements (Goldilocks)
        // Each GoldilocksRingNTT element decomposes to 3 base field elements (Fq3)
        // and each Fq element is 64-bit, so fits in a single Goldilocks element
        let coeffs = v.coeffs();
        for coeff in coeffs.iter() {
            // Get the 3 base field elements representing this extension field element
            let base_elems: Vec<Fq> = coeff.to_base_prime_field_elements().collect();
            for elem in base_elems.iter() {
                // Convert from Fq to Goldilocks
                // Fq::into_bigint() returns a BigInt<1> which has a single u64
                let repr = elem.into_bigint();
                let u64_val = repr.0[0];
                let goldilocks_elem = Goldilocks::from_u64(u64_val);
                self.absorb_goldilocks(goldilocks_elem);
            }
        }
    }

    fn get_challenge(&mut self) -> Fq3 {
        // For GoldilocksRingNTT, the base ring is Fq3 which has extension degree 3
        let extension_degree = 3usize;

        // Squeeze field elements from the sponge
        let mut challenge_elems: Vec<Fq> = Vec::with_capacity(extension_degree);

        for _ in 0..extension_degree {
            let goldilocks_elem = self.squeeze_goldilocks();
            // Convert Goldilocks to Fq by using the canonical u64 value
            let u64_val = goldilocks_elem.as_canonical_u64();
            let fq = Fq::from(u64_val);
            challenge_elems.push(fq);
        }

        // Re-absorb the squeezed elements for domain separation (like original PoseidonTranscript)
        for elem in challenge_elems.iter() {
            let repr = elem.into_bigint();
            let u64_val = repr.0[0];
            let goldilocks_elem = Goldilocks::from_u64(u64_val);
            self.absorb_goldilocks(goldilocks_elem);
        }

        // Construct the Fq3 from base field elements
        Fq3::from_base_prime_field_elems(&challenge_elems)
            .expect("something went wrong: c does not contain 3 elements")
    }

    fn squeeze_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(n);

        // Use existing bytes buffer first
        while result.len() < n && !self.bytes_buffer.is_empty() {
            result.push(self.bytes_buffer.remove(0));
        }

        // If we still need more bytes, squeeze from the sponge
        while result.len() < n {
            let elem = self.squeeze_goldilocks();
            let bytes = elem.as_canonical_u64().to_le_bytes();

            // Take what we need
            let needed = n - result.len();
            let to_take = needed.min(8);
            result.extend_from_slice(&bytes[0..to_take]);

            // Store remaining bytes in buffer
            if to_take < 8 {
                self.bytes_buffer.extend_from_slice(&bytes[to_take..8]);
            }
        }

        result
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
    /// Absorb a single Goldilocks element into the sponge state
    fn absorb_goldilocks(&mut self, elem: Goldilocks) {
        // XOR-like absorption: add element to the rate portion
        // The rate starts at index 4 (capacity is indices 0-3)
        let rate_index = 4 + self.absorb_index;
        self.state[rate_index] = self.state[rate_index] + elem;
        self.absorb_index += 1;

        // If rate is full, permute
        if self.absorb_index >= WIDE_POSEIDON2_RATE {
            self.permute();
            self.absorb_index = 0;
        }
    }

    /// Squeeze a single Goldilocks element from the sponge state
    fn squeeze_goldilocks(&mut self) -> Goldilocks {
        // If there are pending absorptions, permute first
        if self.absorb_index > 0 {
            self.permute();
            self.absorb_index = 0;
        }

        // Clear the bytes buffer since we're switching modes
        self.bytes_buffer.clear();

        // Squeeze from the rate portion (first WIDE_POSEIDON2_RATE elements of rate)
        let rate_index = 4 + self.absorb_index;
        let result = self.state[rate_index];
        self.absorb_index += 1;

        // If we've squeezed all rate elements, permute and reset
        if self.absorb_index >= WIDE_POSEIDON2_RATE {
            self.permute();
            self.absorb_index = 0;
        }

        result
    }

    /// Apply the Poseidon2 permutation to the state
    fn permute(&mut self) {
        let perm =
            WideZkVMPoseidon2Perm::new(WIDTH_16_EXTERNAL_CONSTS.clone(), INTERNAL_CONSTS.clone());
        let _intermediate = perm.permute_mut(&mut self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;

    #[test]
    fn test_poseidon2_transcript_new() {
        let transcript = Poseidon2Transcript::default();
        assert_eq!(transcript.absorb_index, 0);
        assert!(transcript.bytes_buffer.is_empty());
    }

    #[test]
    fn test_absorb_and_get_challenge() {
        let mut transcript = Poseidon2Transcript::default();

        // Absorb some data - create Fq3 from base elements
        let base_elem = Fq::from(0xFFu32);
        let data = GoldilocksRingNTT::from(Fq3::new(base_elem, Fq::from(0u32), Fq::from(0u32)));
        transcript.absorb(&data);

        // Get a challenge
        let challenge: Fq3 = transcript.get_challenge();

        // Challenge should not be zero
        assert!(!challenge.is_zero());
    }

    #[test]
    fn test_squeeze_bytes() {
        let mut transcript = Poseidon2Transcript::default();

        // Squeeze some bytes
        let bytes = transcript.squeeze_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_get_short_challenge() {
        let mut transcript = Poseidon2Transcript::default();

        // Get a short challenge
        let challenge = transcript.get_short_challenge();

        // Challenge should have 24 coefficients
        assert_eq!(challenge.coeffs().len(), 24);
    }

    #[test]
    fn test_transcript_determinism() {
        // Two transcripts with same initial state and same absorptions should
        // produce same challenges
        let mut transcript1 = Poseidon2Transcript::default();
        let mut transcript2 = Poseidon2Transcript::default();

        // Absorb same data
        let base_elem = Fq::from(42u32);
        let data = GoldilocksRingNTT::from(Fq3::new(base_elem, Fq::from(0u32), Fq::from(0u32)));
        transcript1.absorb(&data);
        transcript2.absorb(&data);

        // Get challenges - they should be the same
        let challenge1: Fq3 = transcript1.get_challenge();
        let challenge2: Fq3 = transcript2.get_challenge();

        assert_eq!(challenge1, challenge2);
    }
}
