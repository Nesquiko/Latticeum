use std::sync::LazyLock;

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, MATRIX_DIAG_16_GOLDILOCKS, Poseidon2Goldilocks};
use p3_mds::MdsPermutation;
use p3_poseidon2::{ExternalLayerConstants, MDSMat4, add_rc_and_sbox_generic, matmul_internal};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use tracing::{Level, instrument};

use crate::crypto_consts::{
    FULL_ROUNDS, PARTIAL_ROUNDS, external_width_8_consts, external_width_16_consts,
    internal_constants_len_22,
};

/// Copied from Plonky3, because it is private...
/// Degree of the chosen permutation polynomial for Goldilocks, used as the Poseidon2 S-Box.
///
/// As p - 1 = 2^32 * 3 * 5 * 17 * ... the smallest choice for a degree D satisfying gcd(p - 1, D) = 1 is 7.
pub const GOLDILOCKS_S_BOX_DEGREE: usize = 7;

/// number of field elements in the output digest
pub const POSEIDON2_OUT: usize = 4;

pub type GoldilocksComm = [Goldilocks; POSEIDON2_OUT];

pub const ZERO_GOLDILOCKS_COMM: GoldilocksComm = [Goldilocks::ZERO; 4];

/// Total state size of the Poseidon2 permutation for memory and registers
/// commitments (rate + capacity). The permutation operates on arrays of WIDTH
/// field elements.
pub const POSEIDON2_WIDTH: usize = 8;

/// Number of field elements that can be absorbed per permutation call. This is
/// the "input size" of the sponge construction. Higher rate = faster hashing,
/// but lower security.
pub const POSEIDON2_RATE: usize = 4;

pub type Poseidon2Perm = Poseidon2Goldilocks<POSEIDON2_WIDTH>;
pub type Poseidon2Sponge =
    PaddingFreeSponge<Poseidon2Perm, POSEIDON2_WIDTH, POSEIDON2_RATE, POSEIDON2_OUT>;
pub type Poseidon2Compression =
    TruncatedPermutation<Poseidon2Perm, 2, POSEIDON2_OUT, POSEIDON2_WIDTH>;

pub const WIDTH_8_EXTERNAL_INITIAL_CONSTS: LazyLock<
    ExternalLayerConstants<Goldilocks, POSEIDON2_WIDTH>,
> = LazyLock::new(external_width_8_consts);

pub const INTERNAL_CONSTS: LazyLock<Vec<Goldilocks>> = LazyLock::new(internal_constants_len_22);

/// Total state size of the Poseidon2 permutation for state 0 commitment (rate + capacity).
/// The permutation operates on arrays of WIDTH field elements.
/// WIDTH = RATE + CAPACITY
pub const WIDE_POSEIDON2_WIDTH: usize = 16;

/// Number of field elements that can be absorbed per permutation call. This is
/// the "input size" of the sponge construction.
/// Higher rate = faster hashing, but lower security.
/// Security is (Capacity * field bits) / 2 = (4 * 64) / 2 = 128 bits of security
/// With CAPACITY=4 for 128-bit security, RATE = WIDTH - CAPACITY = 16 - 4 = 12
pub const WIDE_POSEIDON2_RATE: usize = 12;

pub const WIDE_POSEIDON2_13_SPONGE_PASSES: usize = WIDE_POSEIDON2_WIDTH / WIDE_POSEIDON2_RATE + 1;

#[derive(Clone)]
pub struct WideZkVMPoseidon2Perm {
    external_layer: ExternalLayerConstants<Goldilocks, WIDE_POSEIDON2_WIDTH>,
    internal_layer: Vec<Goldilocks>,
}

pub const WIDTH_16_EXTERNAL_CONSTS: LazyLock<
    ExternalLayerConstants<Goldilocks, WIDE_POSEIDON2_WIDTH>,
> = LazyLock::new(external_width_16_consts);

impl WideZkVMPoseidon2Perm {
    pub fn new(
        external_layer: ExternalLayerConstants<Goldilocks, WIDE_POSEIDON2_WIDTH>,
        internal_layer: Vec<Goldilocks>,
    ) -> Self {
        Self {
            external_layer,
            internal_layer,
        }
    }

    pub fn external_layer(&self) -> &ExternalLayerConstants<Goldilocks, WIDE_POSEIDON2_WIDTH> {
        &self.external_layer
    }
}

#[derive(Debug, Clone)]
pub struct PermutationIntermediateStates {
    pub after_initial_mds: [Goldilocks; WIDE_POSEIDON2_WIDTH],
    pub after_ext_init_rounds: [[Goldilocks; WIDE_POSEIDON2_WIDTH]; FULL_ROUNDS / 2],
    pub after_internal_rounds: [[Goldilocks; WIDE_POSEIDON2_WIDTH]; PARTIAL_ROUNDS],
    pub after_ext_terminal_rounds: [[Goldilocks; WIDE_POSEIDON2_WIDTH]; FULL_ROUNDS / 2],
}

/// impl taken from Permutation<[Goldilocks; WIDE_POSEIDON2_WIDTH]>
impl WideZkVMPoseidon2Perm {
    pub fn permute_mut(
        &self,
        state: &mut [Goldilocks; WIDE_POSEIDON2_WIDTH],
    ) -> PermutationIntermediateStates {
        let mut intermediate = PermutationIntermediateStates {
            after_initial_mds: [Goldilocks::default(); WIDE_POSEIDON2_WIDTH],
            after_ext_init_rounds: [[Goldilocks::default(); WIDE_POSEIDON2_WIDTH]; FULL_ROUNDS / 2],
            after_internal_rounds: [[Goldilocks::default(); WIDE_POSEIDON2_WIDTH]; PARTIAL_ROUNDS],
            after_ext_terminal_rounds: [[Goldilocks::default(); WIDE_POSEIDON2_WIDTH];
                FULL_ROUNDS / 2],
        };

        // Replaces Poseidon2 first part of `permute_mut`, the
        // `self.external_layer.permute_state_initial(state)`. The
        // `permute_state_initial` calls code block like this
        //
        // ```rust
        // external_initial_permute_state(
        //     state,
        //     self.external_layer.get_initial_constants(),
        //     add_rc_and_sbox_generic,
        //     &MDSMat4,
        // );
        // ```
        // which is unrolled into this

        let mat4 = MDSMat4 {};

        // the external initial permutation is the same as the later external terminal
        // one, but with different constants and a linear layer (the application of MDS) first.
        {
            mds_width_16_permutation(state, &mat4);
            intermediate.after_initial_mds = state.clone();

            for (round, init_consts) in self
                .external_layer()
                .get_initial_constants()
                .iter()
                .enumerate()
            {
                state
                    .iter_mut()
                    .zip(init_consts.iter())
                    .for_each(|(s, &rc)| add_rc_and_sbox_generic(s, rc));
                mds_width_16_permutation(state, &mat4);
                intermediate.after_ext_init_rounds[round] = state.clone();
            }
        }

        // replaces self.internal_layer.permute_state(state);
        for (round, &elem) in self.internal_layer.iter().enumerate() {
            add_rc_and_sbox_generic(&mut state[0], elem);
            matmul_internal(state, MATRIX_DIAG_16_GOLDILOCKS);
            intermediate.after_internal_rounds[round] = state.clone();
        }

        // replaces self.external_layer.permute_state_terminal(state);
        for (round, external_const) in self
            .external_layer()
            .get_terminal_constants()
            .iter()
            .enumerate()
        {
            state
                .iter_mut()
                .zip(external_const.iter())
                .for_each(|(s, &rc)| add_rc_and_sbox_generic(s, rc));
            mds_width_16_permutation(state, &mat4);
            intermediate.after_ext_terminal_rounds[round] = state.clone();
        }

        intermediate
    }
}

#[derive(Clone)]
pub struct WideZkVMPoseidon2 {
    perm: WideZkVMPoseidon2Perm,
}

impl WideZkVMPoseidon2 {
    pub fn new(
        external_layer: ExternalLayerConstants<Goldilocks, WIDE_POSEIDON2_WIDTH>,
        internal_layer: Vec<Goldilocks>,
    ) -> Self {
        Self {
            perm: WideZkVMPoseidon2Perm::new(external_layer, internal_layer),
        }
    }
}

#[derive(Clone)]
pub struct IntermediateStates {
    pub perm_states: Vec<PermutationIntermediateStates>,
}

impl WideZkVMPoseidon2 {
    #[instrument(skip_all, level = Level::DEBUG)]
    pub fn hash_iter<I>(&self, input: I) -> (GoldilocksComm, IntermediateStates)
    where
        I: IntoIterator<Item = Goldilocks>,
    {
        let mut state = [Goldilocks::default(); WIDE_POSEIDON2_WIDTH];
        let mut input = input.into_iter();

        let mut perm_states = Vec::new();

        'outer: loop {
            for i in 0..WIDE_POSEIDON2_RATE {
                if let Some(x) = input.next() {
                    state[i] = x;
                } else {
                    if i != 0 {
                        perm_states.push(self.perm.permute_mut(&mut state));
                    }
                    break 'outer;
                }
            }
            perm_states.push(self.perm.permute_mut(&mut state));
        }

        (
            state[..POSEIDON2_OUT]
                .try_into()
                .expect("failed to convert state to result"),
            IntermediateStates { perm_states },
        )
    }
}

/// Implement the matrix multiplication used by the external layer.
/// Given a 4x4 MDS matrix M, we multiply by the `4N x 4N` matrix
/// `[[2M M  ... M], [M  2M ... M], ..., [M  M ... 2M]]`.
/// Mutates the state inplace and returns its copy after applying the M_4.
#[inline(always)]
pub fn mds_width_16_permutation<MdsPerm4: MdsPermutation<Goldilocks, 4>>(
    state: &mut [Goldilocks; WIDE_POSEIDON2_WIDTH],
    mdsmat: &MdsPerm4,
) {
    // First, we apply M_4 to each consecutive four elements of the state.
    // In Appendix B's terminology, this replaces each x_i with x_i'.
    for chunk in state.chunks_exact_mut(4) {
        mdsmat.permute_mut(chunk.try_into().unwrap());
    }
    // Now, we apply the outer circulant matrix (to compute the y_i values).

    // We first precompute the four sums of every four elements.
    let sums: [Goldilocks; 4] = core::array::from_fn(|k| {
        (0..WIDE_POSEIDON2_WIDTH)
            .step_by(4)
            .map(|j| state[j + k].clone())
            .sum()
    });

    // The formula for each y_i involves 2x_i' term and x_j' terms for each j that equals i mod 4.
    // In other words, we can add a single copy of x_i' to the appropriate one of our precomputed sums
    state
        .iter_mut()
        .enumerate()
        .for_each(|(i, elem)| *elem += sums[i % 4].clone());
}
