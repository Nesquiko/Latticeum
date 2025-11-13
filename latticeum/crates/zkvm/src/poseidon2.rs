use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, MATRIX_DIAG_16_GOLDILOCKS, Poseidon2Goldilocks};
use p3_poseidon2::{
    ExternalLayerConstants, MDSMat4, add_rc_and_sbox_generic, external_terminal_permute_state,
    internal_permute_state, matmul_internal, mds_light_permutation,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use tracing::{Level, instrument};

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

#[derive(Clone)]
pub struct WideZkVMPoseidon2Perm {
    external_layer: ExternalLayerConstants<Goldilocks, WIDE_POSEIDON2_WIDTH>,
    internal_layer: Vec<Goldilocks>,
}

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
}

#[derive(Clone)]
pub struct PermutationIntermediateStates {
    pub after_external_initial_mds: [Goldilocks; WIDE_POSEIDON2_WIDTH],
}

/// impl taken from Permutation<[Goldilocks; WIDE_POSEIDON2_WIDTH]>
impl WideZkVMPoseidon2Perm {
    fn permute_mut(
        &self,
        state: &mut [Goldilocks; WIDE_POSEIDON2_WIDTH],
    ) -> PermutationIntermediateStates {
        let mut intermediate = PermutationIntermediateStates {
            after_external_initial_mds: [Goldilocks::default(); WIDE_POSEIDON2_WIDTH],
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
        {
            tracing::warn!("{:?}", state);
            mds_light_permutation(state, &mat4);
            intermediate.after_external_initial_mds = state.clone();

            // TODO after mds constrain do this
            // After the initial mds_light_permutation, the remaining layers are identical
            // to the terminal permutation simply with different constants.
            external_terminal_permute_state(
                state,
                self.external_layer.get_initial_constants(),
                add_rc_and_sbox_generic,
                &mat4,
            )
        }

        // replaces self.internal_layer.permute_state(state);
        internal_permute_state(
            state,
            |x| matmul_internal(x, MATRIX_DIAG_16_GOLDILOCKS),
            &self.internal_layer,
        );

        // replaces self.external_layer.permute_state_terminal(state);
        external_terminal_permute_state(
            state,
            self.external_layer.get_terminal_constants(),
            add_rc_and_sbox_generic,
            &MDSMat4,
        );

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
