use crate::{
    ccs::CCSLayout,
    crypto_consts::{FULL_ROUNDS, M_I_INVERSE_TRANSPOSED, MDS_INVERSE_TRANSPOSED, PARTIAL_ROUNDS},
    poseidon2::{
        GOLDILOCKS_S_BOX_DEGREE, INTERNAL_CONSTS, WIDE_POSEIDON2_13_SPONGE_PASSES,
        WIDE_POSEIDON2_RATE, WIDE_POSEIDON2_WIDTH, WIDTH_16_EXTERNAL_CONSTS,
    },
};
use ark_std::log2;
use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::arith::CCS;
use num_traits::identities::One;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use stark_rings_linalg::SparseMatrix;
use std::ops::Neg;

pub type Ring = GoldilocksRingNTT;

#[derive(Debug)]
pub struct CCSBuilder<'a> {
    /// number of constraints = number of rows in matrices[i]
    m: usize,
    /// layout of the witness vector, also used to derive `n` = number of variables
    layout: &'a CCSLayout,
    /// vector of selector matrices (otherwise known as `M`)
    matrices: Vec<SparseMatrix<Ring>>,
    /// vector of multisets which signal which matrices to use in constraint (otherwise known as `S`)
    multisets: Vec<Vec<usize>>,
    /// vector of coefficients to be used in constraint (otherwise known as `c`)
    coeffs: Vec<Ring>,
}

impl<'a> CCSBuilder<'a> {
    fn new<const W: usize>(layout: &'a CCSLayout) -> Self {
        Self {
            m: W,
            layout,
            matrices: Vec::new(),
            multisets: Vec::new(),
            coeffs: Vec::new(),
        }
    }

    pub fn create_riscv_ccs<const W: usize>(layout: &'a CCSLayout) -> CCS<Ring> {
        let mut builder = Self::new::<W>(layout);

        // risc-v specific
        builder.pc_non_branching_constraint();
        builder.add_constraint();
        builder.jal_constraint();
        builder.jalr_constraint();
        builder.bne_constraint();
        builder.auipc_constraint();
        builder.lui_constraint();

        // ivc specific

        builder.ivc_step_after_initial_mds();
        builder.ivc_step_external_initial_rounds();
        builder.ivc_step_internal_rounds();
        builder.ivc_step_external_terminal_rounds_sponge_pass_1();

        builder.build()
    }

    fn ivc_step_after_initial_mds(&mut self) {
        let matrix_base_idx = self.matrices.len();

        let ivc_h_i_state_0_comm_idx = self.layout.ivc_h_i_state_0_comm_idx;
        let ivc_h_i_state_i_comm_idx = self.layout.ivc_h_i_state_i_comm_idx;
        let acc_comm_idx = self.layout.ivc_h_i_acc_i_comm_idx;

        // last round of first sponge pass after external terminal
        let after_external_term_idx: [usize; WIDE_POSEIDON2_WIDTH] =
            self.layout.ivc_h_i_external_terminal[((FULL_ROUNDS / 2 - 1) * WIDE_POSEIDON2_WIDTH)
                ..((FULL_ROUNDS / 2) * WIDE_POSEIDON2_WIDTH)]
                .try_into()
                .expect("failed to convert slice into array of last indices");

        let mut m_after_mds = empty_sparse_matrix(self.m, self.layout.z_vector_size());

        let pass1_state_indices: [usize; WIDE_POSEIDON2_RATE] = [
            self.layout.ivc_h_i_step_idx,
            ivc_h_i_state_0_comm_idx[0],
            ivc_h_i_state_0_comm_idx[1],
            ivc_h_i_state_0_comm_idx[2],
            ivc_h_i_state_0_comm_idx[3],
            ivc_h_i_state_i_comm_idx[0],
            ivc_h_i_state_i_comm_idx[1],
            ivc_h_i_state_i_comm_idx[2],
            ivc_h_i_state_i_comm_idx[3],
            acc_comm_idx[0],
            acc_comm_idx[1],
            acc_comm_idx[2],
        ];

        let pass2_state_indices: [usize; WIDE_POSEIDON2_WIDTH] = [
            acc_comm_idx[3],
            after_external_term_idx[1],
            after_external_term_idx[2],
            after_external_term_idx[3],
            after_external_term_idx[4],
            after_external_term_idx[5],
            after_external_term_idx[6],
            after_external_term_idx[7],
            after_external_term_idx[8],
            after_external_term_idx[9],
            after_external_term_idx[10],
            after_external_term_idx[11],
            // capacity
            after_external_term_idx[12],
            after_external_term_idx[13],
            after_external_term_idx[14],
            after_external_term_idx[15],
        ];

        let m4_4_coeffs: [[u64; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

        for i in 0..WIDE_POSEIDON2_WIDTH {
            let coeff_idx = IVC_H_I_AFTER_MDS_CONSTR[i];
            let after_mds_result_idx = self.layout.ivc_h_i_after_mds_idx[i];

            let mut coeffs_in_row: [u64; WIDE_POSEIDON2_WIDTH] =
                std::iter::repeat(m4_4_coeffs[i % 4])
                    .take(4)
                    .flatten()
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("failed to convert from m4_4_coeffs to m4_4_coeffs_in_row");

            // at each row, the coeffs repeat, e.g. at row 0, the coeffs will be
            // |2a + 3b + 1c + 1d| + |2e + 3f + 1g + 1h| + |2i + 3j + 1k + 1l| + |2m + 3n + 1o + 1p|
            // but, different group of 4 has double the coeefs, e.g. the first group
            // |4a + 6b + 2c + 2d| + |2e + 3f + 1g + 1h| + |2i + 3j + 1k + 1l| + |2m + 3n + 1o + 1p|

            let doubled_group_start = (i / 4) * 4;
            for j in 0..4 {
                coeffs_in_row[doubled_group_start + j] *= 2;
            }

            let coeffs_in_row: [Ring; WIDE_POSEIDON2_WIDTH] = coeffs_in_row
                .map(|c| Ring::from(c))
                .try_into()
                .expect("failed to convert to ring elements");

            m_after_mds.coeffs[coeff_idx].push((Ring::one(), after_mds_result_idx));

            if i < WIDE_POSEIDON2_WIDTH {
                for k in 0..pass1_state_indices.len() {
                    m_after_mds.coeffs[coeff_idx]
                        .push((coeffs_in_row[k].neg(), pass1_state_indices[k]));
                }
            } else {
                for k in 0..pass2_state_indices.len() {
                    m_after_mds.coeffs[coeff_idx]
                        .push((coeffs_in_row[k].neg(), pass2_state_indices[k]));
                }
            }
        }

        self.matrices.push(m_after_mds);

        self.multisets.push(vec![matrix_base_idx]);
        self.coeffs.push(Ring::one());
    }

    fn ivc_step_external_initial_rounds(&mut self) {
        let after_init_mds_idx = self.layout.ivc_h_i_after_mds_idx;
        let after_external_init_rounds_idx = self.layout.ivc_h_i_external_initial;
        let external_layers = WIDTH_16_EXTERNAL_CONSTS;
        let external_initial_consts = external_layers.get_initial_constants();
        assert_eq!(external_initial_consts.len(), FULL_ROUNDS / 2);

        let number_of_rounds = FULL_ROUNDS / 2;
        let sponge_passes = WIDE_POSEIDON2_13_SPONGE_PASSES;

        // Create 7 matrices for -(after_init_mds + constant)^7
        let idx_power7_base = self.matrices.len();

        for _ in 0..GOLDILOCKS_S_BOX_DEGREE {
            let mut m_add_round_consts = empty_sparse_matrix(self.m, self.layout.z_vector_size());

            // ==== Round 0 ====
            //  the input is after_init_mds, not the previous external initial round's output
            for pass in 0..sponge_passes {
                let sponge_pass_offset = pass * number_of_rounds * WIDE_POSEIDON2_WIDTH;

                for i in 0..WIDE_POSEIDON2_WIDTH {
                    let coeff_idx = IVC_H_EXT_INIT_ROUNDS_CONSTR[sponge_pass_offset + i];
                    let constant = external_initial_consts[0][i];

                    m_add_round_consts.coeffs[coeff_idx].push((
                        Ring::one(),
                        after_init_mds_idx[i + pass * WIDE_POSEIDON2_WIDTH],
                    ));
                    m_add_round_consts.coeffs[coeff_idx]
                        .push((from_goldilocks(constant), self.layout.const_1_idx));
                }
            }
            // ==== Round 0 ====

            for round in 1..number_of_rounds {
                let previous_round_idx_offset = (round - 1) * WIDE_POSEIDON2_WIDTH;
                let round_idx_offset = round * WIDE_POSEIDON2_WIDTH;

                for pass in 0..sponge_passes {
                    let sponge_pass_offset = pass * number_of_rounds * WIDE_POSEIDON2_WIDTH;

                    for i in 0..WIDE_POSEIDON2_WIDTH {
                        let coeff_idx =
                            IVC_H_EXT_INIT_ROUNDS_CONSTR[sponge_pass_offset + round_idx_offset + i];
                        let constant = external_initial_consts[round][i];

                        m_add_round_consts.coeffs[coeff_idx].push((
                            Ring::one(),
                            after_external_init_rounds_idx
                                [sponge_pass_offset + previous_round_idx_offset + i],
                        ));

                        m_add_round_consts.coeffs[coeff_idx]
                            .push((from_goldilocks(constant), self.layout.const_1_idx));
                    }
                }
            }

            self.matrices.push(m_add_round_consts);
        }

        // Multiset for -(after_init_mds + constant)^7 or -(previous_round + constant)^7
        let power7_multiset: Vec<usize> =
            (idx_power7_base..idx_power7_base + GOLDILOCKS_S_BOX_DEGREE).collect();
        self.multisets.push(power7_multiset);
        self.coeffs.push(Ring::one().neg());

        // Create 1 matrix for MDS^-1 * external_initial
        let idx_inverse_mds = self.matrices.len();
        let mut m_inverse_mds = empty_sparse_matrix(self.m, self.layout.z_vector_size());

        for round in 0..number_of_rounds {
            let round_idx_offset = round * WIDE_POSEIDON2_WIDTH;

            for pass in 0..sponge_passes {
                let sponge_pass_offset = pass * number_of_rounds * WIDE_POSEIDON2_WIDTH;

                for i in 0..WIDE_POSEIDON2_WIDTH {
                    let coeff_idx =
                        IVC_H_EXT_INIT_ROUNDS_CONSTR[sponge_pass_offset + round_idx_offset + i];

                    for (k, &coeff) in MDS_INVERSE_TRANSPOSED[i].iter().enumerate() {
                        m_inverse_mds.coeffs[coeff_idx].push((
                            from_goldilocks(coeff),
                            self.layout.ivc_h_i_external_initial
                                [sponge_pass_offset + round_idx_offset + k],
                        ));
                    }
                }
            }
        }

        self.matrices.push(m_inverse_mds);

        // Create 6 matrices for the 1^6 padding (to match degree 7)
        for _ in 0..(GOLDILOCKS_S_BOX_DEGREE - 1) {
            let mut m_one = empty_sparse_matrix(self.m, self.layout.z_vector_size());
            for i in 0..(sponge_passes * number_of_rounds * WIDE_POSEIDON2_WIDTH) {
                let coeff_idx = IVC_H_EXT_INIT_ROUNDS_CONSTR[i];
                m_one.coeffs[coeff_idx].push((Ring::one(), self.layout.const_1_idx));
            }
            self.matrices.push(m_one);
        }

        // Multiset for MDS^-1 * external_initial * 1^6
        let inverse_mds_multiset: Vec<usize> =
            (idx_inverse_mds..idx_inverse_mds + GOLDILOCKS_S_BOX_DEGREE).collect();
        self.multisets.push(inverse_mds_multiset);
        self.coeffs.push(Ring::one());
    }

    fn ivc_step_internal_rounds(&mut self) {
        // last round of first sponge pass after external initial
        let after_ext_init_sponge1_idx: [usize; WIDE_POSEIDON2_WIDTH] =
            self.layout.ivc_h_i_external_initial[((FULL_ROUNDS / 2 - 1) * WIDE_POSEIDON2_WIDTH)
                ..((FULL_ROUNDS / 2) * WIDE_POSEIDON2_WIDTH)]
                .try_into()
                .expect("failed to convert slice into array of last indices");

        let after_ext_init_sponge2_idx: [usize; WIDE_POSEIDON2_WIDTH] =
            self.layout.ivc_h_i_external_initial[((FULL_ROUNDS - 1) * WIDE_POSEIDON2_WIDTH)
                ..((FULL_ROUNDS) * WIDE_POSEIDON2_WIDTH)]
                .try_into()
                .expect("failed to convert slice into array of last indices");

        let after_ext_init_indices = [after_ext_init_sponge1_idx, after_ext_init_sponge2_idx];

        let after_internal_idx = self.layout.ivc_h_i_after_internal_idx;

        let internal_layers = INTERNAL_CONSTS;
        assert_eq!(internal_layers.len(), PARTIAL_ROUNDS);

        let number_of_rounds = PARTIAL_ROUNDS;
        let sponge_passes = WIDE_POSEIDON2_13_SPONGE_PASSES;

        // Create 7 matrices for -(s_in[0] + constant)^7
        let idx_state_0 = self.matrices.len();
        for _ in 0..GOLDILOCKS_S_BOX_DEGREE {
            // State 0 is the only one to which constant and sbox is applied
            let mut m_state_0 = empty_sparse_matrix(self.m, self.layout.z_vector_size());

            for round in 0..number_of_rounds {
                let constant = internal_layers[round];

                for (pass, after_ext_init_idx) in after_ext_init_indices
                    .iter()
                    .enumerate()
                    .take(sponge_passes)
                {
                    let sponge_pass_offset = pass * number_of_rounds * WIDE_POSEIDON2_WIDTH;

                    let round_idx_offset = round * WIDE_POSEIDON2_WIDTH;
                    let coeff_idx =
                        IVC_H_INTERNAL_ROUNDS_CONSTS[sponge_pass_offset + round_idx_offset];

                    if round == 0 {
                        // the input is after external initial, not the previous internal round's output
                        // last_external_internal_round_sponge_pass_X[0] + constant
                        m_state_0.coeffs[coeff_idx].push((Ring::one(), after_ext_init_idx[0]));
                        m_state_0.coeffs[coeff_idx]
                            .push((from_goldilocks(constant), self.layout.const_1_idx));
                    } else {
                        let previous_round_idx_offset =
                            sponge_pass_offset + (round - 1) * WIDE_POSEIDON2_WIDTH;
                        m_state_0.coeffs[coeff_idx]
                            .push((Ring::one(), after_internal_idx[previous_round_idx_offset]));
                        m_state_0.coeffs[coeff_idx]
                            .push((from_goldilocks(constant), self.layout.const_1_idx));
                    }
                }
            }
            self.matrices.push(m_state_0);
        }

        let power7_multiset: Vec<usize> =
            (idx_state_0..idx_state_0 + GOLDILOCKS_S_BOX_DEGREE).collect();
        // Multiset for -(s_in[0] + constant)^7
        self.multisets.push(power7_multiset);
        self.coeffs.push(Ring::one().neg());

        let idx_inverse_m_i = self.matrices.len();
        let mut m_inverse_m_i = empty_sparse_matrix(self.m, self.layout.z_vector_size());

        for round in 0..number_of_rounds {
            for (pass, after_ext_init_idx) in after_ext_init_indices
                .iter()
                .enumerate()
                .take(sponge_passes)
            {
                let sponge_pass_offset = pass * number_of_rounds * WIDE_POSEIDON2_WIDTH;
                let round_idx_offset = round * WIDE_POSEIDON2_WIDTH;

                for i in 0..WIDE_POSEIDON2_WIDTH {
                    let coeff_idx =
                        IVC_H_INTERNAL_ROUNDS_CONSTS[sponge_pass_offset + round_idx_offset + i];

                    for (k, &coeff) in M_I_INVERSE_TRANSPOSED[i].iter().enumerate() {
                        m_inverse_m_i.coeffs[coeff_idx].push((
                            from_goldilocks(coeff),
                            self.layout.ivc_h_i_after_internal_idx
                                [sponge_pass_offset + round_idx_offset + k],
                        ));
                    }

                    // state 0 has the whole add constant and sbox matrix (m_state_0)
                    // created above to be subtracted from the M_I^-1 * s_out,
                    // other states have just M_I^-1 * s_out - s_in
                    if i != 0 {
                        if round == 0 {
                            m_inverse_m_i.coeffs[coeff_idx].push((
                                Ring::one().neg(),
                                after_ext_init_idx[round_idx_offset + i],
                            ));
                        } else {
                            let previous_round_idx_offset = (round - 1) * WIDE_POSEIDON2_WIDTH;
                            m_inverse_m_i.coeffs[coeff_idx].push((
                                Ring::one().neg(),
                                after_internal_idx
                                    [sponge_pass_offset + previous_round_idx_offset + i],
                            ));
                        }
                    }
                }
            }
        }
        self.matrices.push(m_inverse_m_i);

        // Create 6 matrices for the 1^6 padding (to match degree 7)
        for _ in 0..(GOLDILOCKS_S_BOX_DEGREE - 1) {
            let mut m_one = empty_sparse_matrix(self.m, self.layout.z_vector_size());

            for i in 0..(sponge_passes * number_of_rounds * WIDE_POSEIDON2_WIDTH) {
                let coeff_idx = IVC_H_INTERNAL_ROUNDS_CONSTS[i];

                m_one.coeffs[coeff_idx].push((Ring::one(), self.layout.const_1_idx));
            }
            self.matrices.push(m_one);
        }

        // Multiset for M_I^-1 * internal * 1^6
        let inverse_m_i_multiset: Vec<usize> =
            (idx_inverse_m_i..idx_inverse_m_i + GOLDILOCKS_S_BOX_DEGREE).collect();
        self.multisets.push(inverse_m_i_multiset);
        self.coeffs.push(Ring::one());
    }

    fn ivc_step_external_terminal_rounds_sponge_pass_1(&mut self) {
        let after_last_round_internal_idx: [usize; WIDE_POSEIDON2_WIDTH] =
            self.layout.ivc_h_i_after_internal_idx[
            // last round of first sponge pass after internal rounds
            ((PARTIAL_ROUNDS-1) * WIDE_POSEIDON2_WIDTH)..(PARTIAL_ROUNDS*WIDE_POSEIDON2_WIDTH)
        ]
                .try_into()
                .expect("failed to convert slice into array of last indices");

        let after_external_term_rounds_idx = self.layout.ivc_h_i_external_terminal;
        let external_layers = WIDTH_16_EXTERNAL_CONSTS;
        let external_terminal_consts = external_layers.get_terminal_constants();
        assert_eq!(external_terminal_consts.len(), FULL_ROUNDS / 2);

        let number_of_rounds = FULL_ROUNDS / 2;

        // Create 7 matrices for -(after_init_mds + constant)^7
        let idx_power7_base = self.matrices.len();
        for _ in 0..GOLDILOCKS_S_BOX_DEGREE {
            let mut m_add_round_consts = empty_sparse_matrix(self.m, self.layout.z_vector_size());

            // ==== Round 0 ====
            //  the input is after_last_round_internal_idx, not the previous external initial round's output
            for i in 0..WIDE_POSEIDON2_WIDTH {
                let coeff_idx = IVC_H_EXT_TERM_ROUNDS_CONSTR[i];
                let constant = external_terminal_consts[0][i];
                m_add_round_consts.coeffs[coeff_idx]
                    .push((Ring::one(), after_last_round_internal_idx[i]));
                m_add_round_consts.coeffs[coeff_idx]
                    .push((from_goldilocks(constant), self.layout.const_1_idx));
            }
            // ==== Round 0 ====

            for round in 1..number_of_rounds {
                let previous_round_idx_offset = (round - 1) * WIDE_POSEIDON2_WIDTH;
                let round_idx_offset = round * WIDE_POSEIDON2_WIDTH;

                for i in 0..WIDE_POSEIDON2_WIDTH {
                    let coeff_idx = IVC_H_EXT_TERM_ROUNDS_CONSTR[round_idx_offset + i];

                    let constant = external_terminal_consts[round][i];

                    m_add_round_consts.coeffs[coeff_idx].push((
                        Ring::one(),
                        after_external_term_rounds_idx[previous_round_idx_offset + i],
                    ));

                    m_add_round_consts.coeffs[coeff_idx]
                        .push((from_goldilocks(constant), self.layout.const_1_idx));
                }
            }

            self.matrices.push(m_add_round_consts);
        }

        // Multiset for -(after_init_mds + constant)^7 or -(previous_round + constant)^7
        let power7_multiset: Vec<usize> =
            (idx_power7_base..idx_power7_base + GOLDILOCKS_S_BOX_DEGREE).collect();
        self.multisets.push(power7_multiset);
        self.coeffs.push(Ring::one().neg());

        // Create 1 matrix for MDS^-1 * external_initial
        let idx_inverse_mds = self.matrices.len();
        let mut m_inverse_mds = empty_sparse_matrix(self.m, self.layout.z_vector_size());

        for round in 0..number_of_rounds {
            let round_idx_offset = round * WIDE_POSEIDON2_WIDTH;

            for i in 0..WIDE_POSEIDON2_WIDTH {
                let coeff_idx = IVC_H_EXT_TERM_ROUNDS_CONSTR[round_idx_offset + i];

                for (k, &coeff) in MDS_INVERSE_TRANSPOSED[i].iter().enumerate() {
                    m_inverse_mds.coeffs[coeff_idx].push((
                        from_goldilocks(coeff),
                        self.layout.ivc_h_i_external_terminal[round_idx_offset + k],
                    ));
                }
            }
        }

        self.matrices.push(m_inverse_mds);

        // Create 6 matrices for the 1^6 padding (to match degree 7)
        for _ in 0..(GOLDILOCKS_S_BOX_DEGREE - 1) {
            let mut m_one = empty_sparse_matrix(self.m, self.layout.z_vector_size());
            for i in 0..(number_of_rounds * WIDE_POSEIDON2_WIDTH) {
                let coeff_idx = IVC_H_EXT_TERM_ROUNDS_CONSTR[i];
                m_one.coeffs[coeff_idx].push((Ring::one(), self.layout.const_1_idx));
            }
            self.matrices.push(m_one);
        }

        // Multiset for MDS^-1 * external_initial * 1^6
        let inverse_mds_multiset: Vec<usize> =
            (idx_inverse_mds..idx_inverse_mds + GOLDILOCKS_S_BOX_DEGREE).collect();
        self.multisets.push(inverse_mds_multiset);
        self.coeffs.push(Ring::one());
    }

    /// Adds an ADD constraint that handles 32-bit overflow:
    /// z[IS_ADD] * (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[VAL_RS1] - z[VAL_RS2]) = 0
    fn add_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_ADD]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[ADD_CONSTR].push((Ring::one(), self.layout.is_add_idx));

        // Matrix B: selects (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[VAL_RS1] - z[VAL_RS2])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[ADD_CONSTR].push((Ring::from(1u64 << 32), self.layout.has_overflown_idx)); // +2^32 * has_overflown
        m_b.coeffs[ADD_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx)); // +val_rd_out
        m_b.coeffs[ADD_CONSTR].push((Ring::one().neg(), self.layout.val_rs1_idx)); // -val_rs1
        m_b.coeffs[ADD_CONSTR].push((Ring::one().neg(), self.layout.val_rs2_idx)); // -val_rs2

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a PC constraint for non-branching instructions:
    /// (1 - z[IS_BRANCHING]) * (z[PC_OUT] - z[PC_IN] - z[INST_SIZE]) = 0
    fn pc_non_branching_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects (1 - z[IS_BRANCHING])
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[PC_NON_BRANCH_CONSTR].push((Ring::one(), self.layout.const_1_idx));
        m_a.coeffs[PC_NON_BRANCH_CONSTR].push((Ring::one().neg(), self.layout.is_branching_idx));

        // Matrix B: selects (z[PC_OUT] - z[PC_IN] - z[INSTRUCTION_SIZE])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[PC_NON_BRANCH_CONSTR].push((Ring::one(), self.layout.pc_out_idx));
        m_b.coeffs[PC_NON_BRANCH_CONSTR].push((Ring::one().neg(), self.layout.pc_in_idx));
        m_b.coeffs[PC_NON_BRANCH_CONSTR]
            .push((Ring::one().neg(), self.layout.instruction_size_idx));

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a JAL constraint that ensures the return address is written correctly:
    /// z[IS_JAL] * (z[VAL_RD_OUT] - (z[PC_IN] + z[INSTRUCTION_SIZE])) = 0
    fn jal_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_JAL]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[JAL_CONSTR].push((Ring::one(), self.layout.is_jal_idx));

        // Matrix B: selects (z[VAL_RD_OUT] - z[PC_IN] - z[INSTRUCTION_SIZE])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[JAL_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx));
        m_b.coeffs[JAL_CONSTR].push((Ring::one().neg(), self.layout.pc_in_idx));
        m_b.coeffs[JAL_CONSTR].push((Ring::one().neg(), self.layout.instruction_size_idx));

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a JALR constraint that ensures the return address is written correctly:
    /// z[IS_JALR] * (z[VAL_RD_OUT] - (z[PC_IN] + z[INSTRUCTION_SIZE])) = 0
    fn jalr_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_JALR]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[JALR_CONSTR].push((Ring::one(), self.layout.is_jalr_idx));

        // Matrix B: selects (z[VAL_RD_OUT] - z[PC_IN] - z[INSTRUCTION_SIZE])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[JALR_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx));
        m_b.coeffs[JALR_CONSTR].push((Ring::one().neg(), self.layout.pc_in_idx));
        m_b.coeffs[JALR_CONSTR].push((Ring::one().neg(), self.layout.instruction_size_idx));

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a BNE constraint that ensures the branch condition is correct:
    /// z[IS_BNE] * (1 - z[IS_BRANCHING]) * (z[VAL_RS1] - z[VAL_RS2]) = 0
    ///
    /// This constraint ensures that:
    /// - If is_branching = 0 (branch not taken), then rs1 - rs2 = 0, so rs1 = rs2
    /// - If is_branching = 1 (branch taken), then rs1 - rs2 != 0 and constraint becomes 0 * (...) = 0
    ///
    /// Since the Goldilocks field is used and it is proving a 32-bit machine,
    /// the rs1 - rs2 = 0 can be directly constrained.
    fn bne_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_BNE]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[BNE_CONSTR].push((Ring::one(), self.layout.is_bne_idx));

        // Matrix B: selects (1 - z[IS_BRANCHING])
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[BNE_CONSTR].push((Ring::one(), 0)); // constant 1 is at() index 0() in z-vector
        m_b.coeffs[BNE_CONSTR].push((Ring::one().neg(), self.layout.is_branching_idx));

        // Matrix C: selects (z[VAL_RS1] - z[VAL_RS2])
        let mut m_c = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_c.coeffs[BNE_CONSTR].push((Ring::one(), self.layout.val_rs1_idx));
        m_c.coeffs[BNE_CONSTR].push((Ring::one().neg(), self.layout.val_rs2_idx));

        self.matrices.push(m_a);
        self.matrices.push(m_b);
        self.matrices.push(m_c);

        // Multiset: A * B * C = IS_BNE * (1 - IS_BRANCHING) * (RS1 - RS2)
        self.multisets.push(vec![
            matrix_base_idx,
            matrix_base_idx + 1,
            matrix_base_idx + 2,
        ]);
        self.coeffs.push(Ring::one());
    }

    /// Adds an AUIPC constraint that handles 32-bit overflow:
    /// z[IS_AUIPC] * (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[PC_IN] - (z[IMM] * 2^12)) = 0
    ///
    /// AUIPC computes: rd = pc + (imm << 12) with 32-bit wrapping
    /// The constraint ensures this computation is performed correctly, including overflow handling.
    pub fn auipc_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_AUIPC]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[AUIPC_CONSTR].push((Ring::one(), self.layout.is_auipc_idx));

        // Matrix B: selects (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[PC_IN] - (z[IMM] * 2^12))
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[AUIPC_CONSTR].push((Ring::from(1u64 << 32), self.layout.has_overflown_idx)); // +2^32 * has_overflown
        m_b.coeffs[AUIPC_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx)); // +rd_out
        m_b.coeffs[AUIPC_CONSTR].push((Ring::one().neg(), self.layout.pc_in_idx)); // -pc_in
        m_b.coeffs[AUIPC_CONSTR].push((Ring::from(1u64 << 12).neg(), self.layout.imm_idx)); // -(imm * 2^12)

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    /// Adds a LUI constraint that ensures the computation is correct:
    /// z[IS_LUI] * (z[VAL_RD_OUT] - (z[IMM] * 2^12)) = 0
    ///
    /// LUI computes: rd = imm << 12 (load upper immediate)
    /// where z[IMM] contains the unshifted immediate value
    /// and the constraint performs the shift by multiplying by 2^12
    fn lui_constraint(&mut self) {
        let matrix_base_idx = self.matrices.len();

        // Matrix A: selects z[IS_LUI]
        let mut m_a = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_a.coeffs[LUI_CONSTR].push((Ring::one(), self.layout.is_lui_idx));

        // Matrix B: selects (z[VAL_RD_OUT] - (z[IMM] * 2^12))
        let mut m_b = empty_sparse_matrix(self.m, self.layout.z_vector_size());
        m_b.coeffs[LUI_CONSTR].push((Ring::one(), self.layout.val_rd_out_idx)); // +rd_out
        m_b.coeffs[LUI_CONSTR].push((Ring::from(1u64 << 12).neg(), self.layout.imm_idx)); // -(imm * 2^12)

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Multiset: A * B
        self.multisets
            .push(vec![matrix_base_idx, matrix_base_idx + 1]);
        self.coeffs.push(Ring::one());
    }

    pub fn build(self) -> CCS<Ring> {
        let mut ccs = CCS::<Ring> {
            m: self.m,
            n: self.layout.z_vector_size(), // z-vector structure: [x_ccs(1), 1, w_ccs(layout.size)] = layout.size + 2 total
            l: CCSLayout::X_ELEMS_SIZE,     // Number of public inputs (memory commitment)
            t: self.matrices.len(),
            q: self.multisets.len(),
            d: self.multisets.iter().map(|s| s.len()).max().unwrap_or(1),
            s: log2(self.m) as usize,
            s_prime: log2(self.layout.z_vector_size()) as usize,
            M: self.matrices,
            S: self.multisets,
            c: self.coeffs,
        };

        // The latticefold library will apply additional padding based on the formula:
        // len = max((n - l - 1) * L, m).next_power_of_two()
        // With our values: n=layout.size+1, l=0, L=1, m=original_m
        // This gives: len = max(layout.size, original_m).next_power_of_two()
        // Need to set dimensions to match this expected padding
        let latticefold_padded_size =
            usize::max((ccs.n - ccs.l - 1) * 1, self.m).next_power_of_two();

        ccs.m = latticefold_padded_size;
        ccs.s = log2(latticefold_padded_size) as usize;
        ccs.M.iter_mut().for_each(|mat| {
            mat.pad_rows(latticefold_padded_size);
        });

        ccs
    }
}

fn empty_sparse_matrix(m: usize, n: usize) -> SparseMatrix<GoldilocksRingNTT> {
    SparseMatrix {
        nrows: m,
        ncols: n,
        coeffs: vec![vec![]; m],
    }
}

fn from_goldilocks(g: Goldilocks) -> Ring {
    Ring::from(g.as_canonical_u64())
}

// Indices of the constraints
const ADD_CONSTR: usize = 0;
const PC_NON_BRANCH_CONSTR: usize = 1;
const JAL_CONSTR: usize = 2;
const JALR_CONSTR: usize = 3;
const BNE_CONSTR: usize = 4;
const AUIPC_CONSTR: usize = 5;
const LUI_CONSTR: usize = 6;

const IVC_H_I_AFTER_MDS_CONSTR_START: usize = 7;
const IVC_H_I_AFTER_MDS_CONSTR: [usize; 2 * WIDE_POSEIDON2_WIDTH] = {
    let mut arr = [0; 2 * WIDE_POSEIDON2_WIDTH];
    let mut i = 0;
    while i < 2 * WIDE_POSEIDON2_WIDTH {
        arr[i] = IVC_H_I_AFTER_MDS_CONSTR_START + i;
        i += 1;
    }
    arr
};

const IVC_H_EXT_INIT_ROUNDS_CONSTS_START: usize =
    IVC_H_I_AFTER_MDS_CONSTR[IVC_H_I_AFTER_MDS_CONSTR.len() - 1] + 1;
const IVC_H_EXT_INIT_ROUNDS_CONSTR: [usize; FULL_ROUNDS * WIDE_POSEIDON2_WIDTH] = {
    let mut arr = [0; FULL_ROUNDS * WIDE_POSEIDON2_WIDTH];
    let mut i = 0;
    while i < FULL_ROUNDS * WIDE_POSEIDON2_WIDTH {
        arr[i] = IVC_H_EXT_INIT_ROUNDS_CONSTS_START + i;
        i += 1;
    }
    arr
};

const IVC_H_INTERNAL_ROUNDS_CONSTS_START: usize =
    IVC_H_EXT_INIT_ROUNDS_CONSTR[IVC_H_EXT_INIT_ROUNDS_CONSTR.len() - 1] + 1;

const IVC_H_INTERNAL_ROUNDS_CONSTS: [usize;
    WIDE_POSEIDON2_13_SPONGE_PASSES * PARTIAL_ROUNDS * WIDE_POSEIDON2_WIDTH] = {
    const N: usize = WIDE_POSEIDON2_13_SPONGE_PASSES * PARTIAL_ROUNDS * WIDE_POSEIDON2_WIDTH;
    let mut arr = [0; N];
    let mut i = 0;
    while i < N {
        arr[i] = IVC_H_INTERNAL_ROUNDS_CONSTS_START + i;
        i += 1;
    }
    arr
};

const IVC_H_EXT_TERM_ROUNDS_CONSTS_START: usize =
    IVC_H_INTERNAL_ROUNDS_CONSTS[IVC_H_INTERNAL_ROUNDS_CONSTS.len() - 1] + 1;
const IVC_H_EXT_TERM_ROUNDS_CONSTR: [usize; FULL_ROUNDS * WIDE_POSEIDON2_WIDTH] = {
    const N: usize = FULL_ROUNDS * WIDE_POSEIDON2_WIDTH;
    let mut arr = [0; N];
    let mut i = 0;
    while i < N {
        arr[i] = IVC_H_EXT_TERM_ROUNDS_CONSTS_START + i;
        i += 1;
    }
    arr
};

#[cfg(feature = "debug")]
use crate::ivc::IVCStepInput;
#[cfg(feature = "debug")]
use tracing::{Level, instrument};

#[cfg(feature = "debug")]
#[instrument(skip_all, level = Level::DEBUG)]
pub fn check_relation_debug(
    ccs: &CCS<GoldilocksRingNTT>,
    z: &Vec<GoldilocksRingNTT>,
    ivc_step: &IVCStepInput,
) {
    use latticefold::arith::Arith;
    use vm::riscvm::riscv_isa::Instruction;

    let inst = ivc_step.trace.instruction.inst;

    match inst {
        Instruction::ADD { .. }
        | Instruction::ADDI { .. }
        | Instruction::BNE { .. }
        | Instruction::LUI { .. }
        | Instruction::AUIPC { .. }
        | Instruction::JAL { .. }
        | Instruction::JALR { .. }
        | Instruction::SW { .. } => {
            ccs.check_relation(z).unwrap_or_else(|e| {
                panic!("CCS relation failed for {:?}: {:?}", inst, e);
            });
        }
        inst => {
            panic!("unchecked instruction {:?}", inst);
        }
    }
}
