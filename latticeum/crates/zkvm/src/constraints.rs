use crate::witness::ZVectorLayout;
use ark_std::log2;
use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::arith::CCS;
use num_traits::identities::One;
use stark_rings_linalg::SparseMatrix;
use std::ops::Neg;

type Ring = GoldilocksRingNTT;

#[derive(Debug)]
pub struct CCSBuilder<'a> {
    /// number of constraints = number of rows in matrices[i]
    m: usize,
    /// layout of the witness vector, also used to derive `n` = number of variables
    z_layout: &'a ZVectorLayout,
    /// vector of selector matrices (otherwise known as `M`)
    matrices: Vec<SparseMatrix<Ring>>,
    /// vector of multisets which signal which matrices to use in constraint (otherwise known as `S`)
    multisets: Vec<Vec<usize>>,
    /// vector of coefficients to be used in constraint (otherwise known as `c`)
    coeffs: Vec<Ring>,
    /// used to perform final check that the predefined number of constraints
    /// is how much of them were used
    used_constraints_counter: usize,
}

impl<'a> CCSBuilder<'a> {
    fn new(m: usize, z_layout: &'a ZVectorLayout) -> Self {
        Self {
            m,
            z_layout,
            matrices: Vec::new(),
            multisets: Vec::new(),
            coeffs: Vec::new(),
            used_constraints_counter: 0,
        }
    }

    pub fn create_riscv_ccs(z_layout: &'a ZVectorLayout) -> CCS<Ring> {
        let mut builder = Self::new(1, z_layout);
        builder.add_constraint();
        builder.build()
    }

    /// Adds an ADD constraint that handles 32-bit overflow:
    /// z[IS_ADD] * (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[VAL_RS1] - z[VAL_RS2]) = 0
    pub fn add_constraint(&mut self) {
        let last_matrix_idx = self.matrices.len();

        // Matrix A: selects z[IS_ADD]
        let mut m_a = empty_sparse_matrix(self.m, self.z_layout.size);
        m_a.coeffs[ADD_CONSTR].push((Ring::one(), self.z_layout.is_add));

        // Matrix B: selects (z[HAS_OVERFLOWN] * 2^32 + z[VAL_RD_OUT] - z[VAL_RS1] - z[VAL_RS2])
        let mut m_b = empty_sparse_matrix(self.m, self.z_layout.size);
        m_b.coeffs[ADD_CONSTR].push((Ring::from(1u64 << 32), self.z_layout.has_overflown)); // +2^32 * has_overflown
        m_b.coeffs[ADD_CONSTR].push((Ring::one(), self.z_layout.val_rd_out)); // +val_rd_out
        m_b.coeffs[ADD_CONSTR].push((Ring::one().neg(), self.z_layout.val_rs1)); // -val_rs1
        m_b.coeffs[ADD_CONSTR].push((Ring::one().neg(), self.z_layout.val_rs2)); // -val_rs2

        self.matrices.push(m_a);
        self.matrices.push(m_b);

        // Add multiset: A * B
        self.multisets
            .push(vec![last_matrix_idx, last_matrix_idx + 1]);
        self.coeffs.push(Ring::one());
        self.used_constraints_counter += 1;
    }

    pub fn build(self) -> CCS<Ring> {
        debug_assert_eq!(
            self.used_constraints_counter, self.m,
            "Expected {} constraints, but {} were added",
            self.used_constraints_counter, self.m
        );

        CCS::<Ring> {
            m: self.m,
            n: self.z_layout.size,
            l: 0,
            t: self.matrices.len(),
            q: self.multisets.len(),
            d: self.multisets.iter().map(|s| s.len()).max().unwrap_or(1),
            s: log2(self.m) as usize,
            s_prime: log2(self.z_layout.size) as usize,
            M: self.matrices,
            S: self.multisets,
            c: self.coeffs,
        }
    }
}

fn empty_sparse_matrix(m: usize, n: usize) -> SparseMatrix<GoldilocksRingNTT> {
    SparseMatrix {
        nrows: m,
        ncols: n,
        coeffs: vec![vec![]; m],
    }
}

// Indices of the constraints
const ADD_CONSTR: usize = 0;
