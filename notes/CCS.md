CCS, a generalized R1CS:

$\sum_{i=1}^{q} c_i \cdot \left( \prod_{j \in S_i} (M_j \cdot z) \right) = \mathbf{0}$

where

- $\mathbf{z}$ is witness vector, for the ZKVM it will represent the state of single CPU step (PC, register values, instruction, ...)
- $\mathbf{M_j}$ are matrices which act like "selectors" or "linear combiners" that pick out and combine specific values from the witness vector. For example one matrix $M_j$ might be designed to output the value in register.
- $\mathbf{S_i}$ are multisets (sets that can contain multiple elements) of indices. Each $\mathbf{S_i}$ tells which of the $M_j * z$ terms to multiply.
	- If a mutltiset $S_i$ has 3 elements, the $\prod$ will be multiplying three terms together, resulting in degree-3 constraint. This is the "custom gate" logic.
- $\mathbf{c_i}$ are constant coefficients
- $\sum$ creates a sum of all products which must equal 0

## Code representation

This code is from [Nethermind/latticefold](https://github.com/NethermindEth/latticefold/blob/main/latticefold/src/arith.rs), which is an implementation of [[LatticeFold.pdf]].

```rust
pub struct CCS<R: Ring> {
    /// m: number of rows in M_i (such that M_i \in F^{m, n})
    pub m: usize,
    /// n = |z|, number of cols in M_i
    pub n: usize,
    /// l = |io|, size of public input/output
    pub l: usize,
    /// t = |M|, number of matrices
    pub t: usize,
    /// q = |c| = |S|, number of multisets
    pub q: usize,
    /// d: max degree in each variable
    pub d: usize,
    /// s = log(m), dimension of x
    pub s: usize,
    /// s_prime = log(n), dimension of y
    pub s_prime: usize,
    /// vector of matrices
    pub M: Vec<SparseMatrix<R>>,
    /// vector of multisets
    pub S: Vec<Vec<usize>>,
    /// vector of coefficients
    pub c: Vec<R>,
}
```

- **m** is the number of constraints/rows such that $M_i \in F^{m, n}$
- **n** the size of witness vector $\mathbf{z}$
- **l** the number of public inputs/outputs. These are part of $\mathbf{z}$ but are known to prover and verifier
- **t** total number of matrices
- **q** number of multisets, also corresponds to the number of product terms
- **d** max degree of constraints, also defines the maximum size of any subset $S_i$
- **s**, **s_prime** can be calculated $s = \log{m}$ and $s_{prime} = \log{n}$, refer to section [[#**s** and **s_prime**|s and s_prime]]
- **M** is a list of **t** selector matrices, most entries are 0
- **S** list of **q** multisets. **S[i]** is a list of indices $\mathbf{j}$ that tells the system to compute $\prod_{j \in S_i}{(M_j * z)}$
- **c** list of **q** coefficients

### **s** and **s_prime**
The **s** (dimension of x) and **s_prime** (dimension of y) refer to the number of variable in [[MLE - Multi-linear extension|MLEs]] that are used to represent constraints and witness vectors.