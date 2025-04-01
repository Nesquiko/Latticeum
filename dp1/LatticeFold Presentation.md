[source](https://www.youtube.com/watch?v=DVHfukc35xk)

## Monolithic SNARKS _[BCCT12](https://dl.acm.org/doi/10.1145/2488608.2488623)_

Generate whole proof at once.

- Pre-quantum: Groth16, Plonk, HyperPlonk, Spartan, Bulletproof
- Post-quantum
  - Hash based: STARK, Brakedown, Ligero, Basefold
  - Lattice based: Lattice Bulletproofs LaBRADOR
    - Large proof sizes and expensive (linear) verifier

Must fix the statement and gather witness before proving. e.g. block of 10K txs are executed correctly.
Prover needs to collect the txs and re-execute them, create a (large polynomial) transcript of the
execution and then start proving. Thus, large prover memory is needed and parallelization is hard.

## Piecemeal SNARKS _Valiant08, BCTV14, BCCT12_

### Based on **IVC/PCD**

#### IVC (Incrementally Verifiable Computation):

- a cryptographic primitive for proving the correctness of an iterated and incremental computation
- the output of step `i` of the computation is fed as input into step `i+1` of the computation

#### PCD (Proof Carrying Data):

- a generalization of IVC to a distributed computation that unfolds over time (i.e., occurs incrementally)
- key difference between **IVC** and **PCD** is that in **PCD** steps of the computation are linked together in an
  arbitrary directed acyclic graph (DAG), whereas in **IVC** the steps are linked in a simple path

Recursive SNARKS are a technique how to construct **IVC/PCD**, [the first implementation](https://eprint.iacr.org/2014/595)
of **PCD** uses recursive SNARKS.

### Ideas

- split the statement into multiple smaller chunks
- each chunk is for a **uniform** and smaller relation $R_{chk}$ where `chk` means chunk
  - [Mangrove NDCTB24](https://eprint.iacr.org/2024/416) an efficient transform from circuits to **uniform** statements
- prove the correctness of chunks recursively

#### Example [(image source)](https://youtu.be/DVHfukc35xk?si=YJBN_gyAAF-LeFDL&t=381)

Chunks are organized into a binary tree as leaf nodes:

![[binary-chunk-tree.png]]

Then recursively prove SNARK circuit, which:

- gets inputs $\pi_1$ and $\pi_2$ (which are recursive proofs of previous chunks/children) come from child nodes
- proves that they are correct
- verifier must have sublinear complexity, which prevents circuit bloat

![[binary-chunk-tree-proved.png]]

The root proof is the proof for the whole statement.

### Benefits

- small memory footprint, as chunk proofs are small
- can be parallelized easily

### Problem

Noticeable recursion overhead. The chunk SNARK verifier are expensive to represent.

## SNAKRs from Folding

I have two witnesses $w_1$ and $w_2$ for some relation, to which I also compute commitments $c_1$ and $c_2$. Then
after folding them returns a $w_{fd}$ and $c_{fd}$ (and a proof $\pi_{fd}$). Then folding verifier
only nneds to check the commitments and the proof, thus reducing check of two witnesses
$w_1$ and $w_2$ to one. To prove a chain of computation, fold previous $c_{fd}$ with the new commitment
and at the end there will be one commitment. But there is problem with authenticity, how to know that commitments
were folded in order and correctly...

### Piecemeal SNARKs

To also prove the authenticity, the folding verification will be embedded into
the relation, so that it proves:

1. $c_{i+1} = com(w_{i+1})$
2. The local computation/statement is correct
3. The folding verification was done correctly at each step

## Warm up: Folding for Ajtai commitment openings
