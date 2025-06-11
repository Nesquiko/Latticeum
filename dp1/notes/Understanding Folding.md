Folding implements [[Folding Schemes#IVC (Incrementally Verifiable Computation)|IVC]] without using SNARKs. Reading Nova, I gave myself few questions:
### What is augmented function?

Quote from Nova paper:

```
In other words, the circuit satisfiability instance that the prover proves at each incremental step computes a step of the incremental computation and includes a circuit for the computation of the verifier in the non-interactive folding scheme for relaxed R1CS.
```

Here is a pseudo code for the folding circuit:

```javascript
// This entire function is what gets converted into a single R1CS circuit.
// The prover must provide a witness that satisfies all the constraints inside.
function AugmentedStep(
    // Inputs from previous IVC step
    U_prev, W_prev, 
    
    // Inputs for current VM step
    s_prev, s_curr, instruction_witness
) {
    // === Part 1: Arithmetize the current VM step ===
    // Create a "fresh" R1CS instance 'u_curr' that claims the VM step is correct.
    // This instance connects the public hashes of the before and after states.
    // The witness 'w_curr' contains the private register values, etc.
    let (u_curr, w_curr) = ArithmetizeVMStep(s_prev, s_curr, instruction_witness);

    // === Part 2: Perform the Folding Verifier's Logic ===
    // This part of the circuit enforces that the folding is done correctly.
    // It takes the previous accumulator (U_prev) and the fresh instance (u_curr)
    // and computes the new accumulator (U_next).
    
    // The prover provides the cross-term commitment 'T' as part of the witness.
    let T_commitment = get_witness("cross_term_commitment");
    
    // The verifier logic computes the new folded instance U_next.
    // This is just algebra based on the folding rules.
    let U_next = FoldingVerifierLogic(U_prev, u_curr, T_commitment);

    // === Part 3: Return the new state ===
    // The output of this entire computation is the new accumulated instance.
    // The prover also computes the new accumulated witness 'W_next' on the side.
    let W_next = FoldWitnesses(W_prev, w_curr, ...);
    
    return (U_next, W_next);
}
```

### Where do i prove the correct state transition?

In folding scheme, there is no proving like in SNARKs. In the above pseudo-code the `let (u_curr, w_curr) = ArithmetizeVMStep(s_prev, s_curr, instruction_witness);` line constructs a claim.

- `u_curr` - A R1CS instance, this instance is a public data structure containing `hash(s_prev)` and `hash(s_curr)`
- `w_curr` - A R1CS witness, this witness contains the private data like the values of the registers involved in the instruction.

The proof happens because the R1CS constraints for `AugmentedStep` include constraints that check if `w_curr` is a valid witness for `u_curr`.
### Where do I prove correct link between `i-1` step and current one?

The public inputs, in Nova it is $u_i.x$, contain a hash of outputs of step `i-1` and this is checked in current step that inputs match that hash, thus the link is correct.
### Where do i prove the correct folding?

The `FoldingVerifierLogic` function implements the algebraic update rules for folding. For example, it enforces that the new slack scalar `u_next` is computed as `U_prev + r * u_curr`.

The R1CS circuit enforces that the output instance `U_next` was correctly computed from the input instances `U_prev` and `u_curr` and the cross-term commitment `T_commitment`.

This is the "proof of folding." It's not a separate SNARK; it's a set of algebraic checks that are part of the very same R1CS circuit that also checks the VM execution.
### How to do first step?
The Initial Accumulated Instance (`U_0`), is a special, publicly known instance of the Relaxed R1CS relation that is satisfied by a default witness. It essentially represents the claim "zero steps have been executed correctly," which is always true.

Typically, this means the public inputs `x` are zero, the slack scalar `u` is zero (or one, depending on the scheme's details), and the error commitment `E` is a commitment to the zero vector.

The Initial Witness (`W_0`), is the corresponding default witness, which is simply the zero vector. This `(U_0, W_0)` pair is the starting point for our recursion. It's the "proof" for step 0.
### How do I prove the Fiat-Shamir was done correctly?

It is proved in the folding verifier, which recomputes the randomness $r = hash(vk, u_1, u_2, \tilde{T})$.
### How do I prove the whole execution?

After folding is done, there one proof $\pi_n$, this can then be wrapped in a SNARK which proves "I know a witness $W_N$ that satisfies the instance $U_N$." And the instance `U_N` is an instance of the Relaxed R1CS relation corresponding to the `AugmentedStep` function.

Verifier is given the definition of the `AugmentedStep` R1CS, public parts of the final accumulated instance `U_n`a and the final proof $\pi_n$