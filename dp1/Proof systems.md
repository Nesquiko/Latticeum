[source](https://zcash.github.io/halo2/index.html)

## [Proof systems](https://zcash.github.io/halo2/concepts/proofs.html)

- proves a statement, public and private inputs that make the statement hold.
- relation _R_ specifies which combination of public and private inputs are valid
- implementation of _R_ is called **circuit**
- language used to express the **circuit** is called **arithmetization**
  - sometimes the process of expressing _R_ as a circuit is also sometimes called "arithmetization"
- to create a proof, prover needs to know private and public inputs and intermediate (**advice**) values
- **advice** values are computed from private and public inputs with the **circuit**
- private inputs and advice values are collectively called a **witness**
  - witness can also be used as synonym for private inputs

### Example: prove preimage of hashed value

- private input: preimage _x_
- public input: digest _y_
- relation: $R = \{(x, y) : H(x) = y\}$
- advice: all of the intermediate values in the circuit implementing the hash function
- witness: _x_ and the advice

### Non-interactive Argument

Allows prover to create a proof for a given statement and witness. Proof is used
to convince verifier that there exists a witness for which the statement holds.
The security property that such proofs can't falsely convince a verifier is called
soundness.

### Non-interactive Argument of Knowledge (NARK)

Further convinces the verifier that the prover **knew** a witness for which the
statement holds. This security property is called knowledge soundness, and it
implies soundness.

Formalized by saying there exists an **extractor**, which can observer how the
proof is generated and must be able to compute the witness.

If the proof yields no additional information (just that prover knew) about
a witness, then the proof system is **zero knowledge**.

If a proof is "short" (poly-logarithmic in the circuit size) then it is **succinct**.
Which is then called **Succinct Non-interactive Argument of Knowledge (SNARK)**.
