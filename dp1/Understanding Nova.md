[source](https://zkplabs.network/blog/understanding-nova-friendly-recursive-zero-knowledge-arguments-from-folding-schemes)

**IVC** = incrementally verifiable computation

### How is Nova formed

IVC allows prover to generate step-by-step proofs. Nova uses folding schemes to achieve IVC.

#### Folding scheme

- combines two instances of a problem into a single instance
- goal is to obtain a folded instance-witness pair that satisfies a relation if and only if the original instance-witness pair satisfies that relation
- folds the previous step's R1CS instance into the running relaxed R1CS instance

The verifier circuit in Nova is of constant size and primarily consists of two group scalar multiplications.