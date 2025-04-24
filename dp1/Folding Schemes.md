Deal with relations $R = \alpha(pp,\;x,\;W)$, where $pp = public\;parameters$[^1],
$x = instance\;or\;public\;inputs$, $W = witness$. For example: $R$ is an equation,
$x$ are coefficients and $w$ are concrete values that satisfy the
equation (when the $x$ instance is valid, there exists a solution $w$
for the equation)

A folding scheme for two relations $R$ and $R_{acc}$ (or $R_1$ and $R_2$) is a interactive protocol between `P` and `V` where:

- `P` has $(pp, x_1, w_1) \in R, (pp, x_2, w_2) \in R_{acc}$
- `V` has $(pp, x_1), (pp, x_2)$

And the result of their interaction is $(pp, x_3, w_3)$ (where `V` only knows $(pp, x_3)$ and $w_3$ is kept private for `P`)

## Requirements

1. **Perfect completeness**: If `P` is honest then $(pp, x_3, w_3) \in R_{acc}$
2. **Knowledge soundness**: If $(pp, x_3, w_3) \in R_{acc}$ w.n.p[^2], then $(pp, x_1, w_1) \in R$ and $(pp, x_2, w_2) \in R_{acc}$
   - more formally, but still not formal definition: For any `P` there exists an polynomial time algorithm `Extractor` that can rewind interactions and extract $w_1, w_2$

Thus, proving $(pp, x_1, w_1) \in R$ and $(pp, x_2, w_2) \in R_{acc}$ can be reduced to only
proving $(pp, x_3, w_3)$. From 2 tasks there is only one.

![[concept-folding.png]]

## IVC (Incrementally Verifiable Computation):

- a cryptographic primitive for proving the correctness of an iterated and incremental computation
- the output of step `i` of the computation is fed as input into step `i+1` of the computation

## PCD (Proof Carrying Data):

- a generalization of IVC to a distributed computation that unfolds over time (i.e., occurs incrementally)
- key difference between **IVC** and **PCD** is that in **PCD** steps of the computation are linked together in an
  arbitrary directed acyclic graph (DAG), whereas in **IVC** the steps are linked in a simple path

Recursive SNARKS are a technique how to construct **IVC/PCD**, [the first implementation](https://eprint.iacr.org/2014/595) of **PCD** uses recursive SNARKS.

## Benefits of folding

There are no FFTs, only multi-exponentiations, which doesn't
require big memory overhead and the steps of folding can be big if
needed.

No pairings, use existing `secp` curve. No need to switch curves like
in recursive SNARKs.

[^1]: They are only for formal description, in practice not used.

[^2]: With negligible probability
