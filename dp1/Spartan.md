SNARK for R1CS relations.

Prover has $(pp, \mathbb{x}, \mathbb{w}) \in R_{R1CS}$, where

- $pp = (\mathbb{F}, A, B, C, n, l)$
  - $A$, $B$, $C$ are matrices $\in \mathbb{F}^{n \times n}$
- $\mathbb{x} = (x)$ where $x$ is a vector $\in \mathbb{F}^l$
- $\mathbb{w} = (w)$ where $w$ is a vector $in \mathbb{F}^{n - 1 - l}$

Prover claims that $Az \cdot Bz = Cz$, where $\cdot$ is component wise
multiplication of two vectors: $u = (u_1, \ldots, u_t)$ and $v = (v_1, \ldots, v_t)$
then $u \cdot v = (u_1v_1, \ldots, u_tv_t)$

TODO ended at https://youtu.be/4alOna5X3ro?si=9fzBIlt5Hdp8u24c&t=2133
