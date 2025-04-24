For $v$ variate polynomial $g(x_1, \ldots, x_v)$, it's MLE $\tilde{f}(x_1, \ldots, x_v)$ where
$\forall x \in {0, 1}^v$.

## Boolean hypercube

Fancy term for saying all possible combinations of 0s and 1s $\{0, 1\}^n$. E.g. for $n = 2$:

|     | 0   | 1   |
| --- | --- | --- |
| 0   | $a$ | $b$ |
| 1   | $c$ | $d$ |

If there is a function $f: \{0, 1\}^n \rightarrow \mathbb{F}$, there exists a unique multi-linear polynomial that has the same behavior over $\{0, 1\}^n$. This polynomial is called MLE $p$

$p(x_1, \ldots x_n) = f(x_1, \ldots x_n)$ where $\forall x_i \in \{0, 1\}^n$

|              | 0   | 1   | ... | $\mathbb{F}$ |
| ------------ | --- | --- | --- | ------------ |
| 0            | $a$ | $b$ |     |
| 1            | $c$ | $d$ |     |
| ...          |     |     |     |
| $\mathbb{F}$ |
There are many polynomial that can extend $f$, but only one is
multi-linear (bold claim, but I believe it). The $p$ can be found with
Lagrange interpolation. Multi-linear means that there are only
linear factors in the polynomial (so no $x_1^2$)

Sum-check protocols typically use functions like $f$ (defined over a
small domain, over a boolean hypercube). The MLEs are used for
distance amplification, so that when two functions over boolean
hypercube differ at one evaulation, their MLEs are distinct and
disagree nearly everywhere. The goal with MLEs is that verifier can
easily catch a lying prover.
