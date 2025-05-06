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
hypercube differ at one evaluation, their MLEs are distinct and
disagree nearly everywhere. The goal with MLEs is that verifier can
easily catch a lying prover.

## Matrix-vector multiplication in polynomial terms

$A = \begin{pmatrix} A_{11} & A_{1n}\\ \vdots & \vdots\\ A_{n1} & A_{nn}\end{pmatrix}$

or a can be looked at like a vector in $\mathbb{F}^{n^2}$. There are $n^2$ entries,
if it is flattened, then there will be a vector of $n^2$ entries.

Then the MLE of $A \rightarrow \tilde{A}(u_1, \ldots, u_{\log{n^2}})$. $\tilde{A}$ is multi-linear polynomial on
$\log{n^2} = 2\times\log{n}$.

To build $\tilde{A}(u) = \sum_{c} A_c\times\tilde{eq}(c, u)$, where $c$ runs over

$\{0, 1\}^{\log{n^2}} = \{0, 1\}^{2\times\log{n}} = \boxed{\{0, 1\}^{\log{n}}} \times \boxed{\{0, 1\}^{\log{n}}}$

Where the first boxed hypercube is indexing rows of matrix $A$ and
the second one indexes columns. We can write $u = (X,Y) = (X_1, \ldots, X_{\log{n}}, Y_1, \ldots, Y_{\log{n}})$ and then the sum which builds $\tilde{A}$
becomes:

$\sum\limits_{\substack{x \in \{0, 0\}^{\log{n}}\\y \in \{0, 0\}^{\log{n}}}} A_{xy} \times \tilde{eq}(x, y, X, Y) = \tilde{A}(X, Y)$

In the end we have a MLE of a matrix, in which $x, y \in \{0,1\}^{\log{n}} \times \{0,1\}^{\log{n}}; \tilde{A}(x,y) = A_{xy}$
