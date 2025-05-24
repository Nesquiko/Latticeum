SNARK for R1CS relations.

Prover has $(pp, \mathbb{x}, \mathbb{w}) \in R_{R1CS}$, where

- $pp = (\mathbb{F}, A, B, C, n, l)$
  - $A$, $B$, $C$ are matrices $\in \mathbb{F}^{n \times n}$
- $\mathbb{x} = (x)$ where $x$ is a vector $\in \mathbb{F}^l$
- $\mathbb{w} = (w)$ where $w$ is a vector $in \mathbb{F}^{n - 1 - l}$

Prover claims that $Az \cdot Bz = Cz$, where $\cdot$ is component wise
multiplication of two vectors: $u = (u_1, \ldots, u_t)$ and $v = (v_1, \ldots, v_t)$
then $u \cdot v = (u_1v_1, \ldots, u_tv_t)$

$Az$ is a vector, which for entry $x \in \{0,1\}^{\log{n}}$

$$
Az = \begin{pmatrix}\vdots\\ \sum_{y \in \{0,1\}^{\log{n}}} A_{xy} \times z_y \\ \vdots \end{pmatrix} =
\begin{pmatrix}\vdots\\ \sum_{y \in \{0,1\}^{\log{n}}} \tilde{A}(xy) \times \tilde{z}(y) \\ \vdots \end{pmatrix}
$$

Each row can be written like $\phi_A(X) = \sum_{y \in \{0,1\}^{\log{n}}} \tilde{A}(X, y)\times\tilde{z}(y)$, so when we
plug in some $X$ we get that row of the $Az$ vector. So $\phi_A(X)$ is the
MLE of $Az$.

Prover claims that

$$
Az \cdot Bz = Cz \iff \begin{pmatrix}
\begin{pmatrix} \vdots\\ \sum A_{xy} \times Z{y} \\\vdots \end{pmatrix} \times
\begin{pmatrix} \vdots\\ \sum B_{xy} \times Z{y} \\\vdots \end{pmatrix} -
\begin{pmatrix} \vdots\\ \sum C_{xy} \times Z{y} \\vdots \end{pmatrix} =
\begin{pmatrix} \vdots\\ 0 \\\vdots \end{pmatrix}
\end{pmatrix}
$$

Which holds only if $g(X) = \phi_A(X) \times \phi_B(X) - \phi_C(X) = 0$. $g(X) is
multivariate polynomial of $\log{n}$ variables. $P$ and $V$ run zerocheck
protocol for $g(X)$:

1. $V$ sends random point $r \in \mathbb{F}^{\log{n}}$
2. $P$ and $V$ run sumcheck for the claim that $\sum_{x \in \{0,1\}^{\log{n}}} \times \tilde{eq}(r, x) = 0$
3. This reduces initial claim to the claim $g(r') = v$ for certain $r' \in \mathbb{F}^{\log{n}}, v \in \mathbb{F}$ and $g(r') = \phi_A(r') \times \phi_B(r') - \phi_C(r')$
4. $P$ provides $V_A, V_B, V_C$ to $V$, and claims that $V_A = \phi_A(r'), V_B = \ldots$
5. $V$ checks $V_A \times V_B - V_C = v$
6. $P$ left to prove $V_A = \phi_A(r'), V_B = \ldots$
