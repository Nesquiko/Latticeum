$R$ is the committed R1CS relation. HyperNova uses high degree
generalization of R1CS, called CCS. [[CCS]] can be though of as R1CS
with more matrices, e.g. $(A_1z \cdot A_2z \cdot A_3z) + (B_1z \cdot B_2z) + \ldots = 0$

$R_{R1CS} = (pp, \mathbb{x}, \mathbb{w})$ such that:

- $pp = (\mathbb{F}, A, B, C, n, l)$
  - $A$, $B$, $C$ are matrices $\in \mathbb{F}^{n \times n}$
- $\mathbb{x} = (x)$ where $x$ is a vector $\in \mathbb{F}^l$
- $\mathbb{w} = (w)$ where $w$ is a vector $in \mathbb{F}^{n - 1 - l}$

And relation $(A \cdot z) \times (B \cdot z) = Cz$ where $z = (x, 1, w)$

$R_{committed\;R1CS} = (pp, x, w)$, only difference is in in $\mathbb{x}$:

- $\mathbb{x} = (x, comm_w)$ where $x$ is a vector $\in \mathbb{F}^l$ and $comm_w$ is commitment to
  the witness $w$

The $comm_w$ is required in the folding scheme to uphold security guarantees.

$R_{acc}$ is committed linearized R1CS (CCS) relation.

$R_{acc} = (pp, \mathbb{x}, \mathbb{w})$ such that:

- $pp = (\mathbb{F}, A, B, C)$
  - $A$, $B$, $C$ are matrices $\in \mathbb{F}^{n \times n}$
- $\mathbb{x} = (x, r, V_A, V_B, V_C, comm_w)$ where
  - $x$ is a vector $\in \mathbb{F}^l$
  - $r$ is an evaluation point (so, a vector $\in \mathbb{F}^{\log{n}}$ )
  - $V_A$, $V_B$, $V_C$ are field elements $\in \mathbb{F}$
  - $comm_w$ is commitment to $w$
- $\mathbb{w} = (w)$ where $w$ is a vector $in \mathbb{F}^{n - 1 - l}$

There are key properties:

- $\sum_{y \in \{0, 1\}^{\log(n)}} \tilde{A}(r, y) \tilde{z}(y) = V_A$
- $\sum_{y \in \{0, 1\}^{\log(n)}} \tilde{B}(r, y) \tilde{z}(y) = V_B$
- $\sum_{y \in \{0, 1\}^{\log(n)}} \tilde{C}(r, y) \tilde{z}(y) = V_C$

Where $\tilde{A}, \tilde{B}, \tilde{C}$ are [[MLE - Multi-linear extension|MLEs]], for more see [[Spartan]].

## Folding

$(pp, \mathbb{x}, \mathbb{w}) \in R_{R1CS}$
$(pp, \mathbb{x}', \mathbb{w}') \in R_{linearized\;R1CS}$

$P$ and $V$ run the zerocheck as described in [[Spartan]] to transform
$(pp, \mathbb{x}, \mathbb{w}) \in R_{R1CS}$ into $(pp, \mathbb{x_0}, \mathbb{w_0}) \in R_{linearized\;R1CS}$.

$\mathbb{x_0} = (x_0, r_0, V_{A0}, V_{B0}, V_{C0}, comm_{w_0})$
$\mathbb{x'} = (x', r', V_A', V_B', V_C', comm_{w'})$

### Assume $r_0 = r' = r$

$x_0$ and $x'$ are true only if

$$
\begin{matrix}
\sum_{y \in \{0, 1\}^{\log(n)}} \tilde{A}(r, y) \times \tilde{z_0}(y) = V_{A0} \; z_0 = (x_0, 1, w_0)\\
\sum_{y \in \{0, 1\}^{\log(n)}} \tilde{A}(r, y) \times \tilde{z}'(y) = V_A' \; z_0 = (x', 1, w')
\end{matrix}
$$

$V$ sends a random $\alpha \in \mathbb{F}$ and it holds $\sum \tilde{A}(r, y) \times (\tilde{z_0}(y) + \alpha\tilde{z'}(y)) = V_{A0} + \alpha V_A'$.
The accumulated witness will come from

$$
\begin{matrix}
z_3 = z_0 + \alpha z' = (x_0, 1, w_0) + \alpha (x', 1, w')\\
V_{A3} = V_{A0} + \alpha V_A'\\
comm_{w_3} = comm(w_0 + \alpha w') = comm(w_0) + \alpha comm(w')
\end{matrix}
$$
