Nova is a [[Folding schemes]], or I can think about it like a "pre-processing" step for SNARKS.

## Toy example

Matrix $A$, $x_i$, such that $Ax_i = \begin{pmatrix} 1 \ldots 1 \end{pmatrix}$. I as a `P` have two vectors $x_1$ and
$x_2$ and provide two commitments $\overline{x_1}$ and $\overline{x_2}$ to `V`. Instead of `P` sending
$x_1$ and $x_2$, `V` provides a random number $r$. `P` computes $x_1 + rx_2$ and, `V` computes $\overline{x_1} + r\overline{x_2}$ and requests opening from `P`. Then `V` checks that they equal. Two instances $x_1$ and $x_2$ were folded into just one.

## Generalization

A R1CS consists of 3 square matrices $A$, $B$, $C$ which define the structure of computation, and they are in relationship $AZ \cdot BZ = CZ$,
where $Z$ is a vector (so $AZ$ is a vector, $BZ$ is a vector, vector times vector is a vector). When $Z = Z_1 + rZ_2$ there will be crossterms (elements from both $Z_1$ and $Z_2$) in the relationship.

In order to cancel crossterms, we generalize the R1CS into a Relaxed R1CS in form $AZ \cdot BZ = uCZ + E$, where $u$ is a scalar and $E$ is "slug" vector. And the witness is $Z$, $u$ and $E$. $E$ "absorbs" crossterms.

Proving two statements with this form $AZ_1 \cdot BZ_1 = u_1CZ_1+E_1$, $AZ_2 \cdot BZ_2 = u_2CZ_2+E_2$, is equivalent to proving $AZ \cdot BZ = uCZ +E$, where $Z = Z_1 + rZ_2$, $u = u_1 + ru_2$, $E = E_1 + r^2E_2 + r(AZ_1 \cdot BZ_2 + AZ_2 \cdot BZ_1 - u_1CZ_2 - u_2CZ_1)$.

## New work

### [[HyperNova]]
Addresses problem in Nova, in higher degree setting there is an exponential blow-up in crossterms.

There is no $E$ in HyperNova, because $E$ has varying size which is expensive to commit to with Pedersen commitments.
### Mova, ProtoGalaxy
Mova shows that commitment to $E$ is not necessary. Mova is a variation of ProtoGalaxy
### KiloNova
Supports of folding different R1CS, matrices $A$, $B$ and $C$ are different.
### [[LatticeFold]]
Analog of HyperNova for [[Lattice based crypto|lattices]].