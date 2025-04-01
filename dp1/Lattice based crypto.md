[source](https://www.youtube.com/watch?v=Mmqwedn__os)

## SIS - Short integer solutions \[Ajtai96\]

Problem $SIS(n, m, q, B)$ where $q$ is a prime number, $B$ is an error bound. Given a $n$ times $m$ matrix where each element is from a $Z_q$

$A \in_R Z^{n*m}_q$

find a non zero $z$, where elements $z_i$ are integers between $-B$ and $B$, such that

$Az = 0 (mod q)$

$z \in [-B, B]^m$, where $B << q/2$.

![[z_elements.png]]

![[z_elements_mod.png]]

The challenge is to find such $z$ where the components are "small".

If $n \ge m$ (matrix has more or equal rows as columns) then one expects that $Az = 0\;(mod\;q)$ has a unique solution $z = 0$ and no SIS solution exists, thus $n < m$ is assumed.

If $(B + 1)^m > q^n$ then, by the pigeonhole principle, there must exist $z_1, z_2 \in [-B/2, B/2]^m$, such that $z_1 \neq z_2$ and $Az_1 = Az_2 (mod q)$. Then $z = z_1 - z_2$.
There are $(B + 1)^m$ vectors $z$, because for each of the $m$ elements, I can choices from $[-B/2, B/2]$.
