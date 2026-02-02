## Polynomial rings
*"Generalization of integers"*

In lattice based, mostly cyclotomic rings are used $R = Z[x] / (x^d + 1);\quad d = 2^x$, where $d$ is some power of 2.

- set of polynomials with degree less than $d$
- addition in this ring is just by adding coefficients of the corresponding terms
- multiplication of two polynomials $a(x)$ and $b(x)$ (both of them are integer polynomials with degree less than $d$): $a(x) \cdot b(x) = f(x) \cdot (x^d + 1) + g(x)$
	- where $g(x) \in R$ is remainder polynomial which has degree less than $d$ and is the result of the multiplication
- norm for $R$: $||a(x)|| = max_{i=0}^{d-1} |a_i|$ where $a(x) = a_0x^0+a_1x^1+\ldots+a_{d-1}x^{d-1}$

To make arithmetic more efficient, the arithmetic happens over $Rq = R / qR$. This is similar, but the coefficients of these polynomials are in $Zq = [-q/2, q/2] \cap Z$.

The arithmetic happens in the modulo $(x^d+1)$ (so the degree stays below $d$) and then coefficients modulo $q$.

The $Rq$ has nice property that
- multiple $Zq$ elements can be packed into one $Rq$ element
	- given $d$ $Zq$ elements, they can be mapped to the coefficients of an element from $Rq$
- fast multiplication over $Rq$ in $O(d \cdot \log{d}) \cdot Zq$

## Ajtai commitment
Given data vector $f \in Z^m$ and $||f|| \lt B$. If the norm of the vector is larger than $B$ than the scheme is no longer binding. And given a public matrix $A \overset{{\scriptscriptstyle\$}}{\leftarrow} Z_q^{n \times m}$, where $n$ parameter depends on the desired security level, and in practice $n << m$ (like 512, 1024).
$$
A \cdot f \; mod \; q = cm \in Z_q^n
$$
But this is inefficient, it takes $O(nm)$ $Zq$ operations.
Better way to do this is using *SWIFFT* (SWI Fast Fourier Transfrom).
The $f$ data vector can be partitioned into chunks of $d$ $Z$ elements. Then each chunk can be though of as an element from $R$ element: $f \in R^l;\;l=m/d$. This time the public matrix $A \overset{{\scriptscriptstyle\$}}{\leftarrow} R_q^{\kappa \times l}$ where $\kappa = n/d$
$$
A \cdot f \; mod \; q = cm \in R_q^\kappa
$$and the length of $cm \in Z_q^n$ is the same as that of $cm \in R_q^\kappa$.
And this takes $O(\kappa \cdot l)$ $Rq$ operations, which is $O(n/d \cdot m/d \cdot d \log{d})$ $Zq$ operations, and if $d = n$ than $O(m \cdot \log{n})$ $Zq$ operations.

Making the $d$ bigger weakens the security guarantees.

## Folding

Toy example of commitment-opening relation $R_{cm,B}$. Given witness $w = (f_1, f_2)$ and instance $x = (cm_1, cm_2)$. The $f_i$ is the vector/opening and $cm_i$ is it's corresponding commitment. The relation checks that $A \cdot f\;mod\;q = cm$ and that $||f|| < B$. The goal of the folding is to reduce $(cm_1, f_1) \in R_{cm,B}$ and $(cm_2, f_2) \in R_{cm,B}$ into checking just one $(cm, f) \in R_{cm,B}$.

Verifier knows only $x$, prover knows $w,x$. Verifier wants to check that prover knows corresponding witness. Verifier sends a random challenge $r \overset{{\scriptscriptstyle\$}}{\leftarrow} S \in R$, $S = \{ g\;\in\;R: ||g|| \le 1 \}$, this means that the the size of $S$ can be $|S| = 3^d$ because each coefficient has 3 possibilities -1, 0, 1. However this is still not ideal, because after one folding the norm can be larger than $d$.

### Decomposition
*A number can be decomposed to some base, e.g. 8 in base 3 is $3^0 \cdot 2 + 3^1 \cdot 2$, same can be done with polynomials*

In order to have the worst case norm not grow in each fold, the polynomials can be decomposed into smaller parts. Prover knows $w = (f_1, f_2)$ and $x = (cm_1, cm_2)$, verifier only knows $x$.

Prover will decompose vectors $f_1 = f_{1, Low} + \sqrt{B} \cdot f_{1, High}$ and $f_2 = f_{2, Low} + \sqrt{B} \cdot f_{2, High}$, and sends 4 commitments $\{cm_{1, Low}, cm_{1, High}, cm_{2, Low}, cm_{2, High}\}$ to verifier. Verifier will check that those commitments are consistent with those known to him, $cm_1 = cm_{1, Low} + \sqrt{B} \cdot cm_{1, High}$ and $cm_2 = cm_{2, Low} + \sqrt{B} \cdot cm_{2, High}$.
Verifier sends back a challenges $r_{1, Low}, r_{1, High}, r_{2, Low}, r_{2, High} \overset{{\scriptscriptstyle\$}}{\leftarrow} S$, and combines the 4 commitments into one $cm$ with those challenges. And prover will use the challenges and combine the decomposed vectors into one vector $f$. The new instance witness pair $(cm, f) \in R_{cm,B}$, because the norm of $f$ is small. $||f|| \le 4 \cdot max_{i \in \{1, 2\} \; j \in \{Low, High\}} ||r_{i,j} \; f_{i,j}||$, where $||r_{i,j} \; f_{i,j}|| \le d\cdot ||f_{i,j}||$ and $||f_{i,j}|| \lt \sqrt{B}$, which summed up gives $||f|| \lt 4 \cdot d \cdot \sqrt{B} \le B$. 

**But there is no way that verifier can check that prover is binding to some polynomials with small norm ($\sqrt{B}$)!**

### LatticeFold's range proofs

In lattice setting existing techniques can't be used, because they don't guarantee low norms, or other lattice based ones don't have a sublinear verifier.

Given a statement $(cm, f) \in R_{cm,B}$ and a large $B = 2^t$, the goal is to transform this into another relation inclusion statement that doesn't require range checks.

Prover will decompose $f = f_1+2f_2+2^2f_3 \ldots 2^{t-1}f_{t}$, these vectors have low norms from set $\{-1, 0, 1\}$. Prover sends commitments to these and verifier checks that they are consistent with the input commitment. Then for each of the $t$ statements check
$$
\begin{aligned}
	(cm_1, f_1) \in R_{cm, 2},\\\\
	(cm_2, f_2) \in R_{cm, 2}, \\\\
	\ldots \\\\
	(cm_t, f_t) \in R_{cm, 2}, \\\\
\end{aligned}
$$
There is a way to batch these $t$ statements into new statement of form $x=(cm, r, v)$ where $r$ is a vector and $v$ is a value, and $w=(f)$, such that $(x, w) \in R_{LIN}$.

### Batching statements

The goal is to batch-prove $t$ statements in $R_{cm,2}$. For just one statement $(cm, f) \in R_{cm,2}$ the relation is $x = cm \in R_q^\kappa$, $w = f \in R^l$, and there are two checks $A \cdot f\;mod\;q=cm$ and $||f|| \lt 2$. This can be also interpreted as $x = cm \in Z_q^n$, $w = f \in Z^m$ and prove that $rot(A) \cdot f\; mod\;q = cm$, and $||f|| \lt 2$.

Proving $||f|| \lt 2$ means that each element in $f$ is from set $\{-1, 0, 1\}$. Thus this can be rewritten as $\forall i \in 1..m:\; f_i \cdot (f_i - 1) \cdot (f_i + 1) = 0\;mod\;q$. This relation can be reduced with sumcheck protocol into a relation $R_{LIN}$
$$
\begin{aligned}
x = (cm, r, v)\\\\
w = f\\\\
rot(A)\ldots\\\
\tilde{f}(r) = v
\end{aligned}
$$
Then all sumcheck witnesses can be combined into one and run sumcheck producing one statement.
### Folding

Given $(cm_1, f_1) \in R_{cm,B}$ and $(cm_2, f_2) \in R_{cm,B}$, prover will decompose both into $2t$ statements:
$$
\begin{aligned}
	(cm_{1,1}, f_{1,1}) \in R_{cm, 2},\\\\
	(cm_{1,2}, f_{1,2}) \in R_{cm, 2}, \\\\
	\ldots \\\\
	(cm_{1,t}, f_{1,t}) \in R_{cm, 2}, \\\\
	\ldots \\\\
	(cm_{2,t}, f_{2,t}) \in R_{cm, 2}
\end{aligned}
$$
And by batching all these $2t$ statements into the one linear statement, we obtain a way of doing the folding. Prover complexity is in order of $2t$ because he must generate $2t$ commitments, plus sumcheck. This is a lot more then just one SWIFFT commitment, but with this approach there is guarantee of the low norm.