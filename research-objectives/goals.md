# Enhancing Zero-knowledge proofs in blockchains

## Binius

Binius is a SNARK protocol over towers of binary fields. Instead of prime field,
a binary field is used. If the underlying data is `n` bits, then the encoding
will have `n` bits.

Works similiar to STARKs, commit to a multilinear polynomial with Merkle tree,
and then open evaluations with proofs.

- [Whitepaper](https://eprint.iacr.org/2023/1784.pdf)
- [Implementation](https://gitlab.com/IrreducibleOSS/binius/)
- [Irreducible Blog](https://www.irreducible.com/posts/binius-hardware-optimized-snark)
- [Vitalik's blog](https://vitalik.eth.limo/general/2024/04/29/binius.html)

## Quantum resistance

### Supersingular elliptic curve isogeny

Their underlying mathemtical concepts are complicated and there is risk that
possible attacks are hidden under this complexity Main benefits are relatively
small key size and ability to port over many kinds of elliptic curve-based
approaches directly.

- [Supersingular isogeny key exchange for beginners](https://eprint.iacr.org/2019/1321.pdf)

### Lattice-based cryptography

Rely on simpler mathematics and enable FHE. But they have larger key sizes.
But one of the NIST Post-Quantum round 3 winners was based on Lattices.

- [Lattice Based Cryptography for Beginners](https://eprint.iacr.org/2015/938.pdf)

### STARKed binary hash trees

A next level of statelesness of Ethereum after Verkle trees. They are post
quantum secure.

- [Vitalik's blog on Possible futures of the Ethereum protocol, part 4: The Verge](https://vitalik.eth.limo/general/2024/10/23/futures4.html#1)
- [Vitalik's blog on Circle STARKs](https://vitalik.eth.limo/general/2024/07/23/circlestarks.html)
