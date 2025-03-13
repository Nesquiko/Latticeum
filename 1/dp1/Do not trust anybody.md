# [Do Not Trust Anybody](https://www.youtube.com/watch?v=X8ebjijCTMA)

1. Splits image into tiles
2. Constructs merkle tree from the commitments to the tiles
3. Signs the merkle tree root
4. Apply transformation on the image
5. For each transformed tile, generate a ZKP that proofs, given:
   - `Ti` - original tile at `ith` position
   - `ci` - commitment to the `ith` tile
   - `Ťi` - transformed tile at `ith` position
   - transformation `f()`
   - prove `com(Ti) == ci && Ťi == f(Ti)`
6. The whole proof consists of the signed merkle root, its signature, merkle openings,
   sub-proofs.
7. Succinct fraud proofs:
    - either one (or more) of the sub-proofs is incorrect
    - or one opening of the merkle tree
    - or signature is wrong
