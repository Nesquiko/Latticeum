## Feedback from DP2

- there are post quantum zkvms, but based on hashes
- be prepared with lattice problems that are hard
- local benchmarks of other zkvms against mine

## Add to analysis

- Neo Lattice-based folding scheme for CCS
  - What to say: Unlike LatticeFold, which operates over cyclotomic rings \(R_q\), Neo works directly over small prime fields (like Goldilocks) and supports CCS.
  - Relevance: This is highly relevant to your design. Your architecture uses the Goldilocks field and CCS. If Neo supports these natively without the overhead of ring mappings or bit-decomposition range proofs (it uses "pay-per-bit" commitments), it might be a superior candidate to LatticeFold for your specific architecture. You should add a "Related Work" comparison between LatticeFold vs. Neo.
- Standardized Benchmarks (EthProofs)
  - Where to add: In the ZkEVM section (2.3).
  - What to say: Mention the EthProofs initiative. You currently cite a 15.5s average proving time. Update this to reference the standardized testing framework (Fenbushi/AlignedLayer benchmarks) to give your comparison more authority. Mention the distinction between "FRI-STARK-based" (SP1, RISC Zero) and "Folding-based" (Nova, LatticeFold).
