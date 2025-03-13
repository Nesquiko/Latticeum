# Designing Zero-Knowledge Proof Solutions in Ethereum ecosystem

Sk: Vylepšenie dôkazov s nulovým vedomím v blockchainových aplikaciách

Zero-knowledge proofs (ZKPs) are a new cryptographic primitive in applied
cryptography with applications in multiple industries, including Web3, supply
chains, and the Internet of Things. By verifying the authenticity of
information without disclosing its content, ZKPs improve privacy, security,
and efficiency in digital systems. Current use cases include
decentralized identity (Worldcoin), private transactions (stealth address schemes
or blockchains like Zcash and Monero), secure and scalable Layer-2s (ZkSync, Scroll)
voting systems, IoT networks, and supply chain management.

Examine existing solutions, proposals, and trends in this domain. Analyse a
specific challenge discovered through related work. Design a solution to
address the challenge. Implement and test the solution on Ethereum (or a
Layer-2) blockchain network. Evaluate and compare results with existing
approaches. Discuss findings and contributions. Conclude with novelty,
scientific findings, and future research directions.

## Literature

[1] Ulrich Haböck, David Levit, Shahar Papini. Circle STARKs. Cryptology ePrint Archive, 2024, https://eprint.iacr.org/2024/278.
[2] Jeremy Bruestle, Paul Gafni, and the RISC Zero Team. RISC Zero zkVM: Scalable, Transparent Arguments of RISC-V Integrity. Risc0. Retrieved January 11, 2024 from https://dev.risczero.com/proof-system-in-detail.pdf.

## Ideas

1. Decrease binius proof sizes by using other proof system to make a proof of
   Binius proof, see end of Vitalik's blog post about Binius
