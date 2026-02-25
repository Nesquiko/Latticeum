# Latticeum

Latticeum is a proof-of-concept post-quantum RISC-V zkVM based on lattice
cryptography, and it is part of my master thesis work. It combines a
`rv32imac` VM emulator with IVC using LatticeFold over CCS. Current demo is
proving execution of a Fibonacci guest program.

This repository also contains the thesis research and milestone documents:

- `research-objectives/`: thesis research objectives, problem framing, and early literature context.
- `dp0/`: initial thesis assignment/scope definition.
- `dp1/`: first thesis milestone document and related assets.
- `dp2/`: second thesis milestone document and related assets.
- `dp3/`: final thesis document.

## What this project does

- Executes RISC-V programs and records per-instruction traces.
- Arithmetizes each step into a CCS witness.
- Commits and folds those steps into a running accumulator using LatticeFold.

## High-level architecture

```text
Rust program -> RISC-V ELF -> VM execution trace -> CCS arithmetization
-> LatticeFold folding -> accumulator -> final wrapping SNARK
```

Main crates:

```text
latticeum/
├── crates/
│   ├── configuration/   # constants (e.g. N_REGS, RESULT_ADDRESS)
│   ├── vm/              # RISC-V emulator and instruction execution
│   ├── zkvm/            # proving loop, CCS, commitments, IVC
│   └── guest/           # guest utils
└── guests/fibonacci/    # Fibonacci guest program
```

## Cryptographic primitives used

- Field over Goldilocks prime `p = 2^64 - 2^32 + 1`.
- Cyclotomic ring `R_q = Z_q[X]/(X^d+1)` with `q` being Goldilocks prime.
- Ajtai lattice commitments for folding.
- LatticeFold non-interactive folding scheme to keep proof state compact across steps.
- Poseidon2 for VM state, accumulator, and step commitments.

### Step commitment structure:

```text
h_i = Poseidon2(i, z_0_comm, z_i_comm, U_i_comm)
```

where `z_0_comm` is the initial "anchor" to the vm's states, `z_i_comm` is
current VM state commitment, and `U_i_comm` is the running accumulator commitment.

## VM and trace model

- ISA target is a subset of `rv32imac`.
- 1 MB RAM (`WORDS_PER_PAGE = 256`, `PAGE_COUNT = 1024`, word size 4 bytes).
- One `ExecutionTrace` per executed instruction (includes `pc`, register values in/out, ...)

The trace is transformed into CCS witness for both:

- step execution constraints (`F`), and
- augmented IVC constraints (`F'`) that connect folded steps.

## Current implementation status

Implemented:

- RISC-V VM execution with ELF loading and trace generation.
- CCS arithmetization for supported instructions.
- Poseidon2 constraints and commitments.
- Off-circuit LatticeFold proving and accumulator updates.
- IVC step commitment verification inside CCS.

In progress / TODO:

- Full in-CCS NIFS verifier constraints.
- Memory consistency proofs (permutation + read-over-write + page-update proofs).
- Additional rv32imac instruction coverage.
- Final wrapping SNARK (SuperSpartan + Greyhound integration).
- EVM integration and Ethereum block proving.

## Build and run

Toolchain:

- Rust nightly: `nightly-2025-08-19`

Run zkVM prover (debug checks enabled):

```bash
RUST_LOG=<LOG_LEVEL> cargo run --bin zkvm --features debug,parallel --release
```

Expected current behavior for the 100th Fibonacci guest:

- About 16 execution traces.
- About 32 seconds proving time.

## Key code locations

- `latticeum/crates/vm/src/riscvm/vm.rs`: VM execution loop.
- `latticeum/crates/vm/src/riscvm/inst.rs`: instruction semantics.
- `latticeum/crates/zkvm/src/ccs.rs`: witness layout and arithmetization.
- `latticeum/crates/zkvm/src/constraints.rs`: CCS constraint construction.
- `latticeum/crates/zkvm/src/zk_latticefold.rs`: folding/linearization witness extraction.
- `latticeum/crates/zkvm/src/main.rs`: end-to-end proving and folding loop.
- `latticeum/crates/zkvm/src/ivc.rs`: IVC step structures.

## Roadmap

1. Complete in-circuit folding verifier constraints.
2. Add memory consistency constraints/proofs.
3. Integrate wrapping SNARK for succinct final verification.
4. Extend ISA support to the guest/EVM requirements.
5. Move from Fibonacci example to full Ethereum block proving.
6. Create benchmarks, similar to https://fenbushicapital.medium.com/benchmarking-zkvms-current-state-and-prospects-ba859b44f560

## References

- LatticeFold and related implementations: https://github.com/NethermindEth/latticefold
- CCS paper: `./papers/CCS.pdf`
- RISC Zero proof-system docs: https://dev.risczero.com/proof-system/
- Poseidon2 and modern folding/IVC literature (Nova, HyperNova, Jolt)
