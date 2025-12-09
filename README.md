# Latticeum

A ZkVM build with lattice based cryptography.

## TODO

- Start writing the paper.
- Optimize the current code.
- In the end, compare against https://fenbushicapital.medium.com/benchmarking-zkvms-current-state-and-prospects-ba859b44f560

## RISC-V VM specs:

- 32bit
- 1MB of RAM
  - words per page / page size = 256 \* 32bit = 8192 bits = 1024 bytes
  - number of pages 256

## IVC of RISC-V

The function `F` is defined by the RISC-V specification, then in order to instantiate
an IVC for `F`, augmented circuit `F'`, represented by the CCS, folded inside LatticeFold,
it must contain two parts, IVC part for verifying IVC advancement and then `F` specific
part for verifying correct execution of `F`. In practice:

### public inputs for the entire IVC chain (step `0`)

These are the top-level public inputs that the final verifier needs to know.
They are computed once and remain constant for the entire execution.

1.  **Initial state commitment `z_0_comm`**: This serves as the **anchor** for
    the entire computation, binding the proof to a specific program and initial
    configuration. Its preimage is public and contains:
    - A Merkle root of the program's binary code (the `code_comm`).
    - The program's entrypoint (`pc`).
    - The Merkle root of the VM's initially zeroed memory pages.
    - A Poseidon2 commitment to the VM's initially zeroed registers.
    - A commitment to the initially empty memory operations log.
2.  **Initial IVC Step Commitment `h_0`**: A commitment that establishes the
    initial state of the IVC, computed as `h_0 = poseidon2(0, z_0_comm, z_0_comm, U_0_comm)`.

### Per-step proof generation (step `i`)

For each step of the VM execution, the prover generates a proof. The `F'`
circuit for step `i` takes the following as **public inputs**:

- **Previous step commitment `h_{i-1}`**: The public hash that commits to the
  state of the entire IVC scheme after the previous step `i - 1`.
- **Initial state commitment `z_0_comm`**: The anchor commitment, passed in
  publicly at every step to ensure the prover does not switch programs.

The `F'` circuit is then satisfied by the following **private witness**:

1.  **IVC witness (proving `i-1` -> `i` transition):**
    - **Preimage of `h_{i-1}`**:
      - Previous step counter `i-1`.
      - Previous state commitment `z_{i-1}_comm`.
      - Previous accumulator commitment `U_{i-1}_comm`.
    - **Preimage of `z_{i-1}_comm` (the full VM state `z_{i-1}`):**
      - The VM's program counter `pc_{i-1}`.
      - The Merkle root of the VM's memory.
      - A Poseidon2 commitment to the VM's registers.
      - A Poseidon2 commitment to the memory operations log.
    - **Preimage of `U_{i-1}_comm`**: The full running accumulator instance
      `U_{i-1}` and its witness `w_acc`.
    - **Folding proof `π_{i-1}`**: The `LatticeFold` proof generated during
      step `i-1`. (This is `None` for the first step).
2.  **RISC-V Witness (proving the execution of `F`):**
    - The **instruction** being executed at `pc_{i-1}`.
    - A **Merkle proof** proving that this instruction is valid,
      verifying its inclusion in the tree rooted at `code_comm` (which is part
      of the public `z_0_comm`).
    - The full **execution trace** for this single instruction, showing the
      transition from input state (`z_{i-1}`) to output state (`z_i`).
    - Any necessary Merkle proofs for memory operations (e.g., proof of a page update).

### Constraints within the augmented circuit `F'`

The CCS for the augmented circuit `F'` enforces the following logic at each step `i`:

1.  **Anchor constraints**: Recalculate `h_{i-1}` from its private preimage
    components. They constrain this result to equal the **public `h_{i-1}`**.
2.  **Instruction fetch constraints**: Verify the provided Merkle proof for
    the current instruction against the `pc_{i-1}` (from the witness) and the
    `code_comm` (from the public `z_0_comm`). This prevents the prover from
    executing a malicious instruction.
3.  **State transition constraints**: Constrain the correctness of the RISC-V
    instruction execution based on the instruction and the `ExecutionTrace` witness.
4.  **Memory consistency constraints**:
    - If a memory operation occurs, it constrains that the memory operations
      log commitment is correctly updated.
    - If a memory write occurs, it constrains that the new memory Merkle root
      is valid by checking the provided Merkle proof for the updated page.
5.  **Recursive folding constraint**: The circuit conditionally performs one of the following:
    - **Base case (`i=0`):** Checks that the step is `0` and that there is no folding proof.
    - **Recursive case (`i>0`):** Constraints the verification of the folding
      proof `π_{i-1}` by running the `LatticeFold` NIFS verifier logic.

## Roadmap

### VM execution

#### 1. RISC-V emulator

Implementation, or fork of a Rust RISC-V 32 bit ISA emulator. After first
Zk EVM implementation, 64 bit ISA could be used, due to the LatticeFold+'s
theoretical advantage in ragne proofs.

##### Execution trace

Modify the emulator so it also outputs a execution trace of one instruction.
It should, for example, include instruction executed, register states,
what memory was read or stored.

| input              | output                           |
| ------------------ | -------------------------------- |
| RISC-V binary file | A collection of execution traces |

#### 2. CCS

There are three CCS parts:

1. CCS structure `s` - defines the rules of entire RISC-V ISA, it defines the
   relation, it is fixed, not changing.
2. CCS instance `u` - public part, contains inputs, outputs, commitments to witness.
   A vector of values, or some structure.
3. CCS witness `w` - private part, contains the selector of the instruction, execution
   trace values. It is a one vector.

In this step, create the universal CCS structure `s` for the RISC-V ISA (and also
it must contain the folding logic). Look at libraries like `bellperson`, `nova-snark`,
or `halo2` for sythetizing such CCS structure.

| input                                          | output                                             |
| ---------------------------------------------- | -------------------------------------------------- |
| RISC-V ISA Specification, Folding Scheme Logic | A file containing the serialized CCS structure `s` |

##### Sources:

- [CCS paper](./papers/CCS.pdf).
- [Nethermind/latticefold](https://github.com/NethermindEth/latticefold/blob/main/latticefold/src/arith.rs#L51).

#### 3. Arithmetize into CCS

For each execution trace, it produces CCS instance (inputs, outputs, ...) and
witness vector. This step can be parallelized, each execution trace can be arithmetized
in parallel.

| input                    | output                                                                      |
| ------------------------ | --------------------------------------------------------------------------- |
| A single execution trace | An instance-witness pair (`u_i`, `w_i`) for the universal CCS structure `s` |

### Folding

Take the stream of instance-witness pairs from [arithmetizer](#4-arithmetize-into-ccs)
and fold them. In this step a implementation of LatticeFold+ is needed.
This can also be parallelized in two ways,
By parallelizing MSM in commitment scheme (intra-step parallelism) or,
inter-step parallelism, one thread can fold `u_1` and `u_2`, other can fold
`u_3` and `u_4`, then fold these two folds and so on... a tree like parallelism.

| input                              | output                                                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| A vector of instance-witness pairs | The last instance-witness pair (`u_n`, `w_n`) and the final accumulated instance-witness pair (`U_N`, `W_N`) |

### Wrapping

Given last instance `u_n`, last witness `w_n`, last running instance `U_n` and
last running witness `W_n`, fold them last time to get `U'` and `W'`.
To create a SNARK proving _I know a witness `W'` that satisfies the CCS instance `U'`._,
implement a Spartan + Greyhound ZKP system.

| input                                                                                                        | output                                            |
| ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| The last instance-witness pair (`u_n`, `w_n`) and the final accumulated instance-witness pair (`U_N`, `W_N`) | A final, succinct, zero-knowledge proof `π_final` |

### RISC-V EVM

Implementation like REVM depend on Rust's `std`, which depends on underlying OS.
The ZkVM environment emulates "bare-metal" one, so it can only run programs
with `no_std` assumption. In this step, either find a `no_std` EVM (maybe `zeth`
from RISC-0), or implement it with `no_std` and ZK in mind.

| input             | output                                                       |
| ----------------- | ------------------------------------------------------------ |
| EVM Specification | A `no_std` Rust code that can be compiled to a RISC-V binary |

### ETH block proof

Use the ZkEVM built in previous step to **prove Ethereum blocks**.

| input                                    | output                                                                           |
| ---------------------------------------- | -------------------------------------------------------------------------------- |
| The RISC-V EVM binary, An Ethereum block | A final, succinct proof `π_eth_block` that the block's state transition is valid |

## Links

- this is golden, they go over everything, I could take inspiration for my ZkVM https://dev.risczero.com/proof-system/
- Jolts book is filled with other goodies https://eprint.iacr.org/2023/1217.pdf, also its paper seems to be readable for me
- cloudflare lattices https://blog.cloudflare.com/lattice-crypto-primer/
- taiko intro to folding https://taiko.mirror.xyz/tk8LoE-rC2w0MJ4wCWwaJwbq8-Ih8DXnLUf7aJX1FbU
- nethermind latticefold https://nethermind.notion.site/Latticefold-and-lattice-based-operations-performance-report-153360fc38d080ac930cdeeffed69559#c8a3b19140cf46dabd68966b04458293
