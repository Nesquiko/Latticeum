# Latticeum

A ZkVM build with lattice based cryptography.

## RISC-V VM specs:

- 32bit
- 1MB of RAM
  - page size 256B
  - number of pages 4096

## IVC of RISC-V

The function `F` is defined by the RISC-V specification, then in order to instantiate
an IVC for `F`, augmented circuit `F'`, represented by the CCS, folded inside LatticeFold
must contain two parts, IVC part for verifying IVC advancement and then `F` specific
part for verifying correct execution of `F`. In practice:

1. The public state commitment passed to IVC step `i` from step `i-1`, `h_{i - 1} = poseidon2(i - 1, hash(state_0), hash(state_{i - 1}), hash(U_{i - 1}))`

   - `i - 1` is just a step number in previous step
   - `hash(state_0)`, where `state_0` is the public initial state of VM, it includes:
     - commitment to the program's binary code
       - Compute a Keccak hash of the binary, this is public, no need to constrain it in CCS.
       - to get field elements, use the 256-bit Keccak digest to deterministically derive 4 Goldilocks elements (using it as a seed).
       - **4 goldilocks elements**
     - programs entrypoint, which is in `pc`
       - **1 goldilocks element**
     - Merkle root of all VM's memory pages (zeroes in all pages)
       - **1 goldilocks element**
     - all registers, all zeroes
       - **32 goldilocks elements**
     - Commitment to an empty memory ops vector `poseidon2(mem_ops_vec = 0, cycle = 0, address = 0, value = 0)`
       - **1 goldilocks element**
   - `hash(state_{i - 1})`, where `state_{i - 1}` is complete state of VM after step `i - 1`, it includes:
     - VM's `pc`
       - **1 goldilocks element**
     - new Merkle root of VM memory
       - **1 goldilocks element**
     - all registers
       - **32 goldilocks elements**
     - commitment to an memory ops vector `poseidon2(mem_ops_vec_{i - 1}, cycle, address, value)`
       - **1 goldilocks element**
   - `hash(U_{i - 1})` binds the running instance
     - TODO read from code how many elements this has

2. The private witness for step `i` contains all necessary information for the
   augmented circuit `F'` to prove the transition from state committed by `h_{i - 1}`
   to new state commited by `h_i`. It must contain:

   - preimage of the `h_{i - 1}`
     - previous step counter `i - 1`
     - the full VM state `z_{i - 1}`
     - the full accumulator instance `U_{i - 1}`
   - folding proof from step `i - 1`
   - the merkle inclusion proof of the new memory merkle root
   - the execution trace for the application circuit `F`

3. The constraints of the `F'` for step `i`:
   - recalculate the `h_{i - 1}` from its preimage and constraint that it equals the public input `h_{i - 1}`
   - constraint that the input of the execution trace equals the output of `z_{i - 1}`
   - constraint the RISC-V instruction execution
   - if memory access/write, then constraint that the new memory merkle root is valid
   - constraint the LatticeFold's NIFS verifier

Compare against https://fenbushicapital.medium.com/benchmarking-zkvms-current-state-and-prospects-ba859b44f560

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
