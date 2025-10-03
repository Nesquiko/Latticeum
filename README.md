# Latticeum

A ZkVM build with lattice based cryptography.

## TODOs

Ok, I was naive, RISC-V is an IVC, in order to have an IVC, I use folding scheme,
but I must implement the IVC myself. The CCS of this IVC does:

1. constraints that the public input comm (poseidon2 hash) to `poseidon2(i, state_0, state_i, U_i)`
2. constraints the RISC-V instruction execution
3. constraints the LatticeFold's NIFS verifier INSIDE THE CCS

The intermediate values (for the poseidon2 and for the NIFS verifier go to private
state, because they are massive). At the end the zkvm calculates the input to
the next step, the `poseidon2(i, state_0, ...`.

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
