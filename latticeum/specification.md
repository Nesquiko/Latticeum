# Lattice-Based RISC-V zkVM Specification

**Purpose**: Technical reference for LLM code assistants implementing and extending the lattice-based zkVM.

**Status**: Proof-of-concept implementation. Core components functional; some features unimplemented.

---

## Executive Summary

This project implements a post-quantum secure Zero-Knowledge Virtual Machine
(zkVM) using lattice-based cryptography. The system proves correct execution
of RISC-V (rv32imac) programs through IVC (Incrementally Verifiable
Computation) instantiated with the LatticeFold folding scheme.

**Key Characteristics:**

- **Architecture**: RISC-V emulator + IVC folding with LatticeFold
- **Field**: Goldilocks prime field `p = 2^64 - 2^32 + 1`
- **Ring**: Cyclotomic ring `R_q = ℤ_q[X]/(X^d+1)` with NTT representation
- **Constraint System**: Customizable Constraint Systems (CCS) for arithmetization
- **Hash Function**: Poseidon2 for step commitments
- **Post-Quantum Security**: Based on Module-SIS and SIS hardness assumptions

**Goal**: Enable proving of Ethereum block execution with post-quantum guarantees (currently supports simpler programs like Fibonacci computation).

---

## System Architecture

### High-Level Flow

```
Rust Program → RISC-V ELF → VM Emulator (traces) → Arithmetization (CCS)
→ LatticeFold Folding (NIFS) → Accumulator → Final Wrapping SNARK
```

### Proof Lifecycle

1. **Setup**: Load ELF binary, construct CCS constraint system
2. **Execution Loop** (for each instruction):
   - Execute instruction, capture `ExecutionTrace`
   - Create Poseidon2 commitments to state components
   - Arithmetize trace into CCS witness vector `z`
   - Fold witness into running accumulator using LatticeFold
3. **Completion**: Final accumulator wrapped in SNARK (SuperSpartan + Greyhound) for succinct verification

### Module Structure

```
latticeum/
├── crates/
│   ├── configuration/   # Constants (N_REGS=32, RESULT_ADDRESS)
│   ├── vm/              # RISC-V emulator
│   │   └── riscvm/
│   │       ├── vm.rs      # VM state and execution loop
│   │       ├── inst.rs    # Instruction execution logic
│   │       ├── inst_decoder.rs  # Instruction decoding
│   │       ├── elf.rs     # ELF loading
│   │       └── consts.rs  # VM constants
│   ├── zkvm/            # Main proving loop
│   │   ├── main.rs       # Execution and folding loop
│   │   ├── ccs.rs        # CCS layout and witness generation
│   │   ├── constraints.rs# CCS constraint matrices
│   │   ├── ivc.rs        # IVC step I/O structures
│   │   ├── commitments.rs# Poseidon2 commitments
│   │   └── poseidon2.rs  # Poseidon2 utilities
│   └── guest/           # Guest programs
└── guests/fibonacci/    # Example program
```

---

## Cryptographic Primitives

### 1. Lattice-Based Commitments (Ajtai)

**Hardness Assumption**: Module Short Integer Solution (Module-SIS)

**Commitment Scheme**: Ajtai commitment over the cyclotomic ring `R_q`

```
A ∈ R_q^{κ×N}  (κ=4, N=layout.w_size * L where L=5)
s ∈ {0,1}^N    (binary witness)
c = A · s      (commitment)
```

**Decomposition**: Binary decomposition with parameters:

- `B = 2^15`, `L = 5`, `B_SMALL = 2`, `K = 15`

**Key Advantage**: Additive homomorphic property enabling efficient folding.

### 2. Incrementally Verifiable Computation (IVC)

**Concept**: Prove long computations by recursively folding steps into a constant-sized accumulator.

**Step Commitment**: Each step `i` produces a Poseidon2 commitment `h_i` to the state:

```
h_i = Poseidon2(i, z_0_comm, z_i_comm, U_i_comm)
```

Where:

- `i`: Step counter
- `z_0_comm`: Initial state commitment (public code + registers)
- `z_i_comm`: Current VM state commitment
- `U_i_comm`: Accumulator commitment

**Integrity enforced in-circuit by verifying:**

- `h_{i-1}` recomputed from witness matches public input
- `U_{i-1}` recomputed from witness
- Folding of `U_{i-1}` into `U_i` via NIFS proof verification

### 3. LatticeFold Folding Scheme

**Purpose**: Compress two CCS instances `(U_{i-1}, W_{i-1})` and `(U_i, W_i)` into folded instance `(U'_i, W'_i)`

**NIFS Prover** (current implementation creates but doesn't use fully):

```
(U_i, W_i, π_i) = NIFSProver::prove(U_{i-1}, W_{i-1}, u_i, w_i, ccs, scheme)
```

**Witness Norm Management**: Decomposition at each fold prevents unbounded noise growth.

### 4. Customizable Constraint Systems (CCS)

**Relation**: Generalizes R1CS to support high-degree gates.

**CCS Structure** (m constraints, n variables, t matrices, q multisets):

```
Σ_{i=0 to q-1} c_i · ⊙_{j∈S_i} (M_j · z) = 0
```

Where:

- `z = (w, 1, x)` is the witness vector
- `⊙` is Hadamard (entry-wise) product
- `S_i` is a multiset of matrix indices
- `c_i` is a constant

**Our CCS Layout** (from `CCSLayout`):

- Total size: ~1500+ elements (depends on instruction set)
- Structure: `[x_ccs (4), 1, w_ccs` (Poseidon2 state, PC, registers, instruction data)]

### 5. Poseidon2 Hash

**Usage**: Step commitments and VM state commitments

**Parameters**:

- Width: 16 (wide version for 13-element preimage)
- Rate: 12
- Full rounds: 8 (4 initial + 4 terminal)
- Partial rounds: 22

**Preimage for step commitment**: `[step, z_0_comm (4), z_i_comm (4), U_i_comm (4)] = 13 elements`

---

## Component Specifications

### VM Emulator Module (`crates/vm`)

#### Purpose

Execute RISC-V programs and generate execution traces for proving.

#### VM State

```rust
pub struct VM<WORD_SIZE, WORDS_PER_PAGE, PAGE_COUNT, P: VmProgram> {
    pub regs: Registers,              // 32 general-purpose registers (u32)
    pub pc: usize,                   // Program counter
    pub memory: Memory<WORDS_PER_PAGE, PAGE_COUNT>,  // 1MB RAM (default)
    program: Program,                // Loaded ELF or uninitialized
}
```

**Constants**:

- `WORD_SIZE = 4` bytes
- `WORDS_PER_PAGE = 256`
- `PAGE_COUNT = 1024` (1MB total)

#### Execution Trace

```rust
pub struct ExecutionTrace {
    pub cycle: usize,
    pub input: ExecutionSnapshot { pc, regs: [u32; 32] },
    pub output: ExecutionSnapshot { pc, regs: [u32; 32] },
    pub instruction: DecodedInstruction,
    pub side_effects: SideEffects {
        has_overflown: bool,
        branched_to: Option<u32>,
        memory_op: Option<MemoryOperation>,
    }
}
```

#### Supported Instructions (Partial)

**Control Flow**:

- `JAL { rd, offset }` - Jump and link
- `JALR { rd, rs1, offset }` - Jump and link register
- `BNE { rs1, rs2, offset }` - Branch if not equal

**Arithmetic**:

- `ADD { rd, rs1, rs2 }` - Add registers
- `ADDI { rd, rs1, imm }` - Add immediate

**Memory**:

- `SW { rs1, rs2, offset }` - Store word

**Immediate**:

- `LUI { rd, imm }` - Load upper immediate
- `AUIPC { rd, imm }` - Add upper immediate to PC

#### Execution Loop

```rust
vm.run(|InterceptArgs { trace, vm_memory, vm_regs, vm_raw_code }| {
    // Process each instruction trace for proving
});
```

### Step Circuit (F)

**Purpose**: Verify correct RISC-V instruction execution.

**State Transition**: `(pc, reg_state) → (pc', reg_state')` based on decoded instruction.

**CCS Witness Elements** (`layout.w_size`):

1. **IVC Witness** (step commitment preimage):
   - `ivc_step`: Step counter
   - `z_0_comm`: Initial state commitment (4 Goldilocks)
   - `z_i_comm`: Current state commitment (4 Goldilocks)
   - `acc_comm`: Accumulator commitment (4 Goldilocks)
   - Poseidon2 internal states (after MDS, initial/terminal/internal rounds)

2. **Execution Trace**:
   - `pc_in`, `pc_out` (program counter)
   - `regs_in[0..31]`, `regs_out[0..31]` (registers)
   - `instruction_size`, `is_branching`, `branched_to`
   - Instruction selector flags (`is_add`, `is_addi`, `is_sw`, etc.)
   - Operands (`val_rs1`, `val_rs2`, `imm`, `val_rd_out`)
   - Arithmetic flags (`has_overflown`)

#### Example Constraints

**PC update (non-branching)**:

```
(1 - is_branching) * (pc_out - pc_in - instruction_size) = 0
```

**ADD with overflow**:

```
is_add * (has_overflown * 2^32 + val_rd_out - val_rs1 - val_rs2) = 0
```

**LUI**:

```
is_lui * (val_rd_out - imm * 2^12) = 0
```

### CCS Constraints Module (`crates/zkvm/src/constraints.rs`)

**Builder Pattern**: Creates sparse matrices for CCS constraints.

**Constraint Types**:

- RISC-V instruction constraints (`add_constraint`, `bne_constraint`, etc.)
- Poseidon2 hash circuit constraints:
  - `ivc_step_after_initial_mds` (16 constraints)
  - `ivc_step_external_initial_rounds` (8 external rounds \* 16 width = 128)
  - `ivc_step_internal_rounds` (22 \* 16 = 352)
  - `ivc_step_external_terminal_rounds` (128)
  - `ivc_step_result_hash` (4)

**Degree-7 Constraints**: S-Box exponentiation in Poseidon2 requires 7-way Hadamard products.

### IVC Circuit (F')

**Purpose**: Augmented circuit maintaining proof chain integrity.

**Structure** (`IVCStepInput`, `IVCStepOutput`):

```
IVCStepInput {
    ivc_step_comm: (GoldilocksComm, IntermediateStates),  // h_{i-1}

    // h_{i-1} preimage
    ivc_step: Goldilocks,
    state_0_comm: GoldilocksComm,       // z_0
    state_comm: GoldilocksComm,         // z_{i-1}
    acc_comm: GoldilocksComm,           // U_{i-1}

    // For folding verification
    acc: &LCCCS,
    folding_proof: Option<&LFProof>,
    w_acc: &Witness,

    trace: &ExecutionTrace,             // Current instruction
}
```

```
IVCStepOutput {
    ivc_step_comm: (GoldilocksComm, IntermediateStates),  // h_i
    ivc_step: Goldilocks,
    z_0_comm: GoldilocksComm,
    z_i_comm: GoldilocksComm,
    acc_comm: GoldilocksComm,
    acc: LCCCS,                           // U_i
    w_acc: Witness,
    folding_proof: Option<LFProof>,
}
```

**In-Circuit Checks** (not yet fully implemented in-constraint):

1. **IVC integrity**: Recompute `h_{i-1}` from witness, verify matches input
2. **Code integrity**: Verify code Merkle root in `z_i_comm` preimage matches expected
3. **NIFS verifier**: Verify folding proof `π_{i-1}` (TODO)
4. **Step verification**: Execute step circuit `F` on current trace

### LatticeFold Integration

**External Libraries**:

```toml
latticefold = { git = "https://github.com/NethermindEth/latticefold.git" }
cyclotomic-rings = { git = "https://github.com/NethermindEth/latticefold.git" }
```

**Main Folding Loop** (`crates/zkvm/src/main.rs`):

```rust
// Initialize with zero witness
let (acc, w_acc) = initialize_accumulator(&ccs, &CCS_LAYOUT, &scheme, ZERO_GOLDILOCKS_COMM);

vm.run(|args| {
    step = trace.cycle + 1;

    // Create Poseidon2 commitments to state
    let state_i_comm = zkvm_commiter.state_i_comm(regs, code, pc, memory_comm, mem_ops_comm);

    // Arithmetize into CCS witness vector
    let z = arithmetize(&ivc_input, &CCS_LAYOUT);

    // Commit and fold
    let (cm_i, w_i) = commit(z, &ccs, &scheme);
    let (folded_acc, folded_w_acc, folding_proof) = fold(...);

    // Update accumulator
    ivc_output = IVCStepOutput { ... };
});
```

### Commitments Module (`crates/zkvm/src/commitments.rs`)

**Purpose**: Create Poseidon2 hashes for VM state components.

**Commitment Types**:

- `state_i_comm`: Hash of PC + register Merkle root + memory Merkle root + memory ops commitment
- `acc_comm`: Hash of `LCCCS` fields
- `ivc_step_comm`: Hash of (step, z_0_comm, state_i_comm, acc_comm)
- `vm_mem_comm`: Merkle commitment to memory page

**Implementation**: Uses `p3-poseidon2` Plonky3 crate.

---

## Implementation Status

### ✅ Completed Components

1. **RISC-V VM Emulator**
   - ELF loading and decoding
   - Subset of rv32imac instruction set execution
   - Register and memory management
   - Execution trace generation

2. **CCS Arithmetization**
   - Constraint matrices for supported instructions
   - Poseidon2 hash circuit constraints
   - Witness generation from execution traces

3. **LatticeFold Integration**
   - NIFS proving (off-circuit)
   - Witness commitment generation
   - Accumulator folding logic

4. **Poseidon2 Commitments**
   - Step commitment to VM state
   - Memory state commitments
   - Accumulator commitments

5. **IVC Data Structures**
   - `IVCStepInput` / `IVCStepOutput`
   - State transition management

### 🚧 In Development / TODO

1. **In-Circuit NIFS Verifier**
   - `NIFSVerifier` constraints in CCS
   - Verify folding proofs within augmented circuit
   - Constraint the decomposition process

2. **Memory Consistency Checks**
   - Permutation proof (sort by address+time)
   - Read-over-write verification
   - Merkle proof generation for page updates

3. **Necessary instructions**
   - Implement rv32imac instructions needed by the guest program (fibonacci, then EVM)
   - Branch condition optimization
   - Range checks for register indices

4. **Final Wrapping SNARK**
   - SuperSpartan IOP instantiation
   - Greyhound PCS integration
   - Succinct proof generation

5. **LatticeFold Norm Management**
   - Verify decomposed witness bounds
   - Sum-check range proofs
   - Noise growth tracking

6. **EVM Integration**
   - Ethereum state machine emulation
   - Block execution verification
   - Gas semantics

---

## Key Data Structures

### Goldilocks Field

```rust
// Prime: p = 2^64 - 2^32 + 1
type Goldilocks = p3_goldilocks::Goldilocks;
```

### Cyclotomic Ring (NTT domain)

```rust
// 8 NTT components per ring element (dimension = log2(256))
type GoldilocksRingNTT = cyclotomic_rings::rings::GoldilocksRingNTT;
```

### Commitment Format

```rust
type GoldilocksComm = [Goldilocks; 4];  // 4 field elements
```

### CCS Structure

```rust
pub struct CCS<Ring> {
    pub m: usize,        // Number of constraints (rows)
    pub n: usize,        // Number of variables (witness size)
    pub l: usize,        // Public inputs count
    pub t: usize,        // Number of matrices
    pub q: usize,        // Number of multisets
    pub d: usize,        // Maximum degree
    pub s: usize,        // log2(m)
    pub s_prime: usize,  // log2(n)
    pub M: Vec<SparseMatrix<Ring>>,  // Constraint matrices
    pub S: Vec<Vec<usize>>,           // Multisets
    pub c: Vec<Ring>,                // Coefficients
}
```

### R1CS Structures (LatticeFold)

```rust
// Committed CCS instance
pub struct CCCS<Ring> {
    pub cm: RingPoly<Ring>,  // Commitment to witness
    pub x_ccs: Vec<Ring>,   // Public inputs
}

// Linear Committed CCS instance
pub struct LCCCS<Ring> {
    pub r: RingPoly<Ring>,  // Evaluator
    pub v: Vec<RingPoly<Ring>>,
    pub cm: RingPoly<Ring>,
    pub u: Vec<Ring>,
    pub x_w: Vec<Ring>,
}
```

---

## Constants and Parameters

### VM Configuration (`crates/configuration`)

```rust
pub const N_REGS: usize = 32;
pub const RESULT_ADDRESS: u32 = 0x40000000;  // Where results are stored
```

### Cryptographic Parameters

```rust
pub const KAPPA: usize = 4;  // Commitment matrix rows
pub const DECOMPOSITION_PARAMS: GoldiLocksDP = {
    const B: u128 = 1 << 15,
    const L: usize = 5,
    const B_SMALL: usize = 2,
    const K: usize = 15,
};
```

### Poseidon2 Constants

```rust
pub const FULL_ROUNDS: usize = 8;      // 4 initial + 4 terminal
pub const PARTIAL_ROUNDS: usize = 22;
pub const WIDE_POSEIDON2_WIDTH: usize = 16;
pub const WIDE_POSEIDON2_RATE: usize = 12;
pub const POSEIDON2_OUT: usize = 4;
```

---

## Testing

Tests for the `vm` module are run by `cd crates/vm && cargo test`. The `vm`
uses the `guests/fibonacci/src/main.rs` → compiled to `fibonacci_100_000`.

### ZkVM testing on 100th fibonacci

The same `guests/fibonacci/src/main.rs` was changed to only produce 100th fibonacci,
and that is in the `./target/riscv32imac-unknown-none-elf/release/fibonacci`.

**Behavior**: Computes 100th Fibonacci number

**Verification**: Result stored at `RESULT_ADDRESS` (0x40000000), should equal `0xc594bfc3`

**Execution**:

The feature `debug` turns on debugging checks (checking that the CCS and witness
comply, and chekcing that the folding proof is valid at each ivc step). Also
run this with `--release` because it is slow otherwise. Now it takes 42 seconds.

```bash
RUST_LOG=<LOG-LEVEL> cargo run --bin zkvm --features debug --release
# Expects 16 execution traces, ~42 seconds proving time
```

---

## References & Papers

### Core Cryptography

- **LatticeFold**: Folding scheme with lattice-based commitments
- **Nova**: Original IVC/folding scheme
- **HyperNova**: Generalized folding schemes
- **CCS**: Customizable Constraint Systems

### Poseidon2

- **Poseidon2**: Optimized Poseidon hash for ZK-friendly circuits

### Memory Checking

- **Memory Access in SNARKs**: Offline memory consistency verification

### Lattice Cryptography

- **Ajtai 1998**: Lattice-based commitments
- **SIS/Module-SIS**: Hardness assumptions

### RISC-V

- **RISC-V Privileged Architecture**: ISA specification (rv32imac)
- **RISC-V Calling Convention**: Register ABI

---

## Notes for LLM Assistants

### When Adding New Instructions

1. Update `inst.rs`: Add execution logic
2. Update `ccs.rs`: Add CCS constraints for new instruction
3. Update `constraints.rs`: Add selector flag and constraint functions
4. Update `ccs.rs` in `set_trace_witness()`: Map trace elements to witness indices
5. Update `CCSLayout`: Add new witness indices if needed

### When Debugging CCS Relations

```rust
#[cfg(feature = "debug")]
ccs.check_relation(z).unwrap_or_else(|e| {
    panic!("CCS relation failed: {:?}", e);
});
```

### Memory Layout Considerations

- VM memory: 1MB (256 words × 1024 pages)
- Word alignment: All memory accesses must be 4-byte aligned
- Overflow: Arithmetic uses 2^32 wrapping with detection flag

### Key Implementation Files

| Module            | File                      | Purpose                   |
| ----------------- | ------------------------- | ------------------------- |
| VM execution      | `vm/src/riscvm/vm.rs`     | Main execution loop       |
| Instruction logic | `vm/src/riscvm/inst.rs`   | Instruction semantics     |
| CCS layout        | `zkvm/src/ccs.rs`         | Witness index mapping     |
| Constraints       | `zkvm/src/constraints.rs` | Constraint matrices       |
| Main loop         | `zkvm/src/main.rs`        | IVC execution and folding |
| IVC structs       | `zkvm/src/ivc.rs`         | Step I/O types            |

### Build System

```bash
# Rust toolchain: nightly-2025-08-19
cargo build --release

# Debug feature for CCS relation verification
cargo build --release --features debug
```
