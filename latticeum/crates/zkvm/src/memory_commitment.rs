use vm::riscvm::inst::MemoryOperation;

pub fn mem_comm(previous_comm: u64, _mem_op: &MemoryOperation) -> u64 {
    previous_comm + 1
}
