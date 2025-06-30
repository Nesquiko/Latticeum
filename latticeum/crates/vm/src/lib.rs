mod riscvm;

// #[derive(Debug)]
// pub struct DecodedInstruction {
//     opcode: Opcode,
//     rd: Option<u8>,
//     rs1: Option<u8>,
//     rs2: Option<u8>,
//     imm: Option<i32>,
// }

#[cfg(test)]
mod tests {
    use crate::riscvm::vm::VM;
    use std::path::PathBuf;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn initialize() {
        let mut vm = VM::new(1);

        let program = PathBuf::from("samples/fibonacci");
        let _result = vm.load_elf(program);
    }
}
