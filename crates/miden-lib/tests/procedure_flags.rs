//! Basic smoke-tests for the new procedure-introspection helpers.
//! For now we simply make sure the assembly snippets assemble and link –
//! full VM execution tests live in the integration crate and batch prover.

#[test]
fn asm_compiles_with_was_procedure_called() {
    let asm = r#"
        begin
            push.0
            exec.account::was_procedure_called
            assert
        end
    "#;

    // Compilation only – we don't execute in this unit test, because the
    // heavy VM harness lives in `miden-testing` integration tests.
    miden_lib::assemble(asm).expect("assembly should compile");
}

#[test]
fn asm_compiles_with_get_procedure_info_four_outputs() {
    let asm = r#"
        begin
            push.0
            exec.account::get_procedure_info
            drop drop drop drop    # discard 4 words
        end
    "#;
    miden_lib::assemble(asm).expect("assembly should compile with 4 outputs");
}

// Helper to reach into the library without pulling the full VM.
mod miden_lib {
    use miden_lib::assembler::assemble;
    pub fn assemble(src: &str) -> Result<(), miden_lib::AssemblerError> {
        assemble(src).map(|_| ())
    }
}