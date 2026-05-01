#![allow(clippy::doc_markdown)] // doc comments reference VM names, opcode kinds, and storage layouts in plain prose

//! Hand-written vm2-vs-zk_evm differential regressions.
//!
//! Each `#[test]` constructs a complete initial VM state explicitly via
//! [`zksync_vm2::single_instruction_test::SingleInstructionTestSetup`], then
//! runs one instruction in vm2 and one cycle in zk_evm via
//! [`zksync_vm2::single_instruction_test::step_diff`] and asserts that both
//! VMs land on the same [`zksync_vm2::single_instruction_test::UniversalVmState`].
//!
//! Compared to the AFL fuzz harness in [`tests/afl-fuzz`], these tests are
//! deterministic (no `Arbitrary`), self-documenting (every field of the
//! initial state is visible at the call site), and run under `cargo test`.

#[cfg(test)]
mod tests;
