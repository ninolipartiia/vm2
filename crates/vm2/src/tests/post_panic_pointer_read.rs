//! Regression test for the post-panic empty-fat-pointer + `PointerRead`
//! host panic.
//!
//! See `security-review/heaps/01-post-panic-empty-fatpointer-pointerread.md`
//! and `security-review/04-post-panic-empty-fatpointer-pointerread.md`.
//!
//! When `far_call`'s `fallible_part` returns `None` (e.g. the target cannot be
//! decommitted), `far_call.rs:131-132` pushes a `Program::new_panicking()`
//! callee with a synthetic empty fat pointer. The callee's first instruction
//! panics, and the panic-return branch of `naked_ret` at `ret.rs:103-108`
//! zeroes the registers but unconditionally sets `register_pointer_flags = 2`
//! — leaving the caller with `r1 = 0` AND `r1`'s pointer flag set, i.e. a fat
//! pointer to `HeapId(0)`.
//!
//! A `pointer_read r1, r3` in the caller's exception handler then takes that
//! poisoned r1 at face value: both guards in `load_pointer`
//! (`heap_access.rs:175-194`) pass (`input_is_pointer = true`,
//! `pointer.offset = 0`), and the next line indexes `vm.state.heaps[HeapId(0)]`
//! — which `Heaps::Index<HeapId>` cannot decode and turns into
//! `panic!("heap page 0 is not allocated")` (`heap.rs:534-541`). That is a
//! Rust `panic!`, not a VM panic: the host aborts.
//!
//! This test should FAIL pre-fix with that exact host-panic message, and PASS
//! (returning `ExecutionEnd::Panicked`) once either recommended fix from the
//! finding is applied:
//!   1. Sanitize the post-panic register state in `naked_ret` so r1's pointer
//!      flag is only set when there is a returned pointer (`ret.rs:103-108`).
//!   2. Make `Heaps::Index<HeapId>` total — return an empty heap instead of
//!      panicking on undecodable ids (`heap.rs:534-541`).

use std::panic::{catch_unwind, AssertUnwindSafe};

use zkevm_opcode_defs::ethereum_types::Address;

use crate::{
    addressing_modes::{Arguments, Immediate1, Register, Register1, Register2},
    interface::opcodes::Normal,
    testonly::{initial_decommit, TestWorld},
    ExecutionEnd, Instruction, ModeRequirements, Predicate, Program, Settings, VirtualMachine,
};

#[test]
fn far_call_panic_followed_by_pointer_read_does_not_crash_host() {
    // Program layout (all in a single non-kernel user contract):
    //   PC=0: far_call r1, r2, exception_handler=1
    //         r2 = 0 ⇒ kernel address 0 with no code ⇒ `fallible_part` returns
    //         `None`, far_call pushes `Program::new_panicking()`.
    //   PC=1: pointer_read r1, r3
    //         Reached via the exception handler after the synthetic panic.
    //         Pre-fix: r1 = 0 with pointer flag set ⇒ heaps[HeapId(0)] ⇒ host panic.
    let instructions = vec![
        Instruction::from_far_call::<Normal>(
            Register1(Register::new(1)),
            Register2(Register::new(2)),
            Immediate1(1),
            false,
            false,
            Arguments::new(Predicate::Always, 25, ModeRequirements::none()),
        ),
        Instruction::from_pointer_read(
            Register1(Register::new(1)),
            Register1(Register::new(3)),
            None,
            Arguments::new(Predicate::Always, 7, ModeRequirements::none()),
        ),
    ];

    let program = Program::from_raw(instructions, vec![]);

    // Non-kernel address — first 18 bytes are not all zero, so this contract
    // would be deployable by an unprivileged user. Demonstrates that the
    // funnel needs no kernel mode and no system-contract laundering.
    let caller = Address::from_low_u64_be(0x_1234_5678_90ab_cdef);
    let mut world = TestWorld::new(&[(caller, program)]);
    let program = initial_decommit(&mut world, caller);

    let mut vm = VirtualMachine::new(
        caller,
        program,
        Address::zero(),
        &[],
        1_000,
        Settings {
            default_aa_code_hash: [0; 32],
            evm_interpreter_code_hash: [0; 32],
            hook_address: 0,
        },
    );

    // Catch the host panic so the test failure carries the message instead of
    // tearing down the test process.
    let result = catch_unwind(AssertUnwindSafe(|| vm.run(&mut world, &mut ())));
    match result {
        Ok(end) => assert_eq!(
            end,
            ExecutionEnd::Panicked,
            "expected a clean VM-level panic exit"
        ),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&'static str>().copied())
                .unwrap_or("<non-string panic payload>");
            panic!(
                "vm.run host-panicked instead of returning ExecutionEnd::Panicked: {msg}"
            );
        }
    }
}
