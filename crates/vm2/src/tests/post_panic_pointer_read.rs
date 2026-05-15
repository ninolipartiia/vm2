//! Regression test for the post-panic empty-fat-pointer + `PointerRead`
//! host panic.
//!
//! See `security-review/heaps/01-post-panic-empty-fatpointer-pointerread.md`
//! and `security-review/04-failed-far-call-r1-poison-host-panic.md`.
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
//! `pointer.offset = 0`), and the next line indexes `vm.state.heaps[HeapId(0)]`.
//! Pre-fix, `Heaps::Index<HeapId>` was partial and `panic!`d on undecodable
//! ids (`heap.rs:534-541`), aborting the host. Post-fix, indexing falls back
//! to a shared empty heap so the read returns zero — matching `zk_evm`'s
//! tolerant memory layer.
//!
//! The program is assembled here as raw EraVM bytecode and loaded via
//! `Program::new`, mirroring the production path for user-deployed contracts.
//! `decode_program` appends `Instruction::from_invalid` as the program
//! terminator, so falling off the end of the user instructions converts into
//! a clean VM-level panic (`ExecutionEnd::Panicked`) rather than UB.

use std::panic::{catch_unwind, AssertUnwindSafe};

use zkevm_opcode_defs::{
    decoding::{EncodingModeProduction, VmEncodingMode},
    ethereum_types::Address,
    Condition, DecodedOpcode, FarCallOpcode, Opcode, OpcodeVariant, Operand, UMAOpcode,
};

use crate::{
    testonly::{initial_decommit, TestWorld},
    ExecutionEnd, Program, Settings, VirtualMachine,
};

fn encode_far_call_normal(abi_reg: u8, dst_reg: u8, exception_handler: u16) -> u64 {
    let opcode = DecodedOpcode::<8, EncodingModeProduction> {
        variant: OpcodeVariant {
            opcode: Opcode::FarCall(FarCallOpcode::Normal),
            src0_operand_type: Operand::RegOnly,
            dst0_operand_type: Operand::RegOnly,
            flags: [false; 2],
        },
        condition: Condition::Always,
        src0_reg_idx: abi_reg,
        src1_reg_idx: dst_reg,
        dst0_reg_idx: 0,
        dst1_reg_idx: 0,
        imm_0: exception_handler,
        imm_1: 0,
    };
    EncodingModeProduction::encode_as_integer(&opcode)
}

fn encode_fat_pointer_read(src_reg: u8, dst_reg: u8) -> u64 {
    // `UMAOpcode::FatPointerRead` is the only UMA read whose src0 is
    // `Operand::RegOnly` rather than `RegOrImm(UseRegOnly)`
    // (zkevm_opcode_defs::definitions::uma::input_operands).
    let opcode = DecodedOpcode::<8, EncodingModeProduction> {
        variant: OpcodeVariant {
            opcode: Opcode::UMA(UMAOpcode::FatPointerRead),
            src0_operand_type: Operand::RegOnly,
            dst0_operand_type: Operand::RegOnly,
            flags: [false; 2],
        },
        condition: Condition::Always,
        src0_reg_idx: src_reg,
        src1_reg_idx: 0,
        dst0_reg_idx: dst_reg,
        dst1_reg_idx: 0,
        imm_0: 0,
        imm_1: 0,
    };
    EncodingModeProduction::encode_as_integer(&opcode)
}

#[test]
fn far_call_panic_followed_by_pointer_read_does_not_crash_host() {
    // Program layout (assembled below as raw EraVM bytecode):
    //   PC=0: far_call r1, r2, exception_handler=1
    //         r2 = 0 ⇒ no code at address 0 ⇒ fallible_part = None ⇒ far_call
    //         pushes Program::new_panicking() with a synthetic empty fat pointer.
    //   PC=1: ptr.r r1, r3 (UMA FatPointerRead)
    //         Reached via the exception handler after the synthetic panic.
    //         Pre-fix: r1 = 0 with pointer flag set ⇒ heaps[HeapId(0)] ⇒ host panic.
    //         Post-fix: empty-heap fallback returns zero into r3 and PC advances.
    //   PC=2: program terminator (`Instruction::from_invalid` appended by
    //         `decode_program`) — drains all gas and exits with
    //         `ExecutionEnd::Panicked`.
    let bytecode: Vec<u8> = [
        encode_far_call_normal(
            /* abi_reg */ 1, /* dst_reg */ 2, /* exception_handler */ 1,
        ),
        encode_fat_pointer_read(/* src_reg */ 1, /* dst_reg */ 3),
    ]
    .iter()
    .flat_map(|word| word.to_be_bytes())
    .collect();

    let program = Program::new(&bytecode, /* enable_hooks */ false);

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
            panic!("vm.run host-panicked instead of returning ExecutionEnd::Panicked: {msg}");
        }
    }
}
