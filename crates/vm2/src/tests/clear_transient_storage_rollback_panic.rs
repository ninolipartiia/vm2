//! Regression test for the rollback-safety violation documented in
//! `security-review/05-clear-transient-storage-snapshot-invalidation.md`.
//!
//! `WorldDiff::clear_transient_storage` swaps `transient_storage_changes` for a
//! fresh `RollbackableMap`, throwing away the `old_entries` history. Any
//! `Snapshot` captured before the swap is a `usize` index into the *old*
//! `old_entries` and becomes meaningless against the new one. On a panic-return
//! from a near-call whose snapshot pre-dates the swap, `RollbackableMap::rollback`
//! calls `Vec::drain(snapshot..)` on a length-0 `Vec`, which panics the host
//! process.
//!
//! Program layout (assembled below as raw EraVM bytecode and decoded by
//! `Program::new`, mirroring the production code path that user contracts go
//! through):
//!
//! ```text
//! PC=0: tstore.w  r1, r2          ; writes (k=0, v=0); old_entries.len() = 1
//! PC=1: near_call r0, 2, 0xFFFF   ; snapshot captures transient_storage = 1,
//!                                 ; error_handler = 0xFFFF (program terminator)
//! PC=2: increment_tx_number       ; clears transient storage → old_entries = []
//! PC=3: ret.panic                  ; naked_ret → rollback(snapshot=1)
//!                                  ; → drain(1..) on empty Vec → host panic
//! ```
//!
//! Pre-fix, `vm.run` host-panics inside `Vec::drain`; the test catches that
//! payload and asserts it points to the drain site. Post-fix the rollback
//! succeeds and the run exits with `ExecutionEnd::Panicked` via the
//! out-of-bounds error-handler PC (0xFFFF → `invalid_instruction` →
//! gas exhaustion → VM-level panic); this test should then be deleted (or
//! flipped to assert the clean exit) since it is intended as a regression
//! guard for the *current* drain-OOB site.
//!
//! Requirements that go beyond what `tests/differential-regressions` can do:
//! - executes four sequential instructions, not one cycle;
//! - traverses a near-call boundary (multi-frame state, near-call snapshot);
//! - the failure mode is a host panic in Rust code, not a divergence in
//!   `UniversalVmState` between vm2 and zk_evm. zk_evm models transient
//!   storage with a rollback-aware structure and produces no observable
//!   anomaly on this sequence.

use std::panic::{catch_unwind, AssertUnwindSafe};

use zkevm_opcode_defs::{
    decoding::{EncodingModeProduction, VmEncodingMode},
    ethereum_types::Address,
    Condition, ContextOpcode, DecodedOpcode, LogOpcode, NearCallOpcode, Opcode, OpcodeVariant,
    Operand, RetOpcode,
};

use crate::{
    testonly::{initial_decommit, TestWorld},
    ExecutionEnd, Program, Settings, VirtualMachine,
};

/// Encodes one EraVM instruction word, using `RegOnly` for both src0 and dst0
/// operand kinds. The opcodes used by this test (`TransientStorageWrite`,
/// `NearCall`, `IncrementTxNumber`, `Ret::Panic`) either ignore those fields
/// at decode time or consume `RegOnly` directly, so a single helper suffices.
fn encode(
    opcode: Opcode,
    src0_reg_idx: u8,
    src1_reg_idx: u8,
    dst0_reg_idx: u8,
    imm_0: u16,
    imm_1: u16,
) -> u64 {
    let opcode = DecodedOpcode::<8, EncodingModeProduction> {
        variant: OpcodeVariant {
            opcode,
            src0_operand_type: Operand::RegOnly,
            dst0_operand_type: Operand::RegOnly,
            flags: [false; 2],
        },
        condition: Condition::Always,
        src0_reg_idx,
        src1_reg_idx,
        dst0_reg_idx,
        dst1_reg_idx: 0,
        imm_0,
        imm_1,
    };
    EncodingModeProduction::encode_as_integer(&opcode)
}

#[test]
fn near_call_rollback_after_clear_transient_storage_host_panics() {
    let bytecode: Vec<u8> = [
        // PC=0: TransientStorageWrite r1, r2 — key from R1, value from R2.
        // Both registers are zero at VM entry; insert((addr, 0), 0) still grows
        // transient_storage_changes.old_entries by one, which is all that the
        // captured snapshot needs to index off-by-one against post-clear.
        encode(
            Opcode::Log(LogOpcode::TransientStorageWrite),
            /* src0_reg_idx (key) = */ 1,
            /* src1_reg_idx (val) = */ 2,
            /* dst0_reg_idx       = */ 0,
            /* imm_0              = */ 0,
            /* imm_1              = */ 0,
        ),
        // PC=1: NearCall r0, dest=2, err_handler=0xFFFF. Register 0 reads as 0,
        // which the near-call handler treats as "pass all remaining gas". The
        // captured snapshot at this point has `transient_storage_changes = 1`.
        encode(
            Opcode::NearCall(NearCallOpcode),
            /* gas_reg = */ 0,
            /* unused  = */ 0,
            /* unused  = */ 0,
            /* dest    = */ 2,
            /* err_pc  = */ 0xFFFF,
        ),
        // PC=2: IncrementTxNumber — kernel-mode-only at the ModeRequirements
        // check inside `boilerplate`. The caller address below is in the
        // kernel range, so this runs and reaches
        // `start_new_tx` → `clear_transient_storage`, which swaps the map
        // (old_entries.len() = 0) while the near-call snapshot still pins 1.
        encode(
            Opcode::Context(ContextOpcode::IncrementTxNumber),
            0,
            0,
            0,
            0,
            0,
        ),
        // PC=3: Ret::Panic (no label). With RET_TO_LABEL = false and the
        // current frame holding a near-call FrameRemnant, `naked_ret` jumps
        // to the captured exception_handler AND calls
        // `vm.world_diff.rollback(snapshot)`. The transient-storage rollback
        // is where the drain OOB fires.
        encode(Opcode::Ret(RetOpcode::Panic), 0, 0, 0, 0, 0),
    ]
    .iter()
    .flat_map(|word| word.to_be_bytes())
    .collect();

    let program = Program::new(&bytecode, /* enable_hooks = */ false);

    // Kernel address: `decommit::is_kernel` returns true when the first 18
    // bytes are zero. `Address::from_low_u64_be(1)` zeroes the first 12 bytes
    // from padding and the next 7 from the leading bytes of the u64 BE form.
    let address = Address::from_low_u64_be(1);
    let mut world = TestWorld::new(&[(address, program)]);
    let program = initial_decommit(&mut world, address);

    let mut vm = VirtualMachine::new(
        address,
        program,
        Address::zero(),
        &[],
        10_000,
        Settings {
            default_aa_code_hash: [0; 32],
            evm_interpreter_code_hash: [0; 32],
            hook_address: 0,
        },
    );

    // `vm.run` is expected to host-panic on the pre-fix code path. Catch the
    // payload so the test failure carries the panic message instead of tearing
    // down the test runner.
    let result = catch_unwind(AssertUnwindSafe(|| vm.run(&mut world, &mut ())));
    let payload = match result {
        Err(p) => p,
        Ok(end) => panic!(
            "expected a host panic from `Vec::drain` inside \
             `RollbackableMap::rollback` after `clear_transient_storage`, \
             but vm.run returned cleanly: {end:?}. If this fails post-fix, \
             delete this test (or convert it into a positive regression that \
             asserts `ExecutionEnd::Panicked` and a restored pre-snapshot \
             transient slot)."
        ),
    };

    let msg = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&'static str>().copied())
        .unwrap_or("<non-string panic payload>");

    eprintln!("captured panic payload: {msg}"); // TEMP for verification

    // The exact std-library message for `Vec::drain` with `start > end` /
    // `start > len` has historically been some variant of these substrings;
    // match liberally to avoid pinning the test to one stdlib release.
    let looks_like_drain_oob = msg.contains("drain")
        || msg.contains("removal index")
        || msg.contains("end <= len")
        || msg.contains("range start index")
        || msg.contains("out of bounds");

    assert!(
        looks_like_drain_oob,
        "host panic was not the expected `Vec::drain` OOB; got: {msg}",
    );

    // Make `ExecutionEnd` reachable for cargo without unused-import warnings
    // once this test is deleted in favour of the positive regression.
    let _ = ExecutionEnd::Panicked;
}
