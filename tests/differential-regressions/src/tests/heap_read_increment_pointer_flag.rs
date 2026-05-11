//! Regression tests for the UMA-read-with-INCREMENT pointer-flag divergence
//! between vm2 and zk_evm.
//!
//! Pre-fix, vm2's `load` and `load_static` use `Register2::set` for the
//! incremented destination register (see
//! `crates/vm2/src/instruction_handlers/heap_access.rs:99` and `:217`),
//! which clears the bit in `register_pointer_flags` — regardless of whether
//! the source operand carried the pointer flag. zk_evm's UMA handler at
//! `zk_evm/src/opcodes/execution/uma.rs:404-413` writes dst1 with
//! `is_pointer: src0_is_ptr`, preserving the flag for all four read variants
//! (HeapRead, AuxHeapRead, FatPointerRead, StaticMemoryRead).
//!
//! The post-panic-Ret state from a far call (`r1 = 0`, `is_pointer = true`,
//! see `crates/vm2/src/instruction_handlers/ret.rs:103-108`) is a concrete
//! reachable trigger: a `HeapRead r1+, dst1` in the caller's exception
//! handler passes the range check in both VMs (`value = 0 <= LAST_ADDRESS`),
//! and the divergence surfaces on `dst1`'s pointer flag. A subsequent
//! `FatPointerRead` / `Ptr*` op on `dst1` then takes different paths in vm2
//! and zk_evm — a consensus-halt-class trace divergence.
//!
//! Writes (HeapWrite / AuxHeapWrite / StaticMemoryWrite) converge between
//! the two VMs — both clear the flag on the increment register; zk_evm even
//! `debug_assert_eq!(src0_is_ptr, false)`. They are not tested here.
//!
//! Each test below builds the post-panic-Ret state explicitly (no need to
//! actually run a panicking Ret — `register_pointer_flags = 1 << src_reg`
//! short-circuits the chain), runs one UMA read instruction in both VMs via
//! [`step_diff`], and asserts equality on `UniversalVmState`. See
//! `security-review/01-static-memory-pointer-flag-divergence.md` for the
//! full narrative.

use pretty_assertions::assert_eq;
use primitive_types::{H160, U256};
use zkevm_opcode_defs::{ethereum_types::Address, Condition, UMAOpcode};
use zksync_vm2::{
    single_instruction_test::{
        encode_uma, step_diff, CallframeSetup, MockWorld, SingleInstructionTestSetup,
    },
    Settings, VirtualMachine,
};
use zksync_vm2_interface::HeapId;

/// `STARTING_BASE_PAGE` from `zkevm_opcode_defs::system_params`.
const STARTING_BASE_PAGE: u32 = 8;
/// Pages a single FarCall reserves: code page, calldata, heap, aux heap.
const PAGES_PER_FAR_CALL: u32 = 4;

/// Kernel address (first 18 bytes zero) — needed for StaticMemoryRead, which
/// is kernel-only per `UMAOpcode::requires_kernel_mode`.
fn kernel_address(low: u64) -> H160 {
    Address::from_low_u64_be(low)
}

/// Non-kernel address — sufficient for HeapRead / AuxHeapRead, which are
/// user-mode accessible.
fn non_kernel_address(byte: u8) -> H160 {
    H160::repeat_byte(byte)
}

/// vm2's UMA opcodes don't read `Settings`, but `zk_evm` asserts that the
/// default-AA and EVM-emulator hashes are well-formed at the top of *every*
/// cycle (see `zk_evm/src/vm_state/cycle.rs:294-317` calling
/// `ContractCodeSha256Format::is_valid`, which requires `byte[0] == 0x01`).
/// So we still need a "looks like a valid code hash" preamble even though
/// the opcode under test never reads it.
fn cycle_safe_settings() -> Settings {
    let mut valid_hash = [0u8; 32];
    valid_hash[0] = 1; // version byte — required by zk_evm's per-cycle assert

    Settings {
        default_aa_code_hash: valid_hash,
        evm_interpreter_code_hash: valid_hash,
        hook_address: 0,
    }
}

/// Builds a single-instruction setup that runs one UMA read with INCREMENT=true
/// on a register that has the pointer flag set.
///
/// `src_reg` holds a small numeric value (`0`) that passes the
/// `bigger_than_last_address` check in both VMs. The pointer flag on
/// `src_reg` is set via `register_pointer_flags`, mirroring the state left
/// by a panicking far-call Ret.
fn uma_read_increment_setup(
    kind: UMAOpcode,
    caller: H160,
    src_reg: u8,
    dst0_reg: u8,
    dst1_reg: u8,
) -> SingleInstructionTestSetup {
    let raw_instruction = encode_uma(
        kind,
        /* src0_reg_idx = */ src_reg,
        /* src1_reg_idx = */ 0,
        /* dst0_reg_idx = */ dst0_reg,
        /* dst1_reg_idx = */ dst1_reg,
        /* increment   = */ true,
        Condition::Always,
    );

    let mut registers = [U256::zero(); 16];
    // src_reg already holds 0; explicit assignment for readability.
    registers[usize::from(src_reg)] = U256::zero();

    SingleInstructionTestSetup {
        current_frame: CallframeSetup {
            address: caller,
            code_address: caller,
            caller: H160::zero(),
            gas: 1_000_000_000,
            exception_handler: 0,
            context_u128: 0,
            is_static: false,
            raw_instruction,
            heap_size: 0,
            aux_heap_size: 0,
            sp: 0,
            base_page: STARTING_BASE_PAGE,
            calldata_heap: HeapId::FIRST_CALLDATA,
        },
        registers,
        // Bit `src_reg` set: src_reg holds a "pointer" (post-panic-Ret state).
        // This is the only bit that differs from the evm_stipend setup.
        register_pointer_flags: 1u16 << src_reg,
        lt_of_flag: false,
        eq_flag: false,
        gt_flag: false,
        transaction_number: 0,
        context_u128: 0,
        next_base_page: STARTING_BASE_PAGE + PAGES_PER_FAR_CALL,
    }
}

/// HeapRead r1+, dst1 with r1 = 0 and r1's pointer flag set.
///
/// Pre-fix: vm2 clears the pointer flag on r2 (dst1); zk_evm preserves it.
/// `UniversalVmState::registers[1].is_pointer` (i.e. r2) diverges → test fails.
/// Post-fix: both VMs leave r2 with `is_pointer = true`.
///
/// Should FAIL if the fix has not been applied.
#[test]
fn heap_read_increment_preserves_pointer_flag_matching_zk_evm() {
    let setup = uma_read_increment_setup(
        UMAOpcode::HeapRead,
        /* caller    = */ non_kernel_address(0x11),
        /* src_reg   = */ 1,
        /* dst0_reg  = */ 3, // destination for the read value
        /* dst1_reg  = */ 2, // destination for the incremented offset
    );

    let mut vm =
        VirtualMachine::<(), MockWorld>::for_test_single_instruction(setup, cycle_safe_settings());
    let mut world = MockWorld::with_storage_slot(None);

    let (zk_evm_state, vm2_state) = step_diff(&mut vm, &mut world);
    assert_eq!(zk_evm_state, vm2_state);
}

/// AuxHeapRead r1+, dst1 — same shape as the HeapRead test. AuxHeapRead is
/// also user-mode accessible and shares the buggy `load` handler with
/// HeapRead, so this test covers the same defect via the AuxHeap variant.
///
/// Should FAIL if the fix has not been applied.
#[test]
fn aux_heap_read_increment_preserves_pointer_flag_matching_zk_evm() {
    let setup = uma_read_increment_setup(
        UMAOpcode::AuxHeapRead,
        /* caller    = */ non_kernel_address(0x11),
        /* src_reg   = */ 1,
        /* dst0_reg  = */ 3,
        /* dst1_reg  = */ 2,
    );

    let mut vm =
        VirtualMachine::<(), MockWorld>::for_test_single_instruction(setup, cycle_safe_settings());
    let mut world = MockWorld::with_storage_slot(None);

    let (zk_evm_state, vm2_state) = step_diff(&mut vm, &mut world);
    assert_eq!(zk_evm_state, vm2_state);
}

/// StaticMemoryRead r1+, dst1 — exercises the separate `load_static` handler
/// in `heap_access.rs:197-219`. Kernel-only per `UMAOpcode::requires_kernel_mode`,
/// so this test runs from a kernel address.
///
/// Should FAIL if the fix has not been applied.
#[test]
fn static_memory_read_increment_preserves_pointer_flag_matching_zk_evm() {
    let setup = uma_read_increment_setup(
        UMAOpcode::StaticMemoryRead,
        /* caller    = */ kernel_address(1),
        /* src_reg   = */ 1,
        /* dst0_reg  = */ 3,
        /* dst1_reg  = */ 2,
    );

    let mut vm =
        VirtualMachine::<(), MockWorld>::for_test_single_instruction(setup, cycle_safe_settings());
    let mut world = MockWorld::with_storage_slot(None);

    let (zk_evm_state, vm2_state) = step_diff(&mut vm, &mut world);
    assert_eq!(zk_evm_state, vm2_state);
}

/// Negative control: HeapRead **without** INCREMENT. There is no increment
/// register write, so the pointer-flag bug cannot fire. This test should
/// PASS under both pre-fix and post-fix vm2 — it guards against a regression
/// in which the non-INCREMENT path itself drifts from zk_evm.
#[test]
fn heap_read_no_increment_matches_zk_evm() {
    let raw_instruction = encode_uma(
        UMAOpcode::HeapRead,
        /* src0_reg_idx = */ 1,
        /* src1_reg_idx = */ 0,
        /* dst0_reg_idx = */ 3,
        /* dst1_reg_idx = */ 0,
        /* increment    = */ false,
        Condition::Always,
    );

    let mut registers = [U256::zero(); 16];
    registers[1] = U256::zero();

    let setup = SingleInstructionTestSetup {
        current_frame: CallframeSetup {
            address: non_kernel_address(0x11),
            code_address: non_kernel_address(0x11),
            caller: H160::zero(),
            gas: 1_000_000_000,
            exception_handler: 0,
            context_u128: 0,
            is_static: false,
            raw_instruction,
            heap_size: 0,
            aux_heap_size: 0,
            sp: 0,
            base_page: STARTING_BASE_PAGE,
            calldata_heap: HeapId::FIRST_CALLDATA,
        },
        registers,
        register_pointer_flags: 1u16 << 1,
        lt_of_flag: false,
        eq_flag: false,
        gt_flag: false,
        transaction_number: 0,
        context_u128: 0,
        next_base_page: STARTING_BASE_PAGE + PAGES_PER_FAR_CALL,
    };

    let mut vm =
        VirtualMachine::<(), MockWorld>::for_test_single_instruction(setup, cycle_safe_settings());
    let mut world = MockWorld::with_storage_slot(None);

    let (zk_evm_state, vm2_state) = step_diff(&mut vm, &mut world);
    assert_eq!(zk_evm_state, vm2_state);
}
