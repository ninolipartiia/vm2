//! Programmatic VM construction for hand-written single-instruction differential tests.
//!
//! [`SingleInstructionTestSetup`] is the explicit input to
//! [`VirtualMachine::for_test_single_instruction`] — every field of the resulting VM
//! state that the differential cares about (frame, registers, flags, heap layout,
//! transaction number, etc.) is set by the caller. No `Arbitrary` magic, no
//! hidden defaults beyond a freshly-empty `Heaps`/`Stack`/`WorldDiff`.
//!
//! Pair with [`MockWorld::with_storage_slot`](super::MockWorld::with_storage_slot)
//! and [`step_diff`] to build a self-contained vm2-vs-zk_evm regression.

use primitive_types::{H160, U256};
use zkevm_opcode_defs::{
    decoding::{EncodingModeProduction, VmEncodingMode},
    Condition, DecodedOpcode, FarCallOpcode, Opcode, OpcodeVariant, Operand, RegOrImmFlags,
    UMAOpcode, FAR_CALL_SHARD_FLAG_IDX, FAR_CALL_STATIC_FLAG_IDX, UMA_INCREMENT_FLAG_IDX,
};
use zksync_vm2_interface::{HeapId, Tracer};

use super::{
    into_zk_evm::{add_heap_to_zk_evm, vm2_to_zk_evm, NoTracer},
    universal_state::UniversalVmState,
    MockWorld,
};
use crate::{
    callframe::Callframe, decommit::is_kernel, predication::Flags, program::Program,
    stack::StackPool, state::State, Settings, VirtualMachine, World, WorldDiff,
};

/// Initial state of the current call frame for a single-instruction test.
///
/// Every field here is set explicitly by the caller; nothing is derived from
/// `Arbitrary`. The frame's heap and aux heap are derived from `base_page`
/// using the same `+2`/`+3` offsets the production code uses
/// (see [`crate::page_ids`]).
#[derive(Debug, Clone)]
pub struct CallframeSetup {
    pub address: H160,
    pub code_address: H160,
    pub caller: H160,
    pub gas: u32,
    pub exception_handler: u16,
    pub context_u128: u128,
    pub is_static: bool,
    /// 64-bit raw opcode word — see [`encode_far_call`].
    pub raw_instruction: u64,
    /// `heap_size` / `aux_heap_size` of the current frame at test start
    /// (i.e. *before* the instruction runs).
    pub heap_size: u32,
    pub aux_heap_size: u32,
    pub sp: u16,
    /// Base page for this frame's heap pages. Heap = `base_page + 2`,
    /// aux heap = `base_page + 3`. Must be ≥ 1 and leave room for `+3`.
    pub base_page: u32,
    pub calldata_heap: HeapId,
}

/// Initial VM state for a single-instruction test. See module docs.
#[derive(Debug, Clone)]
pub struct SingleInstructionTestSetup {
    pub current_frame: CallframeSetup,
    pub registers: [U256; 16],
    /// Bitmask: bit `i` set means register `i` holds a fat pointer.
    pub register_pointer_flags: u16,
    pub lt_of_flag: bool,
    pub eq_flag: bool,
    pub gt_flag: bool,
    pub transaction_number: u16,
    pub context_u128: u128,
    pub next_base_page: u32,
}

impl<T: Tracer, W: World<T>> VirtualMachine<T, W> {
    /// Constructs a VM ready to execute the single instruction encoded in
    /// `setup.current_frame.raw_instruction`. Used by the differential-
    /// regressions test crate.
    ///
    /// The state has one bottom dummy frame plus `current_frame`, mirroring the
    /// `Arbitrary` impl — `zk_evm` requires at least one frame below the active one.
    pub fn for_test_single_instruction(
        setup: SingleInstructionTestSetup,
        settings: Settings,
    ) -> Self {
        let SingleInstructionTestSetup {
            current_frame,
            registers,
            register_pointer_flags,
            lt_of_flag,
            eq_flag,
            gt_flag,
            transaction_number,
            context_u128,
            next_base_page,
        } = setup;

        let world_diff = WorldDiff::default();
        let mut stack_pool = StackPool {};

        let program = Program::with_raw_first_instruction(current_frame.raw_instruction);

        let frame = Callframe::for_test_single_instruction(
            current_frame,
            program,
            &mut stack_pool,
            world_diff.snapshot(),
        );

        let state = State::for_test_single_instruction(
            frame,
            registers,
            register_pointer_flags,
            Flags::new(lt_of_flag, eq_flag, gt_flag),
            transaction_number,
            context_u128,
            next_base_page,
        );

        Self {
            world_diff,
            state,
            settings,
            stack_pool,
            snapshot: None,
        }
    }
}

/// Runs one instruction in vm2 and one cycle in `zk_evm` starting from the same
/// state, then returns the two VMs' projections into [`UniversalVmState`].
///
/// Mirrors the comparison performed by `tests/afl-fuzz/src/show_testcase.rs`
/// and the AFL fuzz target. Far-call panic reconciliation (the `pending_exception`
/// double-step) is handled here so that callers can simply
/// `assert_eq!(zk, vm2)` on the result.
///
/// The vm2 tracer type is fixed to `()` (the no-op vm2 tracer) because that is
/// the only tracer the existing fuzz harness exercises and the only tracer that
/// has a defined `zk_evm`-side counterpart in [`NoTracer`].
///
/// # Panics
///
/// If vm2 is not in a valid state before or after the step.
pub fn step_diff(
    vm: &mut VirtualMachine<(), MockWorld>,
    world: &mut MockWorld,
) -> (UniversalVmState, UniversalVmState) {
    assert!(
        vm.is_in_valid_state(),
        "vm2 entered an invalid state before stepping",
    );
    let is_far_call = vm.instruction_is_far_call();

    let mut zk_evm = vm2_to_zk_evm(vm, world.clone());

    vm.run_single_instruction(world, &mut ());
    assert!(
        vm.is_in_valid_state(),
        "vm2 entered an invalid state after stepping",
    );

    add_heap_to_zk_evm(&mut zk_evm, vm);
    let _ = zk_evm.cycle(&mut NoTracer);

    if is_far_call && zk_evm.local_state.pending_exception {
        vm.run_single_instruction(world, &mut ());
        let _ = zk_evm.cycle(&mut NoTracer);
    }

    let zk_state = UniversalVmState::from(zk_evm);
    let vm2_state = vm2_to_zk_evm(vm, world.clone()).into();
    (zk_state, vm2_state)
}

/// Encodes a `FarCall` opcode word (`u64`) suitable for
/// [`Program::with_raw_first_instruction`].
///
/// The encoding goes through the same `EncodingModeProduction` lookup table
/// the production decoder consumes, so a round-trip
/// (`decode(encode_far_call(...), false)`) is guaranteed to produce a
/// matching `FarCall` instruction.
#[must_use]
pub fn encode_far_call(
    kind: FarCallOpcode,
    abi_register: u8,
    destination_register: u8,
    exception_handler: u16,
    is_static: bool,
    is_shard: bool,
    condition: Condition,
) -> u64 {
    // `OpcodeVariant.flags` is `[bool; NUM_NON_EXCLUSIVE_FLAGS]`, where
    // `NUM_NON_EXCLUSIVE_FLAGS == 2` (private to `zkevm_opcode_defs`).
    let mut flags = [false; 2];
    flags[FAR_CALL_STATIC_FLAG_IDX] = is_static;
    flags[FAR_CALL_SHARD_FLAG_IDX] = is_shard;

    let opcode = DecodedOpcode::<8, EncodingModeProduction> {
        variant: OpcodeVariant {
            opcode: Opcode::FarCall(kind),
            src0_operand_type: Operand::RegOnly,
            dst0_operand_type: Operand::RegOnly,
            flags,
        },
        condition,
        src0_reg_idx: abi_register,
        src1_reg_idx: destination_register,
        dst0_reg_idx: 0,
        dst1_reg_idx: 0,
        imm_0: exception_handler,
        imm_1: 0,
    };
    EncodingModeProduction::encode_as_integer(&opcode)
}

/// Encodes a UMA opcode word (`u64`) suitable for
/// [`Program::with_raw_first_instruction`].
///
/// Mirrors [`encode_far_call`] but for unified memory access opcodes
/// (HeapRead / AuxHeapRead / StaticMemoryRead and their write counterparts).
/// The canonical src0/dst0 operand types come from
/// `UMAOpcode::input_operands` / `output_operands` for ISA v1/v2: src0 is
/// always `RegOrImm(UseRegOnly)` and dst0 is `RegOnly`.
///
/// For reads, `dst0_reg_idx` is the destination of the loaded value and
/// `dst1_reg_idx` receives the incremented offset (when `increment = true`).
/// For writes, `src1_reg_idx` is the value-to-write and `dst0_reg_idx`
/// receives the incremented offset (when `increment = true`); writes have
/// no dst1.
#[must_use]
pub fn encode_uma(
    kind: UMAOpcode,
    src0_reg_idx: u8,
    src1_reg_idx: u8,
    dst0_reg_idx: u8,
    dst1_reg_idx: u8,
    increment: bool,
    condition: Condition,
) -> u64 {
    let mut flags = [false; 2];
    flags[UMA_INCREMENT_FLAG_IDX] = increment;

    let opcode = DecodedOpcode::<8, EncodingModeProduction> {
        variant: OpcodeVariant {
            opcode: Opcode::UMA(kind),
            src0_operand_type: Operand::RegOrImm(RegOrImmFlags::UseRegOnly),
            dst0_operand_type: Operand::RegOnly,
            flags,
        },
        condition,
        src0_reg_idx,
        src1_reg_idx,
        dst0_reg_idx,
        dst1_reg_idx,
        imm_0: 0,
        imm_1: 0,
    };
    EncodingModeProduction::encode_as_integer(&opcode)
}

impl<T: Tracer, W: World<T>> Callframe<T, W> {
    #[allow(clippy::needless_pass_by_value)] // moved-in setup keeps the public API readable
    fn for_test_single_instruction(
        setup: CallframeSetup,
        program: Program<T, W>,
        stack_pool: &mut StackPool,
        world_before_this_frame: crate::world_diff::Snapshot,
    ) -> Self {
        let pc = program.instruction(0).expect("first instruction missing");
        Self {
            address: setup.address,
            code_address: setup.code_address,
            caller: setup.caller,
            exception_handler: setup.exception_handler,
            context_u128: setup.context_u128,
            is_static: setup.is_static,
            is_kernel: is_kernel(setup.address),
            stack: stack_pool.get(),
            sp: setup.sp,
            gas: setup.gas,
            near_calls: vec![],
            pc,
            program,
            heap: HeapId::from_u32_unchecked(setup.base_page + 2),
            aux_heap: HeapId::from_u32_unchecked(setup.base_page + 3),
            heap_size: setup.heap_size,
            aux_heap_size: setup.aux_heap_size,
            calldata_heap: setup.calldata_heap,
            heaps_i_am_keeping_alive: vec![],
            world_before_this_frame,
        }
    }
}

impl<T: Tracer, W: World<T>> State<T, W> {
    #[allow(clippy::large_types_passed_by_value)] // 512-byte register file mirrors Arbitrary's shape
    fn for_test_single_instruction(
        current_frame: Callframe<T, W>,
        registers: [U256; 16],
        register_pointer_flags: u16,
        flags: Flags,
        transaction_number: u16,
        context_u128: u128,
        next_base_page: u32,
    ) -> Self {
        Self {
            registers,
            register_pointer_flags,
            flags,
            current_frame,
            // zk_evm's callstack always has an unused bottom frame; mirror that.
            previous_frames: vec![Callframe::dummy()],
            heaps: super::heap::Heaps::empty(HeapId::FIRST),
            transaction_number,
            context_u128,
            next_base_page,
        }
    }
}
