//! Regression tests for the `BlobSha256Format`-versus-construction-state stipend
//! divergence between vm2 and zk_evm.
//!
//! Pre-fix, vm2's `is_evm_interpreter` was `true` only when `code_info_bytes[0]==0x02`
//! AND `is_constructed != is_constructor_call`, while zk_evm gates the stipend purely
//! on `code_version_byte == 0x02`. Post-fix, vm2 plumbs a separate `is_evm_blob_format`
//! flag through to `Callframe::new` (see `crates/vm2/src/callframe.rs:78-88`).
//!
//! Each test below builds the initial state explicitly, runs one instruction in
//! both VMs through [`step_diff`], and asserts equality on `UniversalVmState`.
//! See `security-review/fuzz-crash-id000000-evm-stipend.md` for the full narrative.

use pretty_assertions::assert_eq;
use primitive_types::{H160, U256};
use zkevm_opcode_defs::{ethereum_types::Address, Condition, FarCallOpcode};
use zksync_vm2::{
    single_instruction_test::{
        encode_far_call, step_diff, CallframeSetup, MockWorld, SingleInstructionTestSetup,
    },
    Settings, VirtualMachine,
};
use zksync_vm2_interface::HeapId;

/// `STARTING_BASE_PAGE` from `zkevm_opcode_defs::system_params`. Hardcoded here so
/// every test reads the page layout literally rather than via a re-export.
const STARTING_BASE_PAGE: u32 = 8;
/// Memory pages a single FarCall reserves for its new frame: code page, calldata,
/// heap, aux heap.
const PAGES_PER_FAR_CALL: u32 = 4;

/// Address whose first 18 bytes are zero — counts as a kernel address per
/// `decommit::is_kernel`. Used for the kernel-constructor polarity.
fn kernel_address(low: u64) -> H160 {
    Address::from_low_u64_be(low)
}

/// Address with all bytes nonzero — guaranteed non-kernel.
fn non_kernel_address(byte: u8) -> H160 {
    H160::repeat_byte(byte)
}

/// Settings whose `default_aa_code_hash` and `evm_interpreter_code_hash` both
/// start with `0x01` (the only "valid" hash format the mocked VM accepts —
/// see the `Arbitrary` impl in `crates/vm2/src/single_instruction_test/vm.rs`).
fn default_settings() -> Settings {
    let mut default_aa_code_hash = [0u8; 32];
    default_aa_code_hash[0] = 1;
    default_aa_code_hash[2] = 1; // arbitrary length-in-words

    let mut evm_interpreter_code_hash = [0u8; 32];
    evm_interpreter_code_hash[0] = 1;
    evm_interpreter_code_hash[2] = 1;

    Settings {
        default_aa_code_hash,
        evm_interpreter_code_hash,
        hook_address: 0,
    }
}

/// Builds the FarCall ABI register: lower 32 bits hold `gas_to_pass`,
/// upper 32 bits encode the settings byte (`is_constructor_call` at bit 16,
/// `is_system_call` at bit 24). See `get_far_call_arguments` in
/// `crates/vm2/src/instruction_handlers/far_call.rs`.
fn far_call_abi(gas_to_pass: u32, is_constructor: bool, is_system: bool) -> U256 {
    let constructor_byte = u32::from(is_constructor) << 16;
    let system_byte = u32::from(is_system) << 24;
    let settings = u64::from(constructor_byte | system_byte);

    let mut abi = U256::zero();
    abi.0[3] = u64::from(gas_to_pass) | (settings << 32);
    abi
}

/// Encodes a 32-byte `AccountCodeStorage` slot in the same shape
/// `ContractDeployer.sol` writes: `[version, construction_state, len_hi, len_lo,
/// 0..28, hash_tag]`.
fn deployer_storage_slot(version_byte: u8, in_construction: bool, hash_tag: u32) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[0] = version_byte;
    bytes[1] = u8::from(in_construction);
    bytes[28..].copy_from_slice(&hash_tag.to_be_bytes());
    U256::from_big_endian(&bytes)
}

/// Builds a `SingleInstructionTestSetup` that's poised to execute one FarCall.
/// Every test in this file uses this helper so the variation across tests
/// (caller kernel-ness, destination, constructor flag, kind) is visible at
/// the test call site.
fn far_call_setup(
    kind: FarCallOpcode,
    caller: H160,
    caller_is_static: bool,
    destination: H160,
    gas_to_pass: u32,
    is_constructor: bool,
) -> SingleInstructionTestSetup {
    let raw_instruction = encode_far_call(
        kind,
        /* abi_register     = */ 1,
        /* dest_register    = */ 2,
        /* exception_handler= */ 0,
        /* is_static        = */ false,
        /* is_shard         = */ false,
        Condition::Always,
    );

    let mut registers = [U256::zero(); 16];
    registers[1] = far_call_abi(gas_to_pass, is_constructor, /*is_system=*/ false);
    registers[2] = {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(destination.as_bytes());
        U256::from_big_endian(&bytes)
    };

    SingleInstructionTestSetup {
        current_frame: CallframeSetup {
            address: caller,
            code_address: caller,
            caller: H160::zero(),
            gas: 1_000_000_000,
            exception_handler: 0,
            context_u128: 0,
            is_static: caller_is_static,
            raw_instruction,
            heap_size: 0,
            aux_heap_size: 0,
            sp: 0,
            base_page: STARTING_BASE_PAGE,
            calldata_heap: HeapId::FIRST_CALLDATA,
        },
        registers,
        register_pointer_flags: 0,
        lt_of_flag: false,
        eq_flag: false,
        gt_flag: false,
        transaction_number: 0,
        context_u128: 0,
        next_base_page: STARTING_BASE_PAGE + PAGES_PER_FAR_CALL,
    }
}

/// Reproduces AFL crash `id:000000` (see
/// `security-review/fuzz-crash-id000000-evm-stipend.md`).
///
/// Configuration:
/// - Caller: non-kernel, `is_static = true` (matches the original fuzz crash).
/// - Destination: non-kernel.
/// - Deployer-storage slot: `V[0] = 0x02` (BlobSha256), `V[1] = 0x01`
///   (in construction).
/// - Call kind: `FarCall<Delegate>`, non-constructor, non-system.
///
/// Pre-fix: vm2 grants `NEW_FRAME_MEMORY_STIPEND` (4096), zk_evm grants
/// `NEW_EVM_FRAME_MEMORY_STIPEND` (57344) → `UniversalVmState` differs on
/// `heap_bound` / `aux_heap_bound`. Post-fix: both VMs grant 57344.
#[test]
fn far_call_to_unconstructed_evm_grants_evm_stipend_matching_zk_evm() {
    let setup = far_call_setup(
        FarCallOpcode::Delegate,
        /* caller           = */ non_kernel_address(0x11),
        /* caller_is_static = */ true,
        /* destination      = */ non_kernel_address(0x5a),
        /* gas_to_pass      = */ 100_000,
        /* is_constructor   = */ false,
    );

    let mut vm = VirtualMachine::<(), MockWorld>::for_test_single_instruction(
        setup,
        default_settings(),
    );
    let mut world = MockWorld::with_storage_slot(Some(deployer_storage_slot(
        /* version_byte    = */ 0x02,
        /* in_construction = */ true,
        /* hash_tag        = */ 0xdead_beef,
    )));

    let (zk_evm_state, vm2_state) = step_diff(&mut vm, &mut world);
    assert_eq!(zk_evm_state, vm2_state);
}

/// Counterpart polarity to the seed test: same caller/destination shape, but
/// the destination is a *fully constructed* EVM contract (`V[1] = 0x00`) and
/// the call is a non-constructor delegate. This hits the `is_constructed != is_constructor_call`
/// branch of vm2's decommit (`is_evm = true`) — pre-fix and post-fix both
/// return `is_evm_blob_format = true`, so this test should pass under either
/// version. It's the **non-divergent control** for the `0x02` version byte.
#[test]
fn far_call_to_constructed_evm_matches_zk_evm() {
    let setup = far_call_setup(
        FarCallOpcode::Delegate,
        non_kernel_address(0x11),
        /* caller_is_static = */ false,
        non_kernel_address(0x5a),
        /* gas_to_pass      = */ 100_000,
        /* is_constructor   = */ false,
    );

    let mut vm = VirtualMachine::<(), MockWorld>::for_test_single_instruction(
        setup,
        default_settings(),
    );
    let mut world = MockWorld::with_storage_slot(Some(deployer_storage_slot(
        /* version_byte    = */ 0x02,
        /* in_construction = */ false,
        /* hash_tag        = */ 0xdead_beef,
    )));

    let (zk_evm_state, vm2_state) = step_diff(&mut vm, &mut world);
    assert_eq!(zk_evm_state, vm2_state);
}

/// Symmetric polarity to the seed test: caller is in kernel mode and the call
/// is a constructor (`is_constructor_call` survives the
/// `&& current_frame.is_kernel` mask in `far_call.rs:52`).
///
/// Uses `FarCall::Normal` (not `Delegate`) so the new frame's address is the
/// **destination** rather than the caller's address — otherwise a kernel
/// caller produces a kernel new frame and the kernel-stipend short-circuit
/// hides the EVM-stipend divergence.
///
/// Storage value: `V[0] = 0x02, V[1] = 0x00` (constructed EVM bytecode).
/// `is_constructed (true) == is_constructor_call (true)` so vm2 masks to the
/// default AA. Pre-fix: heap_size = `NEW_FRAME_MEMORY_STIPEND` (4096).
/// Post-fix and zk_evm: heap_size = `NEW_EVM_FRAME_MEMORY_STIPEND` (57344).
#[test]
fn kernel_constructor_call_to_evm_grants_evm_stipend_matching_zk_evm() {
    let setup = far_call_setup(
        FarCallOpcode::Normal,
        /* caller           = */ kernel_address(1),
        /* caller_is_static = */ false,
        /* destination      = */ non_kernel_address(0x5a),
        /* gas_to_pass      = */ 100_000,
        /* is_constructor   = */ true,
    );

    let mut vm = VirtualMachine::<(), MockWorld>::for_test_single_instruction(
        setup,
        default_settings(),
    );
    let mut world = MockWorld::with_storage_slot(Some(deployer_storage_slot(
        /* version_byte    = */ 0x02,
        /* in_construction = */ false,
        /* hash_tag        = */ 0xdead_beef,
    )));

    let (zk_evm_state, vm2_state) = step_diff(&mut vm, &mut world);
    assert_eq!(zk_evm_state, vm2_state);
}

/// Native EraVM bytecode (`V[0] = 0x01`) — should never receive the EVM
/// stipend in either VM, regardless of construction state. This is the
/// **negative control** for the fix: a regression that flipped
/// `is_evm_blob_format = true` for non-EVM hashes would diverge here against
/// zk_evm or, in the worst case, silently grant 57344 to a native frame
/// without zk_evm doing the same.
#[test]
fn far_call_to_native_eravm_does_not_grant_evm_stipend() {
    let setup = far_call_setup(
        FarCallOpcode::Delegate,
        non_kernel_address(0x11),
        /* caller_is_static = */ false,
        non_kernel_address(0x5a),
        /* gas_to_pass      = */ 100_000,
        /* is_constructor   = */ false,
    );

    let mut vm = VirtualMachine::<(), MockWorld>::for_test_single_instruction(
        setup,
        default_settings(),
    );
    let mut world = MockWorld::with_storage_slot(Some(deployer_storage_slot(
        /* version_byte    = */ 0x01,
        /* in_construction = */ false,
        /* hash_tag        = */ 0xdead_beef,
    )));

    let (zk_evm_state, vm2_state) = step_diff(&mut vm, &mut world);
    assert_eq!(zk_evm_state, vm2_state);
}
