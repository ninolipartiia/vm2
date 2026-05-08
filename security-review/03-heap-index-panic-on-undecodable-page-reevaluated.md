# Heap accessors panic on non-decodable page ids (vm2 vs zk_evm)

- **Severity:** INFO
- **Category:** defense-in-depth
- **Branch:** `popzxc-airbender-eravm-review`
- **Origin:** report against another version of the codebase; validated here

## Summary

vm2 and zk_evm give different answers when a heap accessor is handed a
page id that does not correspond to a currently-allocated heap/aux/calldata/code
page. The divergence is real, but its origin is **architectural**, not a
bug on either side:

- **zk_evm** stores memory as a flat `Vec<SparseMemoryPage>` indexed by
  raw page number ([memory.rs:67-70](../../zksync-protocol/crates/zk_evm/src/reference_impls/memory.rs#L67-L70)).
  Every `u32` is a valid index. `read_slot` returns
  `&PRIMITIVE_VALUE_EMPTY` (zero) when the page is out of range
  ([memory.rs:110-115](../../zksync-protocol/crates/zk_evm/src/reference_impls/memory.rs#L110-L115));
  `write_to_memory` calls `ensure_page_exists` and grows the vector on
  demand ([memory.rs:86-92](../../zksync-protocol/crates/zk_evm/src/reference_impls/memory.rs#L86-L92),
  [121-125](../../zksync-protocol/crates/zk_evm/src/reference_impls/memory.rs#L121-L125)).
  Tolerance is a side-effect of the storage shape, not an intentional
  contract.

- **vm2** uses a structured representation. `Heaps::Index<HeapId>`
  routes through [`DecodedPage::decode`](../crates/vm2/src/heap.rs#L258-L295),
  which only recognizes the four canonical low pages (`STATIC_MEMORY_PAGE = 1`,
  `BOOTLOADER_CALLDATA_PAGE = 7`, `BOOTLOADER_HEAP_PAGE = 10`,
  `BOOTLOADER_AUX_HEAP_PAGE = 11`) and the dynamic
  `STARTING_BASE_PAGE + group·NEW_MEMORY_PAGES_PER_FAR_CALL + k` family
  for `k ∈ {0, 2, 3}`. Anything else (e.g. `8`, `9`, `[12, 2048)`)
  decodes to `None`, and the accessor's `unwrap_or_else(|| panic!(...))`
  aborts the host process.

There is no structurally clean way to retrofit zk_evm's tolerance onto
vm2: vm2 has no parallel sparse map for non-canonical ids, and grafting
one would defeat the point of the structured rep. The only honest fix is
at the **observable boundary** — make the accessor's contract for
non-decodable ids match zk_evm's outcome (read zero, drop write) without
changing storage. That collapses the divergence at the layer that
matters (what callers observe) while leaving each VM's chosen
representation intact.

## Affected code

Panic sites driven by an opcode body (attacker-influenced page ids):

- [`Heaps::write_u256`](../crates/vm2/src/heap.rs#L413-L421) and
  [`Heaps::write_bytes`](../crates/vm2/src/heap.rs#L423-L437)
- [`Heaps::Index<HeapId>`](../crates/vm2/src/heap.rs#L534-L542) — used by
  every `vm.state.heaps[page]` read

Panic sites only on host-controlled paths (frame setup/teardown, tracers
— not attacker-influenced):
[`allocate_with_content_at`](../crates/vm2/src/heap.rs#L340-L358),
[`deallocate`](../crates/vm2/src/heap.rs#L367-L381),
[`tracing.rs:74,78`](../crates/vm2/src/tracing.rs).

## Reachability

The only opcode handler that funnels a caller-supplied page id into the
panicking accessor is `PrecompileCall`
([precompiles.rs:90-102](../crates/vm2/src/instruction_handlers/precompiles.rs#L90-L102):
`memory_page_to_read = HeapId::from_u32_unchecked(raw[2] as u32)` with
zero validation, then `vm.state.heaps[abi.memory_page_to_read]`).
Reaching it requires a kernel-mode frame to land a non-canonical id in
`raw[2]`. Two layers prevent that:

1. **Kernel-mode dispatch gate.** `PrecompileCall` is
   `requires_kernel_mode = true`, enforced in
   [common.rs:60-67](../crates/vm2/src/instruction_handlers/common.rs#L60-L67)
   against `current_frame.is_kernel` (frame address < 2^16,
   [decommit.rs:237-239](../crates/vm2/src/decommit.rs#L237-L239)). Non-system
   addresses get a `free_panic` instead of the handler.

2. **No system contract launders user bytes into `raw[2]`.** User
   calldata flows through the precompile system contracts (Keccak256,
   SHA256, ECRecover, ModExp, EcAdd/EcMul/EcPairing, Secp256r1Verify),
   but those contracts construct the ABI via
   `unsafePackPrecompileParams(inputOff, inputLen, outputOff, outputLen, auxData)`
   — only `raw[0]`, `raw[1]`, `raw[3]` are written. `raw[2]`
   (`memory_page_to_read` / `memory_page_to_write`) is left as zero,
   and the handler remaps `0 → current_frame.heap`
   ([precompiles.rs:93-98](../crates/vm2/src/instruction_handlers/precompiles.rs#L93-L98)).
   The handler's own comment makes the trust model explicit:
   `// This is safe because system contracts are trusted`
   ([precompiles.rs:78](../crates/vm2/src/instruction_handlers/precompiles.rs#L78)).

The only way to land a non-decodable page id at the accessor is a
governance-controlled system-contract upgrade that deliberately writes
non-zero into the page-id slot — i.e. a self-inflicted panic by the
protocol team, not an attacker primitive.

**Why this is still worth flagging.** `Heaps::Index<HeapId>` has several
callers; a future opcode or refactor that places a caller-influenced id
there would silently re-expose the host panic. Closing the contract
prospectively at the accessor is cheap defense in depth, and it removes
a real (if currently unreachable) vm2 ↔ zk_evm semantic gap that any
proving-pipeline or step-diff harness would otherwise have to carry as a
known asymmetry.

## Local validation

Confirmed on this branch with a single-instruction repro that issues a
kernel-mode `PrecompileCall` whose ABI has `memory_page_to_read = 9`
(`BOOTLOADER_STACK_PAGE`, non-decodable):

```
thread '...' panicked at crates/vm2/src/heap.rs:539:
heap page 9 is not allocated
```

The panic is reached through `Heaps::Index<HeapId>` at
[precompiles.rs:102](../crates/vm2/src/instruction_handlers/precompiles.rs#L102).
zk_evm's `read_slot(9, _)` returns zero on the same input.

## Recommended fix

Match zk_evm's **observable** contract at the accessor boundary, not its
storage shape:

- In `Heaps::Index<HeapId>` and `Heaps::write_*`, treat
  `DecodedPage::decode → None` as a zero-extended read / no-op write. No
  new storage, no architectural change — just collapse the panic to the
  same observation zk_evm produces by accident of its `Vec` layout.
- A no-op write differs from zk_evm's auto-allocate-and-store, but in
  vm2 nothing else reaches a non-canonical page id, so a subsequent read
  returns zero on either side — observably equivalent for every caller
  that exists today.

Acceptable alternative for the precompile path alone: validate
`memory_page_to_read` / `memory_page_to_write` at the ABI parse and fold
the rejection into the existing OOG `return 0 to caller` branch. This
doesn't pretend zk_evm's tolerance is a vm2 contract — it just turns the
bad input into a clean error. It does *not* close the divergence for any
future caller of `Heaps::Index<HeapId>`.

Do **not** graft a sparse fallback bucket into `Heaps` to literally
mirror zk_evm's `Vec`. That would import zk_evm's accidental tolerance
as a vm2 contract for no real gain and erode the structured rep that
motivated vm2's heap design in the first place.

The admin paths (`allocate_with_content_at`, `deallocate`, tracer reads)
can keep their panics: their inputs are host-controlled and a panic
there indicates a vm2 internal invariant break, not attacker influence.

## Regression test

To pin the divergence once a fix lands, add to
[`crates/vm2/src/tests/divergence_regressions.rs`](../crates/vm2/src/tests/divergence_regressions.rs)
(uses the already-defined `PrecompileSentinelWorld` and
`IncrementingPrecompiles`):

```rust
#[test]
fn precompile_nondecodable_memory_page_should_not_panic() {
    let precompile_call = Instruction::from_precompile_call(
        Register1(Register::new(4)),
        Register2(Register::new(5)),
        Register1(Register::new(6)),
        Arguments::new(Predicate::Always, 5, ModeRequirements::none()),
    );
    let program = Program::from_raw(vec![precompile_call, ret_instruction()], vec![]);
    let mut world = PrecompileSentinelWorld::default();
    let mut vm = VirtualMachine::new(
        kernel_address(), program, Address::zero(),
        &[], 1_000_000, default_settings(),
    );

    // ABI: read 32 bytes from offset 0, write 1 word at offset 0.
    // memory_page_to_read = 9 (BOOTLOADER_STACK_PAGE, non-decodable).
    let mut abi = U256::zero();
    abi.0[0] = 32_u64 << 32;
    abi.0[1] = 1_u64 << 32;
    abi.0[2] = 9_u64;

    vm.state.register_pointer_flags &= !(1 << 1);
    vm.state.registers[4] = abi;
    vm.state.registers[5] = U256::zero();

    // Pre-fix: panics with `heap page 9 is not allocated`.
    // Post-fix: precompile reads zeros (matching zk_evm), program returns;
    // increment of zero gives `r6 == 1`.
    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::ProgramFinished(vec![])
    );
    assert_eq!(vm.state.registers[6], U256::one());
}
```

Promote it to a `step_diff` differential test against zk_evm (same
pattern as
[`tests/differential-regressions/src/tests/evm_stipend.rs`](../tests/differential-regressions/src/tests/evm_stipend.rs))
once the fix is in, to lock the zero-extension semantics against the
reference implementation.
