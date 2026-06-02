# Informational findings in `vm2` / `vm2-interface`

- **Severity:** INFO
- **Category:** documentation, public APIs, surprising behavior, visibility
  hygiene, arithmetic divergence from `zk_evm`

Companion to [`07-tracer-read-contract-code-empty-codepage-panic.md`](./07-tracer-read-contract-code-empty-codepage-panic.md).
That report covers `read_contract_code` in depth; this one collects the
remaining cases where the public surface of `vm2` / `vm2-interface`
diverges from what its types or doc comments suggest, plus three
arithmetic sites in the precompile handler where `vm2` skips bounds that
`zk_evm` enforces. None of these are exploitable on their own — the
arithmetic sites are not reachable through any production system contract
today — but each is a footgun for downstream callers or for any future
change that breaks one of the invariants holding them in check.

## Findings

### 1. `StateInterface::read_register(u8)` / `set_register(u8, …, …)` - out of bounds panic

The trait accepts any `u8` (0..=255). The backing storage is `[U256; 16]`.

Panic path (read):
- `StateInterface::read_register(register: u8)` — [`tracing.rs:17`](../crates/vm2/src/tracing.rs#L17)
- → `self.state.registers[register as usize]` — [`tracing.rs:19`](../crates/vm2/src/tracing.rs#L19)
- → `State::registers: [U256; 16]` — [`state.rs:20`](../crates/vm2/src/state.rs#L20) — index ≥ 16 panics.

`set_register` panics identically on [`tracing.rs:25`](../crates/vm2/src/tracing.rs#L25).
The `1 << register` shifts against `u16` on [`tracing.rs:27-28`](../crates/vm2/src/tracing.rs#L27-L28)
(and the matching shift in `read_register` at [`tracing.rs:20`](../crates/vm2/src/tracing.rs#L20))
are latent bugs with the same precondition, but the array-index panic always
trips first.

**RECOMMENDATION.** Return `Option<(U256, bool)>` from `read_register` and
make `set_register` return `Result<(), …>` (or accept a bounded
`Register` newtype that can only represent 0..=15), so the panic surface
moves into the type system. Until that lands, document the `register < 16`
precondition with a `# Panics` clause on both methods and clamp or reject
out-of-range inputs at the call boundary.

### 2. `StateInterface::callframe(n)` - out of bounds panic

The trait advertises "frame with the specified index" without a `# Panics`
clause. The implementation has an unconditional `panic!`.

Panic path:
- `StateInterface::callframe(n: usize)` — [`tracing.rs:49`](../crates/vm2/src/tracing.rs#L49)
- → iterates `current_frame` then `previous_frames.iter_mut().rev()`,
  subtracting `near_calls + 1` per skipped frame.
- → `panic!("Callframe index out of bounds")` once the iterator is exhausted — [`tracing.rs:70`](../crates/vm2/src/tracing.rs#L70).

Tripped whenever `n >= number_of_callframes()`.

**RECOMMENDATION.** Change the return type from
`impl CallframeInterface + '_` to `Option<impl CallframeInterface + '_>`
so the out-of-bounds case is reflected in the type and callers handle it
explicitly. If the signature must stay total, add a `# Panics` clause
naming the `n < number_of_callframes()` precondition.

### 3. `StateInterface::write_heap_u256(HeapId, u32, U256)` — over-broad write surface

The trait accepts any `HeapId`, with three undocumented behaviors:

**3a. Undecodable `HeapId` → panic.** Asymmetric with the read path:
`read_heap_byte` / `read_heap_u256` / `Index<HeapId>` fall back to
`&EMPTY_HEAP` and return 0 for unknown pages
([`heap.rs:543-552`](../crates/vm2/src/heap.rs#L543-L552)). The write path
panics instead. The inline comment at
[`heap.rs:409-413`](../crates/vm2/src/heap.rs#L409-L413) characterizes
this panic as a deliberate *tripwire* against new code paths, on the
assumption that all callers pass VM-controlled `HeapId`s. The
`StateInterface::write_heap_u256` tracer entry breaks that assumption: a
tracer can pass any `HeapId`. The remaining issue is therefore the
unrestricted tracer entry, not the tripwire itself.

Panic path:
- `StateInterface::write_heap_u256(heap, …, …)` — [`tracing.rs:81`](../crates/vm2/src/tracing.rs#L81)
- → `self.state.heaps.write_u256(heap, …, …)` — [`heap.rs:407`](../crates/vm2/src/heap.rs#L407)
- → `DecodedPage::decode(page).unwrap_or_else(|| panic!("heap page {} is not decodable", …))` — [`heap.rs:414-415`](../crates/vm2/src/heap.rs#L414-L415)

**3b. Silent writes to read-only-looking pages.** The same write path
*succeeds* without warning when given a page that no opcode would normally
write to:

- `HeapId::FIRST_CALLDATA` (the bootloader's calldata) — calldata pages are
  established at far-call time and never written via opcodes, but the trait
  permits writing them.
- `HeapId::from_u32_unchecked(1)` (the static memory page).

The mutation is observable via `read_heap_u256`. Severity LOW: requires
deliberate misuse, but the behavior is surprising and the trait gives no
signal.

**3c. Writes without rollback tracking.** Only `HeapId::FIRST` and
`HeapId::FIRST_AUX` are recorded in
[`record_bootloader_word_rollback`](../crates/vm2/src/heap.rs#L470-L480).
Tracer writes to any other (decodable) page succeed but are not rolled back
on snapshot revert, even though writes to those same pages from opcodes
either don't exist or die with the frame.

**RECOMMENDATION — narrow the API.** Replace `write_heap_u256(HeapId, …)`
with `write_bootloader_heap_u256(offset, value)` and
`write_bootloader_aux_heap_u256(offset, value)`. `FIRST` and `FIRST_AUX`
are the only rollback-tracked pages, and every observed production caller
(`era_vm` / `vm_fast` bootloader hooks, airbender's
[`write_to_bootloader_heap`](https://github.com/matter-labs/eravm-airbender-verifier/blob/main/crates/multivm/src/versions/vm_fast/vm.rs))
already writes to one of them. Resolves 3a, 3b, and 3c at once.

**RECOMMENDATION — document the current behavior.** The trait should
state on the method: accepted vs. panicking `HeapId` values, the
read/write asymmetry, and that only `FIRST` / `FIRST_AUX` participate in
snapshot rollback.

### 4. `#[doc(hidden)] pub` items that should not be reachable from outside the workspace

Three items are `pub` (marked `#[doc(hidden)]`) but have no external
callers. Leaving them on the public surface lets downstream code reach
panic paths and unsound state mutations.

**4a. `HeapId::from_u32_unchecked(u32)`** — [`state_interface.rs:170-173`](../crates/vm2-interface/src/state_interface.rs#L170-L173).
The constructor that produces the undecodable `HeapId` values feeding
issue 3a. Every observed caller is in-workspace (`page_ids.rs`,
`instruction_handlers/precompiles.rs`, `world_diff.rs`, test harnesses).
Cross-crate usage rules out `pub(crate)`; the realistic fix is either to
move all valid construction paths into `vm2-interface` and drop the
unchecked constructor, or gate it behind an `_internal_api` Cargo
feature enabled only by `vm2`. The doc comment *"Only for dealing with
external data structures"* is inaccurate and should be replaced.

**4b. `Program::from_raw(Vec<Instruction>, Vec<U256>)`** — [`program.rs:94-100`](../crates/vm2/src/program.rs#L94-L100).
Already documented *"should only be used in low-level tests /
benchmarks"*, but reachable from production builds. Callers are
`Program::new_panicking`, in-crate tests, and `benches/nested_near_call.rs`
(separate crate, so `pub(crate)` is too tight). Should be gated behind a
`_test_internals` Cargo feature enabled only in dev-dependencies.

**4c. `VirtualMachine::world_diff_mut()`** — [`vm.rs:74-80`](../crates/vm2/src/vm.rs#L74-L80).
Documented as *"unsound to mutate `WorldDiff` in the middle of VM
execution"* and has no callers anywhere in the workspace
(`grep -rn world_diff_mut`). Dead-but-public unsound API; should be
deleted.

**RECOMMENDATION.** Treat these three items as private by default: prefer
outright removal (4c), feature-gate behind a non-default Cargo feature
when test or bench access is required (4b, and 4a if removal isn't
feasible), and in every remaining case replace the current doc comments
with text that names the actual invariant the caller must uphold and the
concrete failure mode (panic / undefined VM state) when it doesn't.
`#[doc(hidden)]` hides items from rustdoc but does not constrain
downstream callers — it should not be relied on as an access-control
mechanism.

### 5. Precompile handler skips arithmetic bounds that `zk_evm` enforces

Three sites in `PrecompileCall` handling perform `u32` / `i32` arithmetic
on values pulled out of the precompile ABI without the bound checks
`zk_evm` carries on the same inputs. None are reachable through any
production yul precompile today (see "current reachability" notes below),
so all three are **defense-in-depth**: the protection rests on yul
correctness, fat-pointer invariants, and the kernel-mode opcode gate
rather than on local arithmetic checks.

**5a. `pubdata.0 += extra_pubdata_cost as i32`** —
[`precompiles.rs:85-88`](../crates/vm2/src/instruction_handlers/precompiles.rs#L85-L88).
`extra_pubdata_cost` is the upper half of `Register2`'s low 64-bit word
(bits 32-63), taken as `u32`.
Two unchecked steps: `u32 → i32` reinterprets values `≥ 0x8000_0000` as
negative, then `i32 +=` panics in debug builds / wraps in release.
`world_diff.pubdata` is `RollbackablePod<i32>`
([`world_diff.rs:26`](../crates/vm2/src/world_diff.rs#L26)) — the same
accumulator type as `zk_evm`'s `PubdataCost(pub i32)`, but `zk_evm`
asserts `extra_pubdata_cost <= i32::MAX as u32` before the cast and
asserts no overflow on both the per-frame counter and the global revert
counter ([`zk_evm/src/opcodes/execution/log.rs:372-376`](https://github.com/matter-labs/zksync-protocol/blob/c51a7ca/crates/zk_evm/src/opcodes/execution/log.rs#L372-L376),
[`vm_state/helpers.rs:314-342`](https://github.com/matter-labs/zksync-protocol/blob/c51a7ca/crates/zk_evm/src/vm_state/helpers.rs#L314-L342)).
*Current reachability:* every production yul precompile passes
`extra_pubdata_cost = 0`.

**5b. `output_memory_offset * 32` and `write_offset += 32`** —
[`precompiles.rs:118-126`](../crates/vm2/src/instruction_handlers/precompiles.rs#L118-L126).
`abi.output_memory_offset` is an unchecked `u32` from `raw[1] as u32`;
multiplying by 32 overflows `u32` for values `≥ 2^27`. The loop body
also increments `write_offset` by 32 without a check. The loop is bounded
to ≤ 3 iterations by the buffer type
(`PrecompileOutput.buffer: [U256; 3]` —
[`precompiles/mod.rs:67-71`](../crates/vm2/src/precompiles/mod.rs#L67-L71)),
so the stride is unlikely to wrap on its own, but the initial multiply
can. *Current reachability:* every production yul precompile passes
`output_memory_offset = 0`.

**5c. `start_word * 32` on the precompile read path** —
[`precompiles/legacy.rs:74-83`](../crates/vm2/src/precompiles/legacy.rs#L74-L83).
The write branch carries `assert!(start_word < 3, …)`; the read branch
does not. `start_word` is `MemoryIndex(u32)` chosen by
`zk_evm_abstractions::precompiles`; in principle it can exceed
`u32::MAX / 32 = 2^27 - 1` if `input_memory_offset + input_memory_length > u32::MAX`,
at which point `start_word * 32` wraps. *Current reachability:* the only
precompile forwarding user-controlled offsets is `Keccak256.yul`, which
forwards them straight from a fat pointer; fat-pointer minting at
[`far_call.rs:245`](../crates/vm2/src/instruction_handlers/far_call.rs#L245)
does `pointer.start.checked_add(pointer.length)` and rejects any pointer
whose sum overflows `u32`, keeping `start_word * 32 ≤ u32::MAX - 31`.

Consequences if any of these were reached on an out-of-range input:
debug builds abort with an overflow panic (host process crash, not just
VM panic); release builds silently produce a wrapped value — `pubdata.0`
moves to a value `zk_evm` would never compute (observable via
`WorldDiff::pubdata()` and the `ContextMeta::aux_field_0` read in
[`context.rs:88-97`](../crates/vm2/src/instruction_handlers/context.rs#L88-L97)),
or the heap is read/written at a small wrapped byte address. The
divergence is in the **opcode's acceptance domain**: `vm2` accepts inputs
that `zk_evm` rejects with an assertion, so any embedder running both
VMs against the same upgraded, buggy, or hand-crafted system bytecode
(e.g., for differential testing) would observe the gap.

**RECOMMENDATION — document why each site is safe today.** Each of
5a/5b/5c is reachable only because of an external invariant (yul
producing zero or bounded values; fat-pointer minting rejecting
overflowing sums). Annotate each call site with a `// SAFETY:` (or
equivalent) comment naming the specific invariant relied on and the
file/line where it is enforced, so a future change that breaks the
invariant can be caught at review time rather than at runtime.

**RECOMMENDATION — align with `zk_evm`.** Mirror `zk_evm`'s bounds
locally so the handler stops depending on caller correctness. Two
shapes, in increasing order of invasiveness:

1. Clamp / reject at the ABI parse boundary in
   [`PrecompileCallAbi::from_u256`](../crates/vm2/src/instruction_handlers/precompiles.rs#L43-L65)
   and
   [`PrecompileAuxData::from_u256`](../crates/vm2/src/instruction_handlers/precompiles.rs#L18-L30) —
   forecloses all three classes at one location.
2. Per-site checked arithmetic that routes through the existing OOG
   branch at
   [`precompiles.rs:80-83`](../crates/vm2/src/instruction_handlers/precompiles.rs#L80-L83)
   (set `Register1` to zero and return without executing the
   precompile), matching `zk_evm`'s "assert and halt" behaviour with
   `vm2`'s normal failure shape.

