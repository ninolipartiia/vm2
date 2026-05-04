# Vuln 3: Sequencer DoS / Divergence — Heap Access Panics on Undecodable Page IDs

**Files:**
- [crates/vm2/src/heap.rs:367-381](../crates/vm2/src/heap.rs#L367-L381)
- [crates/vm2/src/heap.rs:393-407](../crates/vm2/src/heap.rs#L393-L407)
- [crates/vm2/src/heap.rs:504-512](../crates/vm2/src/heap.rs#L504-L512)
- [crates/vm2/src/instruction_handlers/precompiles.rs:93-102](../crates/vm2/src/instruction_handlers/precompiles.rs#L93-L102)
- [crates/vm2/src/instruction_handlers/ret.rs:54-57](../crates/vm2/src/instruction_handlers/ret.rs#L54-L57)

* **Severity:** MEDIUM
* **Category:** panic_reachability / consensus_divergence
* **Confidence:** 5/10

## Description

Every heap access in the new heap model goes through
`DecodedPage::decode(page).unwrap_or_else(|| panic!("heap page X is not decodable"))`.
The decoder rejects every page id in `[0, STARTING_BASE_PAGE)` other than
the four canonical ones (`STATIC_MEMORY_PAGE`, `BOOTLOADER_CALLDATA_HEAP_PAGE`,
`BOOTLOADER_HEAP_PAGE`, `BOOTLOADER_AUX_HEAP_PAGE`). Reads of e.g. page 8
(`BOOTLOADER_BASE_PAGE`/code), 9 (`BOOTLOADER_STACK_PAGE`), or any other
low/reserved page panic.

Reference `zk_evm` uses a sparse `Vec<SparseMemoryPage>` indexed by raw
page number; missing pages return zeros.

Two reachable paths cross this gap:
1. `precompile_call` indexes `vm.state.heaps[abi.memory_page_to_read]` with
   only a `0 → current_frame.heap` remap (precompiles.rs:93-98, 102).
2. `naked_ret`'s kernel-mode path bypasses the base-page returndata-pointer
   check (ret.rs:54-57), so a kernel frame can return
   `FatPointer { memory_page: 9, .. }` and the caller's reader panics.

## Exploit Scenario

A system contract (kernel-mode) constructs a precompile ABI with
`memory_page_to_read` set to a non-decodable page (e.g. 9), or a kernel-mode
frame returns a `FatPointer` to such a page. vm2 panics, killing the
sequencer process; zk_evm reads zeros and continues.

Even absent malice, a buggy system-contract upgrade that emits an
unexpected page id transitions a recoverable read-zero into a
panic-the-sequencer crash, while the prover happily continues — producing
a sequencer/prover divergence that is also a single-shot DoS.

## Recommendation

Replace the panicking `unwrap_or_else` in `Index<HeapId>` and the `read*` /
`write*` helpers with zero-extension semantics for any non-decodable page
(matching zk_evm's sparse-page behavior). Alternatively, reject
non-decodable pages at the boundary (precompile ABI parsing, returndata
pointer construction) before the read happens — but in either case, do not
panic the host process on attacker-influenced page ids.

## Validation Notes

### Confirmed

- Constants from `zkevm_opcode_defs/src/lib.rs`: `STATIC_MEMORY_PAGE = 1`,
  `BOOTLOADER_CALLDATA_PAGE = 7`, `BOOTLOADER_BASE/CODE_PAGE = 8`,
  `BOOTLOADER_STACK_PAGE = 9`, `BOOTLOADER_HEAP_PAGE = 10`,
  `BOOTLOADER_AUX_HEAP_PAGE = 11`, `STARTING_BASE_PAGE = 2048`. So
  `DecodedPage::decode` returns `None` for pages `0, 2-6, 8, 9, 12-2047`
  (and for `rel % 8 ∈ {1, 4, 5, 6, 7}` in dynamic ranges).
- `zk_evm`'s reference `MemoryWrapper` reads zeros for missing pages
  (`read_slot` at `crates/zk_evm/src/reference_impls/memory.rs:110-115`),
  so a panic here is a genuine vm2 ↔ zk_evm divergence, not just a local DoS.

### Path 1 (precompile_call) — reachable but heavily gated

- `LogOpcode::PrecompileCall` has `requires_kernel_mode = true`
  (`zkevm_opcode_defs/src/definitions/log.rs:294-302`). Only kernel-mode
  contracts (system contracts at addresses < 2^16) can issue it; an external
  attacker cannot reach this path directly.
- vm2 only remaps `0 → current_frame.heap` for the read/write page; any other
  non-decodable value (e.g. 9, 12, 2049) flows straight into the panicking
  `Index<HeapId>` impl.
- zk_evm does the same `0 → current heap` remap (`opcodes/execution/log.rs:315-335`),
  but the subsequent read goes through `SimpleMemory` and yields zeros.
- A real divergence therefore requires a system contract that emits a
  non-decodable page id — buggy upgrade, accidental drift, or a system
  contract that derives the page word from untrusted input.

### Path 2 (naked_ret kernel-mode bypass) — not exploitable as written

The exploit narrative requires a register to contain a `FatPointer` with
`memory_page = 9` (or any non-decodable value) and the pointer flag set.
Tracing every site that sets the pointer flag:

- Initial bootloader R1: `HeapId::FIRST_CALLDATA = 7` (`state.rs:44-50`) — decodable.
- `decommit`: writes `current_frame.heap` (`decommit.rs:46`) — decodable.
- `far_call` `MakeNewPointer`: writes `current_frame.heap` / `aux_heap`
  (`far_call.rs:233/237`) — decodable.
- `PointerAdd/Sub/Pack/Shrink` (`pointer.rs:60-108`) — all preserve `memory_page`
  (PointerPack only takes the high 128 bits from `in2`).
- `LoadFromPointer` increment (`heap_access.rs:192`) — preserves `memory_page`.
- `ForwardFatPointer` (`far_call.rs:221-227`) — preserves `memory_page`.

No instruction lets even a kernel contract *construct* a `FatPointer` with an
arbitrary `memory_page`. The kernel bypass at `ret.rs:55` does relax the base-page
*check*, but no upstream mechanism produces a bad pointer for the kernel frame to
forward. So this path is currently theoretical / defense-in-depth only — it
becomes live if some future change (or an unsafe SDK helper) introduces an
arbitrary-page-pointer primitive.

### Other panic sites not on attacker-influenced paths

`allocate_at` / `deallocate` (`heap.rs:341, 368`) and the `Index<HeapId>` use in
`tracing.rs:74,78` also panic on non-decodable pages, but they're driven by
trusted host code (frame setup/teardown, tracers) with already-decodable inputs,
not by guest-supplied values.

### Severity reassessment

- Real reachable surface: only Path 1, kernel-mode-gated.
- External-attacker exploitability: ~nil without compromising the system-contract
  upgrade pipeline.
- Consequence if reached: sequencer-process abort + sequencer/prover divergence
  (serious).

Adjusted estimate: **LOW–MEDIUM**, confidence ~3-4/10, primarily a
defense-in-depth / forward-compatibility issue. Zero-extension to match zk_evm is
the cheaper and more conservative fix; boundary rejection is reasonable but must
also handle the precompile case without panicking the host.

### Missing context the report should add

1. State that `PrecompileCall` requires kernel mode — materially shrinks the
   attack surface.
2. Either drop Path 2 or explicitly frame it as future-proofing — there is no
   construction mechanism for a kernel-frame register to hold a `FatPointer`
   with a non-decodable `memory_page` in the current codebase.
3. Note that `allocate_at`/`deallocate`/tracer reads also panic but are not
   attacker-influenced.
4. Distinguish "host-process panic" (Rust `panic!`, kills sequencer) from
   "EVM panic" (`spontaneous_panic` — handled). The bug is the former.
