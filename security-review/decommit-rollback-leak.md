# Decommit-pinned dynamic heap leaks across `external_rollback`

- **Category:** state corruption / consensus divergence (vm2 vs zk_evm)
- **Confidence:** 7/10. Local panic reproduces deterministically; the "vm2 panics where zk_evm wouldn't" divergence claim is not cross-validated against a live zk_evm here.
- **Branch:** `popzxc-airbender-eravm`
- **Introduced by:** commit `3553c88` ("Align heaps behavior with zk_evm")

## Summary

When the kernel-only `Decommit` opcode runs from a non-bootloader frame (e.g.
Code Oracle reached via far-call), the materialized page is pinned globally
but is **not** registered in any frame's `heaps_i_am_keeping_alive`. On
`vm.rollback()`, the global pin is reverted but the dynamic heap slot is
never swept, leaving an orphan in `state.heaps.dynamic`. The next far-call
chain that re-derives the same base page panics in
`Heaps::allocate_with_content_at`.

## Affected code

- [crates/vm2/src/decommit.rs:18-43](../crates/vm2/src/decommit.rs#L18-L43) — `materialize_decommit_page` skips keep-alive push when candidate equals current frame's heap
- [crates/vm2/src/instruction_handlers/decommit.rs:42](../crates/vm2/src/instruction_handlers/decommit.rs#L42) — opcode passes `vm.state.current_frame.heap` as candidate
- [crates/vm2/src/state.rs:140-168](../crates/vm2/src/state.rs#L140-L168) — `State::rollback` does not sweep `heaps.dynamic`
- [crates/vm2/src/heap.rs:340-358](../crates/vm2/src/heap.rs#L340-L358) — `allocate_with_content_at` panics on already-allocated slot
- [crates/vm2/src/world_diff.rs:459-477](../crates/vm2/src/world_diff.rs#L459-L477) — `external_rollback` un-pins post-snapshot pins

## Bug chain

1. `materialize_decommit_page` only pushes onto `heaps_i_am_keeping_alive`
   when `heap != current_frame.heap && heap != current_frame.aux_heap`.
2. The Decommit opcode passes `current_frame.heap` as candidate, so for a
   non-bootloader caller the page is recorded only in the global
   `decommit_pinned_pages` set — no keep-alive registration.
3. On frame return, `pop_frame` skips deallocation because the page is
   pinned. The slot stays `Some(...)` in `heaps.dynamic`.
4. On `vm.rollback()`: `external_rollback` un-pins the page, `state.rollback`
   only drains keep-alive lists (which never had it), `Heaps::rollback`
   only replays bootloader heap/aux logs, and `next_base_page` is rewound.
5. The next far-call re-derives the same base page → `allocate_at` hits
   `assert!(slot.is_none())` → panic.

## Trigger scenario

Standard zksync_era bootloader flow:

1. Bootloader takes a snapshot for tx validation.
2. Validation calls a kernel contract (e.g. Code Oracle) that runs
   `Decommit` on a fresh code hash. The Code Oracle frame's heap is
   pinned and orphaned per the chain above.
3. Bootloader rolls back the validation snapshot.
4. Bootloader proceeds (next tx or execution phase) and far-calls deeply
   enough to re-derive the orphaned base page.
5. `Heaps::allocate_at` panics; vm2 cannot continue while zk_evm could.

Depth-2 from the bootloader is required to reach the Decommit frame.
At depth-1, the callee's `Ret`-synthesised return pointer routes the
orphan into bootloader's keep-alive list, masking the leak.

## Recommended fix

Two options:

- **(a) Track rollback-aware pins separately.** When
  `materialize_decommit_page` skips the keep-alive push, record the page
  in a `RollbackableSet` that participates in `external_rollback` cleanup.

- **(b) Sweep `heaps.dynamic` on rollback.** In `State::rollback`,
  deallocate every dynamic slot added after the snapshot. More robust
  because it also covers any future caller whose candidate page happens
  to equal a dynamic page that wasn't keep-alive registered.

**Option (b) is the recommended fix.**

### Implementation note

The sweep threshold should be `heaps.dynamic.len()` captured at
`make_snapshot` time — **not** `next_base_page`. `dynamic` is a `Vec`
only ever extended by `dynamic_slot_mut`'s `resize_with`, so any group
at index `>= snapshotted_dynamic_len` was added after the snapshot,
regardless of how it was allocated. A `next_base_page`-keyed sweep
breaks `rollback_should_preserve_pre_snapshot_decommit_page`, which
installs a pre-snapshot page at `base == next_base_page` via the test
helper `allocate_standalone_heap` (which doesn't advance the counter).

This requires a new `dynamic_heap_count: usize` field on `StateSnapshot`,
written in `State::snapshot` and consumed in `State::rollback`.

Concretely:
- New `Heaps::truncate_dynamic_to(saved_len)` in
  [crates/vm2/src/heap.rs](../crates/vm2/src/heap.rs) drains
  `dynamic[saved_len..]` and recycles each `Some(_)` slot's pages.
- `State::rollback` in
  [crates/vm2/src/state.rs](../crates/vm2/src/state.rs) calls it after
  the existing keep-alive loop and bootloader heap-log replay.
- The shim `Heaps` under the `single_instruction_test` feature needs a
  matching `unimplemented!()` stub for API parity.

## Existing regression tests

Two tests on this branch lock in the buggy behaviour and will fail once
the leak is fixed (each contains a comment describing the assertion to
flip):

- [crates/vm2/src/tests/divergence_regressions.rs:1093](../crates/vm2/src/tests/divergence_regressions.rs#L1093) —
  `rollback_should_deallocate_dynamic_decommit_page_pinned_outside_bootloader_frame`.
  Synthetic: direct `push_frame` / `Decommit` / `pop_frame` / `rollback`,
  panic-catches the re-`push_frame`.
- [crates/vm2/src/tests/divergence_regressions.rs:1290](../crates/vm2/src/tests/divergence_regressions.rs#L1290) —
  `realistic_decommit_rollback_leak_via_validation_chain`. End-to-end via
  real opcodes (`FarCall` → `FarCall` → `Decommit` → `Ret`), matching the
  production trigger.

Both assert: orphan persists in `heaps.dynamic` after rollback, and the
next far-call chain panics with `"is already allocated"`.

## Notes

- The bootloader-frame case is unaffected: `current_frame.heap == HeapId::FIRST`
  is "always allocated" and replayed by `Heaps::rollback`'s log replay.
  Covered by `rollback_should_restore_bootloader_heap_after_fresh_decommit`.
- The far-call code-page materialization path is unaffected: the candidate
  is `code_page_from_base(new_base_page)`, never equal to the calling
  frame's `heap`/`aux_heap`, so the keep-alive push runs and
  `external_rollback` cleans it up.
