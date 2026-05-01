# Decommit-pinned dynamic heap leaks across `external_rollback`

- **Severity:** MEDIUM
- **Category:** state corruption / consensus divergence (vm2 vs zk_evm)
- **Confidence:** 7/10
- **Branch:** `popzxc-airbender-eravm`
- **Introduced by:** commit `3553c88` ("Align heaps behavior with zk_evm")

## Summary

When the kernel-only `Decommit` opcode is executed from a non-bootloader frame
(e.g., Code Oracle at `0x8012` reached via far-call), the materialized page is
pinned globally but is not registered in any frame's `heaps_i_am_keeping_alive`.
On `vm.rollback()`, the global pin is reverted, yet the dynamic heap slot is
never swept, leaving an orphan in `state.heaps.dynamic`. The next snapshot/tx
that reaches the same base page panics in `allocate_with_content_at`.

## Affected code

- [crates/vm2/src/decommit.rs:18-43](../crates/vm2/src/decommit.rs#L18-L43) — `materialize_decommit_page`
- [crates/vm2/src/instruction_handlers/decommit.rs:42](../crates/vm2/src/instruction_handlers/decommit.rs#L42) — opcode passes `vm.state.current_frame.heap`
- [crates/vm2/src/vm.rs:154-169](../crates/vm2/src/vm.rs#L154-L169) — `vm.rollback`
- [crates/vm2/src/vm.rs:249-283](../crates/vm2/src/vm.rs#L249-L283) — `pop_frame` (preserves pinned)
- [crates/vm2/src/state.rs:140-168](../crates/vm2/src/state.rs#L140-L168) — `State::rollback` does not sweep `heaps.dynamic`
- [crates/vm2/src/heap.rs:340-358](../crates/vm2/src/heap.rs#L340-L358) — `allocate_with_content_at` panics on already-allocated slot
- [crates/vm2/src/heap.rs:416-426](../crates/vm2/src/heap.rs#L416-L426) — `Heaps::rollback` only replays bootloader heap/aux logs
- [crates/vm2/src/world_diff.rs:459-477](../crates/vm2/src/world_diff.rs#L459-L477) — `external_rollback` un-pins
- [crates/vm2/src/tests/divergence_regressions.rs:962-965](../crates/vm2/src/tests/divergence_regressions.rs#L962-L965) — codifies the trigger precondition

## Bug chain

1. `materialize_decommit_page` skips the keep-alive push when
   `heap == current_frame.heap` or `current_frame.aux_heap`:

   ```rust
   if heap != vm.state.current_frame.heap && heap != vm.state.current_frame.aux_heap {
       heaps_to_keep_alive.push(heap);
   }
   ```

2. The Decommit opcode passes `vm.state.current_frame.heap` as the candidate
   (`instruction_handlers/decommit.rs:42`). When invoked from a non-bootloader
   frame, this is a dynamic page (e.g., `base+2`), so the pin is registered
   only in the global `decommit_pinned_pages` map.

3. On frame return, `pop_frame` checks `is_decommit_page_pinned` and skips
   deallocation. The dynamic slot remains `Some(...)` in `state.heaps.dynamic`.

4. On `vm.rollback()`:
   - `world_diff.external_rollback` reverts `decommit_pinned_pages` to the
     pre-snapshot snapshot — un-pinning the orphan.
   - `state.rollback` only drains the bootloader frame's
     `heaps_i_am_keeping_alive` for deallocation; the orphaned page is not in
     that list.
   - `Heaps::rollback` only replays bootloader heap/aux rollback logs — it
     does not touch `dynamic`.
   - `next_base_page` is reset to its pre-snapshot value.

5. The next far-call chain that re-derives the same base page hits
   `allocate_with_content_at`, whose `assert!(slot.is_none())` fires:

   ```rust
   panic!("heap page {} is already allocated", page.as_u32());
   ```

The existing test at `divergence_regressions.rs:962-965` explicitly asserts
that `keep_alive_occurrences == 0` for this configuration (the precondition
for the leak). It does NOT exercise rollback after that scenario.

## Threat model alignment

The PR's stated threat model includes "cause divergence between vm2 (fast
path) and zk_evm (proven path)" as an attacker goal. zk_evm does not maintain
this slot-based allocation invariant and would not panic in the same flow,
so the assertion failure is a sequencer-specific divergence rather than
pure local DoS.

## Trigger scenario

Standard zksync_era bootloader flow:

1. Bootloader takes a snapshot for tx validation.
2. Validation runs the user's account validation phase. If validation calls a
   contract that triggers `decommit` of a fresh code hash (Code Oracle path),
   the dynamic page used by the Code Oracle frame is pinned and orphaned per
   the chain above.
3. Bootloader rolls back the validation snapshot.
4. Bootloader proceeds to the execution phase (or processes the next tx) and
   far-calls deeply enough to re-derive the orphaned base page.
5. `Heaps::allocate_at` panics; vm2 cannot continue while zk_evm could.

## Recommended fix

Either of the following:

- **(a) Track rollback-aware pins separately.** When
  `materialize_decommit_page` skips the keep-alive push, record the page in a
  `RollbackableSet` that participates in `external_rollback` cleanup, so that
  on rollback the orphaned dynamic slot is deallocated.

- **(b) Sweep `state.heaps.dynamic` on rollback.** In `State::rollback`,
  after restoring `next_base_page`, deallocate every slot in `heaps.dynamic`
  whose decoded base lies at or beyond the restored `next_base_page` (and
  isn't pinned by a still-live snapshot). This is more robust because it
  also covers any future caller of `materialize_decommit_page` whose
  candidate page happens to equal a dynamic page that wasn't keep-alive
  registered.

Option (b) is the recommended fix.

## Regression test to add

```text
1. make_snapshot
2. push_frame (non-bootloader kernel frame; dynamic heap H)
3. execute Decommit on a fresh hash; assert page H is pinned and that
   no entry was added to any frame's heaps_i_am_keeping_alive
4. pop_frame  -> H persists in state.heaps.dynamic (pinned)
5. rollback   -> H must NOT remain in state.heaps.dynamic
6. push_frame again with the same base page -> must not panic
```

## Notes

- The bootloader-frame case is unaffected: `current_frame.heap == HeapId::FIRST`
  is an "always allocated" page handled via `record_bootloader_word_rollback`
  and replayed by `Heaps::rollback`. The existing test
  `rollback_should_restore_bootloader_heap_after_fresh_decommit` covers this.
- The far-call code-page materialization path is unaffected: the candidate is
  `code_page_from_base(new_base_page)`, never equal to the calling frame's
  `heap`/`aux_heap`, so the keep-alive push is taken and `external_rollback`
  cleans it up.
