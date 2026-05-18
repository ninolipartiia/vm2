# Snapshot-index drift across the external snapshot API

- **Severity:** INFORMATIONAL
- **Category:** snapshot consistency / error-prone API / host panic
- **Exploitability:** Embedder-gated. The doc comments do not forbid the active-near-call configuration ([`vm.rs:186-189`](../crates/vm2/src/vm.rs#L186-L189) explicitly acknowledges it), so any embedder that snapshots while a near-call is active triggers the bug. Whether any in-tree or downstream embedder of vm2 actually exhibits the pattern is outside this review's scope; the `eravm-airbender-verifier` and any downstream embedders should be audited separately before this finding is dismissed.

## Summary

Each frame in vm2 — both `Callframe` (far-call) and `NearCallFrame` — stores a `world_before_this_frame: Snapshot` captured when the frame is entered ([`callframe.rs:48`](../crates/vm2/src/callframe.rs#L48), [`callframe.rs:57`](../crates/vm2/src/callframe.rs#L57)). On panic-revert, `naked_ret` ([`ret.rs:117-120`](../crates/vm2/src/instruction_handlers/ret.rs#L117-L120)) consumes that Snapshot via `WorldDiff::rollback` to undo the frame's writes. The Snapshot itself is a bundle of raw `usize` indices into the backing `Vec`s held inside `WorldDiff`:

```rust
// crates/vm2/src/rollback.rs:39-54 — same shape for RollbackableSet (84-95) and RollbackableLog (121-133)
impl<K: Ord, V> Rollback for RollbackableMap<K, V> {
    type Snapshot = usize;
    fn snapshot(&self) -> Self::Snapshot { self.old_entries.len() }
    fn rollback(&mut self, snapshot: Self::Snapshot) {
        for (k, v) in self.old_entries.drain(snapshot..).rev() { ... }
    }
}
```

`WorldDiff::Snapshot` bundles these indices ([`world_diff.rs:502-511`](../crates/vm2/src/world_diff.rs#L502-L511)). The scheme is rollback-safe only while every backing `Vec` grows append-only between frame entry and panic-revert. vm2 does not enforce this invariant; several call sites mutate the backing `Vec`s out of band. When a `world_before_this_frame` is subsequently consumed, `RollbackableMap::rollback`'s `Vec::drain(X..)` either panics on an out-of-bounds start or drains a range that does not correspond to the frame's own writes.

Two reachable shrinkages affect `world_before_this_frame`:

- **`clear_transient_storage`** wholesale-replaces `transient_storage_changes` while frame snapshots index into it. Reachable from any kernel-mode frame executing `IncrementTxNumber` — see [finding 05](./05-clear-transient-storage-snapshot-invalidation.md).
- **`vm.rollback()` and `vm.pop_snapshot()` calling `delete_history()`** clear every `old_entries` to length 0 while a `NearCallFrame.world_before_this_frame` still indexes into them. The trigger configuration is explicitly acknowledged at [`vm.rs:186-189`](../crates/vm2/src/vm.rs#L186-L189). This is the path the remainder of this finding documents.

A separate consumption surface shares the same root cause: `pub fn WorldDiff::snapshot()` returns a `Snapshot` to the embedder, and the public `_after` query methods raw-slice the relevant backing `Vec` with a field from the held Snapshot, without bounds-checking the index. Each method is invalidated by a different subset of the three shrinkage sources:

| Method | Backing field | Shrunk by `delete_history` | Shrunk by `external_rollback` | Shrunk by internal `WorldDiff::rollback` |
|---|---|:---:|:---:|:---:|
| `get_storage_changes_after` ([`world_diff.rs:301`](../crates/vm2/src/world_diff.rs#L301)) | `storage_changes.old_entries` | yes (clear) | yes (via internal rollback) | yes (drain) |
| `events_after` ([`world_diff.rs:349`](../crates/vm2/src/world_diff.rs#L349)) | `events.entries` | no (`RollbackableLog::delete_history` is a no-op) | yes (truncate) | yes (truncate) |
| `l2_to_l1_logs_after` ([`world_diff.rs:362`](../crates/vm2/src/world_diff.rs#L362)) | `l2_to_l1_logs.entries` | no (same reason) | yes (truncate) | yes (truncate) |
| `storage_log_queries_after` ([`world_diff.rs:269`](../crates/vm2/src/world_diff.rs#L269)) | `storage_logs` (plain `Vec`) | no (untouched) | yes ([`world_diff.rs:474`](../crates/vm2/src/world_diff.rs#L474) `truncate`) | no (`WorldDiff::rollback` does not touch `storage_logs`) |

Every cell marked "yes" is a path from a stale held-Snapshot to a slice-OOB host panic at the query site.

All paths and surfaces share the same root cause and would be closed at once by the class-level generation-tag fix in the Recommendation section below.

## Code-level issue

The root defect is at `delete_history`. Both `vm.rollback()` and `vm.pop_snapshot()` call it ([`vm.rs:168`](../crates/vm2/src/vm.rs#L168), [`vm.rs:183`](../crates/vm2/src/vm.rs#L183)) while a near-call may still be live in the current frame. `delete_history` truncates every rollbackable container's `old_entries` to length 0 ([`rollback.rs:56-58`](../crates/vm2/src/rollback.rs#L56-L58), [`rollback.rs:97-99`](../crates/vm2/src/rollback.rs#L97-L99)). Any `NearCallFrame.world_before_this_frame` snapshot index `X` on the live `near_calls` stack now points past the end of a length-0 `Vec`.

Three external entry points form the exposure surface, each asserting only `previous_frames.is_empty()`:

- **`make_snapshot`** ([`vm.rs:135-146`](../crates/vm2/src/vm.rs#L135-L146)) — does not itself shrink anything, so it is not a direct trigger of the `delete_history` path documented below; it is the prerequisite without which neither `vm.rollback()` nor `vm.pop_snapshot()` is reachable. It does clone the live `Vec<NearCallFrame>` via `CallframeSnapshot::snapshot` ([`callframe.rs:184-197`](../crates/vm2/src/callframe.rs#L184-L197)); on the rollback path this clone is later reinstated by `state.rollback` ([`callframe.rs:201-229`](../crates/vm2/src/callframe.rs#L201-L229)), preserving the captured near-call snapshot indices across any intermediate execution that popped them. (For the consumption-surface arm in the Summary, `make_snapshot` *is* the originating event: it is what hands a `Snapshot` to the embedder in the first place — see also `pub fn WorldDiff::snapshot()` at [`world_diff.rs:399`](../crates/vm2/src/world_diff.rs#L399).)
- **`rollback`** ([`vm.rs:154-169`](../crates/vm2/src/vm.rs#L154-L169)) — calls `external_rollback` ([`world_diff.rs:459-477`](../crates/vm2/src/world_diff.rs#L459-L477)), then `state.rollback` (which reinstates the cloned `near_calls`), then `delete_history` at line 168. The first two steps are individually rollback-safe — `external_rollback` only truncates each `old_entries` to the external-snapshot baseline `N`, and `X ≤ N` makes a hypothetical `drain(X..N)` in-bounds and semantically correct (it would undo the near-call's own writes between its entry and the external snapshot). It is the trailing `delete_history` that drops every `old_entries` from length `N` to 0 and orphans the near-call's index.
- **`pop_snapshot`** ([`vm.rs:177-184`](../crates/vm2/src/vm.rs#L177-L184)) — calls `delete_history` directly. Whatever near-call(s) were live on entry remain live, and their snapshot indices still point into the now-empty history vectors.

The doc comment on `delete_history` at [`vm.rs:186-189`](../crates/vm2/src/vm.rs#L186-L189) acknowledges the trigger configuration explicitly:

```rust
/// This must only be called when it is known that the VM cannot be rolled back,
/// so there must not be any external snapshots and the callstack
/// should ideally be empty, though in practice it sometimes contains
/// a near call inside the bootloader.
```

The *"should ideally be empty, though in practice it sometimes contains a near call"* admission is the source of the contract ambiguity: the public API does not forbid the trigger configuration, even though the resulting `Snapshot` is no longer rollback-safe.

### Failure modes

On a subsequent panic-revert of the surviving near-call, `naked_ret` ([`ret.rs:117-120`](../crates/vm2/src/instruction_handlers/ret.rs#L117-L120)) calls `vm.world_diff.rollback(X)`, which fans out per-field to `RollbackableMap::rollback(X)`. Each map runs `drain(X..)` against its `old_entries`, whose length is now whatever post-`delete_history` writes have grown it to (call it `K_now`):

- `X > K_now` for any of the three `RollbackableMap` fields (`storage_changes`, `paid_changes`, `transient_storage_changes`) → `Vec::drain` panics on the OOB start → vm2 host process aborts. Maps are rolled back in field order; the first violator aborts.
- `X ≤ K_now` → `drain(X..K_now)` succeeds, but the entries removed are post-`delete_history` writes, not the `[X..N)` history the near-call meant to undo (which `delete_history` destroyed). When `X == 0` and `K_now == 0`, the drain is a silent no-op and the near-call's own writes to the live `BTreeMap`s persist past its panic-revert.

`events` and `l2_to_l1_logs` use saturating `Vec::truncate` and are not panic-capable; `pubdata` is a `RollbackablePod<i32>` snapshotting the value rather than an index ([`rollback.rs:155-167`](../crates/vm2/src/rollback.rs#L155-L167)). The host-panic hazard via this consumption surface reduces to the three `RollbackableMap` fields above.

## Exploit reachability

### Preconditions

The bug requires the embedder usage pattern: calling `make_snapshot`, `rollback`, or `pop_snapshot` while the bootloader is inside an active near-call. An embedder that snapshots only at tx boundaries with an empty `near_calls` stack does not trigger the bug — the cloned `near_calls` vector is empty and there is no surviving stale index to consume.

What makes this finding open rather than a non-issue is the contract gap: the public documentation does not forbid the trigger configuration, and `delete_history`'s own comment at [`vm.rs:186-189`](../crates/vm2/src/vm.rs#L186-L189) acknowledges it as occurring in practice. An embedder reading the doc comments on `make_snapshot` / `rollback` / `pop_snapshot` sees `previous_frames.is_empty()` as the only asserted precondition; concluding from this that the bootloader is a uniformly legal snapshot point produces the failure described above.

### Scope of the exploitability claim

Confirmation of total unexploitability across all reachable embedder configurations is outside this review's scope. The current safety property depends on whatever snapshot cadence the embedder happens to use, and would be invalidated by any embedder shipping a different cadence — speculative-execution harnesses, per-step debug/replay harnesses, state-channel checkpointing, or differential-testing tools comparing vm2 against another VM step-by-step are all plausible patterns that would trigger the bug.

### Rationale for keeping the finding open

The VM-level invariant *"any captured `Snapshot` is rollback-safe"* is violated whenever an embedder follows the (legal-per-docs) trigger pattern. A self-contained VM should not delegate its rollback semantics to embedder discipline that the source neither documents precisely nor enforces; the substantive defect is the absence of a precondition check at the three external entry points.

## Recommendation

### Primary fix — tighten the external-API

One change closes the finding. Apply at the three entry points:

1. **Assertion.** Add to `make_snapshot` ([`vm.rs:135-146`](../crates/vm2/src/vm.rs#L135-L146)), `rollback` ([`vm.rs:154-169`](../crates/vm2/src/vm.rs#L154-L169)), and `pop_snapshot` ([`vm.rs:177-184`](../crates/vm2/src/vm.rs#L177-L184)):

   ```rust
   assert!(
       self.state.current_frame.near_calls.is_empty(),
       "Snapshot APIs are only allowed outside any active near-call",
   );
   ```

2. **Documentation.** Update the doc comments at [`vm.rs:129-134`](../crates/vm2/src/vm.rs#L129-L134), [`vm.rs:148-153`](../crates/vm2/src/vm.rs#L148-L153), and [`vm.rs:171-176`](../crates/vm2/src/vm.rs#L171-L176) to state explicitly that the three APIs are only legal when no near-call is active. Remove the *"though in practice it sometimes contains a near call inside the bootloader"* clause at [`vm.rs:186-189`](../crates/vm2/src/vm.rs#L186-L189) — that admission is the source of the contract ambiguity.

This converts an undefined-behavior class (drain-OOB host panic / silent state retention) into a defined embedder-visible assertion failure at the misuse site. The assertion is backwards-compatible with any embedder that already snapshots only outside near-calls.

### Class-level (optional, structurally preferred) — generation-tagged snapshots

Same option called out by [finding 05](./05-clear-transient-storage-snapshot-invalidation.md): change `Snapshot` from `usize` to `(generation: u32, index: usize)` and bump the generation on any backing-`Vec` mutation that violates the append-only invariant. Rolling back with a mismatched generation panics by construction. The API-contract fix above closes this finding's specific `delete_history` path; this class-level fix additionally closes the `clear_transient_storage` path covered by [finding 05](./05-clear-transient-storage-snapshot-invalidation.md) and the externally-held-Snapshot consumption surface described in the Summary. Recommended for that broader coverage and because it promotes the currently-implicit append-only invariant to a type-system-enforced one, preventing future instances at new mutation sites.

