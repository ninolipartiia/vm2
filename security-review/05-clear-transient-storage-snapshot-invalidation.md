# `clear_transient_storage` invalidates outstanding near-call snapshots

- **Severity:** LOW
- **Category:** snapshot consistency / host panic
- **Exploitability:** Unlikely under the current era-contracts bootloader: `IncrementTxNumber` is emitted only at the top of the bootloader frame ([`bootloader.yul:4622`](../../era-contracts/system-contracts/bootloader/bootloader.yul#L4622)), after `processTx` has returned and all near-calls have unwound. Confirming total unexploitability is outside this review's scope. The safety is structural to one specific bootloader bytecode, not enforced by vm2.


## Summary

`WorldDiff::clear_transient_storage` performs a wholesale replacement of `transient_storage_changes`, discarding the `old_entries` history that captured `RollbackableMap` snapshots index into. When a near-call frame whose snapshot was taken *before* the clearing later panic-reverts, `RollbackableMap::rollback` invokes `Vec::drain(snapshot..)` on the now-empty history vector and either:

- panics the host process with an out-of-bounds drain (when the captured `snapshot > 0`), or
- silently consumes the wrong range (when `snapshot == 0` but the post-clearing live map has been further mutated).

The VM-level invariant *"any captured `Snapshot` is rollback-safe"* is violated; vm2's safety here is delegated to bootloader bytecode the VM does not ship.

## Code-level issue

The class-level enabler — `RollbackableMap::Snapshot` is a `usize` index into a backing `Vec` whose append-only invariant is neither type-system-enforced nor runtime-checked — is described in [finding 06](./06-snapshot-index-drift-embedder-api.md#common-foundation--snapshot-index-drift). This finding documents one concrete violation of that invariant inside vm2 itself: `clear_transient_storage` replaces the backing `RollbackableMap` wholesale, discarding the `old_entries` history that captured snapshots still index into.

Three independent guard sites are absent:

| Site | Missing guarantee |
|---|---|
| Mutation (`clear_transient_storage`) | Not rollback-aware. Each clearing should be recorded through `RollbackableMap::insert` so `old_entries` grows monotonically. |
| Call site (`start_new_tx`, [`vm.rs:285-288`](../crates/vm2/src/vm.rs#L285-L288)) | No frame-depth assertion. Does not require `near_calls.is_empty() && previous_frames.is_empty()`. |
| Consumption (`RollbackableMap::rollback`, [`rollback.rs:46-54`](../crates/vm2/src/rollback.rs#L46-L54)) | No semantic check on the index before draining, `drain` can panic. |

**Mutation site** ([`world_diff.rs:494-496`](../crates/vm2/src/world_diff.rs#L494-L496)):

```rust
pub(crate) fn clear_transient_storage(&mut self) {
    self.transient_storage_changes = RollbackableMap::default();
}
```

Both the live `BTreeMap` and its `old_entries` history are replaced. Any `NearCallFrame.world_before_this_frame.transient_storage_changes = N` captured before the call references a discarded `Vec`; the new `Vec` has length 0.

The codebase documents that *"`clear_transient_storage` cannot be undone"* ([`world_diff.rs:441-444`](../crates/vm2/src/world_diff.rs#L441-L444)) and patches the analogous problem on the *external* snapshot path by overriding `transient_storage_changes: 0` ([`world_diff.rs:441-449`](../crates/vm2/src/world_diff.rs#L441-L449)). The patch's stated justification — *"the next instruction in the bootloader (IncrementTxNumber) clears the transient storage anyway"* — encodes a bootloader bytecode assumption into vm2 source. The internal near-call snapshot path receives no equivalent treatment.

<!-- ### Issue 3 — Divergence from the rollback-safe pattern used in the production-style `zk_evm` `Storage` implementation

The production `Storage` implementation at [`eravm-airbender-verifier/crates/multivm/src/versions/vm_latest/oracles/storage.rs:572-591`](../../eravm-airbender-verifier/crates/multivm/src/versions/vm_latest/oracles/storage.rs#L572-L591) clears transient storage by writing zeros *through* the rollback machinery:

```rust
fn start_new_tx(&mut self, timestamp: Timestamp) {
    // ... zeroing out the storage, while maintaining history about it,
    // making it reversible.
    let current_active_keys = self.transient_storage.clone_vec();
    for (key, current_value) in current_active_keys {
        self.write_transient_storage_value(ReducedTstoreLogQuery {
            ... read_value: current_value, written_value: U256::zero(), ...
        });
    }
}
```

Each clearing is appended to the current frame's `rollbacks` queue with the prior value as `read_value`. Surviving frames that later panic-revert iterate the queue and correctly un-write both the clearing and the prior writes. vm2 discards exactly the structure this pattern preserves.

The `zk_evm` testing-only implementation at [`zksync-protocol/crates/zk_evm/src/testing/storage.rs:223-228`](../../zksync-protocol/crates/zk_evm/src/testing/storage.rs#L223-L228) takes a `HashMap::clear()` shortcut and is not a correctness reference. -->

## Exploit reachability

### Preconditions

1. **A `tstore` write while an internal snapshot is live.** `TransientStorageWrite` is not kernel-gated ([`decode.rs:218-235`](../crates/vm2/src/decode.rs#L218-L235)). Any user contract can populate `transient_storage_changes.old_entries`.

2. **`IncrementTxNumber` executes inside a frame whose snapshot is captured.** The opcode is kernel-only ([`zksync-protocol/crates/zkevm_opcode_defs/src/definitions/context.rs:114-118`](../../zksync-protocol/crates/zkevm_opcode_defs/src/definitions/context.rs#L114-L118)) but not frame-depth-gated. A kernel-address frame that issues `near_call` produces a callee in kernel mode that can run `IncrementTxNumber` inside the near-call.

### Trace (host-panic variant)

1. Frame `F` writes `tstore k1, v1` → `transient_storage_changes.old_entries.len() = N ≥ 1`.
2. `F` issues `near_call`; the captured snapshot stores `transient_storage_changes: N`.
3. The near-callee `H`, in kernel mode, executes `IncrementTxNumber` → `start_new_tx` → `clear_transient_storage`. `old_entries.len() = 0`.
4. `H` panic-reverts.
5. `naked_ret` ([`ret.rs:117-119`](../crates/vm2/src/instruction_handlers/ret.rs#L117-L119)) calls `vm.world_diff.rollback(snapshot)` → `transient_storage_changes.rollback(N)` → `Vec::drain(N..)` on a length-0 `Vec` → host process abort.

### Silent-corruption variant

Same prefix; `H` performs `M ≥ N` further `tstore` writes before panicking. `drain(N..)` on the length-`M` `Vec` removes `[N..M)`. Those entries are post-clearing writes that *should* be reverted, but the pre-clearing writes (indexed `[0..N)` against the discarded old `old_entries`) cannot be reached. Post-step transient storage diverges from `zk_evm` without any host-visible signal.

[`crates/vm2/src/tests/clear_transient_storage_rollback_panic.rs`](../crates/vm2/src/tests/clear_transient_storage_rollback_panic.rs) exercises the host-panic variant against the current branch and reaches the abort deterministically with a four-instruction synthetic program.

### Production gating

In the current era-contracts bootloader, `IncrementTxNumber` is emitted once per transaction at the top of the bootloader's outer far-call frame ([`bootloader.yul:4622`](../../era-contracts/system-contracts/bootloader/bootloader.yul#L4622)), after every `processTx` near-call has unwound — so no near-call snapshot is live when the opcode fires. In-depth audit of the bootloader is outside this review's scope.

### Scope of the exploitability claim

Confirming total unexploitability across all reachable bytecode configurations is outside this review's scope. The current safety is structural to one bootloader revision and is not enforced by vm2 — any future bootloader change, new kernel-address contract emitting `IncrementTxNumber` from a non-top frame, or alternate embedder bootloader could invalidate it.

<!-- ### Rationale for keeping the finding open

The VM-level invariant *"any captured `Snapshot` is rollback-safe"* is violated regardless of which bootloader is loaded against the VM. The mitigation comment at [`world_diff.rs:441-444`](../crates/vm2/src/world_diff.rs#L441-L444) explicitly delegates one of vm2's correctness arguments to bootloader bytecode that vm2 does not ship and cannot constrain. A self-contained VM should not depend on guest bytecode for its rollback semantics; the substantive defect is the absence of either a rollback-aware mutation (Issue 2, mutation site) or an enforced precondition (Issue 2, call site). -->

## Recommendations

### Primary fix — rollback-aware mutation

Adopt the pattern from the production-style `zk_evm` implementation. Apply at [`world_diff.rs:494-496`](../crates/vm2/src/world_diff.rs#L494-L496):

```rust
pub(crate) fn clear_transient_storage(&mut self) {
    let keys: Vec<_> = self.transient_storage_changes.as_ref().keys().cloned().collect();
    for key in keys {
        self.transient_storage_changes.insert(key, U256::zero());
    }
}
```

`old_entries` grows monotonically; surviving snapshots roll back through both the clearing and the prior-tx writes. The external-snapshot workaround at [`world_diff.rs:441-449`](../crates/vm2/src/world_diff.rs#L441-L449), and the bootloader-bytecode assumption its comment encodes, become unnecessary and should be removed.

### Defense-in-depth — gate the call site

Add a frame-depth assertion at `start_new_tx` ([`vm.rs:285-288`](../crates/vm2/src/vm.rs#L285-L288)):

```rust
pub(crate) fn start_new_tx(&mut self) {
    assert!(
        self.state.previous_frames.is_empty() && self.state.current_frame.near_calls.is_empty(),
        "IncrementTxNumber must run at the top frame",
    );
    self.state.transaction_number = self.state.transaction_number.wrapping_add(1);
    self.world_diff.clear_transient_storage();
}
```

The bootloader-side convention becomes a VM-side invariant. Future bootloader changes or new kernel contracts that violate it fail with a defined, embedder-visible panic at the misuse site instead of an out-of-bounds drain or silent state corruption.

### Class-level (optional, structurally preferred) — generation-tagged snapshots

The [class-level option in finding 06](./06-snapshot-index-drift-embedder-api.md#class-level-optional-structurally-preferred--generation-tagged-snapshots) — change `Snapshot` from `usize` to `(generation: u32, index: usize)` and bump the generation on any backing-`Vec` mutation that violates append-only — turns the currently-implicit append-only invariant into one the type system enforces, making the entire bug class unrepresentable. Optional in the sense that the per-site fixes above close this specific finding, but recommended: it structurally hardens the snapshot/rollback mechanism and prevents future instances at new mutation sites.
