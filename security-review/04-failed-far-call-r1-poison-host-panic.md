# Vuln: Host panic when reading via `r1` after a failed `far_call`

- **Severity:** HIGH
- **Category:** vm_host_panic / dos / vm2-vs-zk_evm divergence
- **Confidence:** 9/10
- **Branch:** `popzxc-airbender-eravm-review`

## Description

When a `far_call` cannot begin (target has no code, OOG during `pay_for_decommit`, malformed `code_info`), vm2 still pushes a real callee frame seeded with `Program::new_panicking()`, which self-destructs on its first instruction and routes through `naked_ret`'s panic branch for uniform cleanup. The control flow is clean.

The problem is in how that path resets the **register state** for the caller. The post-`pop_frame` tail of `naked_ret` re-establishes the call-boundary convention "r1 holds the returned pointer, everything else is a scalar":

```rust
// crates/vm2/src/instruction_handlers/ret.rs:103-108
vm.state.registers = [U256::zero(); 16];

if let Some(return_value) = return_value_or_panic {
    vm.state.registers[1] = return_value.into_u256();
}
vm.state.register_pointer_flags = 2;   // <-- runs unconditionally
```

The invariant this is meant to maintain — **"r1 is a pointer iff there is a returned pointer"** — breaks on the panic path: with `return_value_or_panic = None` the `registers[1]` write is skipped, but `register_pointer_flags = 2` runs anyway. The caller resumes with `r1 = 0` *and* the pointer flag set, i.e. a fat pointer to `HeapId(0)`.

`HeapId(0)` is undecodable, and `Heaps::Index<HeapId>` `panic!`s on undecodable ids rather than returning an empty heap. `PointerRead` is ungated and both of its guards (`input_is_pointer`, `offset > LAST_ADDRESS`) pass trivially for a zero-with-flag input. A single `pointer_read r1` in the exception handler therefore indexes `heaps[HeapId(0)]` and triggers a host-side Rust `panic!` — there is no `catch_unwind` in the handler path, so the VM host aborts.

The synthetic `HeapId(0)` originates from vm2's own empty-pointer substitution and is laundered into r1 by the unconditional flag write. zk_evm tolerates the same situation (its memory layer returns zero for missing pages, `reference_impls/memory.rs:110-115`); vm2 turns it into a host crash — both a DoS primitive and an execution-trace divergence vs zk_evm.

## Affected code

- [crates/vm2/src/instruction_handlers/ret.rs:103-108](../crates/vm2/src/instruction_handlers/ret.rs#L103-L108) — `register_pointer_flags = 2` set unconditionally even when there is no return value.
- [crates/vm2/src/instruction_handlers/far_call.rs:131-132](../crates/vm2/src/instruction_handlers/far_call.rs#L131-L132) — synthetic empty fat pointer minted with `memory_page = HeapId(0)` on `fallible_part = None`.
- [crates/vm2/src/heap.rs:534-541](../crates/vm2/src/heap.rs#L534-L541) — `Heaps::Index<HeapId>` `panic!`s on undecodable ids instead of returning an empty heap.

## Exploit scenario

Any unprivileged user can deploy a contract whose body executes three opcodes that crash the VM host:

```asm
; non-kernel user contract, deployed to a normal (non-system) address
START:
    far_call r1, r2, EXCEPTION_HANDLER    ; r2 = 0 (or any address with no code)
    ret.ok                                 ; success path (unreachable)

EXCEPTION_HANDLER:
    pointer_read r1, r3                   ; r1 = 0 (pointer flag set) -> heaps[HeapId(0)] -> PANIC
```

Sequence:

1. `far_call` to an address with no deployed code (e.g. `r2 = 0`). `decommit` returns `None`, so vm2 substitutes the synthetic empty fat pointer and a `Program::new_panicking()`, and pushes the callee frame.
2. The callee's single instruction returns via `naked_ret` with `return_value_or_panic = None`. `register_pointer_flags = 2` is set unconditionally; r1 stays `U256::zero()`. PC is set to `EXCEPTION_HANDLER`.
3. The caller's `pointer_read` runs with `input_is_pointer = true`, `input = 0`. Both guards pass. Indexing `heaps[HeapId(0)]` triggers `panic!("heap page 0 is not allocated")`. The host aborts.

The exploit needs no kernel mode, no system contract, no privileged caller, and no gas tuning. `r2 = 0` is sufficient because non-existence of a target is a state property, not a resource property. Cost is roughly 32 gas for the two opcodes.

## Recommendation

Two complementary fixes; either alone closes this exact path.

1. **Sanitize the panic-recovery register state in `naked_ret`** ([ret.rs:103-108](../crates/vm2/src/instruction_handlers/ret.rs#L103-L108)) — keep r1 and the pointer-flag bitmask in sync:

   ```rust
   vm.state.registers = [U256::zero(); 16];
   if let Some(return_value) = return_value_or_panic {
       vm.state.registers[1] = return_value.into_u256();
       vm.state.register_pointer_flags = 2;
   } else {
       vm.state.register_pointer_flags = 0;
   }
   ```

   Note that `register_pointer_flags` is a top-level `State` field, not per-frame ([state.rs:21](../crates/vm2/src/state.rs#L21)), so the `else` arm is required — without it, the bitmask retains whatever bits the callee left, and any of the zeroed registers can still be observed as a fat pointer to `HeapId(0)`.

   Caveat: the unconditional `register_pointer_flags = 2` is not an oversight — it mirrors the call-side convention at [far_call.rs:154-159](../crates/vm2/src/instruction_handlers/far_call.rs#L154-L159), where the callee is also started with r1 pointer-flagged regardless of whether the calldata is a real fat pointer or the synthetic `HeapId(0)` substitution from [far_call.rs:131-132](../crates/vm2/src/instruction_handlers/far_call.rs#L131-L132). The invariant is "post-far-call, r1 is always the returndata-pointer slot"; zk_evm holds the same invariant and tolerates it because its memory layer is total. This fix breaks that invariant on the panic path — callers can no longer assume r1 carries the pointer flag after a far_call returns, which is an observable execution-trace change vs zk_evm. That is why fix 2 is preferred: it removes the host panic without altering the register-state contract.

2. **Make `Heaps::Index<HeapId>` total** ([heap.rs:534-541](../crates/vm2/src/heap.rs#L534-L541)) — for any undecodable id, return a static empty `Heap` instead of panicking. This collapses the vm2-vs-zk_evm divergence at the boundary and defends against any future undecodable-`HeapId` source (tracers, opcode refactors, etc.). This is a prefered solution, because it does not change the semantics of r1 being the returndata-pointer slot, and it might prevent similar unintentional panic.

