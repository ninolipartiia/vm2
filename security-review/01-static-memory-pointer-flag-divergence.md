# Vuln 1: Consensus Divergence — Pointer Flag Cleared on Increment Register

**File:** [crates/vm2/src/instruction_handlers/heap_access.rs:197-219](../crates/vm2/src/instruction_handlers/heap_access.rs#L197-L219)
(also affects [crates/vm2/src/instruction_handlers/heap_access.rs:71-102](../crates/vm2/src/instruction_handlers/heap_access.rs#L71-L102))

* **Severity:** MEDIUM
* **Category:** consensus_divergence / fat_pointer_handling
* **Confidence:** 8/10

## Description

`load_static` (StaticMemoryRead opcode) with `INCREMENT=true` clears the
pointer flag on the incremented destination register because it uses
`Register2::set`, which clears the bit in `register_pointer_flags`.

The reference `zk_evm` UMA handler explicitly preserves `src0_is_ptr` on the
dst1 update for all read variants (HeapRead, AuxHeapRead, FatPointerRead,
StaticMemoryRead — see `zk_evm/src/opcodes/execution/uma.rs:410`:
`is_pointer: src0_is_ptr`).

The same defect also exists in vm2's regular `load` for HeapRead/AuxHeapRead
at lines 71-102, broadening the scope. Because StaticMemoryRead is kernel-only
and is invoked from system/protocol code, any divergence here is
consensus-relevant and will be observed when the prover's zk_evm replay
disagrees with vm2's sequencer trace.

## Exploit Scenario

A system contract issues a `StaticMemoryRead` / `StaticMemoryWrite` (or any
`HeapRead` / `AuxHeapRead`) with `INCREMENT=true` on a register whose source
operand carries the pointer flag. vm2 produces a destination register with
the pointer flag cleared; zk_evm produces the same numeric value but with the
pointer flag set. Any downstream operation that branches on the pointer flag
(FarCall ABI parsing, `FatPointerRead`, `Ptr*` validation) then takes a
different path on the two implementations, producing a state-transition
output mismatch between sequencer and prover.

## Recommendation

When `input_is_pointer == true` (or by always preserving `src0_is_ptr`
regardless), call a pointer-preserving setter (e.g. `set_fat_ptr`) for the
increment register write. Mirror zk_evm's behavior in both
`load_static`/`store_static` and `load`/`store`. Add a divergence-regression
test exercising the increment register's pointer flag.

## Validation Notes

**Status: valid, with corrections to the affected-opcode list and a missing
exploit-precondition explanation.**

### What is correct

The code claim is accurate. [`heap_access.rs:99`](../crates/vm2/src/instruction_handlers/heap_access.rs#L99)
and [`heap_access.rs:217`](../crates/vm2/src/instruction_handlers/heap_access.rs#L217)
call `Register2::set`, which clears the bit in `register_pointer_flags`
([`addressing_modes.rs:493-498`](../crates/vm2/src/addressing_modes.rs#L493-L498)).
zk_evm's UMA read branch at `uma.rs:404-413` writes dst1 with
`is_pointer: src0_is_ptr` — flag preserved. This is a real behavioral
divergence on the increment register for read variants.

### Exploitability — real, but the precondition is non-obvious

The exploit scenario as written assumes a register with `is_pointer=true` and
`value <= LAST_ADDRESS` (otherwise `bigger_than_last_address` panics in both
VMs and there is no divergence). All conventional fat-pointer constructors
(`Decommit`, `FarCall` calldata, pointer arithmetic, `Ret` returndata in the
non-panic path) set `memory_page > 0`, so any "valid" pointer-flagged register
has value ≥ 2³² and traps in both VMs. On inspection, the divergence appears
unreachable.

The concrete reachable path is **a panicking `Ret` from a far call**:

1. Callee executes `Ret.Panic` (or any path that becomes `ReturnType::Panic`).
2. vm2's [`ret.rs:103-108`](../crates/vm2/src/instruction_handlers/ret.rs#L103-L108)
   zeroes all registers, leaves `r1 = 0` (because `return_value_or_panic` is
   `None`), and unconditionally sets `register_pointer_flags = 2`.
3. zk_evm matches: `FatPointer::empty().to_u256() == 0`, written to r1 with
   `is_pointer: true` (`uma`/`ret.rs:219-223`).
4. Both VMs now agree: caller's exception handler observes
   `r1 = 0, is_pointer = true`.
5. Exception handler executes `HeapRead r1+, dst1` (or AuxHeapRead /
   StaticMemoryRead). Both VMs proceed past the range check (value = 0).
6. vm2: `dst1` flag cleared. zk_evm: `dst1` flag set.
7. A subsequent `FatPointerRead` / `Ptr*` op on `dst1` panics in vm2 and
   succeeds in zk_evm → trace divergence.

### Corrections to the original write-up

- **Writes are not affected.** zk_evm's write branch at `uma.rs:471-480`
  writes dst0 with `is_pointer: false` (and `debug_assert_eq!(src0_is_ptr,
  false)`). vm2's `store`/`store_static` ([`heap_access.rs:138`](../crates/vm2/src/instruction_handlers/heap_access.rs#L138),
  [`heap_access.rs:248`](../crates/vm2/src/instruction_handlers/heap_access.rs#L248))
  also clear the flag. Writes converge; the recommendation should target only
  `load`/`load_static` (and not `store`/`store_static`).
- **`FatPointerRead` is already correct in vm2.** `load_pointer` at
  [`heap_access.rs:192`](../crates/vm2/src/instruction_handlers/heap_access.rs#L192)
  uses `set_fat_ptr`. It should not be listed among the affected variants.
- **Kernel-mode framing is misleading.** `HeapRead` / `AuxHeapRead` are
  user-mode accessible, so the attack surface is broader than the
  StaticMemoryRead-centric framing implies. Any user contract can trigger
  the divergence, not just kernel/system code.

### Severity reassessment

MEDIUM is defensible. The impact is sequencer/prover trace divergence — a
consensus halt risk rather than state theft. Trigger requires a contrived
but achievable sequence (panicking callee → caller's exception handler runs
HeapRead+INCREMENT → flag-sensitive op). MEDIUM-HIGH is also defensible
given consensus impact; MEDIUM is fine.

### Test gap to plug

A regression test should pin the post-panic-Ret state explicitly:
construct a frame, execute a panicking far call, then `HeapRead r1+, dst1`
in the caller, and assert `dst1`'s pointer flag matches zk_evm
(`is_pointer = true`).
