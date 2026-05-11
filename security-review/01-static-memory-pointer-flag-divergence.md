# Vuln 1: Pointer Flag Cleared on UMA Read Increment Register

**File:** [crates/vm2/src/instruction_handlers/heap_access.rs:197-219](../crates/vm2/src/instruction_handlers/heap_access.rs#L197-L219)
(also affects [crates/vm2/src/instruction_handlers/heap_access.rs:71-102](../crates/vm2/src/instruction_handlers/heap_access.rs#L71-L102))

* **Severity:** MEDIUM
* **Category:** fat_pointer_handling

## Description

vm2's UMA-read handlers `load` ([heap_access.rs:71-102](../crates/vm2/src/instruction_handlers/heap_access.rs#L71-L102)) and `load_static` ([heap_access.rs:197-219](../crates/vm2/src/instruction_handlers/heap_access.rs#L197-L219)) write the incremented destination register through `Register2::set` ([heap_access.rs:99](../crates/vm2/src/instruction_handlers/heap_access.rs#L99) and [:217](../crates/vm2/src/instruction_handlers/heap_access.rs#L217)), which clears the bit in `register_pointer_flags`
([addressing_modes.rs:493-498](../crates/vm2/src/addressing_modes.rs#L493-L498)). zk_evm's UMA read branch at `uma.rs:404-413` writes dst1 with `is_pointer: src0_is_ptr`, preserving the source's pointer flag:

```rust
                    if increment_offset {
                        let mut updated_value = src0_value;
                        updated_value.0[0] = (updated_value.0[0] & U64_TOP_32_BITS_MASK)
                            + (incremented_offset as u64);
                        let reg_value = PrimitiveValue {
                            value: updated_value,
                            is_pointer: src0_is_ptr,
                        };
                        vm_state.perform_dst1_update(reg_value, self.dst1_reg_idx);
                    }
```

Three opcode variants are affected:

- **HeapRead** (via `load`) — user-mode.
- **AuxHeapRead** (via `load`) — user-mode.
- **StaticMemoryRead** (via `load_static`) — kernel-only per `UMAOpcode::requires_kernel_mode`.

FatPointerRead is unaffected: vm2's `load_pointer` at [heap_access.rs:192](../crates/vm2/src/instruction_handlers/heap_access.rs#L192) uses `set_fat_ptr`, matching zk_evm's `is_pointer: src0_is_ptr` (which is guaranteed `true` because FatPointerRead with a non-pointer src0 panics earlier).

Writes (HeapWrite / AuxHeapWrite / StaticMemoryWrite) converge: vm2's `store` ([heap_access.rs:138](../crates/vm2/src/instruction_handlers/heap_access.rs#L138)) and `store_static` ([heap_access.rs:248](../crates/vm2/src/instruction_handlers/heap_access.rs#L248)) clear the flag on dst0; zk_evm's write branch at `uma.rs:471-480` writes `is_pointer: false` and `debug_assert_eq!(src0_is_ptr, false)`.

## Exploit Scenario

The bug fires only when src0 has `is_pointer = true` **and** `value ≤ LAST_ADDRESS` — otherwise `bigger_than_last_address` panics in both VMs. The one path that produces such a register is a panicking `Ret` from a far call:

1. Callee executes `Ret.Panic` (or any path that becomes `ReturnType::Panic`).
2. vm2 at [ret.rs:103-108](../crates/vm2/src/instruction_handlers/ret.rs#L103-L108) zeroes all registers, leaves `r1 = 0` (because `return_value_or_panic` is `None`), and unconditionally sets `register_pointer_flags = 2`. zk_evm matches: `FatPointer::empty().to_u256() == 0`, written to r1 with `is_pointer: true` (`zk_evm/.../ret.rs:219-223`).
3. Caller's exception handler observes `r1 = 0, is_pointer = true`.
4. Exception handler executes `HeapRead r1+, dst1` (or AuxHeapRead / StaticMemoryRead). Both VMs proceed past the range check (value = 0).
5. vm2 writes dst1 with the flag cleared; zk_evm writes dst1 with the flag set.
6. A subsequent `FatPointerRead` / `Ptr*` op on dst1 panics in vm2 (no flag) and succeeds in zk_evm.

Every other constructor of a pointer-flagged register (`Decommit`, `FarCall` calldata, pointer arithmetic, `Ret.Ok` / `Ret.Revert` returndata) sets `memory_page > 0`, putting the U256 value ≥ 2³² — those all trap in both VMs at the range check.

## Recommendation

In `load` and `load_static`, write the increment register through `Register2::set_fat_ptr` when `input_is_pointer == true` (or unconditionally preserve `src0_is_ptr`) so dst1 matches zk_evm. No changes needed in `store` / `store_static`.

## Test Gap

A regression test should pin the post-panic-Ret state explicitly: construct a frame, execute a panicking far call, then `HeapRead r1+, dst1` in the caller, and assert `dst1`'s pointer flag matches zk_evm (`is_pointer = true`). Equivalent single-instruction differential tests can short-circuit the panicking-Ret prelude by setting `register_pointer_flags = 1 << src_reg` directly.
