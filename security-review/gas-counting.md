# Gas counting in vm2 (EraVM)

This document describes how gas (a.k.a. "ergs" in EraVM terminology) is counted, charged, refunded, and propagated across calls in this codebase. All references are to files under [crates/vm2/src/](../crates/vm2/src/) unless otherwise noted.

## 1. Where gas lives

Gas is a single `u32` field stored per call frame:

- [callframe.rs:29](../crates/vm2/src/callframe.rs#L29) — `pub(crate) gas: u32` on `Callframe<T, W>`.
- [callframe.rs:55](../crates/vm2/src/callframe.rs#L55) — `previous_frame_gas: u32` on `NearCallFrame`, used to save the *caller's* remaining gas across a near call.

There is no separate VM-wide gas register; the active counter is always `vm.state.current_frame.gas`. Heap allocation paid for by the frame is also tracked in `u32`s right next to gas: `heap_size` and `aux_heap_size` ([callframe.rs:37-38](../crates/vm2/src/callframe.rs#L37-L38)).

The single primitive used to spend gas is `State::use_gas`:

```rust
// state.rs:82-91
pub(crate) fn use_gas(&mut self, amount: u32) -> Result<(), ()> {
    if self.current_frame.gas >= amount {
        self.current_frame.gas -= amount;
        Ok(())
    } else {
        self.current_frame.gas = 0;
        Err(())
    }
}
```

[state.rs:82-91](../crates/vm2/src/state.rs#L82-L91). On failure, the frame's gas is **zeroed** and `Err(())` is returned. There is no negative gas; over-spending always becomes "spend everything left and signal failure".

## 2. Per-instruction static cost

### 2.1 Encoding

Each decoded `Instruction` carries an `Arguments` struct that fits into 8 bytes; the static gas cost is one byte (`static_gas_cost: u8`). To cover EraVM costs that exceed 255, four "magic" values 1–4 are reserved as escape codes that decode back to large constants:

- [addressing_modes.rs:99](../crates/vm2/src/addressing_modes.rs#L99) — field declaration.
- [addressing_modes.rs:102-105](../crates/vm2/src/addressing_modes.rs#L102-L105) — special-cost constants:
  - `L1_MESSAGE_COST  = 156_250`
  - `SSTORE_COST      = 5_511`
  - `SLOAD_COST       = 2_008`
  - `INVALID_INSTRUCTION_COST = 4_294_967_295` (i.e. `u32::MAX`, used to drain gas)
- [addressing_modes.rs:130-145](../crates/vm2/src/addressing_modes.rs#L130-L145) — `encode_static_gas_cost`: maps the four magic values into byte tags 1..=4, panics if a "real" cost collides with 1..=4 or exceeds 255.
- [addressing_modes.rs:147-155](../crates/vm2/src/addressing_modes.rs#L147-L155) — `get_static_gas_cost`: decodes back to the `u32` cost.

The actual per-opcode costs come from the upstream `zkevm_opcode_defs` crate during decoding:

- [decode.rs:41-48](../crates/vm2/src/decode.rs#L41-L48) — at decode time the cost is read from `parsed.variant.ergs_price()` and passed into `Arguments::new(...)`.

So opcode prices are not defined in this repository; the `u8`-encoded cost on each `Arguments` is precomputed once when bytecode is decoded.

### 2.2 Charging

Every instruction goes through `boilerplate` / `boilerplate_ext` / `full_boilerplate` in [common.rs](../crates/vm2/src/instruction_handlers/common.rs). The static cost is taken **before** the opcode body runs, and **before** the predicate is checked:

```rust
// common.rs:60-67
if vm.state.use_gas(args.get_static_gas_cost()).is_err()
    || !args.mode_requirements().met(
        vm.state.current_frame.is_kernel,
        vm.state.current_frame.is_static,
    )
{
    return free_panic(vm, world, tracer);
}
```

[common.rs:60-67](../crates/vm2/src/instruction_handlers/common.rs#L60-L67). Two things to note:

1. **Predicated/skipped instructions still pay the static cost.** The predicate check (`args.predicate().satisfied(...)`) is at [common.rs:69](../crates/vm2/src/instruction_handlers/common.rs#L69), *after* the gas charge. A conditional opcode whose predicate is false still consumes its declared cost.
2. **Mode requirement violations are treated identically to OOG.** Both fall into `free_panic`, see §4.

### 2.3 The "invalid instruction" trick

Reaching an invalid instruction (off the end of bytecode, illegal encoding, etc.) is implemented as a single sentinel instruction with `static_gas_cost = INVALID_INSTRUCTION_COST = u32::MAX`. The first thing `full_boilerplate` does is `use_gas(u32::MAX)`, which always fails for any real gas value, zeroing gas and routing through `free_panic`. There's also an explicit zeroing path:

- [ret.rs:161-168](../crates/vm2/src/instruction_handlers/ret.rs#L161-L168) — `invalid()` handler sets `gas = 0` and calls `free_panic`.

## 3. Out-of-gas handling

`free_panic` in [ret.rs:147-159](../crates/vm2/src/instruction_handlers/ret.rs#L147-L159) is the universal "cheap panic" path. Its docblock lists the cases that go through it: gas exhaustion on a fixed instruction cost, side effects in static context, privileged ops outside system calls, and far-call stack overflow. It runs the standard `naked_ret` with `ReturnType::Panic`, which is the same machinery that `ret.panic` uses, but does **not** charge another static cost.

When the *initial* (outermost) frame panics there is no caller to return to, so the VM stops with `ExecutionEnd::Panicked` ([ret.rs:97-99](../crates/vm2/src/instruction_handlers/ret.rs#L97-L99)).

## 4. Near calls — gas pass and refund

Near calls are intra-contract calls with a saved gas snapshot.

```rust
// near_call.rs:21-30
let new_frame_gas = if gas_to_pass == 0 {
    vm.state.current_frame.gas       // 0 means "give all my gas"
} else {
    gas_to_pass.min(vm.state.current_frame.gas)
};
vm.state.current_frame.push_near_call(
    new_frame_gas, error_handler, vm.world_diff.snapshot(),
);
```

[near_call.rs:11-35](../crates/vm2/src/instruction_handlers/near_call.rs#L11-L35).

The push splits gas:

```rust
// callframe.rs:113-127
self.near_calls.push(NearCallFrame {
    ...,
    previous_frame_gas: self.gas - gas_to_call,
    ...
});
self.gas = gas_to_call;
```

[callframe.rs:113-127](../crates/vm2/src/callframe.rs#L113-L127). The caller's "remaining" gas is parked on the near-call stack, the callee runs against `gas_to_call`. **No 63/64 limit applies to near calls.**

On return, `pop_near_call` restores `previous_frame_gas` ([callframe.rs:129-140](../crates/vm2/src/callframe.rs#L129-L140)), and `naked_ret` adds the callee's leftover back on top:

```rust
// ret.rs:28
let near_call_leftover_gas = vm.state.current_frame.gas;
// ret.rs:42
(snapshot, near_call_leftover_gas)
// ret.rs:123
vm.state.current_frame.gas += leftover_gas;
```

Net effect: caller ends up with `caller_gas_before_call − gas_used_by_callee`. Unused gas is fully refunded across a near-call boundary, regardless of `Normal` / `Revert` / `Panic` return type (the only thing failure changes is rollback of side effects and PC redirection to the exception handler, see [ret.rs:117-122](../crates/vm2/src/instruction_handlers/ret.rs#L117-L122)).

## 5. Far calls — 63/64 rule, mandated gas, decommit

Far calls (`far_call`) are inter-contract; gas accounting happens in three steps in [far_call.rs](../crates/vm2/src/instruction_handlers/far_call.rs):

### 5.1 Mandated gas

Some calls (e.g. `MsgValueSimulator`) require a fixed minimum to be transferred regardless of the 63/64 cap.

```rust
// far_call.rs:89-97
if let Some(gas_left) = vm.state.current_frame.gas.checked_sub(mandated_gas) {
    vm.state.current_frame.gas = gas_left;
} else {
    // If the gas is insufficient, the rest is burned
    vm.state.current_frame.gas = 0;
    mandated_gas = 0;
    return None; // forces the new frame to panic
}
```

[far_call.rs:89-97](../crates/vm2/src/instruction_handlers/far_call.rs#L89-L97). If the caller can't afford the mandated portion, **all of the caller's gas is burned** and the new frame is set up to panic immediately.

### 5.2 Decommit cost

Before passing gas, the callee's bytecode must be paid for if it's the first time it's been decommitted in this VM run. The cost is per code word:

```rust
// decommit.rs:118-123
let cost = if was_decommitted {
    0
} else {
    let code_length_in_words = u16::from_be_bytes([code_info[2], code_info[3]]);
    u32::from(code_length_in_words) * zkevm_opcode_defs::ERGS_PER_CODE_WORD_DECOMMITTMENT
};
```

[decommit.rs:118-123](../crates/vm2/src/decommit.rs#L118-L123). The deduction is performed by `pay_for_decommit` against the caller's gas at [far_call.rs:106-111](../crates/vm2/src/instruction_handlers/far_call.rs#L106-L111). Already-decommitted hashes are free.

Failed-with-OOG decommits are remembered as `DecommitState::Unsuccessful` so they don't make subsequent decommits free; see the comment at [world_diff.rs:36-39](../crates/vm2/src/world_diff.rs#L36-L39).

### 5.3 The 63/64 rule

After mandated gas and decommit are paid:

```rust
// far_call.rs:125-128
let maximum_gas = vm.state.current_frame.gas / 64 * 63;
let normally_passed_gas = abi.gas_to_pass.min(maximum_gas);
vm.state.current_frame.gas -= normally_passed_gas;
let new_frame_gas = normally_passed_gas + mandated_gas;
```

[far_call.rs:125-128](../crates/vm2/src/instruction_handlers/far_call.rs#L125-L128).

So the new frame receives at most `⌊63/64 × caller_remaining_gas⌋ + mandated_gas`. Note the integer division order: `gas / 64 * 63` (not `gas * 63 / 64`) — for `gas < 64` this is `0`, meaning a starved caller passes only the mandated portion.

### 5.4 Refund of leftover

Returning from a far call, `pop_frame` is called and the callee's `leftover_gas = vm.state.current_frame.gas` (saved at [ret.rs:66](../crates/vm2/src/instruction_handlers/ret.rs#L66)) is added back to the now-current (caller) frame at [ret.rs:123](../crates/vm2/src/instruction_handlers/ret.rs#L123): `vm.state.current_frame.gas += leftover_gas`. This applies to all return types.

## 6. Storage gas and refunds

Gas accounting for `sload` / `sstore` is split: the *fixed* cost is the static instruction price (`SLOAD_COST = 2_008`, `SSTORE_COST = 5_511`); a *refund* is then handed back synchronously based on the slot's hot/cold status and pubdata accounting.

### 6.1 Refund constants

[world_diff.rs:525-527](../crates/vm2/src/world_diff.rs#L525-L527):

```rust
const WARM_READ_REFUND:                u32 = STORAGE_ACCESS_COLD_READ_COST  - STORAGE_ACCESS_WARM_READ_COST;
const WARM_WRITE_REFUND:               u32 = STORAGE_ACCESS_COLD_WRITE_COST - STORAGE_ACCESS_WARM_WRITE_COST;
const COLD_WRITE_AFTER_WARM_READ_REFUND: u32 = STORAGE_ACCESS_COLD_READ_COST;
```

The four `STORAGE_ACCESS_*_COST` constants come from `zkevm_opcode_defs::system_params`.

### 6.2 SLOAD refund

```rust
// world_diff.rs:91-101
let (value, newly_added) = self.read_storage_inner(...);
let refund = if !newly_added || world.is_free_storage_slot(&contract, &key) {
    WARM_READ_REFUND
} else {
    0
};
```

[world_diff.rs:84-101](../crates/vm2/src/world_diff.rs#L84-L101). First-time read of a non-free slot: refund 0 (you've effectively paid the cold price). Subsequent reads, or any read of a slot the world considers "free", refund the cold-vs-warm delta. The refund is added to the frame's gas right after the call:

```rust
// storage.rs:65-66
assert!(refund <= SLOAD_COST);
vm.state.current_frame.gas += refund;
```

[storage.rs:49-69](../crates/vm2/src/instruction_handlers/storage.rs#L49-L69).

There is also a `read_storage_without_refund` variant ([world_diff.rs:106-116](../crates/vm2/src/world_diff.rs#L106-L116)) used by the `farcall` decommit path — the comment notes this matches legacy `zk_evm` behavior (decommit-time reads must not be refunded).

### 6.3 SSTORE refund and pubdata

```rust
// world_diff.rs:205-242
if world.is_free_storage_slot(&contract, &key) {
    ...
    return WARM_WRITE_REFUND;
}

let update_cost = world.cost_of_writing_storage(*initial_value, value);
let prepaid     = self.paid_changes.insert((contract, key), update_cost).unwrap_or(0);

let refund = if self.written_storage_slots.add((contract, key)) {
    // First write to this slot
    if self.read_storage_slots.add((contract, key)) {
        0                                       // first read AND first write here: full cold cost
    } else {
        COLD_WRITE_AFTER_WARM_READ_REFUND       // already read warm, so refund the cold-read part
    }
} else {
    WARM_WRITE_REFUND                           // slot has been written before in this run
};

let pubdata_cost = (update_cost as i32) - (prepaid as i32);
self.pubdata.0  += pubdata_cost;
```

[world_diff.rs:169-242](../crates/vm2/src/world_diff.rs#L169-L242).

Two channels are tracked:

- **Refund (gas)**: returned to `current_frame.gas` at [storage.rs:30-31](../crates/vm2/src/instruction_handlers/storage.rs#L30-L31) (`assert!(refund <= SSTORE_COST)`).
- **Pubdata cost (i32)**: accumulated in `WorldDiff::pubdata`, separate from gas. The signed delta `update_cost − prepaid` lets the second write to the same slot recover (or be charged) the difference between what was already paid and what's currently due. Pubdata is *not* charged as gas inside the VM — it's exposed via [`pubdata()` (world_diff.rs:244)](../crates/vm2/src/world_diff.rs#L244) for higher-level (bootloader) accounting.

Transient storage (`sstore_transient` / `sload_transient`) only pays the static cost; no refund logic, no pubdata ([storage.rs:35-47](../crates/vm2/src/instruction_handlers/storage.rs#L35-L47), [storage.rs:72-85](../crates/vm2/src/instruction_handlers/storage.rs#L72-L85)).

## 7. Heap growth

Heaps are pay-as-you-grow with linear pricing: 1 erg per additional byte of paid bound. Each frame tracks its paid heap bound separately for the main heap and aux heap ([callframe.rs:35-38](../crates/vm2/src/callframe.rs#L35-L38)). The growth helper:

```rust
// heap_access.rs:151-161
pub(crate) fn grow_heap<T, W, H: HeapFromState>(
    state: &mut State<T, W>,
    new_bound: u32,
) -> Result<(), ()> {
    if let Some(to_pay) = new_bound.checked_sub(*H::get_heap_size(state)) {
        state.use_gas(to_pay)?;
        *H::get_heap_size(state) = new_bound;
    }
    Ok(())
}
```

[heap_access.rs:149-161](../crates/vm2/src/instruction_handlers/heap_access.rs#L149-L161). Note that this only *charges* — actual page allocation is lazy; the bootloader, which gets `u32::MAX` heap "for free" via stipend, never actually allocates that much physical memory.

The starting paid bound for a new frame is a stipend, which kind of frame it is determines which constant:

```rust
// callframe.rs:78-85
let heap_size = if is_kernel {
    NEW_KERNEL_FRAME_MEMORY_STIPEND
} else if is_evm_interpreter {
    NEW_EVM_FRAME_MEMORY_STIPEND
} else {
    NEW_FRAME_MEMORY_STIPEND
};
```

[callframe.rs:78-85](../crates/vm2/src/callframe.rs#L78-L85). This stipend is *initial bound*, not gas — heap usage up to it is implicitly free (no `use_gas` call has to happen because `to_pay = new_bound − heap_size` is `0` while `new_bound ≤ heap_size`).

## 8. Precompiles

`precompile_call` lets the **caller** (a trusted system contract) declare how much gas to burn:

```rust
// precompiles.rs:79-88
let aux_data = PrecompileAuxData::from_u256(Register2::get(args, &mut vm.state));
let Ok(()) = vm.state.use_gas(aux_data.extra_ergs_cost) else {
    Register1::set(args, &mut vm.state, U256::zero());
    return;
};
vm.world_diff.pubdata.0 += aux_data.extra_pubdata_cost as i32;
```

[precompiles.rs:67-130](../crates/vm2/src/instruction_handlers/precompiles.rs#L67-L130). If the caller's stated `extra_ergs_cost` exceeds available gas, the precompile call returns 0 (failure) without running. There is no per-precompile pricing table inside vm2 — the system contracts are trusted to compute the right cost. Pubdata is charged separately, same model as storage.

## 9. The `decommit` opcode (vs. far-call decommit)

The `Decommit` opcode (different from far-call decommit) lets the caller pre-budget the cost; if the bytecode was already decommitted, the budget is refunded:

```rust
// instruction_handlers/decommit.rs:21-40
let extra_cost = Register2::get(args, &mut vm.state).low_u32();
...
if vm.state.use_gas(extra_cost).is_err() || !is_valid_format(&buffer) {
    Register1::set(args, &mut vm.state, U256::zero());
    return;
}
let (code, is_fresh) = vm.world_diff.decommit_opcode(world, tracer, code_hash);
if !is_fresh {
    vm.state.current_frame.gas += extra_cost;
}
```

[instruction_handlers/decommit.rs:14-52](../crates/vm2/src/instruction_handlers/decommit.rs#L14-L52). The static instruction cost is paid as usual through the boilerplate; `extra_cost` is the per-call budget.

## 10. Putting it together — request flow for one instruction

For any opcode the order of gas operations is:

1. **Static cost** (`use_gas(args.get_static_gas_cost())`) — [common.rs:60](../crates/vm2/src/instruction_handlers/common.rs#L60). Failure → `free_panic`.
2. **Mode-requirements check** — same `if`; failure → `free_panic`.
3. **Predicate** — if false, the body is skipped (but step 1's gas is already spent).
4. **Body**, which may:
   - `use_gas(...)` for variable costs (e.g. heap growth, precompile burn, mandated gas, decommit cost).
   - Add to `current_frame.gas` (storage refunds, leftover-gas refund on return, decommit-opcode reuse).
   - Modify `world_diff.pubdata` (signed i32, separate channel from gas).
5. **PC advance**, then `after_instruction` tracer hook ([common.rs:73](../crates/vm2/src/instruction_handlers/common.rs#L73)).

## 11. Quick reference — values and where they come from

| Concept                            | Constant / formula                                         | Defined at                                                                                                       |
|------------------------------------|------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| Per-opcode static cost             | `parsed.variant.ergs_price()`                              | [decode.rs:43](../crates/vm2/src/decode.rs#L43) (sourced from `zkevm_opcode_defs`)                               |
| L1 message                         | `156_250`                                                  | [addressing_modes.rs:102](../crates/vm2/src/addressing_modes.rs#L102)                                            |
| Sstore                             | `5_511`                                                    | [addressing_modes.rs:103](../crates/vm2/src/addressing_modes.rs#L103)                                            |
| Sload                              | `2_008`                                                    | [addressing_modes.rs:104](../crates/vm2/src/addressing_modes.rs#L104)                                            |
| Invalid instruction                | `u32::MAX`                                                 | [addressing_modes.rs:105](../crates/vm2/src/addressing_modes.rs#L105)                                            |
| Decommit cost                      | `code_length_in_words × ERGS_PER_CODE_WORD_DECOMMITTMENT`  | [decommit.rs:121-122](../crates/vm2/src/decommit.rs#L121-L122)                                                   |
| Heap growth                        | `new_bound − current_heap_size` (1 erg per byte)           | [heap_access.rs:155-156](../crates/vm2/src/instruction_handlers/heap_access.rs#L155-L156)                        |
| Far-call gas cap                   | `caller_gas / 64 * 63`                                     | [far_call.rs:125](../crates/vm2/src/instruction_handlers/far_call.rs#L125)                                       |
| Warm-read refund                   | `STORAGE_ACCESS_COLD_READ_COST − STORAGE_ACCESS_WARM_READ_COST` | [world_diff.rs:525](../crates/vm2/src/world_diff.rs#L525)                                                  |
| Warm-write refund                  | `STORAGE_ACCESS_COLD_WRITE_COST − STORAGE_ACCESS_WARM_WRITE_COST` | [world_diff.rs:526](../crates/vm2/src/world_diff.rs#L526)                                                |
| Cold-write-after-warm-read refund  | `STORAGE_ACCESS_COLD_READ_COST`                            | [world_diff.rs:527](../crates/vm2/src/world_diff.rs#L527)                                                        |
| New-frame heap stipend             | `NEW_FRAME_MEMORY_STIPEND` / kernel / evm-interpreter      | [callframe.rs:78-85](../crates/vm2/src/callframe.rs#L78-L85)                                                     |

## 12. Comparison with the legacy `zk_evm` reference implementation

vm2 is intended to match the upstream `zk_evm` (the original EraVM Rust implementation, which the test suite uses as a "shadow" reference). For this section the upstream is taken from
[`zksync-protocol`@`55f7a4c`/`crates/zk_evm/src/`](https://github.com/matter-labs/zksync-protocol) (the revision currently pinned by [Cargo.toml:35](../Cargo.toml#L35)). I read both implementations side-by-side and verified the behaviors below.

### 12.1 Verified to match

| Topic | `zk_evm` location | vm2 location |
|---|---|---|
| Static cost charged before predicate | `cycle.rs:182-194` (ergs deducted at decode), `cycle.rs:246-250` (predicate-false masks to NOP after gas is gone) | [common.rs:60-67](../crates/vm2/src/instruction_handlers/common.rs#L60-L67) |
| OOG → set gas to 0 + panic | `cycle.rs:192-194` `ergs_remaining = 0` + `NOT_ENOUGH_ERGS`, then `mask_into_panic` at `cycle.rs:222-223` | [state.rs:88](../crates/vm2/src/state.rs#L88) zeroes, then `free_panic` ([ret.rs:147-159](../crates/vm2/src/instruction_handlers/ret.rs#L147-L159)) |
| 63/64 formula (literal `/64*63`, not `*63/64`) | `far_call.rs:579` `(remaining_ergs_to_pass / 64) * 63` | [far_call.rs:125](../crates/vm2/src/instruction_handlers/far_call.rs#L125) `gas / 64 * 63` |
| Mandated gas: burn caller's entire balance on shortfall | `far_call.rs` mandated-stipend block | [far_call.rs:89-97](../crates/vm2/src/instruction_handlers/far_call.rs#L89-L97) |
| **Decommit OOG does NOT burn gas** | `far_call.rs:545-550` — comment: *"do not burn, as it's irrelevant"* | [decommit.rs:166-178](../crates/vm2/src/decommit.rs#L166-L178) — comment: *"Unlike all other gas costs, this one is not paid if low on gas"* |
| Decommit cost: per-word, free if cached | `far_call.rs:538-542` (`prepared_decommmit_query.is_fresh`) | [decommit.rs:118-123](../crates/vm2/src/decommit.rs#L118-L123) |
| Failed-OOG decommit hashes still recorded as "used" | (legacy "used contracts" output) | [world_diff.rs:36-39](../crates/vm2/src/world_diff.rs#L36-L39), [decommit.rs:170-176](../crates/vm2/src/decommit.rs#L170-L176) |
| Leftover gas refunded on return (far and near) | zk_evm `ret.rs` adds callee leftover to caller | [ret.rs:123](../crates/vm2/src/instruction_handlers/ret.rs#L123) |
| Near call: `gas_to_pass == 0` ⇒ pass everything | `near_call.rs:42-57` `pass_all_ergs = ergs_passed == 0` | [near_call.rs:21-25](../crates/vm2/src/instruction_handlers/near_call.rs#L21-L25) |
| Memory stipends applied as initial heap bound (free up to stipend) | `far_call.rs:660-687` (`heap_bound: memory_stipend`) | [callframe.rs:78-100](../crates/vm2/src/callframe.rs#L78-L100) |
| Heap growth at 1 erg per byte | `uma.rs` using `MEMORY_GROWTH_ERGS_PER_BYTE` | [heap_access.rs:155-156](../crates/vm2/src/instruction_handlers/heap_access.rs#L155-L156) |
| Pubdata as separate signed `i32` accumulator | `helpers.rs:314-339` `add_pubdata_cost(PubdataCost(i32))` | [world_diff.rs:26](../crates/vm2/src/world_diff.rs#L26) |
| Storage refund constants (warm/cold deltas) | both crates pull `STORAGE_ACCESS_*_COST` from `zkevm_opcode_defs::system_params` | [world_diff.rs:5-7, 525-527](../crates/vm2/src/world_diff.rs#L525-L527) |
| Predicated/skipped instructions still pay static cost | `cycle.rs:182-194` (charge), `cycle.rs:246-250` (mask to NOP) — gas already gone | [common.rs:60-67](../crates/vm2/src/instruction_handlers/common.rs#L60-L67) (charge), [common.rs:69](../crates/vm2/src/instruction_handlers/common.rs#L69) (predicate) |

### 12.2 Structural differences with no observable effect

These are places where the two implementations look different at the file level but produce the same externally observable gas / pubdata state.

1. **Invalid-instruction sentinel.**
   - `zk_evm`: sets `ErrorFlags::INVALID_OPCODE` at `cycle.rs:177-178`, then `mask_into_panic` at `cycle.rs:222-223`. The original opcode's listed price has already been subtracted at `cycle.rs:187` before masking.
   - vm2: encodes the cost as `INVALID_INSTRUCTION_COST = u32::MAX` ([addressing_modes.rs:105](../crates/vm2/src/addressing_modes.rs#L105)) so the very first `use_gas` always fails and routes through `free_panic`. The dedicated `invalid()` handler at [ret.rs:161-168](../crates/vm2/src/instruction_handlers/ret.rs#L161-L168) also explicitly zeroes gas.

   End state in both: gas is zero, the VM reports a panic. The `u32::MAX` trick is a vm2 implementation shortcut, not a semantic change.

2. **Pubdata bookkeeping location.**
   - `zk_evm`: the VM core asks the `Storage` trait for the pubdata cost of each individual query and adds whatever the trait returns (`opcodes/execution/log.rs:235-247` plumbed through `helpers.rs:155-176, 314-339`). The "prepaid vs new" logic lives **inside the storage backend**.
   - vm2: the equivalent computation lives **inside the VM core** ([world_diff.rs:216-239](../crates/vm2/src/world_diff.rs#L216-L239)). It maintains its own `paid_changes: RollbackableMap<(H160, U256), u32>` and computes `pubdata_cost = update_cost − prepaid` itself, where `update_cost = world.cost_of_writing_storage(initial_value, value)`.

   Net delta is identical as long as `World::cost_of_writing_storage` agrees with what the legacy storage backend would have returned per query. This is the contract that shadow-mode tests verify; a misbehaving custom `World` could diverge, but that would be a `World` impl bug rather than a vm2/zk_evm semantic difference.

3. **Multi-cycle vs single-cycle opcodes.**
   - `zk_evm`: opcodes like UMA and far-call run across multiple machine cycles using `pending_exception` / `skip_cycle`; `cycle.rs:183-185` zeros `ergs_cost` on follow-up cycles ("we have already paid for it") so the same opcode isn't billed twice.
   - vm2: implements these as single instruction handlers and bills exactly once at entry.

   Total ergs charged per opcode invocation matches; the per-cycle accounting is invisible to anything that observes only frame state at instruction boundaries.

### 12.3 Caveats

- I did not numerically verify every refund constant inside the `system_params` module — both crates import the same upstream constants from `zkevm_opcode_defs::system_params`, so equality is by construction unless one of the crates ever overrides locally (it doesn't).
- The pinned `zksync-protocol` revision is marked `# TODO: Must be pinned before merge` in [Cargo.toml:34-35](../Cargo.toml#L34-L35); this analysis is only valid against `55f7a4c`. If that pin moves, re-verify, particularly `crates/zk_evm/src/vm_state/cycle.rs`, `opcodes/execution/far_call.rs`, `opcodes/execution/near_call.rs`, `opcodes/execution/log.rs`.

### 12.4 Bottom line

No material divergences in gas semantics. The places where the code reads differently (invalid-opcode sentinel, location of pubdata "prepaid" arithmetic, multi-cycle handling of UMA / far-call) all produce the same gas and pubdata state at instruction-level granularity, which is what the shadow-mode comparator checks.
