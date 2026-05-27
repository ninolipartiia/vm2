# vm2 carries two PR #217 out-of-circuit fixes it hasn't applied (cumulative)

> **Cumulative issue.** PR #217 ("v31 ooc patch") made several changes to the
> out-of-circuit `zk_evm` so it matches the proving circuit. vm2 mirrors the
> *pre*-#217 `zk_evm` and is still missing the same changes. Each such gap is a
> subsection below; append new PR #217-class divergences here rather than opening
> a new file.

- **Severity:** MEDIUM — divergences; liveness ceiling
  (unprovable batch, or a differential-comparison mismatch once the dep
  advances), not theft.
- **Category:** determinism (register file; return-path gas).
- **Confidence:** High — verified on all three (pinned `zk_evm` @ `55f7a4c`, the
  proving circuit `zkevm_circuits`, and vm2) and against the PR #217 patch.
- **Status:** **NEW**
- **Reference:**
  [matter-labs/zksync-protocol PR #217 "feat: v31 ooc patch"](https://github.com/matter-labs/zksync-protocol/pull/217)
  (merge commit
  [`76452f79`](https://github.com/matter-labs/zksync-protocol/commit/76452f799091ae9a4524dd99a189e39ca46a1fbe),
  merged 2026-05-19).

## Shared context: PR #217 and the pinned-dependency caveat

The proving circuit `zkevm_circuits` defines the behavior a state transition must
satisfy to be provable. PR #217 fixed **two** places where the out-of-circuit
reference VM `zk_evm` computed a different result than the circuit
("overconstraint" divergences): the `dst1` register (Divergence 1) and the
`ret.panic` return-ABI heap-growth charge (Divergence 2). In both cases the
circuit was already correct and `zk_evm` was patched to match it.

vm2 reproduces the *pre*-#217 `zk_evm` behavior in both cases, so it currently:

- **agrees** with its pinned reference — vm2 pins `zk_evm` to the
  `popzxc-airbender-precompiles` branch at `55f7a4c`, which predates PR #217 — so
  the `single_instruction_test` differential harness shows no mismatch *today*;
- **disagrees with the proving circuit** now (→ unprovable batch); and
- **will disagree with `zk_evm`** as soon as the dependency is advanced past
  PR #217 (which it must be, to track the latest VM) → differential-comparison
  mismatch.

Neither divergence is reachable from zksolc / ordinary Solidity output; both
require a custom/malicious contract (details per subsection).

**Fix sequencing (applies to every divergence below).** Landing a vm2 fix while
still pinned to pre-#217 `zk_evm` makes vm2 newly diverge from its
`single_instruction_test` differential reference. Land each fix together with —
or after — advancing the `zk_evm` dependency past PR #217, and add a regression
test to
[crates/vm2/src/tests/divergence_regressions.rs](../../crates/vm2/src/tests/divergence_regressions.rs).

**Direction / why MEDIUM (both).** vm2 is *more permissive* than the circuit (it
keeps a value the spec clears / skips a charge the spec applies), so neither is a
soundness/forgery break — the stricter circuit rejects the divergent state. The
ceiling is liveness (unprovable batch / node crash), not theft.

---

## Divergence 1 — single-output opcodes leave `dst1` stale

**Rule.** On every executed, non-masked cycle the circuit clears the register
named by the second-destination nibble (`dst1_reg_idx`) to zero. Opcodes with a
real second output (`Mul` high word, `Div` remainder, increment-form UMA) write
it; all others (`Add`/`Sub`/`And`/`Or`/`Xor`/`Shl`/`Shr`/`Rol`/`Ror`, …) must
leave the zero. The circuit's `dst1` write is ungated (`write_as_dst1 =
*flag_dst1`, value defaulting to zero —
[`cycle.rs:334-336`](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zkevm_circuits/src/main_vm/cycle.rs#L334-L336),
[`decoded_opcode.rs:170-202`](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zkevm_circuits/src/main_vm/decoded_opcode.rs#L170-L202)).

**zk_evm fix.** Pre-#217, `zk_evm` wrote `dst1` only inside `Mul`/`Div`/`UMA` and
left it stale otherwise. PR #217 added the unconditional per-cycle clear before
`apply()` (`crates/zk_evm/src/vm_state/cycle.rs`):

```rust
self.update_register_value(after_masking_decoded.dst1_reg_idx, PrimitiveValue::empty());
after_masking_decoded.apply(self, prestate)?;
```

`update_register_value` is an r0-sink (writes only when the 1-based index is
`> 0`). PR #217 also adds `test_dirty_dst1_encoding_on_add` and a
`dirty_encoding_overconstraints.rs` suite that patches an `add` to carry a
non-zero `dst1` nibble.

**vm2's gap.** For single-output opcodes vm2 passes `SecondOutput = ()`, whose
writer is a no-op
([decode.rs:84-127](../../crates/vm2/src/decode.rs#L84-L127),
[binop.rs:152-155](../../crates/vm2/src/instruction_handlers/binop.rs#L152-L155)):

```rust
Opcode::Add(_) => binop!(Add, ()),     // second output = (), ignored
Opcode::Mul(_) => binop!(Mul, out2),   // only Mul/Div write out2
// ...
impl SecondOutput for () { fn write(self, _, _) {} }   // no-op
```

The per-instruction boilerplate doesn't zero `dst1` either
([common.rs:47-81](../../crates/vm2/src/instruction_handlers/common.rs#L47-L81)),
so the register named by the `dst1` nibble keeps its prior value.

**Divergence condition.** All of: (1) opcode does not itself write `dst1`
(anything but `Mul`/`Div`/increment-UMA); (2) the opcode actually executes
(predicate true, no error — NOP/PANIC masking resets `dst1_reg_idx = 0`,
[opcode.rs:53-65](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zkevm_opcode_defs/src/opcode.rs#L53-L65));
(3) the `dst1` nibble is non-zero (r0 is a sink in all three —
[addressing_modes.rs:493-498](../../crates/vm2/src/addressing_modes.rs#L493-L498)).
Then circuit/post-#217 `zk_evm` set `register[dst1] = 0`; vm2 leaves it stale.

**Reachability.** Not from zksolc — the assembler leaves `dst1_reg_idx = 0` for
single-output opcodes
([zkEVM-assembly/.../instruction/mod.rs:449-463](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zkEVM-assembly/src/assembly/instruction/mod.rs#L449-L463)).
But the decoder takes the raw high nibble for every opcode with no opcode-aware
validation
([encoding_mode_production.rs:93](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zkevm_opcode_defs/src/decoding/encoding_mode_production.rs#L93)),
so hand-crafted bytecode with a non-zero `dst1` nibble on an `add` reaches it
(this is what PR #217's "dirty encoding" tests cover).

**PoC.** Hand-assemble `add r1, r2, r3` with the dst byte's high nibble set to r5,
pre-load r5 with a sentinel, step once: circuit/post-#217 `zk_evm` → `r5 == 0`;
vm2 → `r5 == sentinel`.

---

## Divergence 2 — `ret.panic` skips the return-ABI heap-growth charge

**Rule.** On a **far** return the circuit parses the return-ABI fat pointer from
the *raw* source register and charges any implied heap growth — **even on
panic**. A crafted "quasi-fat-pointer" with forwarding mode `UseHeap`/`UseAuxHeap`
whose `start + length` overflows `u32` is flagged non-addressable and incurs the
`u32::MAX` growth penalty, draining the frame's ergs to zero. In the circuit the
panic erasure is for *returndata only* and uses the *pre-erasure* `upper_bound`:

[`call_ret_impl/ret.rs:108-110`](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zkevm_circuits/src/main_vm/opcodes/call_ret_impl/ret.rs#L108-L110):
```rust
let mut src0 = common_opcode_state.src0.clone();
src0.conditionally_erase(cs, is_ret_panic);   // erases returndata only, not upper_bound
```
[`call_ret_impl/ret.rs:257-275`](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zkevm_circuits/src/main_vm/opcodes/call_ret_impl/ret.rs#L257-L275):
```rust
let penalize_heap_overflow = multi_and(cs, &[is_non_addressable, do_not_forward_ptr]);
let upper_bound = select(cs, penalize_heap_overflow, &u32_max, &upper_bound);
// growth is gated on use_heap & execute & is_far_return — NOT on !panic
let grow_heap = multi_and(cs, &[forwarding_data.use_heap, execute, is_far_return]);
```

**zk_evm fix.** Pre-#217, `zk_evm`'s `ret` opcode zeroed `src0` whenever the inner
variant was `Panic`, *before* building the `RetABI` — so the crafted pointer was
never seen and no growth was charged. PR #217 deleted that block
(`crates/zk_evm/src/opcodes/execution/ret.rs`), so the OOC VM now parses the raw
ABI and charges the same penalty as the circuit:

```rust
//  --- removed by PR #217 ---
// on panic, we should never return any data. in this case, zero out src0 data
RetOpcode::Panic => { src0 = U256::default(); src0_is_ptr = false; }
```

PR #217 adds `test_ret_panic_heap_growth_overconstraint`
(`zkevm_test_harness/src/tests/simple_tests/far_call.rs`) whose testdata builds
`start = 0xFFFFFFFF, length = 1, UseHeap` and runs `ret.panic r1`. Its comments
state the divergence: OOC zeroes `src0` before parsing → `growth_cost = 0` →
ergs preserved, while the circuit parses the raw `r1` → `is_non_addressable` →
`u32::MAX` growth → ergs drained to 0, making the batch unprovable.

**vm2's gap.** On panic vm2 sets the return value to `None` and never parses the
return-ABI register, so the heap-growth path is skipped
([ret.rs:44-66](../../crates/vm2/src/instruction_handlers/ret.rs#L44-L66)):

```rust
let return_value_or_panic = if return_type == ReturnType::Panic {
    None                                  // <-- panic skips get_calldata entirely
} else {
    let (raw_abi, is_pointer) = Register1::get_with_pointer_flag(args, &mut vm.state);
    get_calldata(raw_abi, is_pointer, vm, false).filter(/* ... */)   // ret.ok / ret.revert DO charge
};
let leftover_gas = vm.state.current_frame.gas;   // no heap deduction on panic; returned to caller
```

vm2 already has the exact `u32::MAX` penalty — in `get_calldata`
([far_call.rs:209-256](../../crates/vm2/src/instruction_handlers/far_call.rs#L209-L256)):

```rust
if let Some(bound) = pointer.start.checked_add(pointer.length) {
    // ...
    grow(bound)?;
} else {
    grow(u32::MAX);   // drains all gas — identical to the circuit's penalty
    return None;
}
```

— but on the `ret` path it is reached only on the non-panic branch. (The failed
*far-call* path does reach it, via `already_failed = true`; only `ret.panic`
omits it.) So the caller receives the callee's full leftover gas where the
circuit would have burned it.

**Divergence condition.** Both of: (1) a **far** frame returns via `ret.panic`
specifically — `ret.ok`/`ret.revert` take vm2's `else` branch and *do* charge via
`get_calldata`, near returns and `free_panic` with `r0` carry no pointer, so none
of those diverge; (2) the source register encodes a fresh-pointer ABI
(`MakeNewPointer`, `UseHeap`/`UseAuxHeap`, `offset = 0`, integer) whose
`start + length` overflows `u32`. Then the circuit charges `u32::MAX` growth
(ergs → 0); vm2 charges nothing and returns the leftover ergs to the caller.

**Reachability.** Higher than Divergence 1: the trigger is a normal `ret.panic r1`
with a crafted value in `r1`, expressible in plain zkasm — the PR #217 testdata
callee compiles with the standard assembler. Still not emitted by zksolc for
ordinary Solidity (compiled panics use `r0` / a clean pointer), so it requires a
custom/malicious far-called contract.

**PoC.** Port the PR #217 testdata: a callee that builds `r1` with
`start = 0xFFFFFFFF, length = 1, UseHeap` then `ret.panic r1`; a caller that
records `ergs_left` before the far-call and after the panic returns to its
handler. Circuit / post-#217 `zk_evm`: caller ergs `== 0`; vm2 (and pinned
pre-#217 `zk_evm`): caller ergs preserved.

**Fix.** Don't short-circuit to `None` on `ReturnType::Panic`; resolve the return
pointer for *cost* (run the `get_calldata` / `grow(u32::MAX)` path) before
computing `leftover_gas`, and suppress only the *returndata* — mirroring the
circuit's "erase returndata, keep `upper_bound`" split, and matching how vm2's
own `ret.ok`/`ret.revert` paths already charge.

---

## Impact (both divergences)

Each makes vm2 compute observable state (register file / caller ergs) that the
stricter circuit cannot reproduce:

- **Unprovable batch (liveness / chain halt).** A sequencer using vm2 would commit
  a state transition for which no valid proof exists — exactly the
  "overconstraint" class PR #217 closed on the `zk_evm` side.
- **Differential-comparison failure — conditional on the `zk_evm` version.**
  Against the pinned pre-#217 `zk_evm` vm2 agrees (no mismatch yet); against
  post-#217 `zk_evm` the crafted input makes the two VMs disagree, so any check
  that compares their outputs aborts. Remotely triggerable by anyone who can
  deploy and call a contract.
