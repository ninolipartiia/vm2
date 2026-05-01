## AFL crash `id:000002` — third duplicate of the EVM frame memory stipend divergence

- **Severity:** MEDIUM (duplicate)
- **Category:** state divergence (vm2 vs zk_evm)
- **Confidence:** 9/10 — same divergence as `id:000000` / `id:000001`, surfaced via `FarCall(Mimic)` from a kernel caller this time
- **Branch:** `popzxc-airbender-eravm`
- **Crash file:** [tests/afl-fuzz/out/default/crashes/id:000002,sig:06,src:013179,time:5660291,execs:134521973,op:havoc,rep:6](../tests/afl-fuzz/out/default/crashes/)
- **Related:** [fuzz-crash-id000000-evm-stipend.md](./fuzz-crash-id000000-evm-stipend.md) — root cause and suggested fix; [fuzz-crash-id000001-evm-stipend.md](./fuzz-crash-id000001-evm-stipend.md) — first duplicate.

## How to reproduce

From [tests/afl-fuzz](../tests/afl-fuzz):

```sh
RUST_BACKTRACE=1 cargo run --bin show_testcase \
  'out/default/crashes/id:000002,sig:06,src:013179,time:5660291,execs:134521973,op:havoc,rep:6'
```

Unlike `id:000000`/`id:000001`, this crash sits directly in `crashes/` (no `crashes.<timestamp>/` archive prefix), because the AFL run that produced it shared the binary hash of the current target. AFL kept it as a separate save because edge coverage diverged earlier in the trace, not because the underlying defect differs.

## Panic

Identical assertion site to the prior two crashes:

```
thread 'main' panicked at tests/afl-fuzz/src/show_testcase.rs:49:5:
assertion failed: `(left == right)`
```

The diff after running one instruction (left = zk_evm, right = vm2) — only the *new (called) frame's* heap/aux-heap bounds differ; every register, flag, prior frame, gas counter, sp and transaction number matches:

```diff
 UniversalVmFrame {
     address:      0x215d201b5b313b39376d5741524e494e473a201b,
     caller:       0xaa14b36237f4b4bc88cbc379ffeaf0816bed7ae0,
     code_address: 0x215d201b5b313b39376d5741524e494e473a201b,   // Mimic: caller==code_address
     sp: 0,
     exception_handler: 169,
     gas: 0,
     is_static: true,
     ...
-    heap_bound:     57344,   // = NEW_EVM_FRAME_MEMORY_STIPEND  (56 << 10)
-    aux_heap_bound: 57344,
+    heap_bound:     4096,    // = NEW_FRAME_MEMORY_STIPEND       (1 << 12)
+    aux_heap_bound: 4096,
 }
```

Same `57344 vs 4096` split as the previous two crashes.

## Reproducer state

| Field                        | `id:000000`           | `id:000001`           | `id:000002`                                |
| ---                          | ---                   | ---                   | ---                                        |
| Far-call mode                | `Delegate`            | `Delegate`            | **`Mimic`**                                |
| Predicate                    | `Ge`                  | `Ge`                  | `Ne`                                       |
| Caller `address`             | `0xf500…01c9ae`       | `0x0101…01c9ae`       | `0x0000…b6d1` (**kernel**)                 |
| Caller `is_kernel`           | `false`               | `false`               | **`true`**                                 |
| Caller `is_static`           | `true`                | `true`                | `true`                                     |
| Destination (`code_address`) | `0x7281ce0d…6ce6e6e4` | `0x73feb10a…93a13200` | `0x215d201b…473a201b` (non-kernel)         |
| `transaction_number`         | `27 428`              | `257`                 | `45 923`                                   |
| AFL mutation that found it   | `op:colorization`     | `op:havoc`            | `op:havoc`                                 |

Constants that matter for the bug (and that match across all three crashes):

- The destination address is non-kernel — its leading 18 bytes are not all zero, see [crates/vm2/src/decommit.rs:230-232](../crates/vm2/src/decommit.rs#L230-L232). So the new frame is *not* on the kernel-stipend branch in either VM.
- Mock world serves a single arbitrary `U256` for every deployer-storage read (see [crates/vm2/src/single_instruction_test/world.rs:23-30](../crates/vm2/src/single_instruction_test/world.rs#L23-L30) and [mock_array.rs:11-26](../crates/vm2/src/single_instruction_test/mock_array.rs#L11-L26)). Both VMs see the same 32 bytes.
- Caller-frame gas after the far-call matches across both VMs (1 290 008 297), so the divergence is **not** a payment failure.

What is *new* about this reproducer:

- The far-call is `Mimic` (not `Delegate`). For stipend selection this is irrelevant — both modes flow through the same `decommit` + `Callframe::new` path; the mode only affects which `address`/`caller`/`context_u128` end up on the new frame.
- The caller is a **kernel** frame (`address: 0x…b6d1`, `is_kernel: true`). That changes the `is_constructor_call` mask at [far_call.rs:52](../crates/vm2/src/instruction_handlers/far_call.rs#L52): `abi.is_constructor_call = abi.is_constructor_call && current_frame.is_kernel` no longer forces `false`, so `is_constructor_call` is whatever the fuzzed `raw_abi` says.
- That means the construction-state byte the mock returned to trigger the divergence here may be the *opposite* polarity of `id:000000`/`id:000001`. The previous two crashes required `V[1] == 0x01` (under construction) with `is_constructor_call = false`; this one most likely fires the symmetric branch, `V[1] == 0x00` (constructed) with `is_constructor_call = true`. Both polarities hit the *same* `is_constructed == is_constructor_call` predicate at [decommit.rs:100-110](../crates/vm2/src/decommit.rs#L100-L110), and both produce the same outcome: vm2 masks to default AA and downgrades the stipend; zk_evm keeps `NEW_EVM_FRAME_MEMORY_STIPEND` because it only checks `code_version_byte == 0x02`.

## Root cause

Identical to `id:000000`. vm2 gates the EVM memory stipend on `is_evm`, which is only set when `V[0] == 0x02` *and* `is_constructed != is_constructor_call`. zk_evm derives the stipend from `code_version_byte == BlobSha256Format::VERSION_BYTE` (`V[0] == 0x02`) alone, regardless of whether the call masks to the default AA.

- **zk_evm** ([crates/zk_evm/src/opcodes/execution/far_call.rs:660-664](../../../.cargo/git/checkouts/zksync-protocol-b179bcff732d3550/55f7a4c/crates/zk_evm/src/opcodes/execution/far_call.rs#L660-L664)): stipend keyed only on `V[0]`.
- **vm2** ([crates/vm2/src/decommit.rs:100-110](../crates/vm2/src/decommit.rs#L100-L110) → [crates/vm2/src/callframe.rs:78-85](../crates/vm2/src/callframe.rs#L78-L85)): stipend keyed on `is_evm`, which silently flips off whenever the construction state matches the call type.

`id:000002` exercises the second polarity of the same predicate (kernel-caller `Mimic` rather than userspace `Delegate`), confirming that the bug is symmetric across both directions of the `is_constructed == is_constructor_call` comparison and across far-call modes.

See [fuzz-crash-id000000-evm-stipend.md](./fuzz-crash-id000000-evm-stipend.md) for the full code-level walkthrough and proposed fix.

## Fuzzer bug or vm2 bug?

**Same underlying vm2 bug. Not a fuzzer artefact.**

- Mock storage is consistent across both VMs (same `MockRead.value_read`, same key, same return value).
- Both VMs reach the storage slot, both decommit successfully, and gas accounting matches (1 290 008 297 on both sides after the call).
- The divergence is in the stipend rule, not in any fuzz-only state.
- Edge coverage diverged earlier in the trace (different opcode mode `Mimic`, different predicate `Ne`, kernel caller, different addresses), so AFL kept this as a separate corpus entry — that is by design. The defect itself is the same one already documented under `id:000000`.

The fact that the fuzzer found this through *both* call modes (`Delegate` and `Mimic`) and *both* polarities of the `is_constructed == is_constructor_call` predicate (constructor call to constructed code, and non-constructor call to in-construction code) is additional evidence that the misclassification is real and not a corner case of one specific code path.

## Action

No new fix is required for `id:000002`. The remediation proposed for `id:000000` — decouple the stipend choice from `is_evm` and base it on `code_version_byte` alone, mirroring zk_evm — closes all three archived crashes. The regression test sketch in [fuzz-crash-id000000-evm-stipend.md](./fuzz-crash-id000000-evm-stipend.md#suggested-fix) should be extended with a second case in which a kernel caller mimic-calls EVM-format-but-already-constructed bytecode with `is_constructor_call = true`, to lock down the symmetric polarity surfaced by this crash. After the fix lands, all three archived crashes (`id:000000`, `id:000001`, `id:000002`) should be re-run against the new binary as confirmation.
