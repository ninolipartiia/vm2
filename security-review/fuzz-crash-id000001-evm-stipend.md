# AFL crash `id:000001` — duplicate of the EVM frame memory stipend divergence

- **Severity:** MEDIUM (duplicate)
- **Category:** state divergence (vm2 vs zk_evm)
- **Confidence:** 9/10 — same divergence as `id:000000`, surfaced from a different starting state
- **Branch:** `popzxc-airbender-eravm`
- **Crash file:** [tests/afl-fuzz/out/default/crashes.2026-05-01-13:38:50/id:000001,sig:06,src:007692,time:2024381,execs:48210415,op:havoc,rep:14](../tests/afl-fuzz/out/default/crashes.2026-05-01-13:38:50/)
- **Related:** [fuzz-crash-id000000-evm-stipend.md](./fuzz-crash-id000000-evm-stipend.md) — root cause and suggested fix.

## How to reproduce

From [tests/afl-fuzz](../tests/afl-fuzz):

```sh
RUST_BACKTRACE=1 cargo run --bin show_testcase \
  'out/default/crashes.2026-05-01-13:38:50/id:000001,sig:06,src:007692,time:2024381,execs:48210415,op:havoc,rep:14'
```

Same `op:havoc` vs `op:colorization` is just AFL describing how it mutated to find this input; AFL kept it as a separate save because its edge-coverage signature differed slightly from `id:000000`, not because it was a different defect.

## Panic

Identical assertion site to `id:000000`:

```
thread 'main' panicked at tests/afl-fuzz/src/show_testcase.rs:49:5:
assertion failed: `(left == right)`
```

The diff after running one instruction (left = zk_evm, right = vm2):

```diff
 UniversalVmFrame {
     address:      0x010101010101010101010101010124010101c9ae,   // delegate-call: caller's storage addr
     caller:       0x60ec5fdce807d1e548e079ed6e0040636278c3cb,
     code_address: 0x73feb10a01010101000000000000000093a13200,
     sp: 0,
     exception_handler: 23017,
     gas: 0,
     is_static: true,
     ...
-    heap_bound:     57344,   // = NEW_EVM_FRAME_MEMORY_STIPEND  (56 << 10)
-    aux_heap_bound: 57344,
+    heap_bound:     4096,    // = NEW_FRAME_MEMORY_STIPEND       (1 << 12)
+    aux_heap_bound: 4096,
 }
```

Every other state component — registers, flags, prior frames, gas, sp, transaction number — matches between the two VMs. The only differing fields are the new (called) frame's `heap_bound`/`aux_heap_bound`, with the same `57344 vs 4096` split as `id:000000`.

## Reproducer state

Differences from `id:000000`, all incidental:

| Field | `id:000000` | `id:000001` |
|---|---|---|
| caller `address` | `0xf500…01c9ae` | `0x0101…01c9ae` |
| destination (`code_address`) | `0x7281ce0d…6ce6e6e4` | `0x73feb10a…93a13200` |
| caller `is_static` | `true` | `true` |
| caller `gas` after call | `3 295 677 904` | `3 429 922 632` |
| `transaction_number` | `27 428` | `257` |
| heap mock `value_read` | ASCII text | binary `[0, 1, 140, 34, …]` |
| AFL mutation that found it | `op:colorization` | `op:havoc` |

Constants that matter for the bug (and that match `id:000000`):

- Opcode: `FarCall(Delegate)` with predicate `Ge`.
- Destination is non-kernel (the leading 18 bytes are not all zero — see [crates/vm2/src/decommit.rs:230-232](../crates/vm2/src/decommit.rs#L230-L232)).
- Caller frame `is_kernel: false`, so `abi.is_constructor_call` is forced to `false` by [far_call.rs:52](../crates/vm2/src/instruction_handlers/far_call.rs#L52).
- Mock world serves a single arbitrary `U256` for every storage read; both VMs see the same bytes.
- Gas accounting agrees (caller-frame gas after the far-call matches across both VMs), so the divergence is **not** caused by a payment failure on either side.

## Root cause

Identical to `id:000000`: vm2 and zk_evm derive the new frame's memory stipend from the deployer-storage hash *differently*.

- **zk_evm** ([zk_evm/src/opcodes/execution/far_call.rs:660-664](../../../.cargo/git/checkouts/zksync-protocol-b179bcff732d3550/55f7a4c/crates/zk_evm/src/opcodes/execution/far_call.rs#L660-L664)) sets `memory_stipend_userspace = NEW_EVM_FRAME_MEMORY_STIPEND` whenever `code_version_byte == BlobSha256Format::VERSION_BYTE` (`V[0] == 0x02`), regardless of whether the call ultimately masks to default AA.
- **vm2** ([crates/vm2/src/decommit.rs:100-110](../crates/vm2/src/decommit.rs#L100-L110)) only sets `is_evm = true` when `V[0] == 0x02` *and* `is_constructed != is_constructor_call`. The `is_evm` bool is then plumbed through to [callframe.rs:78-85](../crates/vm2/src/callframe.rs#L78-L85), where it gates the EVM stipend.

When `V[0] == 0x02` and `is_constructed == is_constructor_call`, vm2 masks to the default AA and downgrades the stipend to `NEW_FRAME_MEMORY_STIPEND` (4096). zk_evm masks to the default AA but keeps `NEW_EVM_FRAME_MEMORY_STIPEND` (57344). With `is_constructor_call = false` forced by the non-kernel caller, vm2 takes the masking branch precisely when `V[1] == 0x00` (EVM bytecode at rest interpreted as in-construction by the call type) — same byte pattern that triggered `id:000000`.

See [fuzz-crash-id000000-evm-stipend.md](./fuzz-crash-id000000-evm-stipend.md) for the full code-level walkthrough.

## Fuzzer bug or vm2 bug?

**Same underlying vm2 issue. Not a fuzzer bug.** AFL deduplicates by edge-coverage signature, so divergent paths *into* the same defect can produce two saved crashes — it is normal and expected for AFL to keep both. Edge coverage diverged earlier in the trace (the fuzzed registers, flags, addresses and predicate evaluation differ), but the panic comes from the same `assert_eq!` and the same field of `UniversalVmFrame`.

## Action

No new fix is required for `id:000001`. The remediation proposed for `id:000000` (decouple the stipend choice from `is_evm` and base it on `code_version_byte` alone, mirroring zk_evm) closes both crashes. The regression test described in [fuzz-crash-id000000-evm-stipend.md](./fuzz-crash-id000000-evm-stipend.md#suggested-fix) covers this case as well; once that fix lands, both archived crashes should be re-run against the new binary as confirmation.
