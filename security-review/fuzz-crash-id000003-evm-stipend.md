## AFL crash `id:000003` — fourth duplicate of the EVM frame memory stipend divergence

- **Severity:** MEDIUM (duplicate)
- **Category:** state divergence (vm2 vs zk_evm)
- **Confidence:** 9/10 — near-twin of `id:000002`; same `FarCall(Mimic)` from the same kernel caller, only register selection / destination address differ
- **Branch:** `popzxc-airbender-eravm`
- **Crash file:** [tests/afl-fuzz/out/default/crashes/id:000003,sig:06,src:013178,time:5726295,execs:135724813,op:havoc,rep:4](../tests/afl-fuzz/out/default/crashes/)
- **Related:** [fuzz-crash-id000000-evm-stipend.md](./fuzz-crash-id000000-evm-stipend.md) — root cause and suggested fix; [fuzz-crash-id000001-evm-stipend.md](./fuzz-crash-id000001-evm-stipend.md), [fuzz-crash-id000002-evm-stipend.md](./fuzz-crash-id000002-evm-stipend.md) — earlier duplicates.

## How to reproduce

From [tests/afl-fuzz](../tests/afl-fuzz):

```sh
RUST_BACKTRACE=1 cargo run --bin show_testcase \
  'out/default/crashes/id:000003,sig:06,src:013178,time:5726295,execs:135724813,op:havoc,rep:4'
```

Like `id:000002`, this crash sits directly in `crashes/` (no `crashes.<timestamp>/` archive prefix) because the AFL run that produced it shared the binary hash of the current target.

## Panic

Identical assertion site to all three prior crashes:

```
thread 'main' panicked at tests/afl-fuzz/src/show_testcase.rs:49:5:
assertion failed: `(left == right)`
```

The diff after running one instruction (left = zk_evm, right = vm2) — only the *new (called) frame's* heap/aux-heap bounds differ; every register, flag, prior frame, gas counter, sp and transaction number matches:

```diff
 UniversalVmFrame {
     address:      0x727265643a2025642e2045697468657220696e63,
     caller:       0xaa14b36237f4b4bc88cbc379ffeaf0816bed7ae0,
     code_address: 0x727265643a2025642e2045697468657220696e63,   // Mimic: caller==code_address
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

Same `57344 vs 4096` split as the previous three crashes.

## Reproducer state

Differences from `id:000002` are essentially cosmetic — the AFL mutation flipped a few registers and the destination address, leaving the relevant trigger conditions unchanged:

| Field                         | `id:000002`                            | `id:000003`                            |
| ---                           | ---                                    | ---                                    |
| Far-call mode                 | `Mimic`                                | `Mimic`                                |
| Predicate                     | `Ne`                                   | `Ne`                                   |
| Caller `address`              | `0x0000…b6d1` (kernel)                 | `0x0000…b6d1` (kernel)                 |
| Caller `is_kernel`            | `true`                                 | `true`                                 |
| Caller `is_static`            | `true`                                 | `true`                                 |
| Destination (`code_address`)  | `0x215d201b…473a201b`                  | `0x727265643a…20696e63`                |
| New frame `context_u128`      | `336 697 958 083 733 990 220 …`        | `338 027 186 079 518 906 093 …`        |
| `transaction_number`          | `45 923`                               | `45 923`                               |
| `raw_first_instruction`       | `8 247 217 543 509 498 921`            | `8 247 217 544 289 639 465`            |
| Source register `src1`        | `r4`                                   | `r12`                                  |
| AFL mutation that found it    | `op:havoc`                             | `op:havoc`                             |

Both new destinations are non-kernel (the leading 18 bytes of the address are not all zero, see [crates/vm2/src/decommit.rs:230-232](../crates/vm2/src/decommit.rs#L230-L232)). The register-selection delta (r4 → r12) only changes which fuzzed register supplies the destination address bits to the far-call ABI — the resulting destination still hits the non-kernel, EVM-format-hash branch in `decommit`.

Constants that matter for the bug (and that match across all four crashes):

- Mock world serves a single arbitrary `U256` for every deployer-storage read (see [crates/vm2/src/single_instruction_test/world.rs:23-30](../crates/vm2/src/single_instruction_test/world.rs#L23-L30) and [mock_array.rs:11-26](../crates/vm2/src/single_instruction_test/mock_array.rs#L11-L26)). Both VMs see the same 32 bytes.
- Caller-frame gas after the far-call matches across both VMs (1 290 008 297 — same as `id:000002`), so the divergence is **not** a payment failure.
- Caller is a kernel frame, so `is_constructor_call` is *not* forced to `false` at [far_call.rs:52](../crates/vm2/src/instruction_handlers/far_call.rs#L52); the bug fires through the same polarity of vm2's `is_constructed == is_constructor_call` predicate as `id:000002`.

Notably, the *new* frame's `context_u128` (`338 027 186 …`) differs from `id:000002`'s (`336 697 958 …`) — but `context_u128` is not part of the stipend rule, so this is irrelevant to the panic. It just confirms AFL flipped some bits in the caller-frame state and the corresponding `Mimic` ABI bytes that happened to alter the new-frame context.

## Root cause

Identical to `id:000000`. vm2 gates the EVM memory stipend on `is_evm`, which is only set when `V[0] == 0x02` *and* `is_constructed != is_constructor_call`. zk_evm derives the stipend from `code_version_byte == BlobSha256Format::VERSION_BYTE` (`V[0] == 0x02`) alone, regardless of whether the call masks to the default AA.

- **zk_evm** ([crates/zk_evm/src/opcodes/execution/far_call.rs:660-664](../../../.cargo/git/checkouts/zksync-protocol-b179bcff732d3550/55f7a4c/crates/zk_evm/src/opcodes/execution/far_call.rs#L660-L664)): stipend keyed only on `V[0]`.
- **vm2** ([crates/vm2/src/decommit.rs:100-110](../crates/vm2/src/decommit.rs#L100-L110) → [crates/vm2/src/callframe.rs:78-85](../crates/vm2/src/callframe.rs#L78-L85)): stipend keyed on `is_evm`, which silently flips off whenever the construction state matches the call type.

`id:000003` adds no new information about the bug beyond what `id:000002` already established — it's the same code path, the same trigger predicate, only different fuzzed bytes.

See [fuzz-crash-id000000-evm-stipend.md](./fuzz-crash-id000000-evm-stipend.md) for the full code-level walkthrough and proposed fix.

## Fuzzer bug or vm2 bug?

**Same underlying vm2 bug. Not a fuzzer artefact.**

- Mock storage is consistent across both VMs (same `MockRead.value_read`, same key, same return value).
- Both VMs reach the storage slot, both decommit successfully, and gas accounting matches (1 290 008 297 on both sides after the call).
- The divergence is in the stipend rule, not in any fuzz-only state.
- Edge coverage in this run diverged only slightly from `id:000002` (different `src1` register and a different fuzzed destination address), so AFL kept this as a separate corpus entry — that is by design. AFL deduplicates by edge-coverage hash, not by panic site or by underlying defect; tightly-clustered duplicates of a single bug are normal and expected.

The shrinking distance between consecutive saves (`id:000002` and `id:000003` differ in only one register selection and the destination bits) is the typical AFL pattern around an "easy" defect: once havoc finds a triggering ancestor, small mutations of it keep crashing the harness in slightly different basic-block traces. This *is not* evidence of multiple bugs — it is evidence that the single underlying bug sits on a wide reachability surface.

## Action

No new fix is required for `id:000003`. The remediation proposed for `id:000000` — decouple the stipend choice from `is_evm` and base it on `code_version_byte` alone, mirroring zk_evm — closes all four archived crashes (`id:000000`, `id:000001`, `id:000002`, `id:000003`). After the fix lands, all four should be re-run against the new binary as confirmation. No additional regression test is needed beyond the kernel-caller `Mimic` case already proposed for `id:000002`; `id:000003` exercises the same code path.
