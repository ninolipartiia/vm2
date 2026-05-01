# EVM frame memory stipend divergence on FarCall (vm2 vs zk_evm)

- **Severity:** MEDIUM
- **Category:** state divergence (vm2 vs zk_evm)
- **Branch:** `popzxc-airbender-eravm`
- **Status:** fixed; covered by differential regression tests
- **Per-crash reports:**
  [`fuzz-crash-id000000`](./fuzz-crash-id000000-evm-stipend.md) ·
  [`fuzz-crash-id000001`](./fuzz-crash-id000001-evm-stipend.md) ·
  [`fuzz-crash-id000002`](./fuzz-crash-id000002-evm-stipend.md) ·
  [`fuzz-crash-id000003`](./fuzz-crash-id000003-evm-stipend.md)
- **Fix patch:** [`stipend-fix.patch`](./stipend-fix.patch)

## Summary

AFL surfaced four separate crashes (`id:000000`–`id:000003`) in the
[differential fuzz harness](../tests/afl-fuzz/src/show_testcase.rs#L49-L52). All
four panic at the same `assert_eq!` after one instruction, with the same
projected-state diff, and all four trace back to a single root cause in the
`FarCall` decommit path. The four reports above describe the crashes
individually; this document is the consolidated picture.

The panic, in every case, is on the *new* (called) frame's heap and aux-heap
bounds:

```diff
 UniversalVmFrame {
     // ... address / caller / code_address / sp / gas / is_static / ... all match ...
-    heap_bound:     57344,   // = NEW_EVM_FRAME_MEMORY_STIPEND  (56 << 10)
-    aux_heap_bound: 57344,
+    heap_bound:     4096,    // = NEW_FRAME_MEMORY_STIPEND       (1 << 12)
+    aux_heap_bound: 4096,
 }
```

Every other state component — registers, flags, prior frames, gas counters,
sp, transaction number — agrees between the two VMs. Only the new frame's
memory stipend differs, and only by exactly the EVM-vs-userspace stipend
delta (53 KiB).

## Root cause

vm2 and zk_evm both read the per-address code-info slot from
`AccountCodeStorage` and receive the same 32-byte value `V`. They disagree on
**how `V` selects the new frame's memory stipend.**

**zk_evm** keys the stipend on the version byte alone
([zk_evm/src/opcodes/execution/far_call.rs:660-668](../../../.cargo/git/checkouts/zksync-protocol-b179bcff732d3550/55f7a4c/crates/zk_evm/src/opcodes/execution/far_call.rs#L660-L668)):

```rust
let memory_stipend_userspace = if code_version_byte == BlobSha256Format::VERSION_BYTE {
    NEW_EVM_FRAME_MEMORY_STIPEND   // 57344
} else {
    NEW_FRAME_MEMORY_STIPEND       // 4096
};
```

— granted whenever `V[0] == 0x02`, even when the call is later masked to
the default AA because the construction state didn't match the call type.

**vm2 (pre-fix)** gates the stipend on `is_evm`, which is set in
[crates/vm2/src/decommit.rs](../crates/vm2/src/decommit.rs) only when
`V[0] == 0x02` *and* `is_constructed != is_constructor_call`:

```rust
match code_info_bytes[0] {
    2 => {
        if is_constructed == is_constructor_call {
            try_default_aa?            // is_evm stays false
        } else {
            is_evm = true;
            evm_interpreter_code_hash
        }
    }
    ...
}
```

When `V[0] == 0x02` *and* `is_constructed == is_constructor_call`, vm2
silently masks to the default AA *and* downgrades the stipend to
`NEW_FRAME_MEMORY_STIPEND` (4096). zk_evm masks to the default AA but keeps
`NEW_EVM_FRAME_MEMORY_STIPEND` (57344). That is the divergence.

The full code-level walkthrough — including the `is_constructor_call` mask
at [far_call.rs:52](../crates/vm2/src/instruction_handlers/far_call.rs#L52)
and the (post-fix) stipend selection in
[callframe.rs:78-88](../crates/vm2/src/callframe.rs#L78-L88) — lives in
[`fuzz-crash-id000000-evm-stipend.md`](./fuzz-crash-id000000-evm-stipend.md#root-cause).

## The four AFL crashes

AFL deduplicates by edge-coverage signature, not by panic site, so a single
defect can produce many saved corpora when the path leading into it varies.
The four archived crashes traverse the same `decommit` → `Callframe::new`
seam from four slightly different starting states:

| Crash | Far-call mode | Caller is_kernel | Predicate | Polarity of `is_constructed == is_constructor_call` | Report |
| --- | --- | --- | --- | --- | --- |
| `id:000000` | `Delegate` | `false` | `Ge` | `V[1]=0x01`, `is_constructor_call=false` (forced) | [report](./fuzz-crash-id000000-evm-stipend.md) |
| `id:000001` | `Delegate` | `false` | `Ge` | `V[1]=0x01`, `is_constructor_call=false` (forced) | [report](./fuzz-crash-id000001-evm-stipend.md) |
| `id:000002` | `Mimic`    | `true`  | `Ne` | `V[1]=0x00`, `is_constructor_call=true`            | [report](./fuzz-crash-id000002-evm-stipend.md) |
| `id:000003` | `Mimic`    | `true`  | `Ne` | `V[1]=0x00`, `is_constructor_call=true`            | [report](./fuzz-crash-id000003-evm-stipend.md) |

Both **polarities** of vm2's `is_constructed == is_constructor_call`
predicate hit the same masking branch and produce the same stipend
downgrade. Both far-call modes that flow through the divergent path
(`Delegate`, `Mimic`) reproduce the bug. `id:000001` and `id:000003` are
near-twins of `id:000000` and `id:000002` respectively, differing only in
fuzzed register choices and destination address bits.

To re-run any one of them after the fix, from
[`tests/afl-fuzz`](../tests/afl-fuzz):

```sh
RUST_BACKTRACE=1 cargo run --bin show_testcase \
  '<path-to-crash-file>'
```

The exact paths are in each per-crash report.

## Reachability

Gated on the chain having **EVM-on-EraVM contracts** enabled — i.e. the EVM
emulator system contract is live and at least one user has deployed EVM
bytecode through it. The two version bytes EraVM stores in
`AccountCodeStorage` are:

- `0x01` — `ContractCodeSha256Format` (native EraVM bytecode);
- `0x02` — `BlobSha256Format` (EVM bytecode, executed via the emulator).

Without EVM equivalence, the `code_info_bytes[0] == 2` arm of `decommit.rs`
is dead code in practice and the bug is unreachable.

With EVM equivalence live, the trigger window is **routine**:
[`ContractDeployer._constructEVMContract`](https://github.com/matter-labs/era-contracts/blob/zkos-v0.30.2/system-contracts/contracts/ContractDeployer.sol#L606-L638)
writes the `0x0201…` sentinel before invoking the EVM constructor and
replaces it with the constructed hash afterward. For the entire duration of
the constructor run, any non-constructor far-call into that address — most
commonly the EVM constructor calling a function on `this` — hits the
divergent path.

The **practical execution effect** is currently masked by `DefaultAccount`'s
ignore-modifiers (see
[`fuzz-crash-id000000-evm-stipend.md`](./fuzz-crash-id000000-evm-stipend.md#reachability-in-production)
for the full analysis), so the masked frame returns without growing its
heap. What still diverges is the `Callframe::heap_bound` /
`aux_heap_bound` snapshot field itself — exactly what the differential
harness caught — which any state representation hashing call-stack frame
fields would observe.

## Fix

`is_evm` retains its prior meaning (it drives the
`is_static && !is_evm_interpreter` rule and the `call_type` encoding in
`far_call.rs`). A separate `is_evm_blob_format` flag is set whenever
`code_info_bytes[0] == 0x02`, independent of the construction-state mask,
and plumbed through to `Callframe::new` to select the heap stipend:

```rust
// crates/vm2/src/decommit.rs:60-66
let mut is_evm = false;
// Whether the deployer-storage entry is in EVM blob format
// (code_version_byte == 0x02). Tracked separately from is_evm so that
// the new frame's heap stipend can match zk_evm, which keys the stipend
// on the version byte alone — even when the call ultimately masks to
// the default AA.
let mut is_evm_blob_format = false;
...
2 => {
    is_evm_blob_format = true;
    if is_constructed == is_constructor_call {
        try_default_aa?
    } else {
        is_evm = true;
        evm_interpreter_code_hash
    }
}
```

This mirrors zk_evm's own split between `code_version_byte` (drives the
stipend) and `call_to_evm_emulator` (drives static / call_type).

See [`stipend-fix.patch`](./stipend-fix.patch) for the full diff and the
post-fix code at
[`crates/vm2/src/decommit.rs`](../crates/vm2/src/decommit.rs) +
[`crates/vm2/src/callframe.rs`](../crates/vm2/src/callframe.rs).

## Regression tests

The bug is locked down by four differential regression tests in
[`tests/differential-regressions/src/tests/evm_stipend.rs`](../tests/differential-regressions/src/tests/evm_stipend.rs).
Each test builds the initial state explicitly, runs one instruction in
**both** vm2 and zk_evm via `step_diff`, and asserts that the projected
[`UniversalVmState`](../crates/vm2/src/single_instruction_test/universal_state.rs)
agrees. This is a true differential check — the fuzzer's mock world serves
the same bytes to both VMs, exactly as it did when AFL hit the original
crashes.

| Test | Crash(es) covered | Setup |
| --- | --- | --- |
| [`far_call_to_unconstructed_evm_grants_evm_stipend_matching_zk_evm`](../tests/differential-regressions/src/tests/evm_stipend.rs#L157) | `id:000000`, `id:000001` | non-kernel `FarCall<Delegate>`, non-kernel destination, `V[0]=0x02`, `V[1]=0x01` (in construction) |
| [`kernel_constructor_call_to_evm_grants_evm_stipend_matching_zk_evm`](../tests/differential-regressions/src/tests/evm_stipend.rs#L226) | `id:000002`, `id:000003` | kernel-caller `FarCall<Normal>` with `is_constructor_call=true`, non-kernel destination, `V[0]=0x02`, `V[1]=0x00` (constructed) — symmetric polarity |
| [`far_call_to_constructed_evm_matches_zk_evm`](../tests/differential-regressions/src/tests/evm_stipend.rs#L188) | non-divergent control | `V[0]=0x02`, `V[1]=0x00`, non-constructor delegate; the `is_constructed != is_constructor_call` branch — should pass under both pre- and post-fix |
| [`far_call_to_native_eravm_does_not_grant_evm_stipend`](../tests/differential-regressions/src/tests/evm_stipend.rs#L257) | negative control | `V[0]=0x01` (native EraVM); a regression that flipped `is_evm_blob_format=true` for non-EVM hashes would diverge here |

`Mimic`-mode coverage is not exercised separately because the stipend
selection runs through the same `decommit` + `Callframe::new` seam regardless
of mode (`id:000002` and `id:000003` confirmed this empirically); the
two productive tests above span both polarities of the predicate that was
the actual root cause.

The earlier in-tree single-VM check
(`far_call_to_unconstructed_evm_downgrades_stipend_versus_zk_evm` in
`crates/vm2/src/tests/divergence_regressions.rs`) was removed in favour of
these differential tests — it only ran vm2 with a hard-coded zk_evm
reference value rather than running zk_evm itself, which is a strictly
weaker check than `step_diff`.

## Confirmation

After the fix, the four archived crashes should be re-run against the new
binary using `show_testcase` (commands in each per-crash report). The
differential regression tests above are run on every `cargo test` of the
[`zksync_vm2_differential_regressions`](../tests/differential-regressions/Cargo.toml)
crate.
