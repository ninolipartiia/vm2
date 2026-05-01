# AFL crash `id:000000` — EVM frame memory stipend divergence on FarCall

- **Severity:** MEDIUM
- **Category:** state divergence (vm2 vs zk_evm)
- **Confidence:** 8/10
- **Branch:** `popzxc-airbender-eravm`
- **Crash file:** [tests/afl-fuzz/out/default/crashes.2026-05-01-13:38:50/id:000000,sig:06,src:013026,time:1767743,execs:40963283,op:colorization,rep:15](../tests/afl-fuzz/out/default/crashes.2026-05-01-13:38:50/)

## How to reproduce

From [tests/afl-fuzz](../tests/afl-fuzz):

```sh
RUST_BACKTRACE=1 cargo run --bin show_testcase \
  'out/default/crashes.2026-05-01-13:38:50/id:000000,sig:06,src:013026,time:1767743,execs:40963283,op:colorization,rep:15'
```

(Crashes were archived by AFL when the target binary hash changed; the `crashes.<timestamp>/` sibling is the real corpus, `crashes/` is empty save for `README.txt`.)

## Panic

```
thread 'main' panicked at tests/afl-fuzz/src/show_testcase.rs:49:5:
assertion failed: `(left == right)`
```

The differential harness in [tests/afl-fuzz/src/show_testcase.rs:49-52](../tests/afl-fuzz/src/show_testcase.rs#L49-L52) compares `UniversalVmState::from(zk_evm)` against `vm2_to_zk_evm(&vm, world.clone()).into()` after running a single instruction in both VMs.

The minimal diff (left = zk_evm, right = vm2):

```diff
 UniversalVmFrame {
     address: 0xf50000000000000000000000010101010101c9ae,   // delegate-call: caller's storage addr
     code_address: 0x7281ce0d203f204900000000000000006ce6e6e4,
     ...
-    heap_bound:     57344,   // = NEW_EVM_FRAME_MEMORY_STIPEND   (56 << 10)
-    aux_heap_bound: 57344,
+    heap_bound:     4096,    // = NEW_FRAME_MEMORY_STIPEND        (1 << 12)
+    aux_heap_bound: 4096,
 }
```

All other VM state — registers, flags, prior frames, gas, sp — agrees. The only divergence is the new (called) frame's heap/aux-heap bound.

## Reproducer state

- Opcode: `FarCall(Delegate)` (mode-requirements byte 24, predicate `Ge`).
- Destination address (`code_address` in the new frame): `0x7281ce0d203f204900000000000000006ce6e6e4` — **not** a kernel address (`is_kernel` requires `address.0[..18]` to be all zero, see [crates/vm2/src/decommit.rs:230-232](../crates/vm2/src/decommit.rs#L230-L232)).
- Caller frame: `is_kernel: false`, `is_static: true`, plenty of gas (`3 295 706 115`).
- Mock world serves a single arbitrary `U256` for *every* deployer-storage read (see [crates/vm2/src/single_instruction_test/world.rs:23-30](../crates/vm2/src/single_instruction_test/world.rs#L23-L30) and [mock_array.rs:11-26](../crates/vm2/src/single_instruction_test/mock_array.rs#L11-L26)). Both VMs receive the same bytes.

## Root cause

vm2 and zk_evm both read the deployer-system-contract storage slot keyed by the destination address. They get the same arbitrary 32-byte value `V`. They disagree on **how `V` selects the new frame's memory stipend**.

### zk_evm — stipend keyed *only* on `V[0]`

[crates/zk_evm/src/opcodes/execution/far_call.rs:660-668](../../../.cargo/git/checkouts/zksync-protocol-b179bcff732d3550/55f7a4c/crates/zk_evm/src/opcodes/execution/far_call.rs#L660-L668):

```rust
let memory_stipend_userspace = if code_version_byte == BlobSha256Format::VERSION_BYTE {
    NEW_EVM_FRAME_MEMORY_STIPEND   // 57344
} else {
    NEW_FRAME_MEMORY_STIPEND       // 4096
};
let memory_stipend = if address_is_kernel(&address_for_next) {
    NEW_KERNEL_FRAME_MEMORY_STIPEND
} else {
    memory_stipend_userspace
};
```

`code_version_byte` is just `V[0]`. zk_evm grants the EVM stipend whenever `V[0] == 0x02` (`BlobSha256Format::VERSION_BYTE`) — even when, later in the same handler, the call is masked to the default AA (`mask_to_default_aa = true`) because the construction state didn't match the call type.

### vm2 — stipend gated on a successful EVM-interpreter resolution

[crates/vm2/src/decommit.rs:60-111](../crates/vm2/src/decommit.rs#L60-L111):

```rust
let mut is_evm = false;
...
let is_constructed = match code_info_bytes[1] {
    0 => true,
    1 => false,
    _ => return None,
};
...
match code_info_bytes[0] {
    1 => { ... }
    2 => {
        if is_constructed == is_constructor_call {
            try_default_aa?            // <-- masks to default AA, is_evm stays false
        } else {
            is_evm = true;
            evm_interpreter_code_hash
        }
    }
    _ if code_info == U256::zero() => try_default_aa?,
    _ => return None,
}
```

[crates/vm2/src/callframe.rs:78-85](../crates/vm2/src/callframe.rs#L78-L85):

```rust
let heap_size = if is_kernel {
    NEW_KERNEL_FRAME_MEMORY_STIPEND
} else if is_evm_interpreter {
    NEW_EVM_FRAME_MEMORY_STIPEND
} else {
    NEW_FRAME_MEMORY_STIPEND
};
```

`is_evm_interpreter` is the `is_evm` bool plumbed through [far_call.rs:103,131,141](../crates/vm2/src/instruction_handlers/far_call.rs#L103). It is true **only** when `V[0] == 0x02` *and* `is_constructed != is_constructor_call`. If construction state matches, vm2 silently masks to the default AA and downgrades the stipend to `NEW_FRAME_MEMORY_STIPEND`.

### The exact storage value the fuzzer hit

The crash dump implies the arbitrary `V` returned by the mock satisfied `V[0] == 0x02` and `is_constructed == is_constructor_call` (so vm2 masks, zk_evm doesn't downgrade). With `is_constructor_call = false` for a non-kernel `Delegate` (forced by `abi.is_constructor_call = abi.is_constructor_call && current_frame.is_kernel` at [far_call.rs:52](../crates/vm2/src/instruction_handlers/far_call.rs#L52)), `is_constructed` must have been `false` — i.e. `V[1] == 0x01`, "EVM bytecode under construction". Calling unfinished EVM code as a normal (non-constructor) far-call: zk_evm masks to the default AA but keeps the EVM stipend; vm2 masks and uses the regular stipend.

## Fuzzer bug or vm2 bug?

**Real implementation difference between vm2 and zk_evm — the fuzzer is doing its job.**

The differential harness exposed a genuine semantic divergence: when a far-called address has an EVM-format hash whose construction state forces a default-AA mask, the two VMs assign different memory stipends to the new frame. This is not a fuzzer artefact:

- The mock storage is consistent across both VMs (same `MockRead.value_read`, same key, same return value).
- Both VMs reach the storage slot, both receive `V`, both succeed at decommit/payment (caller-frame gas matches: `3 295 677 904` on both sides).
- The divergence is in the stipend rule, not in any fuzz-only state.

zk_evm's behaviour predates vm2 and is the de-facto reference. **vm2 should match zk_evm**: derive `is_evm_interpreter` (for stipend purposes) from `V[0] == BlobSha256Format::VERSION_BYTE` alone, independent of the construction-state-vs-call-type comparison. The construction-state branch should only affect what bytecode actually runs (default AA vs EVM emulator), not the heap stipend.

### Reachability in production

Triggering this on a real chain requires the deployer storage slot for some address to hold a `0x02`-prefixed hash with `byte[1] == 0x01` (under construction) while a far call to it has `is_constructor_call == false` (or the symmetric `byte[1] == 0x00` + constructor call). That's the "transitional" state during EVM contract deployment — narrow, but reachable. The consequence is a 53 KiB difference in the called frame's free heap budget, which can change OOG outcomes and therefore consensus hash. Same severity bucket as `decommit-rollback-leak.md`: silent vm2-vs-zk_evm divergence on edge-case state.

## Suggested fix

Hoist the version-byte → stipend mapping out of the `is_evm`-success path. Either:

1. Always set `is_evm = (code_info_bytes[0] == 2)` regardless of `is_constructed`, and let the masking decide *which bytecode* to run while leaving the stipend tied to the version byte; or
2. Plumb `code_version_byte` separately from `is_evm` through to `Callframe::new` so the stipend choice mirrors zk_evm's `code_version_byte == BlobSha256Format::VERSION_BYTE` check exactly.

A regression test belongs in [crates/vm2/src/tests/divergence_regressions.rs](../crates/vm2/src/tests/divergence_regressions.rs): construct a delegate far-call to a non-kernel address whose deployer-storage hash starts with `0x02` and is "in construction", then assert the new frame's heap/aux-heap bound is `NEW_EVM_FRAME_MEMORY_STIPEND`.