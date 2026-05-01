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
- Mock world serves a single arbitrary `U256` for *every* `AccountCodeStorage` read (see [crates/vm2/src/single_instruction_test/world.rs:23-30](../crates/vm2/src/single_instruction_test/world.rs#L23-L30) and [mock_array.rs:11-26](../crates/vm2/src/single_instruction_test/mock_array.rs#L11-L26)). Both VMs receive the same bytes.

## Root cause

vm2 and zk_evm both read the per-address code-info slot from `AccountCodeStorage` (system contract at `0x8002`, see `ADDRESS_ACCOUNT_CODE_STORAGE` in [zkevm_opcode_defs/src/system_params.rs:70](../../../.cargo/git/checkouts/zksync-protocol-b179bcff732d3550/55f7a4c/crates/zkevm_opcode_defs/src/system_params.rs#L70)) keyed by the destination address. The vm2 constant `DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW` used at [decommit.rs:58](../crates/vm2/src/decommit.rs#L58) is a legacy misnomer: it resolves to `0x8002` (`AccountCodeStorage`), not `0x8006` (`ContractDeployer`). Records in this slot are written by `ContractDeployer.sol` via `storeAccountConstructing/ConstructedCodeHash`. Both VMs get the same arbitrary 32-byte value `V`. They disagree on **how `V` selects the new frame's memory stipend**.

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

The bug is gated on the chain having **EVM-on-EraVM contracts** — i.e. the EVM emulator system contract is enabled and at least one user has deployed EVM (Solidity) bytecode through it. EraVM stores two distinct version bytes in `AccountCodeStorage`'s per-address slot:

- `0x01` — `ContractCodeSha256Format`: native EraVM bytecode (compiled with `zksolc`/`zkvyper`); executed directly by the VM.
- `0x02` — `BlobSha256Format`: a hash of EVM bytecode; executed indirectly via the EVM emulator (a system contract that interprets EVM opcodes). Despite the name "Blob", this has nothing to do with L1 data-availability blobs — here it just means "an opaque blob of EVM bytecode that the emulator interprets at runtime". This is the format introduced as part of zksync-era's EVM-equivalence rollout.

The divergent code path in vm2 is the `code_info_bytes[0] == 2` arm of [crates/vm2/src/decommit.rs:100-110](../crates/vm2/src/decommit.rs#L100-L110). On a chain configured without the EVM emulator (older ZK Stack deployments, or appchains that opt out of EVM equivalence), no `AccountCodeStorage` entry ever has `V[0] == 0x02`, that arm is dead code in practice, and the bug is **not reachable**. The code path is latent there, waiting for EVM equivalence to ship.

On a chain where EVM equivalence *is* live, the trigger window is **routine, not narrow**. [`ContractDeployer._constructEVMContract`](https://github.com/matter-labs/era-contracts/blob/zkos-v0.30.2/system-contracts/contracts/ContractDeployer.sol#L606-L638) writes the in-construction marker as the literal sentinel `0x0201000000...` (`V[0]==0x02, V[1]==0x01`) at line 606, then runs the EVM constructor via `mimicCall` at line 619 with `_isConstructor: true`, then replaces the slot with the real "constructed" hash at line 638. For the entire duration of the constructor execution, the slot reads `0x0201...`. Any non-constructor far-call into `_newAddress` during that window — most commonly the EVM constructor calling a function on `this`, or a sibling EVM contract simultaneously under construction — hits the divergent path: `is_constructed=false`, `is_constructor_call=false`, vm2 masks to default AA, zk_evm keeps the EVM stipend. The symmetric polarity (`V[1] == 0x00` + constructor call) requires kernel-mode origin (forced by [far_call.rs:52](../crates/vm2/src/instruction_handlers/far_call.rs#L52)) and is uncommon. `AccountCodeStorage` is privileged (only `ContractDeployer` writes here), so an attacker cannot synthesise a `0x02`-prefixed entry, but they don't need to — deploying any EVM contract whose constructor self-calls is enough.

When the window hits, the called frame's free heap budget differs by 53 KiB (57 344 vs 4 096 bytes) — but the **practical consensus impact is bounded by what runs on the masked path, which is `DefaultAccount`**. Inspecting [DefaultAccount.sol](https://github.com/matter-labs/era-contracts/blob/5e7d0b405b49f42131565a291a82f22565f72e33/system-contracts/contracts/DefaultAccount.sol): every external entry point either carries the `ignoreNonBootloader` modifier ([line 31-37](https://github.com/matter-labs/era-contracts/blob/5e7d0b405b49f42131565a291a82f22565f72e33/system-contracts/contracts/DefaultAccount.sol#L31-L37) — `return(0,0)` for any non-bootloader caller) or `ignoreInDelegateCall` ([line 48-59](https://github.com/matter-labs/era-contracts/blob/5e7d0b405b49f42131565a291a82f22565f72e33/system-contracts/contracts/DefaultAccount.sol#L48-L59) — `return(0,0)` on delegate call, which is the exact opcode in the fuzz crash). The remaining bodies (`executeTransactionFromOutside`, `receive()`, `fallback()`) are empty. So the masked target returns essentially immediately without growing its heap toward either 4 KiB or 56 KiB, and the stipend mismatch does not translate into divergent gas consumption or OOG outcomes via the heap-grow opcode in current `DefaultAccount`. What *does* diverge is the snapshot field itself: `Callframe::heap_bound` / `aux_heap_bound` carry different values across vm2 and zk_evm during the masked frame's lifetime, which is exactly what the differential harness caught. Any state representation that hashes call-stack frame fields sees the divergence regardless of whether the called code uses the heap.

Net assessment: still MEDIUM. The trigger is broader than I first claimed (every EVM constructor performing inward calls), but the consequence is narrower (current `DefaultAccount` masks the practical execution effect). Relying on `DefaultAccount`'s accidental "doesn't grow heap" property to keep consensus alive is fragile — any future expansion of `DefaultAccount` to use ≥4 KiB scratch memory turns this latent snapshot-level divergence into a hard consensus split with no contract-level signal. Same severity bucket as `decommit-rollback-leak.md`: silent vm2-vs-zk_evm divergence on edge-case state, with a real but bounded reachability surface.

## Suggested fix

Hoist the version-byte → stipend mapping out of the `is_evm`-success path. Either:

1. Always set `is_evm = (code_info_bytes[0] == 2)` regardless of `is_constructed`, and let the masking decide *which bytecode* to run while leaving the stipend tied to the version byte; or
2. Plumb `code_version_byte` separately from `is_evm` through to `Callframe::new` so the stipend choice mirrors zk_evm's `code_version_byte == BlobSha256Format::VERSION_BYTE` check exactly.

A regression test belongs in [crates/vm2/src/tests/divergence_regressions.rs](../crates/vm2/src/tests/divergence_regressions.rs): construct a delegate far-call to a non-kernel address whose deployer-storage hash starts with `0x02` and is "in construction", then assert the new frame's heap/aux-heap bound is `NEW_EVM_FRAME_MEMORY_STIPEND`.