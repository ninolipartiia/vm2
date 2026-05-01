# `vm2` — High-Performance Out-of-Circuit EraVM

A reimplementation of the ZKsync Era VM ("EraVM") executor, designed to drive transaction execution outside the prover's circuit (so it does **not** need to produce a SNARK witness — only correct state transitions). It is single-threaded, unsynchronized, and tuned around dispatching ~10⁸ instruction-handlers/sec.

The repo is two published crates plus tests:

- [crates/vm2-interface/](crates/vm2-interface/) — the *frozen* tracer/state-inspection ABI.
- [crates/vm2/](crates/vm2/) — the implementation (decoder, dispatch loop, callframes, heaps, world-diff, etc.).
- [tests/afl-fuzz/](tests/afl-fuzz/) — AFL fuzzing harness.

There is also a `single_instruction_test` cargo feature that swaps several modules ([single_instruction_test/](crates/vm2/src/single_instruction_test/)) for mocked, randomly-generated versions, so a single instruction can be cross-checked against the legacy `zk_evm`.

---

## 1. The execution loop is just chained function pointers

Everything else is in service of this code in [vm.rs:83-93](crates/vm2/src/vm.rs#L83-L93):

```rust
pub fn run(&mut self, world: &mut W, tracer: &mut T) -> ExecutionEnd {
    unsafe {
        loop {
            if let ExecutionStatus::Stopped(end) =
                ((*self.state.current_frame.pc).handler)(self, world, tracer)
            {
                return end;
            }
        }
    }
}
```

`current_frame.pc` is a `*const Instruction<T, W>` pointing into the contiguous slice owned by `Program::instructions`. Each `Instruction` is a `(handler: fn, arguments: 8-byte packed Arguments)` ([instruction.rs:11-25](crates/vm2/src/instruction.rs#L11-L25)). The handler decides the next `pc` (default: `pc.add(1)` inside the boilerplate), and the loop keeps invoking handlers until one returns `ExecutionStatus::Stopped`.

This is essentially a **threaded interpreter** in the dragon-book sense — there is no central `match`/dispatch table; opcode dispatch is the indirect call itself.

### The handler boilerplate

Every handler funnels through the same wrapper in [instruction_handlers/common.rs:36-81](crates/vm2/src/instruction_handlers/common.rs#L36-L81):

1. Read `Arguments` from the current instruction (`vm.state.current_frame.pc`).
2. Charge `static_gas_cost`. If gas runs out, **`free_panic`** — i.e. synthesize a `Ret<Panic>` in-place ([instruction_handlers/ret.rs:147-159](crates/vm2/src/instruction_handlers/ret.rs#L147-L159)).
3. Check `mode_requirements` (kernel/static).
4. Evaluate the predicate against the `Flags`. If unsatisfied, fire tracer hooks for `Nop`, advance `pc`, and return.
5. Otherwise: `tracer.before_instruction::<Op, _>`, `pc += 1`, run business logic, `tracer.after_instruction::<Op, _>`.

So normal control flow advances the PC *before* the business logic runs, but a handler can override `pc` (jumps, near calls, returns). Exceptional paths overwrite `pc` with `spontaneous_panic()` or `invalid_instruction()` — both are `'static` references to `Instruction`s that live outside any program ([ret.rs:170-191](crates/vm2/src/instruction_handlers/ret.rs#L170-L191)).

### How handlers get specialized — type-driven monomorphization

Handlers are generic functions, not table entries. The decoder picks one variant per source/destination/boolean flag with a custom `monomorphize!` macro ([instruction_handlers/monomorphization.rs](crates/vm2/src/instruction_handlers/monomorphization.rs)):

```rust
handler: monomorphize!(load [T W H] match_reg_imm src match_boolean increment),
```

That expands to (roughly) `load::<T, W, H, RegisterOrImmediateVariant, {true|false}>` — meaning every combination of addressing modes is its own monomorphized fn-pointer with no runtime branches inside. This is the central code-size↔throughput trade-off in the codebase.

---

## 2. The crate boundary: `vm2-interface`

The interface crate is deliberately small and frozen — see the long comment in [vm2-interface/src/lib.rs](crates/vm2-interface/src/lib.rs). The promise is: a tracer compiled against version `N` of this crate must keep working against any future VM that depends on version `≥ N`. The way new opcodes/methods are added is by *adding a new version of the trait*, not modifying the old one, and bridging via a blanket impl. This is the lesson from `multivm`-with-many-`zk_evm`-versions, baked into the architecture.

It defines four things:

- **`StateInterface`** + **`GlobalStateInterface`** ([state_interface.rs:4-67](crates/vm2-interface/src/state_interface.rs#L4-L67)): a read/write view onto registers, callframes, heaps, flags, storage, transient storage, events, pubdata. Implemented by the VM itself in [tracing.rs](crates/vm2/src/tracing.rs).
- **`CallframeInterface`** ([state_interface.rs:81-153](crates/vm2-interface/src/state_interface.rs#L81-L153)): per-frame view (gas, PC, exception handler, heap IDs/bounds, stack slot access). The VM exposes both far-call and near-call frames through this.
- **`HeapId`** ([state_interface.rs:159-179](crates/vm2-interface/src/state_interface.rs#L159-L179)): a `u32` identifying a memory page. Includes `FIRST_CALLDATA = 7`, `FIRST = 10`, `FIRST_AUX = 11` for the bootloader; everything else is allocated dynamically.
- **`Tracer`** ([tracer_interface.rs:260-287](crates/vm2-interface/src/tracer_interface.rs#L260-L287)): two `before_instruction` / `after_instruction` hooks generic over the type-level `OP: OpcodeType`. The `Opcode` enum and the `forall_simple_opcodes!` macro at [tracer_interface.rs:3-49](crates/vm2-interface/src/tracer_interface.rs#L3-L49) generate one zero-sized struct per opcode, which is what gets passed as the `OP` parameter from the boilerplate. Tracers can be tupled (`(A, B)`) to compose, and `()` is the no-op tracer.

The `World<T>` trait — the VM's hook into the embedder — is in the implementation crate ([lib.rs:95-109](crates/vm2/src/lib.rs#L95-L109)) because it uses `Program<T, W>`. It extends `StorageInterface` (read storage, cost-of-write, free-slot test) with `decommit`/`decommit_code` and an optional `precompiles()`.

---

## 3. The VM's data model

`VirtualMachine<T, W>` is generic over a tracer `T` and a world `W` ([vm.rs:30-36](crates/vm2/src/vm.rs#L30-L36)):

```rust
pub struct VirtualMachine<T, W> {
    pub(crate) world_diff: WorldDiff,
    pub(crate) state: State<T, W>,
    pub(crate) settings: Settings,
    pub(crate) stack_pool: StackPool,
    pub(crate) snapshot: Option<VmSnapshot>,
}
```

Two big trees: **`State`** (everything that the EraVM ISA reads or writes) and **`WorldDiff`** (everything the VM accumulates *for* the outside world: storage changes, events, pubdata, decommit cache).

### `State<T, W>` — registers, frames, heaps

Defined in [state.rs:18-31](crates/vm2/src/state.rs#L18-L31):

```rust
pub(crate) struct State<T, W> {
    registers: [U256; 16],
    register_pointer_flags: u16,           // bit i = is register i a fat pointer?
    flags: Flags,                          // 1 byte: LT/EQ/GT + ALWAYS bit
    current_frame: Callframe<T, W>,
    previous_frames: Vec<Callframe<T, W>>, // far-call stack
    heaps: Heaps,
    transaction_number: u16,
    context_u128: u128,
    next_base_page: u32,                   // page allocator cursor
}
```

Sixteen registers, each `U256`, each with a single "is pointer" bit packed into `register_pointer_flags`. The pointer-flag is what lets `FatPointer` survive in registers without a separate type.

### `Callframe<T, W>` — far calls, with embedded near calls

[callframe.rs:18-49](crates/vm2/src/callframe.rs#L18-L49):

- `address` / `code_address` / `caller` (delegate-call disambiguates these).
- `pc: *const Instruction<T, W>` — direct pointer into `program.instructions`.
- `program: Program<T, W>` — `Arc<[U256]>` (code page) + `Arc<[Instruction]>` (decoded), so cloning is two refcount bumps ([program.rs:14-29](crates/vm2/src/program.rs#L14-L29)).
- `stack: Box<Stack>` — the 64KB stack is a heap-allocated `[U256; 1<<16]` with a parallel pointer-bitset, recycled through `StackPool` to avoid hot 2 MiB zeroing on every call ([stack.rs:11-52](crates/vm2/src/stack.rs#L11-L52)). Dirty-area tracking (`dirty_areas: u64`) lets `zero()` skip untouched 1-KB regions.
- `near_calls: Vec<NearCallFrame>` — *near* calls don't push a new `Callframe`; they push into this Vec, snapshotting `(sp, gas, pc, exception_handler, world_before_this_frame)`. This is much cheaper than a full far-call.
- `heap` / `aux_heap` / `calldata_heap` (`HeapId`s) plus paid `heap_size` / `aux_heap_size` (memory growth charging).
- `heaps_i_am_keeping_alive: Vec<HeapId>` — for the heap-aliasing rule (see §4).
- `world_before_this_frame: Snapshot` — opaque token into `WorldDiff` to roll back on revert/panic.
- `is_kernel`, `is_static` — propagated from the call.

A *far call* allocates a new base page, derives `heap = base+2`, `aux = base+3`, `code = base`, pushes the parent into `previous_frames`, transfers ≤ 63/64 of the parent's gas, and zeroes the registers ([vm.rs:198-247](crates/vm2/src/vm.rs#L198-L247), [instruction_handlers/far_call.rs:135-158](crates/vm2/src/instruction_handlers/far_call.rs#L135-L158)).

A *near call* just pushes onto `near_calls` ([instruction_handlers/near_call.rs:11-36](crates/vm2/src/instruction_handlers/near_call.rs#L11-L36)) — same callframe, same registers, same heaps, just a saved (sp, gas, pc, exc-handler) and a `WorldDiff::snapshot()` for rollback.

`Ret` ([ret.rs:23-126](crates/vm2/src/instruction_handlers/ret.rs#L23-L126)) handles both: it first tries `pop_near_call()`; if that returns `None`, it falls back to `pop_frame`. If the return type is failure (`Revert`/`Panic`), it `world_diff.append_rollback_logs(&snapshot); world_diff.rollback(snapshot)`.

### `Heaps` — paged dynamic memory

[heap.rs:308-318](crates/vm2/src/heap.rs#L308-L318):

```rust
pub(crate) struct Heaps {
    static_memory: Heap,
    bootloader_calldata: Heap,
    bootloader_heap: Heap,
    bootloader_aux_heap: Heap,
    dynamic: Vec<DynamicPageGroup>,        // per-far-call group of {code, heap, aux}
    pagepool: PagePool,                    // recycled 4KB pages
    bootloader_heap_rollback_info: Vec<(u32, U256)>,
    bootloader_aux_rollback_info: Vec<(u32, U256)>,
}
```

A `Heap` is a `Vec<Option<HeapPage>>` where `HeapPage` is `Box<[u8; 4096]>` — sparse paged 32-bit memory. Pages are zeroed on allocation and recycled to a `PagePool` on deallocation. Reads of unpopulated pages return zero. Writes lazily allocate.

A `HeapId` decodes ([heap.rs:249-306](crates/vm2/src/heap.rs#L249-L306)) into one of: the four bootloader-fixed pages, or `Dynamic { group, kind ∈ {Code, Heap, Aux} }` where `group = (raw - STARTING_BASE_PAGE) / NEW_MEMORY_PAGES_PER_FAR_CALL`. So heap IDs are not opaque — they have arithmetic structure tied to far-call sequence numbers, which is what makes the calldata-forwarding rule in `Ret` work (see §4).

Bootloader heaps get *word-level* rollback logs: every `write_u256` to `HeapId::FIRST` or `FIRST_AUX` first reads and saves the prior 32 bytes ([heap.rs:433-442](crates/vm2/src/heap.rs#L433-L442)). That's why bootloader writes survive nested-frame rollback — only the bootloader gets this treatment because that's where snapshotting is allowed.

### `WorldDiff` — accumulated side effects with multi-level rollback

[world_diff.rs:18-53](crates/vm2/src/world_diff.rs#L18-L53). Every field is one of four rollbackable structures from [rollback.rs](crates/vm2/src/rollback.rs):

- `RollbackableMap<K, V>` — BTreeMap + history of `(key, prev_value)` pairs; snapshot is just the history length.
- `RollbackableSet<K>` — same for BTreeSet.
- `RollbackableLog<T>` — Vec; rollback truncates.
- `RollbackablePod<T: Copy>` — single value; snapshot is a copy.

A `Snapshot` is just a tuple of these history-lengths ([world_diff.rs:499-511](crates/vm2/src/world_diff.rs#L499-L511)). Cheap to take, cheap to roll back to — but **rollback is destructive**: it drains the history past the snapshot and replays inverses. So you can only roll back to a given snapshot once, and you can't roll back to one earlier than another rollback already consumed.

There are two tiers:

- **Internal snapshots** (`Snapshot`): taken on every near/far call, stored in the callframe; rolled back on revert/panic in `Ret`. Cover storage_changes, paid_changes, events, l2_to_l1_logs, transient_storage_changes, pubdata, plus length markers for storage_logs / rollback_storage_logs.
- **External snapshots** (`ExternalSnapshot`): taken only by the embedder via `VirtualMachine::make_snapshot()`, and only when `previous_frames.is_empty()` (i.e., still in the bootloader frame, [vm.rs:135-146](crates/vm2/src/vm.rs#L135-L146)). Additionally cover `decommitted_hashes`, `decommit_pinned_pages`, `read_storage_slots`, `written_storage_slots`, `storage_refunds`, `pubdata_costs` — the "warm/cold" and refund tracking that internal rollbacks deliberately preserve.

The hot/cold model matches the EraVM gas spec: `read_storage_slots` and `written_storage_slots` are `RollbackableSet`s tracking what's been touched in this *VM run* (not within a frame); the read/write fns return refunds based on whether `add()` returned `false` ([world_diff.rs:84-242](crates/vm2/src/world_diff.rs#L84-L242)).

`storage_initial_values` is a non-rollbackable `BTreeMap` cache of `World::read_storage()` results — it's just a lookup-amortizer, never affects correctness.

`decommitted_hashes` is also outside per-frame rollback because EraVM's gas model says decommits are paid once per VM-run, not per frame. The `DecommitState::Unsuccessful` variant ([world_diff.rs:67-80](crates/vm2/src/world_diff.rs#L67-L80)) is a deliberate legacy-compat hack: a far-call that ran out of gas before materializing a decommit is still reported in `used_contract_hashes` for shadow-mode comparison against the old VM.

---

## 4. Two model rules that show up everywhere

### a) Calldata pointers may not flow upward

When a frame returns a pointer (via `Ret`), [ret.rs:48-58](crates/vm2/src/instruction_handlers/ret.rs#L48-L58) checks (outside kernel mode):

```rust
pointer.memory_page.as_u32() >= base_page_from_heap(vm.state.current_frame.heap)
    && pointer.memory_page != vm.state.current_frame.calldata_heap
```

Translation: a callee can return a pointer into its own (or its descendants') heap, but not into its caller's heap, and not back into its own calldata. The structural reason ([callframe.rs:39-48](crates/vm2/src/callframe.rs#L39-L48)) is that returning the calldata pointer would create two paths — direct heap access *and* fat-pointer access — to the caller's memory, breaking the non-aliasing assumptions the rest of the VM relies on. The rule is enforced via `HeapId` arithmetic: page IDs are monotonically increasing per far call.

### b) Heap deallocation must respect dependencies

`heaps_i_am_keeping_alive: Vec<HeapId>` ([callframe.rs:43-48](crates/vm2/src/callframe.rs#L43-L48)) is the inverse: when a callee returns a pointer to one of its heaps, the caller adopts responsibility for keeping that heap alive. `pop_frame` ([vm.rs:249-283](crates/vm2/src/vm.rs#L249-L283)) deallocates the dying frame's `heap`/`aux_heap`/kept-alive set *except* the one being passed up and except any page pinned by `world_diff.is_decommit_page_pinned` (decommitted bytecodes are global and deduplicated, so they're pinned in `WorldDiff` and outlive their first frame).

---

## 5. Decoder + bytecode pipeline

`Program::new` ([program.rs:54-101](crates/vm2/src/program.rs#L54-L101)):

1. Group bytecode bytes into `u64` instruction words (8 bytes each) and `U256` code-page words (32 bytes each).
2. For each `u64`, call `decode()` ([decode.rs:28-332](crates/vm2/src/decode.rs#L28-L332)) which uses `EncodingModeProduction::parse_preliminary_variant_and_absolute_number` from `zkevm_opcode_defs` to extract:
   - `condition` → maps to `Predicate`.
   - `variant.opcode` → giant `match` selecting an `Instruction::from_*` constructor.
   - Source/destination operand types → `AnySource` / `AnyDestination` enums.
   - Various flag bits (`SET_FLAGS_FLAG_IDX`, `UMA_INCREMENT_FLAG_IDX`, etc.).
3. Each `Instruction::from_*` does the `monomorphize!`-driven specialization to pick the concrete `handler` fn-pointer.
4. Append an end-of-program marker — `Instruction::from_invalid()` if the program is short, or a `jump_to_beginning` handler if it's exactly `1 << 16` instructions (simulating 16-bit PC overflow as required by the spec).

The decoded instructions sit in `Arc<[Instruction<T, W>]>` so `Program::clone()` is two atomic increments. Both `Arc`s being unsafe-shareable across threads is irrelevant here because the `VirtualMachine` is single-threaded by design.

`Arguments` ([addressing_modes.rs:90-100](crates/vm2/src/addressing_modes.rs#L90-L100)) is exactly 8 bytes: two packed `RegisterAndImmediate` source/dest descriptors, two `u16` immediates, and two `u8`s for `(predicate | mode_requirements)` and `static_gas_cost`. Keeping it 8 bytes is load-bearing for instruction-cache density in the dispatch loop.

---

## 6. Integrations and side-channel APIs

### Tracer integration

[tracing.rs](crates/vm2/src/tracing.rs) implements `StateInterface` directly on `VirtualMachine<T, W>` and `GlobalStateInterface` on a transient `VmAndWorld<'a, T, W>` adapter that the boilerplate constructs whenever it calls a tracer method. The reason for the adapter: only `before_instruction`/`after_instruction` need access to the world (for `get_storage`), and lifetimes there must be reborrowable per-call. Tracer composition via tuples (`Tracer for (A, B)`) is in [tracer_interface.rs:340-359](crates/vm2-interface/src/tracer_interface.rs#L340-L359) and works as a linked list of arbitrarily many tracers.

### Precompiles

`World::precompiles()` returns `&impl Precompiles` (default `LegacyPrecompiles`). The `precompile_call` opcode ([precompiles.rs:67-130](crates/vm2/src/instruction_handlers/precompiles.rs#L67-L130)) parses an ABI describing input/output heap regions and a precompile address, calls into the `Precompiles` impl, and writes the output back to the heap. Crucially, the `aux_data` ABI lets the *caller* tell the VM how much gas/pubdata to charge — the comment at L77-78 says this is "safe because system contracts are trusted," which is the whole privilege model: precompile dispatch is itself a privileged opcode, only called from kernel-mode contracts.

### `single_instruction_test`

Behind the `single_instruction_test` cargo feature, `Heaps`, `Stack`, and `Program` are replaced by mocked, randomly-instantiated versions that allocate only the bytes/words actually touched by the instruction under test ([single_instruction_test/mod.rs](crates/vm2/src/single_instruction_test/mod.rs)). `into_zk_evm.rs` then converts the post-state back to a legacy `zk_evm` state for divergence checking. This is what underpins the AFL fuzzing.

---

## 7. Threading and `unsafe`

There is no concurrency. `VirtualMachine` holds raw pointers (`pc: *const Instruction`) and `Box<Stack>` allocated via `alloc_zeroed` ([stack.rs:23-25](crates/vm2/src/stack.rs#L23-L25)); the `Send`/`Sync` story is whatever auto-derives, and the dispatch loop dereferences `pc` through an `unsafe` block in [vm.rs:84](crates/vm2/src/vm.rs#L84). The invariant the code relies on is that `Program::instructions` is an `Arc<[Instruction]>` whose backing memory outlives the callframe holding the pointer, because every callframe owns a `Program: Clone` that has been `Arc::clone`'d. Special instructions outside any program (`PANIC`, `INVALID`, `jump_to_beginning`) are constructed as `'static` constants ([ret.rs:170-191](crates/vm2/src/instruction_handlers/ret.rs#L170-L191)) and the invariants in [callframe.rs:142-153](crates/vm2/src/callframe.rs#L142-L153) explicitly handle the case where `pc` doesn't lie within `program.instructions`.

`Stack` uses `unsafe` for two reasons: a manual `Box::from_raw(alloc_zeroed(...))` for the 2 MiB allocation (so it doesn't get a bulk `mov` from a stack-built temporary), and a manual `Clone` impl ([stack.rs:99-108](crates/vm2/src/stack.rs#L99-L108)) because the derive-generated clone overflows the *call* stack in debug mode. `FatPointer::from(U256)` does a `transmute<u128, FatPointer>` ([fat_pointer.rs:27-32](crates/vm2/src/fat_pointer.rs#L27-L32)) gated on `target_endian = "little"`.

So: assume single-threaded, little-endian, and that instruction memory is held alive by reference-counted `Program`s. Those are the load-bearing assumptions.

---

## 8. End-to-end: what one `vm.run()` actually does

1. `VirtualMachine::new` ([vm.rs:40-67](crates/vm2/src/vm.rs#L40-L67)) seeds the bootloader frame with the entry program, register `r1` set to a `FatPointer` over the calldata heap (`HeapId::FIRST_CALLDATA = 7`), and `next_base_page = STARTING_BASE_PAGE`.
2. `run()` enters the indirect-call loop.
3. Each handler:
   - Charges static gas, checks predicate/mode, calls `tracer.before_instruction::<Op, _>`.
   - Runs the business logic: read operands via the addressing-mode `Source` traits, mutate `state` and/or `world_diff`.
   - On `FarCall`: read a fat-pointer ABI from registers, call `WorldDiff::decommit` (charges the cold-decommit cost, returns an `UnpaidDecommit`), pay for it, `World::decommit` to get a `Program`, optionally materialize the decommit page into `Heaps`, push a new `Callframe`, take a `WorldDiff::snapshot()` ([far_call.rs:34-170](crates/vm2/src/instruction_handlers/far_call.rs#L34-L170)).
   - On `Ret`: pop frame (near or far), if failure call `world_diff.rollback(snapshot)`, restore registers, deliver return-data fat-pointer to caller's `r1`.
   - On a heap UMA op: bounds-check, `grow_heap` (charges memory expansion against the frame's gas), read/write through `Heaps`.
   - On storage: route through `WorldDiff` which records a `LogQuery`, computes refunds, charges pubdata.
   - Calls `tracer.after_instruction::<Op, _>` and merges its `ShouldStop` with its own status.
4. The loop exits via `ExecutionEnd::ProgramFinished | Reverted | Panicked | SuspendedOnHook(u32) | StoppedByTracer` ([instruction.rs:54-66](crates/vm2/src/instruction.rs#L54-L66)). `SuspendedOnHook` fires when the bootloader writes to `Settings.hook_address` — the caller can inspect bootloader state and call `run()` again to resume.

The embedder's responsibility is just: implement `World<T>` (storage + decommit + optional precompiles), build a `Program` from bootloader bytecode, construct a `VirtualMachine`, loop on `run()`/`resume_with_additional_gas_limit()`, and use `make_snapshot`/`rollback`/`pop_snapshot` at transaction boundaries.
