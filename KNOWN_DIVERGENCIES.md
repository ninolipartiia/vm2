## Known divergencies that are NOT implemented:

We don't implement them since they don't seem to affect the execution for our use cases.

### Event emission scope parity

Status: Not implemented

vm2 still gates event emission by a specific event-writer address, while zk_evm's event path is broader in kernel context execution. This remains an accepted divergence in the current branch scope.

- vm2 current behavior:
  - `crates/vm2/src/instruction_handlers/event.rs:17-29`
- zk_evm reference:
  - [crates/zk_evm/src/opcodes/execution/log.rs#L252-L289](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zk_evm/src/opcodes/execution/log.rs#L252-L289)

### Full shard metadata and shard behavior parity

Status: Not implemented

vm2 continues to treat shard support as limited scope, with multiple paths hardcoding shard-related values. Full shard semantics and metadata parity with zk_evm are intentionally deferred.

- vm2 current behavior:
  - `crates/vm2/src/instruction_handlers/context.rs:82-98`
  - `crates/vm2/src/instruction_handlers/far_call.rs:160-177`
- zk_evm reference:
  - [crates/zk_evm/src/opcodes/execution/far_call.rs#L94-L122](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zk_evm/src/opcodes/execution/far_call.rs#L94-L122)
  - [crates/zk_evm/src/opcodes/execution/log.rs#L64-L68](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zk_evm/src/opcodes/execution/log.rs#L64-L68)
  - [crates/zk_evm/src/opcodes/execution/log.rs#L276-L281](https://github.com/matter-labs/zksync-protocol/blob/main/crates/zk_evm/src/opcodes/execution/log.rs#L276-L281)
