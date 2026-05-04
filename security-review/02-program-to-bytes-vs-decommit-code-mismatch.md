# Vuln 2: API Hygiene — `program_to_bytes` Round-Trip vs `World::decommit_code`

**Files:**
- [crates/vm2/src/instruction_handlers/far_call.rs:113-120](../crates/vm2/src/instruction_handlers/far_call.rs#L113-L120)
- [crates/vm2/src/instruction_handlers/far_call.rs:194-203](../crates/vm2/src/instruction_handlers/far_call.rs#L194-L203)
- [crates/vm2/src/instruction_handlers/decommit.rs:34-46](../crates/vm2/src/instruction_handlers/decommit.rs#L34-L46)

* **Severity:** LOW (informational / hardening)
* **Category:** api_contract / decommit_bytecode_loading
* **Confidence:** 3/10

## Description

The far-call handler materializes the callee's decommit page by re-encoding
`Program::code_page()` back into raw bytes via `program_to_bytes` (a naive
32-byte big-endian dump of each `U256`). The standalone `Decommit` opcode
instead calls `World::decommit_code(hash)` separately.

The `World` trait places no enforced constraint that
`program_to_bytes(world.decommit(hash)) == world.decommit_code(hash)`; the
in-tree TODO comment at far_call.rs:114-117 explicitly acknowledges this
awkwardness.

`Program::new` uses `chunks_exact(32)`, silently dropping any tail bytes
whose length is not a multiple of 32, and `Program::from_words` /
`Program::from_raw` decouple `code_page` from any raw bytes entirely. In
principle, a divergence between the two paths produces a code-page whose
contents disagree with what `Decommit` would observe for the same hash
(since `set_decommit_page` keys on `code_hash` and the first materializer
wins).

## Why this is not exploitable as written

1. **Bytecode formats are 32-byte aligned by spec.** Both
   `ContractCodeSha256Format` (EraVM) and `BlobSha256Format` (EVM blob
   `0x02`) require 32-byte aligned bytecode and are validated upstream
   ([decommit.rs:30-31](../crates/vm2/src/instruction_handlers/decommit.rs#L30-L31)).
   Under that invariant `program_to_bytes(Program::new(bytes))` is the
   identity function — the `chunks_exact(32)` tail-dropping never fires.

2. **The code page is not used for execution.** Execution dispatches from
   `program.instructions` (already parsed); the `CodePage` addressing mode
   ([addressing_modes.rs:459-468](../crates/vm2/src/addressing_modes.rs#L459-L468))
   reads `program.code_page()` (the in-memory `Vec<U256>`), not the
   materialized heap bytes. The materialized bytes are observable only via
   the fat pointer returned by the `Decommit` opcode, which narrows the
   blast radius substantially.

3. **Sequencer-vs-prover framing is off.** Both run the same `World`
   implementation in vm2's deployment context; a buggy impl would produce a
   self-consistent wrong answer, not a divergence. True sequencer/prover
   divergence requires the prover's bytecode loader (zk_evm) to disagree
   with vm2 — which is a separate question this report does not establish.

4. **The in-tree `World` impls do not diverge.** `TestWorld::decommit_code`
   derives its bytes from `decommit().code_page()`
   ([testonly.rs:67-77](../crates/vm2/src/testonly.rs#L67-L77)) and is
   trivially consistent. No concrete real-world implementation with a
   divergence is identified.

## Residual concern

This is an API-hygiene smell rather than a vulnerability:

- The trait silently makes consistency the implementer's responsibility
  with no docstring or test enforcing it.
- A future EVM-blob-aware `World` implementation that stored raw bytes
  with any wrapper / non-aligned tail and forgot to normalize one of the
  two methods would silently materialize different bytes depending on
  call order.

## Recommendation

Add a debug-mode equality assertion between
`program_to_bytes(&program)` and `world.decommit_code(hash)` in the
far-call materialization path, and exercise it across all in-tree `World`
implementations in CI. Optionally, tighten the `World` trait docstrings
to state that the two methods must agree byte-for-byte after the
`program_to_bytes` round-trip.

A more invasive fix — having `Program` carry the canonical raw bytes
alongside the parsed instructions, or routing far-call through
`World::decommit_code` and parsing on the VM side — would eliminate the
dual-source design entirely, but is not required to address the
exploitability concern.
