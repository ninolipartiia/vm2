## Vuln 2: API Hygiene — `program_to_bytes` Round-Trip vs `World::decommit_code`

**Files:**
- [crates/vm2/src/instruction_handlers/far_call.rs:113-120](../crates/vm2/src/instruction_handlers/far_call.rs#L113-L120)
- [crates/vm2/src/instruction_handlers/far_call.rs:194-203](../crates/vm2/src/instruction_handlers/far_call.rs#L194-L203)
- [crates/vm2/src/instruction_handlers/decommit.rs:34-46](../crates/vm2/src/instruction_handlers/decommit.rs#L34-L46)

* **Severity:** INFORMATIONAL (hardening)
* **Category:** api_contract / decommit_bytecode_loading
* **Confidence:** 3/10

## Description

The same code hash can be materialized to a heap page via two paths that
source bytes differently:

- **Far call:** `program_to_bytes(world.decommit(hash))` — re-encodes the
  parsed `Program::code_page()` (a `Vec<U256>`) by dumping each word as
  32 big-endian bytes.
- **`Decommit` opcode:** `world.decommit_code(hash)` — returns raw bytes
  directly.

`materialize_decommit_page` is keyed on `code_hash` and short-circuits on
the second call ([decommit.rs:24-26](../crates/vm2/src/decommit.rs#L24-L26)),
so whichever path runs first wins. If the two paths disagree byte-for-byte,
the heap contents observed for a given hash become call-order dependent.
The TODO at far_call.rs:114-117 explicitly flags the awkwardness.

## Why this is informational, not exploitable

1. **No execution-path consequence.** Instructions dispatch from
   `program.instructions` (already parsed); the `CodePage` addressing mode
   reads `program.code_page()` directly, not the heap. The materialized
   bytes are only observable through the fat pointer returned by the
   `Decommit` opcode.

2. **Bytecode is 32-byte aligned by spec.** Both `ContractCodeSha256Format`
   and `BlobSha256Format` require alignment, enforced at bytecode
   publication. Under that invariant `program_to_bytes ∘ Program::new` is
   the identity, so the `chunks_exact(32)` tail-drop in `Program::new`
   never fires for any hash a real deployer can produce. Far-call itself
   gates on `code_info_bytes[0] ∈ {1,2}` from deployer storage rather
   than re-validating, so the alignment guarantee is structural, not
   runtime-checked.

3. **No in-tree `World` impl diverges.** `TestWorld::decommit_code`
   ([testonly.rs:67-77](../crates/vm2/src/testonly.rs#L67-L77)) derives
   bytes from `decommit().code_page()`, making the round-trip trivially
   consistent.

4. **Not a vm2/zk_evm divergence.** Both paths run the same `World` impl
   in any given deployment; a buggy impl produces a self-consistent wrong
   answer, not a per-VM split.

## Residual concern

The `World` trait silently makes round-trip consistency the implementer's
responsibility — no docstring, no test enforces it. A future EVM-blob-aware
or wrapper-storing `World` that normalized one method but not the other
would produce call-order-dependent heap contents for the same hash.

## Recommendation

Document the invariant on the `World` trait
(`program_to_bytes(decommit(h)) == decommit_code(h)`) and add a debug
assertion in the far-call materialization path, exercised across in-tree
`World` impls in CI. A more invasive fix — having `Program` carry the
canonical raw bytes, or routing far-call through `decommit_code` and
parsing VM-side — would eliminate the dual-source design but is not
required.
