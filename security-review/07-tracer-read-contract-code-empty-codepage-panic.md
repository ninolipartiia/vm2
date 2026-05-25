# `CallframeInterface::read_contract_code` panics on the post-failed-far-call frame

- **Severity:** LOW (tracer-side host panic; only reachable if an embedder
  calls this accessor on the active frame after a failed `far_call`)
- **Category:** liveness / undocumented panic in public tracer API

## Summary

When a `far_call` cannot begin (no code at target, OOG on `pay_for_decommit`,
malformed `code_info`), vm2 installs `Program::new_panicking()`, whose
`code_page` is `vec![]`. The tracer-facing accessor `read_contract_code`
indexes this slice directly, so any tracer that calls it on the active
panic-frame triggers an out-of-bounds index panic and aborts the host.

## Affected code

[`crates/vm2/src/tracing.rs:245-247`](../crates/vm2/src/tracing.rs#L245-L247):

```rust
fn read_contract_code(&self, slot: u16) -> U256 {
    self.frame.program.code_page()[slot as usize]
}
```

`slot: u16` ranges `0..=65_535`; `code_page()` is empty for the
`Program::new_panicking()` frame installed at
[`far_call.rs:132`](../crates/vm2/src/instruction_handlers/far_call.rs#L132),
so every `slot` value panics.

## Why it is undocumented

The trait declaration ([`vm2-interface/src/state_interface.rs:151-152`](../crates/vm2-interface/src/state_interface.rs#L151-L152))
is:

```rust
/// Reads a word from the bytecode of the executing contract.
fn read_contract_code(&self, slot: u16) -> U256;
```

No `# Panics` note, no `Option`/`Result` return. The neighbouring
`program_counter` (line 99) explicitly documents the panic-frame case and
returns `Option<u16>`, so the trait author *is* aware of this VM state —
they just didn't extend the same handling here. An embedder reading the
trait would reasonably assume the call is total.


## Why severity is LOW

Embedder-conditional: the panic only fires if an embedder happens to call
this accessor on the active frame after a failed `far_call`. This reads
more like a dangerous-API shape than a concrete bug — the trait advertises
a total `u16 → U256` read with no panic warning, so any future tracer
written against the trait could fall into it.

## Fix

Bounds-check at the accessor:

```rust
fn read_contract_code(&self, slot: u16) -> U256 {
    self.frame
        .program
        .code_page()
        .get(slot as usize)
        .copied()
        .unwrap_or_default()
}
```

